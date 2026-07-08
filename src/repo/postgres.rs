//! idm 仓储 Postgres 实现 —— sea-query 构建 + sqlx 执行(idm role 连接,search_path=idm)。

use async_trait::async_trait;
use sea_query::extension::postgres::PgExpr;
use sea_query::{
    Alias, Condition, Expr, ExprTrait, NullOrdering, OnConflict, Order, PostgresQueryBuilder,
    Query, SelectStatement,
};
use sea_query_sqlx::SqlxBinder;
use serde_json::{json, Value};
use sqlx::{AssertSqlSafe, PgPool, Postgres};
use time::OffsetDateTime;
use uuid::Uuid;

use super::{
    ListPage, Outbox, OutboxRecord, OutboxRepo, Role, RoleRepo, Roles, Session, SessionRepo,
    Sessions, SortDir, User, UserListFilter, UserListResult, UserListRow, UserPassword, UserRepo,
    UserRoles, UserSortBy, UserWithHash, Users,
};
use crate::error::IdmError;

/// EXISTS/NOT EXISTS 子查询:该 user 拥有名在 `names` 里的存活角色。相关子查询(引用外层 `users.id`)。
fn user_has_role_subquery(names: &[String]) -> SelectStatement {
    let mut sub = Query::select();
    sub.expr(Expr::val(1))
        .from(UserRoles::Table)
        .inner_join(
            Roles::Table,
            Expr::col((Roles::Table, Roles::Id)).equals((UserRoles::Table, UserRoles::RoleId)),
        )
        .and_where(
            Expr::col((UserRoles::Table, UserRoles::UserId)).equals((Users::Table, Users::Id)),
        )
        .and_where(Expr::col((Roles::Table, Roles::DeletedAt)).is_null())
        .and_where(Expr::col((Roles::Table, Roles::Name)).is_in(names.iter().cloned()));
    sub
}

/// 把 list 过滤条件(存活 + username 模糊 + created 区间 + roles_any/none)套到 select 上。
/// 主查询与 COUNT 查询共用,保证 total 与 rows 同一过滤口径。
fn apply_user_filters(q: &mut SelectStatement, filter: &UserListFilter) {
    q.and_where(Expr::col((Users::Table, Users::DeletedAt)).is_null());
    if let Some(u) = &filter.username {
        // 转义 LIKE 元字符(\ % _),让用户输入按字面子串匹配,与内存 `contains` 对齐。
        // PG 默认 LIKE 转义符是 \,故 \% \_ 即字面百分号/下划线。
        let esc = u
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        q.and_where(Expr::col((Users::Table, Users::Username)).ilike(format!("%{esc}%")));
    }
    if let Some(from) = filter.created_from {
        q.and_where(Expr::col((Users::Table, Users::CreatedAt)).gte(from));
    }
    if let Some(to) = filter.created_to {
        q.and_where(Expr::col((Users::Table, Users::CreatedAt)).lte(to));
    }
    if !filter.roles_any.is_empty() {
        q.and_where(Expr::exists(user_has_role_subquery(&filter.roles_any)));
    }
    if !filter.roles_none.is_empty() {
        q.and_where(Expr::not_exists(user_has_role_subquery(&filter.roles_none)));
    }
}

/// 唯一冲突(撞存活唯一索引)→ `Conflict`;其它库错误 → `Internal`(原始进日志)。
fn map_unique(e: sqlx::Error, msg: &str) -> IdmError {
    if let sqlx::Error::Database(db) = &e {
        if db.is_unique_violation() {
            return IdmError::Conflict(msg.to_owned());
        }
    }
    IdmError::Internal(e.into())
}

/// `user_roles.role_id` 外键冲突(role_id 不存在)→ `NotFound`,镜像内存 `resolve_role_names`
/// 对非法 role_id 的语义;其它库错误 → `Internal`(原始进日志)。
fn map_role_fk(e: sqlx::Error) -> IdmError {
    if let sqlx::Error::Database(db) = &e {
        if db.is_foreign_key_violation() {
            return IdmError::NotFound;
        }
    }
    IdmError::Internal(e.into())
}

// ── 用户 ──

pub struct PgUserRepo {
    pool: PgPool,
}
impl PgUserRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// find_by_identifier 的 join 行(users + user_password 扁平),转 `UserWithHash`。
#[derive(sqlx::FromRow)]
struct UserHashRow {
    id: Uuid,
    username: String,
    email: Option<String>,
    email_verified: bool,
    created_at: OffsetDateTime,
    password_hash: String,
}

#[async_trait]
impl UserRepo for PgUserRepo {
    async fn create(
        &self,
        username: &str,
        email: Option<&str>,
        password_hash: &str,
        by: Option<String>,
    ) -> Result<User, IdmError> {
        let id = Uuid::now_v7();
        // 同事务:users + user_password,任一失败回滚(凭据分表不会半截)。
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| IdmError::Internal(e.into()))?;

        let (usql, uvalues) = Query::insert()
            .into_table(Users::Table)
            .columns([
                Users::Id,
                Users::Username,
                Users::Email,
                Users::CreatedBy,
                Users::UpdatedBy,
            ])
            .values_panic([
                id.into(),
                username.to_owned().into(),
                email.map(str::to_owned).into(),
                by.clone().into(),
                by.into(),
            ])
            .returning(Query::returning().columns([
                Users::Id,
                Users::Username,
                Users::Email,
                Users::EmailVerified,
                Users::CreatedAt,
            ]))
            .build_sqlx(PostgresQueryBuilder);
        let user = sqlx::query_as_with::<Postgres, User, _>(AssertSqlSafe(usql), uvalues)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| map_unique(e, "Username or email already taken"))?;

        let (psql, pvalues) = Query::insert()
            .into_table(UserPassword::Table)
            .columns([UserPassword::UserId, UserPassword::PasswordHash])
            .values_panic([id.into(), password_hash.to_owned().into()])
            .build_sqlx(PostgresQueryBuilder);
        sqlx::query_with::<Postgres, _>(AssertSqlSafe(psql), pvalues)
            .execute(&mut *tx)
            .await
            .map_err(|e| IdmError::Internal(e.into()))?;

        emit_outbox(
            &mut tx,
            "user.created",
            user.id,
            json!({
                "user_id": user.id,
                "username": user.username,
                "email": user.email,
                "email_verified": user.email_verified,
                "created_at": user.created_at,
                "roles": Vec::<String>::new(),
            }),
        )
        .await?;

        tx.commit()
            .await
            .map_err(|e| IdmError::Internal(e.into()))?;
        Ok(user)
    }

    async fn find_by_identifier(&self, identifier: &str) -> Result<Option<UserWithHash>, IdmError> {
        // WHERE (username = $ OR email = $) AND deleted_at IS NULL
        let (sql, values) = Query::select()
            .column((Users::Table, Users::Id))
            .column((Users::Table, Users::Username))
            .column((Users::Table, Users::Email))
            .column((Users::Table, Users::EmailVerified))
            .column((Users::Table, Users::CreatedAt))
            .column((UserPassword::Table, UserPassword::PasswordHash))
            .from(Users::Table)
            .inner_join(
                UserPassword::Table,
                Expr::col((UserPassword::Table, UserPassword::UserId))
                    .equals((Users::Table, Users::Id)),
            )
            .cond_where(
                Condition::any()
                    .add(Expr::col((Users::Table, Users::Username)).eq(identifier))
                    .add(Expr::col((Users::Table, Users::Email)).eq(identifier)),
            )
            .and_where(Expr::col((Users::Table, Users::DeletedAt)).is_null())
            .build_sqlx(PostgresQueryBuilder);
        let row = sqlx::query_as_with::<Postgres, UserHashRow, _>(AssertSqlSafe(sql), values)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| IdmError::Internal(e.into()))?;
        Ok(row.map(|r| UserWithHash {
            user: User {
                id: r.id,
                username: r.username,
                email: r.email,
                email_verified: r.email_verified,
                created_at: r.created_at,
            },
            password_hash: r.password_hash,
        }))
    }

    async fn find_by_id(&self, id: Uuid) -> Result<User, IdmError> {
        let (sql, values) = Query::select()
            .columns([
                Users::Id,
                Users::Username,
                Users::Email,
                Users::EmailVerified,
                Users::CreatedAt,
            ])
            .from(Users::Table)
            .and_where(Expr::col(Users::Id).eq(id))
            .and_where(Expr::col(Users::DeletedAt).is_null())
            .build_sqlx(PostgresQueryBuilder);
        sqlx::query_as_with::<Postgres, User, _>(AssertSqlSafe(sql), values)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| IdmError::Internal(e.into()))?
            .ok_or(IdmError::NotFound)
    }

    async fn find_by_ids(&self, ids: &[Uuid]) -> Result<Vec<User>, IdmError> {
        if ids.is_empty() {
            return Ok(Vec::new()); // 空集省一次查询,也避开空 IN ()
        }
        let (sql, values) = Query::select()
            .columns([
                Users::Id,
                Users::Username,
                Users::Email,
                Users::EmailVerified,
                Users::CreatedAt,
            ])
            .from(Users::Table)
            .and_where(Expr::col(Users::Id).is_in(ids.iter().copied()))
            .and_where(Expr::col(Users::DeletedAt).is_null())
            .build_sqlx(PostgresQueryBuilder);
        sqlx::query_as_with::<Postgres, User, _>(AssertSqlSafe(sql), values)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| IdmError::Internal(e.into()))
    }

    async fn update(
        &self,
        id: Uuid,
        username: &str,
        email: Option<&str>,
        by: Option<String>,
    ) -> Result<User, IdmError> {
        // 事务:UPDATE + emit outbox 同提交(镜像 create/soft_delete)。
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| IdmError::Internal(e.into()))?;

        // PUT 全量替换:username/email 都 set(email 含清空 null),替换 email 即重置 email_verified。
        let (sql, values) = Query::update()
            .table(Users::Table)
            .value(Users::Username, username.to_owned())
            .value(Users::Email, email.map(str::to_owned))
            .value(Users::EmailVerified, false)
            .value(Users::UpdatedBy, by)
            .and_where(Expr::col(Users::Id).eq(id))
            .and_where(Expr::col(Users::DeletedAt).is_null())
            .returning(Query::returning().columns([
                Users::Id,
                Users::Username,
                Users::Email,
                Users::EmailVerified,
                Users::CreatedAt,
            ]))
            .build_sqlx(PostgresQueryBuilder);
        let user = sqlx::query_as_with::<Postgres, User, _>(AssertSqlSafe(sql), values)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| map_unique(e, "Username or email already taken"))?
            .ok_or(IdmError::NotFound)?;

        emit_outbox(
            &mut tx,
            "user.updated",
            user.id,
            json!({
                "user_id": user.id,
                "username": user.username,
                "email": user.email,
                "email_verified": user.email_verified,
            }),
        )
        .await?;

        tx.commit()
            .await
            .map_err(|e| IdmError::Internal(e.into()))?;
        Ok(user)
    }

    async fn soft_delete(&self, id: Uuid, by: Option<String>) -> Result<(), IdmError> {
        // 事务:UPDATE + emit outbox 同提交。
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| IdmError::Internal(e.into()))?;

        let (sql, values) = Query::update()
            .table(Users::Table)
            .value(Users::DeletedAt, OffsetDateTime::now_utc())
            .value(Users::UpdatedBy, by)
            .and_where(Expr::col(Users::Id).eq(id))
            .and_where(Expr::col(Users::DeletedAt).is_null())
            .build_sqlx(PostgresQueryBuilder);
        let res = sqlx::query_with::<Postgres, _>(AssertSqlSafe(sql), values)
            .execute(&mut *tx)
            .await
            .map_err(|e| IdmError::Internal(e.into()))?;
        if res.rows_affected() == 0 {
            return Err(IdmError::NotFound);
        }

        emit_outbox(&mut tx, "user.deleted", id, json!({ "user_id": id })).await?;

        tx.commit()
            .await
            .map_err(|e| IdmError::Internal(e.into()))?;
        Ok(())
    }

    async fn update_password(&self, user_id: Uuid, password_hash: &str) -> Result<(), IdmError> {
        let (sql, values) = Query::update()
            .table(UserPassword::Table)
            .value(UserPassword::PasswordHash, password_hash.to_owned())
            .value(UserPassword::PasswordUpdatedAt, OffsetDateTime::now_utc())
            .and_where(Expr::col(UserPassword::UserId).eq(user_id))
            .build_sqlx(PostgresQueryBuilder);
        sqlx::query_with::<Postgres, _>(AssertSqlSafe(sql), values)
            .execute(&self.pool)
            .await
            .map_err(|e| IdmError::Internal(e.into()))?;
        Ok(())
    }

    async fn password_hash(&self, user_id: Uuid) -> Result<Option<String>, IdmError> {
        // 仅存活用户:join users 过滤 deleted_at
        let (sql, values) = Query::select()
            .column((UserPassword::Table, UserPassword::PasswordHash))
            .from(UserPassword::Table)
            .inner_join(
                Users::Table,
                Expr::col((Users::Table, Users::Id))
                    .equals((UserPassword::Table, UserPassword::UserId)),
            )
            .and_where(Expr::col((Users::Table, Users::Id)).eq(user_id))
            .and_where(Expr::col((Users::Table, Users::DeletedAt)).is_null())
            .build_sqlx(PostgresQueryBuilder);
        sqlx::query_scalar_with::<Postgres, String, _>(AssertSqlSafe(sql), values)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| IdmError::Internal(e.into()))
    }

    async fn create_with_roles(
        &self,
        username: &str,
        email: Option<&str>,
        password_hash: &str,
        role_ids: &[Uuid],
        by: Option<String>,
    ) -> Result<User, IdmError> {
        let id = Uuid::now_v7();
        // 一个事务:users + user_password + user_roles,任一步失败整体回滚。
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| IdmError::Internal(e.into()))?;

        let (usql, uvalues) = Query::insert()
            .into_table(Users::Table)
            .columns([
                Users::Id,
                Users::Username,
                Users::Email,
                Users::CreatedBy,
                Users::UpdatedBy,
            ])
            .values_panic([
                id.into(),
                username.to_owned().into(),
                email.map(str::to_owned).into(),
                by.clone().into(),
                by.clone().into(),
            ])
            .returning(Query::returning().columns([
                Users::Id,
                Users::Username,
                Users::Email,
                Users::EmailVerified,
                Users::CreatedAt,
            ]))
            .build_sqlx(PostgresQueryBuilder);
        let user = sqlx::query_as_with::<Postgres, User, _>(AssertSqlSafe(usql), uvalues)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| map_unique(e, "Username or email already taken"))?;

        let (psql, pvalues) = Query::insert()
            .into_table(UserPassword::Table)
            .columns([UserPassword::UserId, UserPassword::PasswordHash])
            .values_panic([id.into(), password_hash.to_owned().into()])
            .build_sqlx(PostgresQueryBuilder);
        sqlx::query_with::<Postgres, _>(AssertSqlSafe(psql), pvalues)
            .execute(&mut *tx)
            .await
            .map_err(|e| IdmError::Internal(e.into()))?;

        if !role_ids.is_empty() {
            let mut q = Query::insert();
            q.into_table(UserRoles::Table).columns([
                UserRoles::UserId,
                UserRoles::RoleId,
                UserRoles::GrantedBy,
            ]);
            for rid in role_ids {
                q.values_panic([id.into(), (*rid).into(), by.clone().into()]);
            }
            q.on_conflict(
                OnConflict::columns([UserRoles::UserId, UserRoles::RoleId])
                    .do_nothing()
                    .to_owned(),
            );
            let (rsql, rvalues) = q.build_sqlx(PostgresQueryBuilder);
            sqlx::query_with::<Postgres, _>(AssertSqlSafe(rsql), rvalues)
                .execute(&mut *tx)
                .await
                .map_err(map_role_fk)?;
        }

        let role_names = resolve_role_names(&mut tx, role_ids).await?;
        emit_outbox(
            &mut tx,
            "user.created",
            user.id,
            json!({
                "user_id": user.id,
                "username": user.username,
                "email": user.email,
                "email_verified": user.email_verified,
                "created_at": user.created_at,
                "roles": role_names,
            }),
        )
        .await?;

        tx.commit()
            .await
            .map_err(|e| IdmError::Internal(e.into()))?;
        Ok(user)
    }

    async fn list(
        &self,
        filter: &UserListFilter,
        sort_by: UserSortBy,
        dir: SortDir,
        page: &ListPage,
    ) -> Result<UserListResult, IdmError> {
        let order = match dir {
            SortDir::Asc => Order::Asc,
            SortDir::Desc => Order::Desc,
        };
        // 排序主键表达式:字符串列(username/email)加 COLLATE "C" 强制字节序,与内存 str Ord parity
        // (否则 PG 按列 collation 可能大小写混排漂移)。created_at 是时间戳,无 collation。
        let sort_expr = match sort_by {
            UserSortBy::CreatedAt => Expr::col((Users::Table, Users::CreatedAt)),
            UserSortBy::Username => Expr::cust(r#""users"."username" COLLATE "C""#),
            UserSortBy::Email => Expr::cust(r#""users"."email" COLLATE "C""#),
        };

        let mut q = Query::select();
        q.column((Users::Table, Users::Id))
            .column((Users::Table, Users::Username))
            .column((Users::Table, Users::Email))
            .column((Users::Table, Users::EmailVerified))
            .column((Users::Table, Users::CreatedAt))
            // roles 列:相关子查询聚合成 text[](按名排序,parity with 内存)。
            .expr_as(
                Expr::cust(
                    "array(SELECT r.name FROM user_roles ur JOIN roles r ON r.id = ur.role_id \
                     WHERE ur.user_id = users.id AND r.deleted_at IS NULL ORDER BY r.name COLLATE \"C\")",
                ),
                Alias::new("roles"),
            )
            .from(Users::Table);
        apply_user_filters(&mut q, filter);

        // cursor keyset:id 相对 after(dir 决定方向)。
        if let ListPage::Cursor { after: Some(a), .. } = page {
            let cond = match dir {
                SortDir::Asc => Expr::col((Users::Table, Users::Id)).gt(*a),
                SortDir::Desc => Expr::col((Users::Table, Users::Id)).lt(*a),
            };
            q.and_where(cond);
        }

        q.order_by_expr_with_nulls(sort_expr, order.clone(), NullOrdering::Last)
            .order_by((Users::Table, Users::Id), order);

        match page {
            ListPage::Offset { offset, limit, .. } => {
                q.limit(*limit).offset(*offset);
            }
            ListPage::Cursor { limit, .. } => {
                q.limit(*limit + 1);
            }
        }

        let (sql, values) = q.build_sqlx(PostgresQueryBuilder);
        let mut rows = sqlx::query_as_with::<Postgres, UserListRow, _>(AssertSqlSafe(sql), values)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| IdmError::Internal(e.into()))?;

        let (total, next_after) = match page {
            ListPage::Offset { with_total, .. } => {
                let total = if *with_total {
                    let mut cq = Query::select();
                    cq.expr(Expr::col((Users::Table, Users::Id)).count())
                        .from(Users::Table);
                    apply_user_filters(&mut cq, filter);
                    let (csql, cvalues) = cq.build_sqlx(PostgresQueryBuilder);
                    let n =
                        sqlx::query_scalar_with::<Postgres, i64, _>(AssertSqlSafe(csql), cvalues)
                            .fetch_one(&self.pool)
                            .await
                            .map_err(|e| IdmError::Internal(e.into()))?;
                    Some(n as u64)
                } else {
                    None
                };
                (total, None)
            }
            ListPage::Cursor { limit, .. } => {
                let has_more = rows.len() as u64 > *limit;
                rows.truncate(*limit as usize);
                let next_after = if has_more {
                    rows.last().map(|r| r.id)
                } else {
                    None
                };
                (None, next_after)
            }
        };

        Ok(UserListResult {
            rows,
            total,
            next_after,
        })
    }
}

// ── 会话 ──

pub struct PgSessionRepo {
    pool: PgPool,
}
impl PgSessionRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SessionRepo for PgSessionRepo {
    async fn create(
        &self,
        user_id: Uuid,
        token_hash: &str,
        expires_at: OffsetDateTime,
        by: Option<String>,
    ) -> Result<Session, IdmError> {
        let id = Uuid::now_v7();
        let (sql, values) = Query::insert()
            .into_table(Sessions::Table)
            .columns([
                Sessions::Id,
                Sessions::UserId,
                Sessions::TokenHash,
                Sessions::ExpiresAt,
                Sessions::CreatedBy,
                Sessions::UpdatedBy,
            ])
            .values_panic([
                id.into(),
                user_id.into(),
                token_hash.to_owned().into(),
                expires_at.into(),
                by.clone().into(),
                by.into(),
            ])
            .build_sqlx(PostgresQueryBuilder);
        sqlx::query_with::<Postgres, _>(AssertSqlSafe(sql), values)
            .execute(&self.pool)
            .await
            .map_err(|e| IdmError::Internal(e.into()))?;
        Ok(Session { id, user_id })
    }

    async fn find_active(
        &self,
        token_hash: &str,
        now: OffsetDateTime,
    ) -> Result<Option<Session>, IdmError> {
        let (sql, values) = Query::select()
            .columns([Sessions::Id, Sessions::UserId])
            .from(Sessions::Table)
            .and_where(Expr::col(Sessions::TokenHash).eq(token_hash))
            .and_where(Expr::col(Sessions::RevokedAt).is_null())
            .and_where(Expr::col(Sessions::ExpiresAt).gt(now))
            .build_sqlx(PostgresQueryBuilder);
        sqlx::query_as_with::<Postgres, Session, _>(AssertSqlSafe(sql), values)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| IdmError::Internal(e.into()))
    }

    async fn revoke(&self, session_id: Uuid) -> Result<(), IdmError> {
        let (sql, values) = Query::update()
            .table(Sessions::Table)
            .value(Sessions::RevokedAt, OffsetDateTime::now_utc())
            .and_where(Expr::col(Sessions::Id).eq(session_id))
            .and_where(Expr::col(Sessions::RevokedAt).is_null())
            .build_sqlx(PostgresQueryBuilder);
        sqlx::query_with::<Postgres, _>(AssertSqlSafe(sql), values)
            .execute(&self.pool)
            .await
            .map_err(|e| IdmError::Internal(e.into()))?;
        Ok(())
    }

    async fn revoke_all(&self, user_id: Uuid, except: Option<Uuid>) -> Result<(), IdmError> {
        let mut q = Query::update();
        q.table(Sessions::Table)
            .value(Sessions::RevokedAt, OffsetDateTime::now_utc())
            .and_where(Expr::col(Sessions::UserId).eq(user_id))
            .and_where(Expr::col(Sessions::RevokedAt).is_null());
        if let Some(id) = except {
            q.and_where(Expr::col(Sessions::Id).ne(id));
        }
        let (sql, values) = q.build_sqlx(PostgresQueryBuilder);
        sqlx::query_with::<Postgres, _>(AssertSqlSafe(sql), values)
            .execute(&self.pool)
            .await
            .map_err(|e| IdmError::Internal(e.into()))?;
        Ok(())
    }
}

// ── 角色 ──

pub struct PgRoleRepo {
    pool: PgPool,
}
impl PgRoleRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RoleRepo for PgRoleRepo {
    async fn upsert(
        &self,
        name: &str,
        display_name: &str,
        by: Option<String>,
    ) -> Result<Uuid, IdmError> {
        // 幂等:先查存活同名(seed 单次串行跑,并发竞态可忽略;真要强一致再加 ON CONFLICT)。
        let (ssql, svalues) = Query::select()
            .column(Roles::Id)
            .from(Roles::Table)
            .and_where(Expr::col(Roles::Name).eq(name))
            .and_where(Expr::col(Roles::DeletedAt).is_null())
            .build_sqlx(PostgresQueryBuilder);
        if let Some(id) = sqlx::query_scalar_with::<Postgres, Uuid, _>(AssertSqlSafe(ssql), svalues)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| IdmError::Internal(e.into()))?
        {
            return Ok(id);
        }
        let id = Uuid::now_v7();
        let (isql, ivalues) = Query::insert()
            .into_table(Roles::Table)
            .columns([
                Roles::Id,
                Roles::Name,
                Roles::DisplayName,
                Roles::CreatedBy,
                Roles::UpdatedBy,
            ])
            .values_panic([
                id.into(),
                name.to_owned().into(),
                display_name.to_owned().into(),
                by.clone().into(),
                by.into(),
            ])
            .build_sqlx(PostgresQueryBuilder);
        sqlx::query_with::<Postgres, _>(AssertSqlSafe(isql), ivalues)
            .execute(&self.pool)
            .await
            .map_err(|e| map_unique(e, "Role name already exists"))?;
        Ok(id)
    }

    async fn grant(
        &self,
        user_id: Uuid,
        role_id: Uuid,
        by: Option<String>,
    ) -> Result<(), IdmError> {
        let (sql, values) = Query::insert()
            .into_table(UserRoles::Table)
            .columns([UserRoles::UserId, UserRoles::RoleId, UserRoles::GrantedBy])
            .values_panic([user_id.into(), role_id.into(), by.into()])
            .on_conflict(
                OnConflict::columns([UserRoles::UserId, UserRoles::RoleId])
                    .do_nothing()
                    .to_owned(),
            )
            .build_sqlx(PostgresQueryBuilder);
        sqlx::query_with::<Postgres, _>(AssertSqlSafe(sql), values)
            .execute(&self.pool)
            .await
            .map_err(|e| IdmError::Internal(e.into()))?;
        Ok(())
    }

    async fn roles_for_user(&self, user_id: Uuid) -> Result<Vec<String>, IdmError> {
        // SELECT r.name FROM user_roles ur JOIN roles r ON r.id = ur.role_id
        //   WHERE ur.user_id = $ AND r.deleted_at IS NULL
        let (sql, values) = Query::select()
            .column((Roles::Table, Roles::Name))
            .from(UserRoles::Table)
            .inner_join(
                Roles::Table,
                Expr::col((Roles::Table, Roles::Id)).equals((UserRoles::Table, UserRoles::RoleId)),
            )
            .and_where(Expr::col((UserRoles::Table, UserRoles::UserId)).eq(user_id))
            .and_where(Expr::col((Roles::Table, Roles::DeletedAt)).is_null())
            .build_sqlx(PostgresQueryBuilder);
        sqlx::query_scalar_with::<Postgres, String, _>(AssertSqlSafe(sql), values)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| IdmError::Internal(e.into()))
    }

    async fn list(&self) -> Result<Vec<Role>, IdmError> {
        // SELECT id, name, display_name FROM roles WHERE deleted_at IS NULL ORDER BY name
        let (sql, values) = Query::select()
            .columns([Roles::Id, Roles::Name, Roles::DisplayName])
            .from(Roles::Table)
            .and_where(Expr::col(Roles::DeletedAt).is_null())
            .order_by(Roles::Name, Order::Asc)
            .build_sqlx(PostgresQueryBuilder);
        sqlx::query_as_with::<Postgres, Role, _>(AssertSqlSafe(sql), values)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| IdmError::Internal(e.into()))
    }

    async fn set_roles(
        &self,
        user_id: Uuid,
        role_ids: &[Uuid],
        by: Option<String>,
    ) -> Result<(), IdmError> {
        // 一个事务:清该 user 全部授予,再批量加新(role_ids 空则只删)。幂等全量替换。
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| IdmError::Internal(e.into()))?;

        let (dsql, dvalues) = Query::delete()
            .from_table(UserRoles::Table)
            .and_where(Expr::col(UserRoles::UserId).eq(user_id))
            .build_sqlx(PostgresQueryBuilder);
        sqlx::query_with::<Postgres, _>(AssertSqlSafe(dsql), dvalues)
            .execute(&mut *tx)
            .await
            .map_err(|e| IdmError::Internal(e.into()))?;

        if !role_ids.is_empty() {
            let mut q = Query::insert();
            q.into_table(UserRoles::Table).columns([
                UserRoles::UserId,
                UserRoles::RoleId,
                UserRoles::GrantedBy,
            ]);
            for rid in role_ids {
                q.values_panic([user_id.into(), (*rid).into(), by.clone().into()]);
            }
            q.on_conflict(
                OnConflict::columns([UserRoles::UserId, UserRoles::RoleId])
                    .do_nothing()
                    .to_owned(),
            );
            let (isql, ivalues) = q.build_sqlx(PostgresQueryBuilder);
            sqlx::query_with::<Postgres, _>(AssertSqlSafe(isql), ivalues)
                .execute(&mut *tx)
                .await
                .map_err(map_role_fk)?;
        }

        let role_names = resolve_role_names(&mut tx, role_ids).await?;
        emit_outbox(
            &mut tx,
            "user.roles_set",
            user_id,
            json!({ "user_id": user_id, "roles": role_names }),
        )
        .await?;

        tx.commit()
            .await
            .map_err(|e| IdmError::Internal(e.into()))?;
        Ok(())
    }
}

// ── 发件箱(outbox)──

pub struct PgOutboxRepo {
    pool: PgPool,
}
impl PgOutboxRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl OutboxRepo for PgOutboxRepo {
    async fn poll_unpublished(&self, limit: i64) -> Result<Vec<OutboxRecord>, IdmError> {
        // 走部分索引 outbox_unpublished_idx(WHERE published_at IS NULL),按 id 升序 FIFO。
        let (sql, values) = Query::select()
            .columns([
                Outbox::Id,
                Outbox::EventType,
                Outbox::AggregateId,
                Outbox::Payload,
                Outbox::CreatedAt,
            ])
            .from(Outbox::Table)
            .and_where(Expr::col(Outbox::PublishedAt).is_null())
            .order_by(Outbox::Id, Order::Asc)
            .limit(std::cmp::max(limit, 0) as u64)
            .build_sqlx(PostgresQueryBuilder);
        sqlx::query_as_with::<Postgres, OutboxRecord, _>(AssertSqlSafe(sql), values)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| IdmError::Internal(e.into()))
    }

    async fn mark_published(&self, ids: &[i64]) -> Result<(), IdmError> {
        if ids.is_empty() {
            return Ok(()); // 空集省一次 UPDATE(同 find_by_ids 的空集短路)
        }
        let (sql, values) = Query::update()
            .table(Outbox::Table)
            .value(Outbox::PublishedAt, OffsetDateTime::now_utc())
            .and_where(Expr::col(Outbox::Id).is_in(ids.iter().copied()))
            .build_sqlx(PostgresQueryBuilder);
        sqlx::query_with::<Postgres, _>(AssertSqlSafe(sql), values)
            .execute(&self.pool)
            .await
            .map_err(|e| IdmError::Internal(e.into()))?;
        Ok(())
    }

    async fn emit(
        &self,
        event_type: &str,
        aggregate_id: Uuid,
        payload: Value,
    ) -> Result<(), IdmError> {
        // 与内部 `emit_outbox` 同一插入形状,但走本 repo 自己的连接池(非事务、单条)。
        let (sql, values) = Query::insert()
            .into_table(Outbox::Table)
            .columns([Outbox::EventType, Outbox::AggregateId, Outbox::Payload])
            .values_panic([
                event_type.to_owned().into(),
                aggregate_id.into(),
                payload.into(),
            ])
            .build_sqlx(PostgresQueryBuilder);
        sqlx::query_with::<Postgres, _>(AssertSqlSafe(sql), values)
            .execute(&self.pool)
            .await
            .map_err(|e| IdmError::Internal(e.into()))?;
        Ok(())
    }
}

/// 在给定事务上把 role_ids 解到存活角色名(按名排序,parity 内存侧 sort)——供 `create_with_roles`/
/// `set_roles` 的 outbox payload 用。非法(不存在的)role_id 在插 `user_roles` 时已被 FK 挡住、
/// 整个写方法提前 `?` 返回,故走到这里的 role_ids 必定已全部实际存在(可能含已软删角色,不强求"存活")。
async fn resolve_role_names(
    tx: &mut sqlx::Transaction<'_, Postgres>,
    role_ids: &[Uuid],
) -> Result<Vec<String>, IdmError> {
    if role_ids.is_empty() {
        return Ok(Vec::new());
    }
    // 按名排序须 COLLATE "C" 强制字节序,与内存 `.sort()` parity(同 `list()` 的排序理由)。
    let (sql, values) = Query::select()
        .column(Roles::Name)
        .from(Roles::Table)
        .and_where(Expr::col(Roles::Id).is_in(role_ids.iter().copied()))
        .and_where(Expr::col(Roles::DeletedAt).is_null())
        .order_by_expr(Expr::cust(r#""roles"."name" COLLATE "C""#), Order::Asc)
        .build_sqlx(PostgresQueryBuilder);
    sqlx::query_scalar_with::<Postgres, String, _>(AssertSqlSafe(sql), values)
        .fetch_all(&mut **tx)
        .await
        .map_err(|e| IdmError::Internal(e.into()))
}

/// 内部 emit 助手,由各 repo 写方法在其**已有事务**上调用:在给定 `&mut Transaction` 上插一行
/// outbox,不参与 `PgOutboxRepo` 自己的连接(`PgOutboxRepo` 只 poll/mark,不进写事务)。
pub(crate) async fn emit_outbox(
    tx: &mut sqlx::Transaction<'_, Postgres>,
    event_type: &str,
    aggregate_id: Uuid,
    payload: Value,
) -> Result<(), IdmError> {
    let (sql, values) = Query::insert()
        .into_table(Outbox::Table)
        .columns([Outbox::EventType, Outbox::AggregateId, Outbox::Payload])
        .values_panic([
            event_type.to_owned().into(),
            aggregate_id.into(),
            payload.into(),
        ])
        .build_sqlx(PostgresQueryBuilder);
    sqlx::query_with::<Postgres, _>(AssertSqlSafe(sql), values)
        .execute(&mut **tx)
        .await
        .map_err(|e| IdmError::Internal(e.into()))?;
    Ok(())
}
