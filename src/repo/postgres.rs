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
    finish_cursor_page, member_payload, tenant_payload, user_created_payload, ListPage, ListResult,
    MemberRepo, MemberRoles, Outbox, OutboxRecord, OutboxRepo, Role, RoleRepo, Roles, Session,
    SessionRepo, Sessions, SortDir, TenantMembers, TenantRepo, Tenants, User, UserListFilter,
    UserListResult, UserListRow, UserPassword, UserRepo, UserRoles, UserSortBy, UserWithHash,
    Users,
};
use crate::error::IdmError;
use crate::tenant::{MemberStatus, Membership, RoleScope, Tenant, TenantStatus};

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

/// 外键冲突(引用的角色 / 租户 / 用户不存在,如 `user_roles.role_id`)→ `NotFound`,镜像内存
/// `resolve_role_names` 对非法 role_id 的语义;其它库错误 → `Internal`(原始进日志)。
fn map_fk_not_found(e: sqlx::Error) -> IdmError {
    if let sqlx::Error::Database(db) = &e {
        if db.is_foreign_key_violation() {
            return IdmError::NotFound;
        }
    }
    IdmError::Internal(e.into())
}

/// 建号三处(create / create_with_roles / create_with_membership)共用:在调用方事务里插 users + user_password
/// (凭据分表),返回新用户。username / email 撞存活唯一索引 → `Conflict`。
async fn insert_user_with_password(
    tx: &mut sqlx::Transaction<'_, Postgres>,
    id: Uuid,
    username: &str,
    email: Option<&str>,
    password_hash: &str,
    by: Option<String>,
) -> Result<User, IdmError> {
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
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| map_unique(e, "Username or email already taken"))?;

    let (psql, pvalues) = Query::insert()
        .into_table(UserPassword::Table)
        .columns([UserPassword::UserId, UserPassword::PasswordHash])
        .values_panic([id.into(), password_hash.to_owned().into()])
        .build_sqlx(PostgresQueryBuilder);
    sqlx::query_with::<Postgres, _>(AssertSqlSafe(psql), pvalues)
        .execute(&mut **tx)
        .await
        .map_err(|e| IdmError::Internal(e.into()))?;
    Ok(user)
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
    #[tracing::instrument(name = "pg.users.create", skip_all)]
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

        let user =
            insert_user_with_password(&mut tx, id, username, email, password_hash, by).await?;

        emit_outbox(
            &mut tx,
            "user.created",
            user.id,
            user_created_payload(&user, &[]),
        )
        .await?;

        tx.commit()
            .await
            .map_err(|e| IdmError::Internal(e.into()))?;
        Ok(user)
    }

    #[tracing::instrument(name = "pg.users.find_by_identifier", skip_all)]
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

    #[tracing::instrument(name = "pg.users.find_by_id", skip_all)]
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

    #[tracing::instrument(name = "pg.users.find_by_ids", skip_all)]
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

    #[tracing::instrument(name = "pg.users.update", skip_all)]
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

    #[tracing::instrument(name = "pg.users.soft_delete", skip_all)]
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

    #[tracing::instrument(name = "pg.users.update_password", skip_all)]
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

    #[tracing::instrument(name = "pg.users.password_hash", skip_all)]
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

    #[tracing::instrument(name = "pg.users.create_with_roles", skip_all)]
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

        let user =
            insert_user_with_password(&mut tx, id, username, email, password_hash, by.clone())
                .await?;

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
                .map_err(map_fk_not_found)?;
        }

        let role_names = resolve_role_names(&mut tx, role_ids).await?;
        emit_outbox(
            &mut tx,
            "user.created",
            user.id,
            user_created_payload(&user, &role_names),
        )
        .await?;

        tx.commit()
            .await
            .map_err(|e| IdmError::Internal(e.into()))?;
        Ok(user)
    }

    #[tracing::instrument(name = "pg.users.create_with_membership", skip_all)]
    async fn create_with_membership(
        &self,
        username: &str,
        email: Option<&str>,
        password_hash: &str,
        tenant_id: Uuid,
        role_ids: &[Uuid],
        by: Option<String>,
    ) -> Result<User, IdmError> {
        let id = Uuid::now_v7();
        // 一个事务:users + user_password +(租户可加入时)tenant_members + member_roles,任一步失败整体回滚。
        let mut tx = self.pool.begin().await.map_err(internal)?;

        let user =
            insert_user_with_password(&mut tx, id, username, email, password_hash, by.clone())
                .await?;

        emit_outbox(
            &mut tx,
            "user.created",
            user.id,
            user_created_payload(&user, &[]),
        )
        .await?;

        // 租户须存活且 active(FOR SHARE:挡住同时进行的软删 / 停用);否则只建账号。
        let joinable: Option<i32> = sqlx::query_scalar(
            "select 1 from tenants where id = $1 and deleted_at is null and status = 'active' for share",
        )
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(internal)?;
        if joinable.is_some() {
            let (msql, mvalues) = Query::insert()
                .into_table(TenantMembers::Table)
                .columns([
                    TenantMembers::TenantId,
                    TenantMembers::UserId,
                    TenantMembers::AddedBy,
                ])
                .values_panic([tenant_id.into(), id.into(), by.clone().into()])
                .build_sqlx(PostgresQueryBuilder);
            sqlx::query_with::<Postgres, _>(AssertSqlSafe(msql), mvalues)
                .execute(&mut *tx)
                .await
                .map_err(internal)?;
            insert_member_roles(&mut tx, tenant_id, id, role_ids, &by).await?;
            let m = fetch_membership(&mut *tx, tenant_id, id)
                .await?
                .ok_or_else(|| IdmError::Internal(anyhow::anyhow!("刚插入的成员读不回")))?;
            emit_outbox(
                &mut tx,
                "tenant.member_added",
                tenant_id,
                member_payload(tenant_id, id, Some(m.status), Some(&m.roles)),
            )
            .await?;
        }

        tx.commit().await.map_err(internal)?;
        Ok(user)
    }

    #[tracing::instrument(name = "pg.users.list", skip_all)]
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
    #[tracing::instrument(name = "pg.sessions.create", skip_all)]
    async fn create(
        &self,
        user_id: Uuid,
        tenant_id: Option<Uuid>,
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
                Sessions::TenantId,
                Sessions::TokenHash,
                Sessions::ExpiresAt,
                Sessions::CreatedBy,
                Sessions::UpdatedBy,
            ])
            .values_panic([
                id.into(),
                user_id.into(),
                tenant_id.into(),
                token_hash.to_owned().into(),
                expires_at.into(),
                by.clone().into(),
                by.into(),
            ])
            .build_sqlx(PostgresQueryBuilder);
        sqlx::query_with::<Postgres, _>(AssertSqlSafe(sql), values)
            .execute(&self.pool)
            .await
            .map_err(map_fk_not_found)?;
        Ok(Session {
            id,
            user_id,
            tenant_id,
        })
    }

    #[tracing::instrument(name = "pg.sessions.find_active", skip_all)]
    async fn find_active(
        &self,
        token_hash: &str,
        now: OffsetDateTime,
    ) -> Result<Option<Session>, IdmError> {
        let (sql, values) = Query::select()
            .columns([Sessions::Id, Sessions::UserId, Sessions::TenantId])
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

    #[tracing::instrument(name = "pg.sessions.revoke", skip_all)]
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

    #[tracing::instrument(name = "pg.sessions.revoke_all", skip_all)]
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

    #[tracing::instrument(name = "pg.sessions.revoke_for_member", skip_all)]
    async fn revoke_for_member(&self, tenant_id: Uuid, user_id: Uuid) -> Result<(), IdmError> {
        let (sql, values) = Query::update()
            .table(Sessions::Table)
            .value(Sessions::RevokedAt, OffsetDateTime::now_utc())
            .and_where(Expr::col(Sessions::TenantId).eq(tenant_id))
            .and_where(Expr::col(Sessions::UserId).eq(user_id))
            .and_where(Expr::col(Sessions::RevokedAt).is_null())
            .build_sqlx(PostgresQueryBuilder);
        sqlx::query_with::<Postgres, _>(AssertSqlSafe(sql), values)
            .execute(&self.pool)
            .await
            .map_err(|e| IdmError::Internal(e.into()))?;
        Ok(())
    }

    #[tracing::instrument(name = "pg.sessions.revoke_for_tenant", skip_all)]
    async fn revoke_for_tenant(&self, tenant_id: Uuid) -> Result<(), IdmError> {
        let (sql, values) = Query::update()
            .table(Sessions::Table)
            .value(Sessions::RevokedAt, OffsetDateTime::now_utc())
            .and_where(Expr::col(Sessions::TenantId).eq(tenant_id))
            .and_where(Expr::col(Sessions::RevokedAt).is_null())
            .build_sqlx(PostgresQueryBuilder);
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
    #[tracing::instrument(name = "pg.roles.upsert", skip_all)]
    async fn upsert(
        &self,
        name: &str,
        display_name: &str,
        scope: RoleScope,
        by: Option<String>,
    ) -> Result<Uuid, IdmError> {
        // 幂等:先查存活同名(seed 单次串行跑,并发竞态可忽略;真要强一致再加 ON CONFLICT)。
        let (ssql, svalues) = Query::select()
            .columns([Roles::Id, Roles::Scope])
            .from(Roles::Table)
            .and_where(Expr::col(Roles::Name).eq(name))
            .and_where(Expr::col(Roles::DeletedAt).is_null())
            .build_sqlx(PostgresQueryBuilder);
        if let Some((id, current)) =
            sqlx::query_as_with::<Postgres, (Uuid, String), _>(AssertSqlSafe(ssql), svalues)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| IdmError::Internal(e.into()))?
        {
            // scope 以调用方代码闭集为准:迁移出来的默认 'tenant' 由此收敛
            if current != scope.as_str() {
                let (usql, uvalues) = Query::update()
                    .table(Roles::Table)
                    .value(Roles::Scope, scope.as_str())
                    .value(Roles::UpdatedBy, by)
                    .and_where(Expr::col(Roles::Id).eq(id))
                    .build_sqlx(PostgresQueryBuilder);
                sqlx::query_with::<Postgres, _>(AssertSqlSafe(usql), uvalues)
                    .execute(&self.pool)
                    .await
                    .map_err(|e| IdmError::Internal(e.into()))?;
            }
            return Ok(id);
        }
        let id = Uuid::now_v7();
        let (isql, ivalues) = Query::insert()
            .into_table(Roles::Table)
            .columns([
                Roles::Id,
                Roles::Name,
                Roles::DisplayName,
                Roles::Scope,
                Roles::CreatedBy,
                Roles::UpdatedBy,
            ])
            .values_panic([
                id.into(),
                name.to_owned().into(),
                display_name.to_owned().into(),
                scope.as_str().into(),
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

    #[tracing::instrument(name = "pg.roles.grant", skip_all)]
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

    #[tracing::instrument(name = "pg.roles.roles_for_user", skip_all)]
    async fn roles_for_user(&self, user_id: Uuid) -> Result<Vec<String>, IdmError> {
        // SELECT r.name FROM user_roles ur JOIN roles r ON r.id = ur.role_id
        //   WHERE ur.user_id = $ AND r.deleted_at IS NULL AND r.scope = 'platform'(只回平台角色)
        let (sql, values) = Query::select()
            .column((Roles::Table, Roles::Name))
            .from(UserRoles::Table)
            .inner_join(
                Roles::Table,
                Expr::col((Roles::Table, Roles::Id)).equals((UserRoles::Table, UserRoles::RoleId)),
            )
            .and_where(Expr::col((UserRoles::Table, UserRoles::UserId)).eq(user_id))
            .and_where(Expr::col((Roles::Table, Roles::DeletedAt)).is_null())
            .and_where(Expr::col((Roles::Table, Roles::Scope)).eq(RoleScope::Platform.as_str()))
            .build_sqlx(PostgresQueryBuilder);
        sqlx::query_scalar_with::<Postgres, String, _>(AssertSqlSafe(sql), values)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| IdmError::Internal(e.into()))
    }

    #[tracing::instrument(name = "pg.roles.list", skip_all)]
    async fn list(&self) -> Result<Vec<Role>, IdmError> {
        // SELECT id, name, display_name, scope FROM roles WHERE deleted_at IS NULL ORDER BY name
        let (sql, values) = Query::select()
            .columns([Roles::Id, Roles::Name, Roles::DisplayName, Roles::Scope])
            .from(Roles::Table)
            .and_where(Expr::col(Roles::DeletedAt).is_null())
            .order_by(Roles::Name, Order::Asc)
            .build_sqlx(PostgresQueryBuilder);
        sqlx::query_as_with::<Postgres, Role, _>(AssertSqlSafe(sql), values)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| IdmError::Internal(e.into()))
    }

    #[tracing::instrument(name = "pg.roles.set_roles", skip_all)]
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
                .map_err(map_fk_not_found)?;
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

// ── 租户 ──

const SLUG_TAKEN: &str = "Tenant slug already taken";

/// 租户读回的列(与 `Tenant` 的 FromRow 字段一一对应)。
fn tenant_cols() -> [Tenants; 7] {
    [
        Tenants::Id,
        Tenants::Slug,
        Tenants::Name,
        Tenants::Status,
        Tenants::CreatedAt,
        Tenants::UpdatedAt,
        Tenants::DeletedAt,
    ]
}

fn internal(e: sqlx::Error) -> IdmError {
    IdmError::Internal(e.into())
}

pub struct PgTenantRepo {
    pool: PgPool,
}
impl PgTenantRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// 改一个存活租户(UPDATE ... RETURNING)+ 同事务发 `tenant.updated`。不存在 / 已软删 → `NotFound`。
    async fn update_alive(
        &self,
        id: Uuid,
        col: Tenants,
        value: sea_query::Value,
        by: Option<String>,
    ) -> Result<Tenant, IdmError> {
        let mut tx = self.pool.begin().await.map_err(internal)?;
        let (sql, values) = Query::update()
            .table(Tenants::Table)
            .value(col, value)
            .value(Tenants::UpdatedBy, by)
            .and_where(Expr::col(Tenants::Id).eq(id))
            .and_where(Expr::col(Tenants::DeletedAt).is_null())
            .returning(Query::returning().columns(tenant_cols()))
            .build_sqlx(PostgresQueryBuilder);
        let t = sqlx::query_as_with::<Postgres, Tenant, _>(AssertSqlSafe(sql), values)
            .fetch_optional(&mut *tx)
            .await
            .map_err(internal)?
            .ok_or(IdmError::NotFound)?;
        emit_outbox(&mut tx, "tenant.updated", t.id, tenant_payload(&t)).await?;
        tx.commit().await.map_err(internal)?;
        Ok(t)
    }

    /// 按单列等值查存活租户。
    async fn get_alive_by(&self, cond: sea_query::SimpleExpr) -> Result<Tenant, IdmError> {
        let (sql, values) = Query::select()
            .columns(tenant_cols())
            .from(Tenants::Table)
            .and_where(cond)
            .and_where(Expr::col(Tenants::DeletedAt).is_null())
            .build_sqlx(PostgresQueryBuilder);
        sqlx::query_as_with::<Postgres, Tenant, _>(AssertSqlSafe(sql), values)
            .fetch_optional(&self.pool)
            .await
            .map_err(internal)?
            .ok_or(IdmError::NotFound)
    }
}

#[async_trait]
impl TenantRepo for PgTenantRepo {
    #[tracing::instrument(name = "pg.tenants.create", skip_all)]
    async fn create(&self, slug: &str, name: &str, by: Option<String>) -> Result<Tenant, IdmError> {
        let mut tx = self.pool.begin().await.map_err(internal)?;
        let (sql, values) = Query::insert()
            .into_table(Tenants::Table)
            .columns([
                Tenants::Id,
                Tenants::Slug,
                Tenants::Name,
                Tenants::CreatedBy,
                Tenants::UpdatedBy,
            ])
            .values_panic([
                Uuid::now_v7().into(),
                slug.to_owned().into(),
                name.to_owned().into(),
                by.clone().into(),
                by.into(),
            ])
            .returning(Query::returning().columns(tenant_cols()))
            .build_sqlx(PostgresQueryBuilder);
        let t = sqlx::query_as_with::<Postgres, Tenant, _>(AssertSqlSafe(sql), values)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| map_unique(e, SLUG_TAKEN))?;
        emit_outbox(&mut tx, "tenant.created", t.id, tenant_payload(&t)).await?;
        tx.commit().await.map_err(internal)?;
        Ok(t)
    }

    #[tracing::instrument(name = "pg.tenants.upsert_fixed", skip_all)]
    async fn upsert_fixed(
        &self,
        id: Uuid,
        slug: &str,
        name: &str,
        by: Option<String>,
    ) -> Result<Tenant, IdmError> {
        let mut tx = self.pool.begin().await.map_err(internal)?;
        // ON CONFLICT (id) DO NOTHING:并发 seed 也只建一次;slug 被别的 id 占 → 唯一冲突 → Conflict。
        let (sql, values) = Query::insert()
            .into_table(Tenants::Table)
            .columns([
                Tenants::Id,
                Tenants::Slug,
                Tenants::Name,
                Tenants::CreatedBy,
                Tenants::UpdatedBy,
            ])
            .values_panic([
                id.into(),
                slug.to_owned().into(),
                name.to_owned().into(),
                by.clone().into(),
                by.into(),
            ])
            .on_conflict(OnConflict::column(Tenants::Id).do_nothing().to_owned())
            .returning(Query::returning().columns(tenant_cols()))
            .build_sqlx(PostgresQueryBuilder);
        let inserted = sqlx::query_as_with::<Postgres, Tenant, _>(AssertSqlSafe(sql), values)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| map_unique(e, SLUG_TAKEN))?;
        let t = match inserted {
            Some(t) => {
                emit_outbox(&mut tx, "tenant.created", t.id, tenant_payload(&t)).await?;
                t
            }
            None => {
                // 已在(含已软删):原样返回,不改名、不发事件
                let (ssql, svalues) = Query::select()
                    .columns(tenant_cols())
                    .from(Tenants::Table)
                    .and_where(Expr::col(Tenants::Id).eq(id))
                    .build_sqlx(PostgresQueryBuilder);
                sqlx::query_as_with::<Postgres, Tenant, _>(AssertSqlSafe(ssql), svalues)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(internal)?
            }
        };
        tx.commit().await.map_err(internal)?;
        Ok(t)
    }

    #[tracing::instrument(name = "pg.tenants.get", skip_all)]
    async fn get(&self, id: Uuid) -> Result<Tenant, IdmError> {
        self.get_alive_by(Expr::col(Tenants::Id).eq(id)).await
    }

    #[tracing::instrument(name = "pg.tenants.get_by_slug", skip_all)]
    async fn get_by_slug(&self, slug: &str) -> Result<Tenant, IdmError> {
        self.get_alive_by(Expr::col(Tenants::Slug).eq(slug)).await
    }

    #[tracing::instrument(name = "pg.tenants.list", skip_all)]
    async fn list(&self, page: &ListPage) -> Result<ListResult<Tenant>, IdmError> {
        let mut q = Query::select();
        q.columns(tenant_cols())
            .from(Tenants::Table)
            .and_where(Expr::col(Tenants::DeletedAt).is_null())
            .order_by(Tenants::Id, Order::Asc);
        match *page {
            ListPage::Offset {
                offset,
                limit,
                with_total,
            } => {
                q.limit(limit).offset(offset);
                let (sql, values) = q.build_sqlx(PostgresQueryBuilder);
                let rows = sqlx::query_as_with::<Postgres, Tenant, _>(AssertSqlSafe(sql), values)
                    .fetch_all(&self.pool)
                    .await
                    .map_err(internal)?;
                let total = if with_total {
                    let (csql, cvalues) = Query::select()
                        .expr(Expr::col(Tenants::Id).count())
                        .from(Tenants::Table)
                        .and_where(Expr::col(Tenants::DeletedAt).is_null())
                        .build_sqlx(PostgresQueryBuilder);
                    let n =
                        sqlx::query_scalar_with::<Postgres, i64, _>(AssertSqlSafe(csql), cvalues)
                            .fetch_one(&self.pool)
                            .await
                            .map_err(internal)?;
                    Some(n as u64)
                } else {
                    None
                };
                Ok(ListResult {
                    rows,
                    total,
                    next_after: None,
                })
            }
            ListPage::Cursor { after, limit } => {
                if let Some(a) = after {
                    q.and_where(Expr::col(Tenants::Id).gt(a));
                }
                q.limit(limit + 1);
                let (sql, values) = q.build_sqlx(PostgresQueryBuilder);
                let rows = sqlx::query_as_with::<Postgres, Tenant, _>(AssertSqlSafe(sql), values)
                    .fetch_all(&self.pool)
                    .await
                    .map_err(internal)?;
                Ok(finish_cursor_page(rows, limit, |t| t.id))
            }
        }
    }

    #[tracing::instrument(name = "pg.tenants.update_name", skip_all)]
    async fn update_name(
        &self,
        id: Uuid,
        name: &str,
        by: Option<String>,
    ) -> Result<Tenant, IdmError> {
        self.update_alive(id, Tenants::Name, name.to_owned().into(), by)
            .await
    }

    #[tracing::instrument(name = "pg.tenants.set_status", skip_all)]
    async fn set_status(
        &self,
        id: Uuid,
        status: TenantStatus,
        by: Option<String>,
    ) -> Result<Tenant, IdmError> {
        self.update_alive(id, Tenants::Status, status.as_str().into(), by)
            .await
    }

    #[tracing::instrument(name = "pg.tenants.soft_delete", skip_all)]
    async fn soft_delete(&self, id: Uuid, by: Option<String>) -> Result<(), IdmError> {
        let mut tx = self.pool.begin().await.map_err(internal)?;
        let (sql, values) = Query::update()
            .table(Tenants::Table)
            .value(Tenants::DeletedAt, OffsetDateTime::now_utc())
            .value(Tenants::UpdatedBy, by)
            .and_where(Expr::col(Tenants::Id).eq(id))
            .and_where(Expr::col(Tenants::DeletedAt).is_null())
            .returning(Query::returning().column(Tenants::Slug))
            .build_sqlx(PostgresQueryBuilder);
        let slug = sqlx::query_scalar_with::<Postgres, String, _>(AssertSqlSafe(sql), values)
            .fetch_optional(&mut *tx)
            .await
            .map_err(internal)?
            .ok_or(IdmError::NotFound)?;
        emit_outbox(
            &mut tx,
            "tenant.deleted",
            id,
            json!({ "tenant_id": id, "slug": slug }),
        )
        .await?;
        tx.commit().await.map_err(internal)?;
        Ok(())
    }
}

// ── 成员 ──

/// 成员关系读回的公共 SELECT(tenant_members m JOIN 存活 tenants t)。`roles` = 相关子查询聚合
/// 该成员在该租户的**存活租户角色**(scope = 'tenant',按字节序排序,parity 内存 sort)。
/// 宏而非 const:要在 `concat!` 里拼出各查询的 'static SQL(免 AssertSqlSafe)。调用方接 `and ...` 与 ORDER BY。
macro_rules! membership_select {
    () => {
        r#"select t.id, t.slug, t.name, t.status, t.created_at, t.updated_at, t.deleted_at,
       m.user_id, m.status as member_status, m.last_used_at,
       array(select r.name from member_roles mr join roles r on r.id = mr.role_id
             where mr.tenant_id = m.tenant_id and mr.user_id = m.user_id
               and r.deleted_at is null and r.scope = 'tenant'
             order by r.name collate "C") as roles
from tenant_members m
join tenants t on t.id = m.tenant_id
where t.deleted_at is null"#
    };
}

#[derive(sqlx::FromRow)]
struct MembershipRow {
    #[sqlx(flatten)]
    tenant: Tenant,
    user_id: Uuid,
    #[sqlx(try_from = "String")]
    member_status: MemberStatus,
    last_used_at: Option<OffsetDateTime>,
    roles: Vec<String>,
}

impl From<MembershipRow> for Membership {
    fn from(r: MembershipRow) -> Self {
        Membership {
            tenant: r.tenant,
            user_id: r.user_id,
            status: r.member_status,
            roles: r.roles,
            last_used_at: r.last_used_at,
        }
    }
}

/// 查单个成员关系(任何状态)。在事务里也能用(add 读回)。
async fn fetch_membership<'e, E: sqlx::PgExecutor<'e>>(
    exec: E,
    tenant_id: Uuid,
    user_id: Uuid,
) -> Result<Option<Membership>, IdmError> {
    const SQL: &str = concat!(
        membership_select!(),
        " and m.tenant_id = $1 and m.user_id = $2"
    );
    sqlx::query_as::<Postgres, MembershipRow>(SQL)
        .bind(tenant_id)
        .bind(user_id)
        .fetch_optional(exec)
        .await
        .map(|r| r.map(Membership::from))
        .map_err(internal)
}

/// 往 member_roles 批量插(去重靠主键冲突跳过)。role_id 不存在 → FK → `NotFound`。
async fn insert_member_roles(
    tx: &mut sqlx::Transaction<'_, Postgres>,
    tenant_id: Uuid,
    user_id: Uuid,
    role_ids: &[Uuid],
    by: &Option<String>,
) -> Result<(), IdmError> {
    if role_ids.is_empty() {
        return Ok(());
    }
    let mut q = Query::insert();
    q.into_table(MemberRoles::Table).columns([
        MemberRoles::TenantId,
        MemberRoles::UserId,
        MemberRoles::RoleId,
        MemberRoles::GrantedBy,
    ]);
    for rid in role_ids {
        q.values_panic([
            tenant_id.into(),
            user_id.into(),
            (*rid).into(),
            by.clone().into(),
        ]);
    }
    q.on_conflict(
        OnConflict::columns([
            MemberRoles::TenantId,
            MemberRoles::UserId,
            MemberRoles::RoleId,
        ])
        .do_nothing()
        .to_owned(),
    );
    let (sql, values) = q.build_sqlx(PostgresQueryBuilder);
    sqlx::query_with::<Postgres, _>(AssertSqlSafe(sql), values)
        .execute(&mut **tx)
        .await
        .map_err(map_fk_not_found)?;
    Ok(())
}

/// 成员写操作的附加条件:成员所在租户未软删(已删租户的成员关系对写一律 `NotFound`,和读看不见一致)。
const MEMBER_TENANT_ALIVE: &str = "exists (select 1 from tenants t where t.id = tenant_members.tenant_id and t.deleted_at is null)";

pub struct PgMemberRepo {
    pool: PgPool,
}
impl PgMemberRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl MemberRepo for PgMemberRepo {
    #[tracing::instrument(name = "pg.tenant_members.add", skip_all)]
    async fn add(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        role_ids: &[Uuid],
        by: Option<String>,
    ) -> Result<Membership, IdmError> {
        let mut tx = self.pool.begin().await.map_err(internal)?;
        // 租户须存活(FOR SHARE:挡住同时进行的软删)。
        let alive: Option<i32> = sqlx::query_scalar(
            "select 1 from tenants where id = $1 and deleted_at is null for share",
        )
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(internal)?;
        if alive.is_none() {
            return Err(IdmError::NotFound);
        }
        let (sql, values) = Query::insert()
            .into_table(TenantMembers::Table)
            .columns([
                TenantMembers::TenantId,
                TenantMembers::UserId,
                TenantMembers::AddedBy,
            ])
            .values_panic([tenant_id.into(), user_id.into(), by.clone().into()])
            .build_sqlx(PostgresQueryBuilder);
        sqlx::query_with::<Postgres, _>(AssertSqlSafe(sql), values)
            .execute(&mut *tx)
            .await
            .map_err(|e| match &e {
                sqlx::Error::Database(db) if db.is_unique_violation() => {
                    IdmError::Conflict("Already a member of this tenant".to_owned())
                }
                _ => map_fk_not_found(e), // 用户不存在
            })?;
        insert_member_roles(&mut tx, tenant_id, user_id, role_ids, &by).await?;
        let m = fetch_membership(&mut *tx, tenant_id, user_id)
            .await?
            .ok_or_else(|| IdmError::Internal(anyhow::anyhow!("刚插入的成员读不回")))?;
        emit_outbox(
            &mut tx,
            "tenant.member_added",
            tenant_id,
            member_payload(tenant_id, user_id, Some(m.status), Some(&m.roles)),
        )
        .await?;
        tx.commit().await.map_err(internal)?;
        Ok(m)
    }

    #[tracing::instrument(name = "pg.tenant_members.remove", skip_all)]
    async fn remove(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        _by: Option<String>,
    ) -> Result<(), IdmError> {
        let mut tx = self.pool.begin().await.map_err(internal)?;
        // member_roles 经复合 FK ON DELETE CASCADE 一并删
        let (sql, values) = Query::delete()
            .from_table(TenantMembers::Table)
            .and_where(Expr::col(TenantMembers::TenantId).eq(tenant_id))
            .and_where(Expr::col(TenantMembers::UserId).eq(user_id))
            .and_where(Expr::cust(MEMBER_TENANT_ALIVE))
            .build_sqlx(PostgresQueryBuilder);
        let res = sqlx::query_with::<Postgres, _>(AssertSqlSafe(sql), values)
            .execute(&mut *tx)
            .await
            .map_err(internal)?;
        if res.rows_affected() == 0 {
            return Err(IdmError::NotFound);
        }
        emit_outbox(
            &mut tx,
            "tenant.member_removed",
            tenant_id,
            member_payload(tenant_id, user_id, None, None),
        )
        .await?;
        tx.commit().await.map_err(internal)?;
        Ok(())
    }

    #[tracing::instrument(name = "pg.tenant_members.set_status", skip_all)]
    async fn set_status(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        status: MemberStatus,
        _by: Option<String>,
    ) -> Result<(), IdmError> {
        let mut tx = self.pool.begin().await.map_err(internal)?;
        let (sql, values) = Query::update()
            .table(TenantMembers::Table)
            .value(TenantMembers::Status, status.as_str())
            .and_where(Expr::col(TenantMembers::TenantId).eq(tenant_id))
            .and_where(Expr::col(TenantMembers::UserId).eq(user_id))
            .and_where(Expr::cust(MEMBER_TENANT_ALIVE))
            .build_sqlx(PostgresQueryBuilder);
        let res = sqlx::query_with::<Postgres, _>(AssertSqlSafe(sql), values)
            .execute(&mut *tx)
            .await
            .map_err(internal)?;
        if res.rows_affected() == 0 {
            return Err(IdmError::NotFound);
        }
        emit_outbox(
            &mut tx,
            "tenant.member_updated",
            tenant_id,
            member_payload(tenant_id, user_id, Some(status), None),
        )
        .await?;
        tx.commit().await.map_err(internal)?;
        Ok(())
    }

    #[tracing::instrument(name = "pg.tenant_members.set_roles", skip_all)]
    async fn set_roles(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        role_ids: &[Uuid],
        by: Option<String>,
    ) -> Result<(), IdmError> {
        let mut tx = self.pool.begin().await.map_err(internal)?;
        // 成员须存在且租户未软删(FOR UPDATE:与并发 remove / set_roles 串行)
        let exists: Option<i32> = sqlx::query_scalar(
            "select 1 from tenant_members where tenant_id = $1 and user_id = $2 \
             and exists (select 1 from tenants t where t.id = tenant_members.tenant_id and t.deleted_at is null) \
             for update",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(internal)?;
        if exists.is_none() {
            return Err(IdmError::NotFound);
        }
        let (dsql, dvalues) = Query::delete()
            .from_table(MemberRoles::Table)
            .and_where(Expr::col(MemberRoles::TenantId).eq(tenant_id))
            .and_where(Expr::col(MemberRoles::UserId).eq(user_id))
            .build_sqlx(PostgresQueryBuilder);
        sqlx::query_with::<Postgres, _>(AssertSqlSafe(dsql), dvalues)
            .execute(&mut *tx)
            .await
            .map_err(internal)?;
        insert_member_roles(&mut tx, tenant_id, user_id, role_ids, &by).await?;
        let roles = fetch_membership(&mut *tx, tenant_id, user_id)
            .await?
            .map(|m| m.roles)
            .unwrap_or_default();
        emit_outbox(
            &mut tx,
            "tenant.member_roles_set",
            tenant_id,
            member_payload(tenant_id, user_id, None, Some(&roles)),
        )
        .await?;
        tx.commit().await.map_err(internal)?;
        Ok(())
    }

    #[tracing::instrument(name = "pg.tenant_members.get", skip_all)]
    async fn get(&self, tenant_id: Uuid, user_id: Uuid) -> Result<Option<Membership>, IdmError> {
        fetch_membership(&self.pool, tenant_id, user_id).await
    }

    #[tracing::instrument(name = "pg.tenant_members.list_by_tenant", skip_all)]
    async fn list_by_tenant(
        &self,
        tenant_id: Uuid,
        page: &ListPage,
    ) -> Result<ListResult<Membership>, IdmError> {
        match *page {
            ListPage::Offset {
                offset,
                limit,
                with_total,
            } => {
                const SQL: &str = concat!(
                    membership_select!(),
                    " and m.tenant_id = $1 order by m.user_id limit $2 offset $3"
                );
                let rows = sqlx::query_as::<Postgres, MembershipRow>(SQL)
                    .bind(tenant_id)
                    .bind(limit as i64)
                    .bind(offset as i64)
                    .fetch_all(&self.pool)
                    .await
                    .map_err(internal)?;
                let total = if with_total {
                    let n: i64 = sqlx::query_scalar(
                        "select count(*) from tenant_members m join tenants t on t.id = m.tenant_id \
                         where t.deleted_at is null and m.tenant_id = $1",
                    )
                    .bind(tenant_id)
                    .fetch_one(&self.pool)
                    .await
                    .map_err(internal)?;
                    Some(n as u64)
                } else {
                    None
                };
                Ok(ListResult {
                    rows: rows.into_iter().map(Membership::from).collect(),
                    total,
                    next_after: None,
                })
            }
            ListPage::Cursor { after, limit } => {
                // after 为空时用 nil UUID 作下界(user_id 不会是 nil)
                const SQL: &str = concat!(
                    membership_select!(),
                    " and m.tenant_id = $1 and m.user_id > $2 order by m.user_id limit $3"
                );
                let rows = sqlx::query_as::<Postgres, MembershipRow>(SQL)
                    .bind(tenant_id)
                    .bind(after.unwrap_or(Uuid::nil()))
                    .bind(limit as i64 + 1)
                    .fetch_all(&self.pool)
                    .await
                    .map_err(internal)?;
                let rows: Vec<Membership> = rows.into_iter().map(Membership::from).collect();
                Ok(finish_cursor_page(rows, limit, |m| m.user_id))
            }
        }
    }

    #[tracing::instrument(name = "pg.tenant_members.memberships_for_user", skip_all)]
    async fn memberships_for_user(&self, user_id: Uuid) -> Result<Vec<Membership>, IdmError> {
        // 有效成员关系:成员 active + 租户 active(存活由公共 SELECT 保证);最近用过的在前
        const SQL: &str = concat!(
            membership_select!(),
            " and m.user_id = $1 and m.status = 'active' and t.status = 'active'",
            " order by m.last_used_at desc nulls last, t.id"
        );
        let rows = sqlx::query_as::<Postgres, MembershipRow>(SQL)
            .bind(user_id)
            .fetch_all(&self.pool)
            .await
            .map_err(internal)?;
        Ok(rows.into_iter().map(Membership::from).collect())
    }

    #[tracing::instrument(name = "pg.tenant_members.touch_last_used", skip_all)]
    async fn touch_last_used(&self, tenant_id: Uuid, user_id: Uuid) -> Result<(), IdmError> {
        let (sql, values) = Query::update()
            .table(TenantMembers::Table)
            .value(TenantMembers::LastUsedAt, OffsetDateTime::now_utc())
            .and_where(Expr::col(TenantMembers::TenantId).eq(tenant_id))
            .and_where(Expr::col(TenantMembers::UserId).eq(user_id))
            .and_where(Expr::cust(MEMBER_TENANT_ALIVE))
            .build_sqlx(PostgresQueryBuilder);
        let res = sqlx::query_with::<Postgres, _>(AssertSqlSafe(sql), values)
            .execute(&self.pool)
            .await
            .map_err(internal)?;
        if res.rows_affected() == 0 {
            return Err(IdmError::NotFound);
        }
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

    #[tracing::instrument(name = "pg.outbox.mark_published", skip_all)]
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

    #[tracing::instrument(name = "pg.outbox.emit", skip_all)]
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
