//! idm 仓储内存实现 —— 脚手架默认,无 DB 即可跑通注册/登录全链路 + 写单测。
//! 镜像 PG 的软删过滤、username 唯一、email(有则)唯一,保 parity。

use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde_json::{json, Value};
use time::OffsetDateTime;
use uuid::Uuid;

use super::{
    ListPage, ListResult, MemberRepo, OutboxRecord, OutboxRepo, Role, RoleRepo, Session,
    SessionRepo, SortDir, TenantRepo, User, UserListFilter, UserListResult, UserListRow, UserRepo,
    UserSortBy, UserWithHash,
};
use crate::error::IdmError;
use crate::tenant::{MemberStatus, Membership, RoleScope, Tenant, TenantStatus, DEFAULT_TENANT_ID};

/// 内存内部行:比 `User` 多 password_hash + created_at + deleted_at(DTO 不暴露)。
#[derive(Clone)]
struct UserRow {
    id: Uuid,
    username: String,
    email: Option<String>,
    email_verified: bool,
    password_hash: String,
    created_at: OffsetDateTime,
    deleted_at: Option<OffsetDateTime>,
}

/// 角色 + 授予关系的**共享**存储:内存下 `UserRepo`(create_with_roles / list 读角色名)与
/// `RoleRepo`(upsert / grant / set_roles / roles_for_user)必须共用同一份 `roles` / `user_roles`,
/// 才能镜像 PG 两 repo 共表的语义。独立 `new()` 各自一份;`InMemoryRoleRepo::sharing_with` 共享。
#[derive(Default)]
struct RoleStore {
    roles: Mutex<Vec<RoleRec>>,       // 存活角色(内存无软删)
    grants: Mutex<Vec<(Uuid, Uuid)>>, // (user_id, role_id)
}

struct RoleRec {
    id: Uuid,
    name: String,
    display_name: String,
    scope: RoleScope,
}

/// 把 role_ids 解到存活角色名,供 `user.created`/`user.roles_set` 的 outbox payload 用。
/// 任一 id 查不到存活角色 → `NotFound`(镜像 PG user_roles→roles 的 FK:非法 role_id 整体失败)。
fn resolve_role_names(store: &RoleStore, role_ids: &[Uuid]) -> Result<Vec<String>, IdmError> {
    let roles = store.roles.lock().expect("锁未中毒");
    role_ids
        .iter()
        .map(|rid| {
            roles
                .iter()
                .find(|r| r.id == *rid)
                .map(|r| r.name.clone())
                .ok_or(IdmError::NotFound)
        })
        .collect()
}

/// role_ids 里**租户角色**的名字(按名排序)——`Membership.roles` 与成员事件 payload 共用。
fn tenant_role_names(store: &RoleStore, role_ids: &[Uuid]) -> Vec<String> {
    let roles = store.roles.lock().expect("锁未中毒");
    let mut names: Vec<String> = roles
        .iter()
        .filter(|r| r.scope == RoleScope::Tenant && role_ids.contains(&r.id))
        .map(|r| r.name.clone())
        .collect();
    names.sort();
    names
}

/// 去重保序(镜像 PG 主键冲突跳过)。
fn dedup_ids(role_ids: &[Uuid]) -> Vec<Uuid> {
    let mut ids: Vec<Uuid> = Vec::new();
    for rid in role_ids {
        if !ids.contains(rid) {
            ids.push(*rid);
        }
    }
    ids
}

/// 发件箱内部行:比 `OutboxRecord` 多 `published_at`(是否已发布,对外不暴露——poll 只返未发布行)。
struct OutboxRow {
    id: i64,
    event_type: String,
    aggregate_id: Uuid,
    payload: Value,
    created_at: OffsetDateTime,
    published_at: Option<OffsetDateTime>,
}

impl OutboxRow {
    fn to_record(&self) -> OutboxRecord {
        OutboxRecord {
            id: self.id,
            event_type: self.event_type.clone(),
            aggregate_id: self.aggregate_id,
            payload: self.payload.clone(),
            created_at: self.created_at,
        }
    }
}

/// 发件箱的**共享**存储:内存下 `InMemoryUserRepo`/`InMemoryRoleRepo`(Task 2 起写方法内 emit)与
/// `InMemoryOutboxRepo`(poll/mark)必须共用同一份 `Vec`,才能镜像 PG "同库不同表读写" 的语义。
/// 独立 `new()` 各自一份;`sharing_with` 系列共享(同 `RoleStore` 手法)。
#[derive(Default)]
struct OutboxStore {
    rows: Mutex<Vec<OutboxRow>>,
}

impl OutboxStore {
    /// 内部 emit 助手,由 `UserRepo`/`RoleRepo` 写方法在自己的锁内调用:追加一行(id 递增,未发布)。
    fn emit(&self, event_type: &str, aggregate_id: Uuid, payload: Value) {
        let mut rows = self.rows.lock().expect("锁未中毒");
        let id = rows.len() as i64 + 1;
        rows.push(OutboxRow {
            id,
            event_type: event_type.to_owned(),
            aggregate_id,
            payload,
            created_at: OffsetDateTime::now_utc(),
            published_at: None,
        });
    }
}

/// 排序方向套到一个原始 `Ordering` 上。
fn apply_dir(o: Ordering, dir: SortDir) -> Ordering {
    match dir {
        SortDir::Asc => o,
        SortDir::Desc => o.reverse(),
    }
}

/// `NULLS LAST` 比较:非空恒排在空之前(与 `dir` 无关),两非空按 `dir` 比。
fn opt_last_cmp(a: Option<&str>, b: Option<&str>, dir: SortDir) -> Ordering {
    match (a, b) {
        (Some(x), Some(y)) => apply_dir(x.cmp(y), dir),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

/// 单行比较:主键按 `sort_by`×`dir`(email `NULLS LAST`),再以 id 兜底(同 `dir`,镜像 PG)。
fn cmp_row(a: &UserListRow, b: &UserListRow, sort_by: UserSortBy, dir: SortDir) -> Ordering {
    let primary = match sort_by {
        UserSortBy::Username => apply_dir(a.username.cmp(&b.username), dir),
        UserSortBy::CreatedAt => apply_dir(a.created_at.cmp(&b.created_at), dir),
        UserSortBy::Email => opt_last_cmp(a.email.as_deref(), b.email.as_deref(), dir),
    };
    primary.then_with(|| apply_dir(a.id.cmp(&b.id), dir))
}

impl UserRow {
    fn to_user(&self) -> User {
        User {
            id: self.id,
            username: self.username.clone(),
            email: self.email.clone(),
            email_verified: self.email_verified,
            created_at: self.created_at,
        }
    }
}

/// 建号三处(create / create_with_roles / create_with_membership)共用:查重 → `precheck` → 写用户行。
/// 唯一性只看存活行(镜像 username / email 两个 partial unique 索引)。`precheck` 在查重**之后**、写入**之前**跑
/// (镜像 PG 先撞唯一索引、再撞后续外键的错误优先级),失败则不写;其返回值原样带回给调用方。
fn insert_user_row<R>(
    store: &mut HashMap<Uuid, UserRow>,
    username: &str,
    email: Option<&str>,
    password_hash: &str,
    precheck: impl FnOnce() -> Result<R, IdmError>,
) -> Result<(User, R), IdmError> {
    let dup = store.values().any(|r| {
        r.deleted_at.is_none()
            && (r.username == username || (email.is_some() && r.email.as_deref() == email))
    });
    if dup {
        return Err(IdmError::Conflict(
            "Username or email already taken".to_owned(),
        ));
    }
    let extra = precheck()?;
    let row = UserRow {
        id: Uuid::now_v7(),
        username: username.to_owned(),
        email: email.map(str::to_owned),
        email_verified: false,
        password_hash: password_hash.to_owned(),
        created_at: OffsetDateTime::now_utc(),
        deleted_at: None,
    };
    let user = row.to_user();
    store.insert(row.id, row);
    Ok((user, extra))
}

pub struct InMemoryUserRepo {
    /// `Arc`:成员仓储共享它,镜像 PG `tenant_members.user_id → users` 的 FK(查用户是否存在)。
    store: Arc<Mutex<HashMap<Uuid, UserRow>>>,
    roles: Arc<RoleStore>,
    outbox: Arc<OutboxStore>,
    tenants: Arc<TenantStore>,
}

impl InMemoryUserRepo {
    pub fn new() -> Self {
        Self {
            store: Arc::new(Mutex::new(HashMap::new())),
            roles: Arc::new(RoleStore::default()),
            outbox: Arc::new(OutboxStore::default()),
            tenants: Arc::new(TenantStore::default()),
        }
    }
}

impl Default for InMemoryUserRepo {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl UserRepo for InMemoryUserRepo {
    async fn create(
        &self,
        username: &str,
        email: Option<&str>,
        password_hash: &str,
        _by: Option<String>,
    ) -> Result<User, IdmError> {
        let mut store = self.store.lock().expect("锁未中毒");
        let (user, ()) = insert_user_row(&mut store, username, email, password_hash, || Ok(()))?;
        drop(store);
        self.outbox.emit(
            "user.created",
            user.id,
            super::user_created_payload(&user, &[]),
        );
        Ok(user)
    }

    async fn find_by_identifier(&self, identifier: &str) -> Result<Option<UserWithHash>, IdmError> {
        Ok(self
            .store
            .lock()
            .expect("锁未中毒")
            .values()
            .find(|r| {
                r.deleted_at.is_none()
                    && (r.username == identifier || r.email.as_deref() == Some(identifier))
            })
            .map(|r| UserWithHash {
                user: r.to_user(),
                password_hash: r.password_hash.clone(),
            }))
    }

    async fn find_by_id(&self, id: Uuid) -> Result<User, IdmError> {
        self.store
            .lock()
            .expect("锁未中毒")
            .get(&id)
            .filter(|r| r.deleted_at.is_none())
            .map(UserRow::to_user)
            .ok_or(IdmError::NotFound)
    }

    async fn find_by_ids(&self, ids: &[Uuid]) -> Result<Vec<User>, IdmError> {
        let store = self.store.lock().expect("锁未中毒");
        // 镜像 PG:只返存活行,查不到的 id 直接缺席(不报错)。
        Ok(ids
            .iter()
            .filter_map(|id| store.get(id))
            .filter(|r| r.deleted_at.is_none())
            .map(UserRow::to_user)
            .collect())
    }

    async fn update(
        &self,
        id: Uuid,
        username: &str,
        email: Option<&str>,
        _by: Option<String>,
    ) -> Result<User, IdmError> {
        let mut store = self.store.lock().expect("锁未中毒");
        // 冲突检查(排除自己):username / email 撞别的存活用户
        let dup = store.values().any(|r| {
            r.id != id
                && r.deleted_at.is_none()
                && (r.username == username || (email.is_some() && r.email.as_deref() == email))
        });
        if dup {
            return Err(IdmError::Conflict(
                "Username or email already taken".to_owned(),
            ));
        }
        match store.get_mut(&id) {
            Some(r) if r.deleted_at.is_none() => {
                // PUT 全量替换:username 必填、email 总替换(含清空),替换 email 即重置验证。
                r.username = username.to_owned();
                r.email = email.map(str::to_owned);
                r.email_verified = false;
                let user = r.to_user();
                self.outbox.emit(
                    "user.updated",
                    user.id,
                    json!({
                        "user_id": user.id,
                        "username": user.username,
                        "email": user.email,
                        "email_verified": user.email_verified,
                    }),
                );
                Ok(user)
            }
            _ => Err(IdmError::NotFound),
        }
    }

    async fn soft_delete(&self, id: Uuid, _by: Option<String>) -> Result<(), IdmError> {
        let mut store = self.store.lock().expect("锁未中毒");
        match store.get_mut(&id) {
            Some(r) if r.deleted_at.is_none() => {
                r.deleted_at = Some(OffsetDateTime::now_utc());
                self.outbox
                    .emit("user.deleted", id, json!({ "user_id": id }));
                Ok(())
            }
            _ => Err(IdmError::NotFound),
        }
    }

    async fn update_password(&self, user_id: Uuid, password_hash: &str) -> Result<(), IdmError> {
        let mut store = self.store.lock().expect("锁未中毒");
        match store.get_mut(&user_id) {
            Some(r) if r.deleted_at.is_none() => {
                r.password_hash = password_hash.to_owned();
                Ok(())
            }
            _ => Err(IdmError::NotFound),
        }
    }

    async fn password_hash(&self, user_id: Uuid) -> Result<Option<String>, IdmError> {
        Ok(self
            .store
            .lock()
            .expect("锁未中毒")
            .get(&user_id)
            .filter(|r| r.deleted_at.is_none())
            .map(|r| r.password_hash.clone()))
    }

    async fn create_with_roles(
        &self,
        username: &str,
        email: Option<&str>,
        password_hash: &str,
        role_ids: &[Uuid],
        _by: Option<String>,
    ) -> Result<User, IdmError> {
        let mut store = self.store.lock().expect("锁未中毒");
        // 查重之后、写入之前校验 role_ids 都是存活角色(镜像 PG user_roles 对 roles 的 FK),否则不动任何存储。
        let (user, mut role_names) =
            insert_user_row(&mut store, username, email, password_hash, || {
                resolve_role_names(&self.roles, role_ids)
            })?;
        drop(store);
        role_names.sort();
        // 授角色:写共享 user_roles(去重),parity with PG on_conflict do nothing。
        let mut grants = self.roles.grants.lock().expect("锁未中毒");
        for rid in role_ids {
            if !grants.contains(&(user.id, *rid)) {
                grants.push((user.id, *rid));
            }
        }
        drop(grants);
        self.outbox.emit(
            "user.created",
            user.id,
            super::user_created_payload(&user, &role_names),
        );
        Ok(user)
    }

    async fn create_with_membership(
        &self,
        username: &str,
        email: Option<&str>,
        password_hash: &str,
        tenant_id: Uuid,
        role_ids: &[Uuid],
        _by: Option<String>,
    ) -> Result<User, IdmError> {
        let mut store = self.store.lock().expect("锁未中毒");
        // 查重之后、写入之前:校验角色(FK)+ 取可加入的租户快照(存活且 active;否则只建账号)。
        let (user, tenant) = insert_user_row(&mut store, username, email, password_hash, || {
            resolve_role_names(&self.roles, role_ids)?;
            Ok(self
                .tenants
                .tenants
                .lock()
                .expect("锁未中毒")
                .iter()
                .find(|t| {
                    t.id == tenant_id && t.deleted_at.is_none() && t.status == TenantStatus::Active
                })
                .map(|t| t.id))
        })?;
        drop(store);
        self.outbox.emit(
            "user.created",
            user.id,
            super::user_created_payload(&user, &[]),
        );

        if let Some(tid) = tenant {
            let ids = dedup_ids(role_ids);
            let names = tenant_role_names(&self.roles, &ids);
            self.tenants
                .members
                .lock()
                .expect("锁未中毒")
                .push(MemberRec {
                    tenant_id: tid,
                    user_id: user.id,
                    status: MemberStatus::Active,
                    last_used_at: None,
                    role_ids: ids,
                });
            self.outbox.emit(
                "tenant.member_added",
                tid,
                super::member_payload(tid, user.id, Some(MemberStatus::Active), Some(&names)),
            );
        }
        Ok(user)
    }

    async fn list(
        &self,
        filter: &UserListFilter,
        sort_by: UserSortBy,
        dir: SortDir,
        page: &ListPage,
    ) -> Result<UserListResult, IdmError> {
        let store = self.store.lock().expect("锁未中毒");
        let grants = self.roles.grants.lock().expect("锁未中毒");
        let roles = self.roles.roles.lock().expect("锁未中毒");
        // 某用户的存活角色名(按名排序,parity with PG 子查询 ORDER BY r.name)。
        let role_names = |uid: Uuid| -> Vec<String> {
            let mut ns: Vec<String> = grants
                .iter()
                .filter(|(u, _)| *u == uid)
                .filter_map(|(_, rid)| roles.iter().find(|r| r.id == *rid).map(|r| r.name.clone()))
                .collect();
            ns.sort();
            ns
        };
        let uname = filter.username.as_ref().map(|s| s.to_lowercase());
        let mut rows: Vec<UserListRow> = store
            .values()
            .filter(|r| r.deleted_at.is_none())
            .filter(|r| match &uname {
                Some(q) => r.username.to_lowercase().contains(q),
                None => true,
            })
            .filter(|r| filter.created_from.is_none_or(|f| r.created_at >= f))
            .filter(|r| filter.created_to.is_none_or(|t| r.created_at <= t))
            .filter_map(|r| {
                let rn = role_names(r.id);
                if !filter.roles_any.is_empty() && !filter.roles_any.iter().any(|x| rn.contains(x))
                {
                    return None;
                }
                if filter.roles_none.iter().any(|x| rn.contains(x)) {
                    return None;
                }
                Some(UserListRow {
                    id: r.id,
                    username: r.username.clone(),
                    email: r.email.clone(),
                    email_verified: r.email_verified,
                    created_at: r.created_at,
                    roles: rn,
                })
            })
            .collect();
        rows.sort_by(|a, b| cmp_row(a, b, sort_by, dir));

        match *page {
            ListPage::Offset {
                offset,
                limit,
                with_total,
            } => {
                let total = with_total.then_some(rows.len() as u64);
                let page_rows = rows
                    .into_iter()
                    .skip(offset as usize)
                    .take(limit as usize)
                    .collect();
                Ok(UserListResult {
                    rows: page_rows,
                    total,
                    next_after: None,
                })
            }
            ListPage::Cursor { after, limit } => {
                // 镜像 PG:先 WHERE id keyset(相对 dir),再 ORDER BY,再取 limit+1 判下一页。
                let mut kept: Vec<UserListRow> = rows
                    .into_iter()
                    .filter(|r| match after {
                        Some(a) => match dir {
                            SortDir::Asc => r.id > a,
                            SortDir::Desc => r.id < a,
                        },
                        None => true,
                    })
                    .collect();
                let has_more = kept.len() as u64 > limit;
                kept.truncate(limit as usize);
                let next_after = if has_more {
                    kept.last().map(|r| r.id)
                } else {
                    None
                };
                Ok(UserListResult {
                    rows: kept,
                    total: None,
                    next_after,
                })
            }
        }
    }
}

/// 会话内存行。
#[derive(Clone)]
struct SessionRow {
    id: Uuid,
    user_id: Uuid,
    tenant_id: Option<Uuid>,
    token_hash: String,
    expires_at: OffsetDateTime,
    revoked_at: Option<OffsetDateTime>,
}

pub struct InMemorySessionRepo {
    store: Mutex<Vec<SessionRow>>,
    /// 租户存储(镜像 PG `sessions.tenant_id → tenants` 的外键:建会话时校验租户存在)。
    tenants: Arc<TenantStore>,
}

impl InMemorySessionRepo {
    /// 独立一份租户存储(只有默认租户)。要和别的内存仓储看同一批租户 → [`Self::sharing_with`]。
    pub fn new() -> Self {
        Self {
            store: Mutex::new(Vec::new()),
            tenants: Arc::new(TenantStore::default()),
        }
    }

    /// 与给定 `InMemoryUserRepo` **共享**租户存储(镜像 PG 外键看的是同一张 tenants 表)。
    pub fn sharing_with(users: &InMemoryUserRepo) -> Self {
        Self {
            store: Mutex::new(Vec::new()),
            tenants: Arc::clone(&users.tenants),
        }
    }
}

impl Default for InMemorySessionRepo {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SessionRepo for InMemorySessionRepo {
    async fn create(
        &self,
        user_id: Uuid,
        tenant_id: Option<Uuid>,
        token_hash: &str,
        expires_at: OffsetDateTime,
        _by: Option<String>,
    ) -> Result<Session, IdmError> {
        // 镜像 PG 外键:租户行须存在(已软删的行也还在,外键不拦)。
        if let Some(t) = tenant_id {
            let exists = self
                .tenants
                .tenants
                .lock()
                .expect("锁未中毒")
                .iter()
                .any(|x| x.id == t);
            if !exists {
                return Err(IdmError::NotFound);
            }
        }
        let row = SessionRow {
            id: Uuid::now_v7(),
            user_id,
            tenant_id,
            token_hash: token_hash.to_owned(),
            expires_at,
            revoked_at: None,
        };
        let session = Session {
            id: row.id,
            user_id,
            tenant_id,
        };
        self.store.lock().expect("锁未中毒").push(row);
        Ok(session)
    }

    async fn find_active(
        &self,
        token_hash: &str,
        now: OffsetDateTime,
    ) -> Result<Option<Session>, IdmError> {
        Ok(self
            .store
            .lock()
            .expect("锁未中毒")
            .iter()
            .find(|r| r.token_hash == token_hash && r.revoked_at.is_none() && r.expires_at > now)
            .map(|r| Session {
                id: r.id,
                user_id: r.user_id,
                tenant_id: r.tenant_id,
            }))
    }

    async fn revoke(&self, session_id: Uuid) -> Result<(), IdmError> {
        let mut store = self.store.lock().expect("锁未中毒");
        if let Some(r) = store.iter_mut().find(|r| r.id == session_id) {
            r.revoked_at.get_or_insert(OffsetDateTime::now_utc());
        }
        Ok(())
    }

    async fn revoke_all(&self, user_id: Uuid, except: Option<Uuid>) -> Result<(), IdmError> {
        let now = OffsetDateTime::now_utc();
        let mut store = self.store.lock().expect("锁未中毒");
        for r in store.iter_mut() {
            if r.user_id == user_id && Some(r.id) != except && r.revoked_at.is_none() {
                r.revoked_at = Some(now);
            }
        }
        Ok(())
    }

    async fn revoke_for_member(&self, tenant_id: Uuid, user_id: Uuid) -> Result<(), IdmError> {
        self.revoke_where(|r| r.tenant_id == Some(tenant_id) && r.user_id == user_id);
        Ok(())
    }

    async fn revoke_for_tenant(&self, tenant_id: Uuid) -> Result<(), IdmError> {
        self.revoke_where(|r| r.tenant_id == Some(tenant_id));
        Ok(())
    }
}

impl InMemorySessionRepo {
    /// 给满足条件的活跃会话盖 revoked_at(已撤销的不动,幂等)。
    fn revoke_where(&self, pred: impl Fn(&SessionRow) -> bool) {
        let now = OffsetDateTime::now_utc();
        for r in self.store.lock().expect("锁未中毒").iter_mut() {
            if r.revoked_at.is_none() && pred(r) {
                r.revoked_at = Some(now);
            }
        }
    }
}

/// 角色内存实现。与 `InMemoryUserRepo` 可共享 `RoleStore`(见 [`InMemoryRoleRepo::sharing_with`]),
/// 从而 `create_with_roles` / `set_roles` 写的授予对 `roles_for_user` / `list` 可见(镜像 PG 共表)。
pub struct InMemoryRoleRepo {
    inner: Arc<RoleStore>,
    outbox: Arc<OutboxStore>,
}

impl InMemoryRoleRepo {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RoleStore::default()),
            outbox: Arc::new(OutboxStore::default()),
        }
    }

    /// 与给定 `InMemoryUserRepo` **共享**角色/授予存储 —— 内存模式下让两 repo 语义等价于 PG 共表。
    pub fn sharing_with(users: &InMemoryUserRepo) -> Self {
        Self {
            inner: Arc::clone(&users.roles),
            outbox: Arc::clone(&users.outbox),
        }
    }
}

impl Default for InMemoryRoleRepo {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RoleRepo for InMemoryRoleRepo {
    async fn upsert(
        &self,
        name: &str,
        display_name: &str,
        scope: RoleScope,
        _by: Option<String>,
    ) -> Result<Uuid, IdmError> {
        let mut roles = self.inner.roles.lock().expect("锁未中毒");
        if let Some(r) = roles.iter_mut().find(|r| r.name == name) {
            r.scope = scope; // 以调用方的代码闭集为准校正 scope
            return Ok(r.id);
        }
        let id = Uuid::now_v7();
        roles.push(RoleRec {
            id,
            name: name.to_owned(),
            display_name: display_name.to_owned(),
            scope,
        });
        Ok(id)
    }

    async fn grant(
        &self,
        user_id: Uuid,
        role_id: Uuid,
        _by: Option<String>,
    ) -> Result<(), IdmError> {
        let mut grants = self.inner.grants.lock().expect("锁未中毒");
        if !grants.contains(&(user_id, role_id)) {
            grants.push((user_id, role_id));
        }
        Ok(())
    }

    async fn roles_for_user(&self, user_id: Uuid) -> Result<Vec<String>, IdmError> {
        let grants = self.inner.grants.lock().expect("锁未中毒");
        let roles = self.inner.roles.lock().expect("锁未中毒");
        // 只回平台角色(镜像 PG 的 scope = 'platform' 过滤)
        Ok(grants
            .iter()
            .filter(|(u, _)| *u == user_id)
            .filter_map(|(_, rid)| {
                roles
                    .iter()
                    .find(|r| r.id == *rid && r.scope == RoleScope::Platform)
                    .map(|r| r.name.clone())
            })
            .collect())
    }

    async fn list(&self) -> Result<Vec<Role>, IdmError> {
        let mut list: Vec<Role> = self
            .inner
            .roles
            .lock()
            .expect("锁未中毒")
            .iter()
            .map(|r| Role {
                id: r.id,
                name: r.name.clone(),
                display_name: r.display_name.clone(),
                scope: r.scope,
            })
            .collect();
        list.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(list)
    }

    async fn set_roles(
        &self,
        user_id: Uuid,
        role_ids: &[Uuid],
        _by: Option<String>,
    ) -> Result<(), IdmError> {
        // 先校验:role_ids 必须都是存活角色,否则不动 grants(镜像 PG FK)。
        let mut role_names = resolve_role_names(&self.inner, role_ids)?;
        role_names.sort();

        // 全量替换:清该 user 的所有授予,再批量加新(去重)。幂等。
        let mut grants = self.inner.grants.lock().expect("锁未中毒");
        grants.retain(|(u, _)| *u != user_id);
        for rid in role_ids {
            if !grants.contains(&(user_id, *rid)) {
                grants.push((user_id, *rid));
            }
        }
        drop(grants);

        self.outbox.emit(
            "user.roles_set",
            user_id,
            json!({ "user_id": user_id, "roles": role_names }),
        );
        Ok(())
    }
}

/// 租户 + 成员关系的**共享**存储:内存下 `InMemoryTenantRepo` / `InMemoryMemberRepo` 经
/// `sharing_with(&users)` 共用同一份,镜像 PG 共表。构造时就带默认租户(镜像迁移 0004 的插入)。
struct TenantStore {
    tenants: Mutex<Vec<Tenant>>, // 含已软删(slug 不复用要看它们)
    members: Mutex<Vec<MemberRec>>,
}

impl Default for TenantStore {
    fn default() -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            tenants: Mutex::new(vec![Tenant {
                id: DEFAULT_TENANT_ID,
                slug: "default".to_owned(),
                name: "默认组织".to_owned(),
                status: TenantStatus::Active,
                created_at: now,
                updated_at: now,
                deleted_at: None,
            }]),
            members: Mutex::new(Vec::new()),
        }
    }
}

/// 成员内存行:`role_ids` 即该成员在该租户的 member_roles。
struct MemberRec {
    tenant_id: Uuid,
    user_id: Uuid,
    status: MemberStatus,
    last_used_at: Option<OffsetDateTime>,
    role_ids: Vec<Uuid>,
}

/// 内存侧 offset / cursor 分页(`rows` 已按 key 升序)。
fn paginate<T>(rows: Vec<T>, page: &ListPage, key: impl Fn(&T) -> Uuid) -> ListResult<T> {
    match *page {
        ListPage::Offset {
            offset,
            limit,
            with_total,
        } => {
            let total = with_total.then_some(rows.len() as u64);
            ListResult {
                rows: rows
                    .into_iter()
                    .skip(offset as usize)
                    .take(limit as usize)
                    .collect(),
                total,
                next_after: None,
            }
        }
        ListPage::Cursor { after, limit } => {
            let kept: Vec<T> = rows
                .into_iter()
                .filter(|r| after.is_none_or(|a| key(r) > a))
                .take(limit as usize + 1)
                .collect();
            super::finish_cursor_page(kept, limit, key)
        }
    }
}

/// 租户内存实现。
pub struct InMemoryTenantRepo {
    inner: Arc<TenantStore>,
    outbox: Arc<OutboxStore>,
}

impl InMemoryTenantRepo {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(TenantStore::default()),
            outbox: Arc::new(OutboxStore::default()),
        }
    }

    /// 与给定 `InMemoryUserRepo` **共享**租户 / 成员 / 发件箱存储。
    pub fn sharing_with(users: &InMemoryUserRepo) -> Self {
        Self {
            inner: Arc::clone(&users.tenants),
            outbox: Arc::clone(&users.outbox),
        }
    }

    /// 改一个存活租户并发 `event_type`;不存在 / 已软删 → `NotFound`。
    fn mutate_alive(
        &self,
        id: Uuid,
        event_type: &str,
        f: impl FnOnce(&mut Tenant),
    ) -> Result<Tenant, IdmError> {
        let mut tenants = self.inner.tenants.lock().expect("锁未中毒");
        let t = tenants
            .iter_mut()
            .find(|t| t.id == id && t.deleted_at.is_none())
            .ok_or(IdmError::NotFound)?;
        f(t);
        t.updated_at = OffsetDateTime::now_utc();
        let out = t.clone();
        self.outbox
            .emit(event_type, id, super::tenant_payload(&out));
        Ok(out)
    }
}

impl Default for InMemoryTenantRepo {
    fn default() -> Self {
        Self::new()
    }
}

fn new_tenant(id: Uuid, slug: &str, name: &str) -> Tenant {
    let now = OffsetDateTime::now_utc();
    Tenant {
        id,
        slug: slug.to_owned(),
        name: name.to_owned(),
        status: TenantStatus::Active,
        created_at: now,
        updated_at: now,
        deleted_at: None,
    }
}

const SLUG_TAKEN: &str = "Tenant slug already taken";

#[async_trait]
impl TenantRepo for InMemoryTenantRepo {
    async fn create(
        &self,
        slug: &str,
        name: &str,
        _by: Option<String>,
    ) -> Result<Tenant, IdmError> {
        let mut tenants = self.inner.tenants.lock().expect("锁未中毒");
        // slug 唯一含已软删(镜像不带 deleted_at 条件的唯一索引)
        if tenants.iter().any(|t| t.slug == slug) {
            return Err(IdmError::Conflict(SLUG_TAKEN.to_owned()));
        }
        let t = new_tenant(Uuid::now_v7(), slug, name);
        tenants.push(t.clone());
        self.outbox
            .emit("tenant.created", t.id, super::tenant_payload(&t));
        Ok(t)
    }

    async fn upsert_fixed(
        &self,
        id: Uuid,
        slug: &str,
        name: &str,
        _by: Option<String>,
    ) -> Result<Tenant, IdmError> {
        let mut tenants = self.inner.tenants.lock().expect("锁未中毒");
        if let Some(t) = tenants.iter().find(|t| t.id == id) {
            return Ok(t.clone()); // 已在:原样返回,不改名、不发事件
        }
        if tenants.iter().any(|t| t.slug == slug) {
            return Err(IdmError::Conflict(SLUG_TAKEN.to_owned()));
        }
        let t = new_tenant(id, slug, name);
        tenants.push(t.clone());
        self.outbox
            .emit("tenant.created", t.id, super::tenant_payload(&t));
        Ok(t)
    }

    async fn get(&self, id: Uuid) -> Result<Tenant, IdmError> {
        self.inner
            .tenants
            .lock()
            .expect("锁未中毒")
            .iter()
            .find(|t| t.id == id && t.deleted_at.is_none())
            .cloned()
            .ok_or(IdmError::NotFound)
    }

    async fn get_by_slug(&self, slug: &str) -> Result<Tenant, IdmError> {
        self.inner
            .tenants
            .lock()
            .expect("锁未中毒")
            .iter()
            .find(|t| t.slug == slug && t.deleted_at.is_none())
            .cloned()
            .ok_or(IdmError::NotFound)
    }

    async fn list(&self, page: &ListPage) -> Result<ListResult<Tenant>, IdmError> {
        let mut rows: Vec<Tenant> = self
            .inner
            .tenants
            .lock()
            .expect("锁未中毒")
            .iter()
            .filter(|t| t.deleted_at.is_none())
            .cloned()
            .collect();
        rows.sort_by_key(|t| t.id);
        Ok(paginate(rows, page, |t| t.id))
    }

    async fn update_name(
        &self,
        id: Uuid,
        name: &str,
        _by: Option<String>,
    ) -> Result<Tenant, IdmError> {
        self.mutate_alive(id, "tenant.updated", |t| t.name = name.to_owned())
    }

    async fn set_status(
        &self,
        id: Uuid,
        status: TenantStatus,
        _by: Option<String>,
    ) -> Result<Tenant, IdmError> {
        self.mutate_alive(id, "tenant.updated", |t| t.status = status)
    }

    async fn soft_delete(&self, id: Uuid, _by: Option<String>) -> Result<(), IdmError> {
        let mut tenants = self.inner.tenants.lock().expect("锁未中毒");
        let t = tenants
            .iter_mut()
            .find(|t| t.id == id && t.deleted_at.is_none())
            .ok_or(IdmError::NotFound)?;
        let now = OffsetDateTime::now_utc();
        t.deleted_at = Some(now);
        t.updated_at = now;
        let payload = json!({ "tenant_id": t.id, "slug": t.slug });
        self.outbox.emit("tenant.deleted", id, payload);
        Ok(())
    }
}

/// 成员内存实现。与 `InMemoryUserRepo` 共享用户(FK 校验)、角色(名 + scope)、租户、发件箱存储。
pub struct InMemoryMemberRepo {
    users: Arc<Mutex<HashMap<Uuid, UserRow>>>,
    roles: Arc<RoleStore>,
    tenants: Arc<TenantStore>,
    outbox: Arc<OutboxStore>,
}

impl InMemoryMemberRepo {
    pub fn new() -> Self {
        Self::sharing_with(&InMemoryUserRepo::new())
    }

    /// 与给定 `InMemoryUserRepo` **共享**用户 / 角色 / 租户 / 发件箱存储(镜像 PG 共表)。
    pub fn sharing_with(users: &InMemoryUserRepo) -> Self {
        Self {
            users: Arc::clone(&users.store),
            roles: Arc::clone(&users.roles),
            tenants: Arc::clone(&users.tenants),
            outbox: Arc::clone(&users.outbox),
        }
    }

    fn tenant_role_names(&self, role_ids: &[Uuid]) -> Vec<String> {
        tenant_role_names(&self.roles, role_ids)
    }

    /// 先校验:role_ids 都得存在(镜像 PG member_roles → roles 的 FK),否则 `NotFound`、不动任何存储。
    fn check_roles_exist(&self, role_ids: &[Uuid]) -> Result<(), IdmError> {
        resolve_role_names(&self.roles, role_ids).map(|_| ())
    }

    fn to_membership(&self, t: &Tenant, m: &MemberRec) -> Membership {
        Membership {
            tenant: t.clone(),
            user_id: m.user_id,
            status: m.status,
            roles: self.tenant_role_names(&m.role_ids),
            last_used_at: m.last_used_at,
        }
    }

    /// 在成员行上改一下;不是成员 / 租户已软删 → `NotFound`。
    fn with_member<R>(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        f: impl FnOnce(&mut MemberRec) -> R,
    ) -> Result<R, IdmError> {
        let mut members = self.tenants.members.lock().expect("锁未中毒");
        self.ensure_tenant_alive(tenant_id)?;
        let m = members
            .iter_mut()
            .find(|m| m.tenant_id == tenant_id && m.user_id == user_id)
            .ok_or(IdmError::NotFound)?;
        Ok(f(m))
    }
}

impl InMemoryMemberRepo {
    /// 租户须存活(未软删),否则 `NotFound` —— 成员写操作对已删租户一律 404(镜像 PG)。
    /// 锁序:调用方已持 members 锁,这里再取 tenants 锁(与 get / list 同序)。
    fn ensure_tenant_alive(&self, tenant_id: Uuid) -> Result<(), IdmError> {
        let alive = self
            .tenants
            .tenants
            .lock()
            .expect("锁未中毒")
            .iter()
            .any(|t| t.id == tenant_id && t.deleted_at.is_none());
        if alive {
            Ok(())
        } else {
            Err(IdmError::NotFound)
        }
    }
}

impl Default for InMemoryMemberRepo {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl MemberRepo for InMemoryMemberRepo {
    async fn add(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        role_ids: &[Uuid],
        _by: Option<String>,
    ) -> Result<Membership, IdmError> {
        // 先校验(各自短暂持锁,避免与 UserRepo::list 的锁序交叉),后改状态。
        self.check_roles_exist(role_ids)?;
        if !self.users.lock().expect("锁未中毒").contains_key(&user_id) {
            return Err(IdmError::NotFound);
        }
        let mut members = self.tenants.members.lock().expect("锁未中毒");
        let tenants = self.tenants.tenants.lock().expect("锁未中毒");
        let tenant = tenants
            .iter()
            .find(|t| t.id == tenant_id && t.deleted_at.is_none())
            .ok_or(IdmError::NotFound)?;
        if members
            .iter()
            .any(|m| m.tenant_id == tenant_id && m.user_id == user_id)
        {
            return Err(IdmError::Conflict(
                "Already a member of this tenant".to_owned(),
            ));
        }
        let ids = dedup_ids(role_ids);
        let rec = MemberRec {
            tenant_id,
            user_id,
            status: MemberStatus::Active,
            last_used_at: None,
            role_ids: ids,
        };
        let out = self.to_membership(tenant, &rec);
        members.push(rec);
        self.outbox.emit(
            "tenant.member_added",
            tenant_id,
            super::member_payload(tenant_id, user_id, Some(out.status), Some(&out.roles)),
        );
        Ok(out)
    }

    async fn remove(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        _by: Option<String>,
    ) -> Result<(), IdmError> {
        let mut members = self.tenants.members.lock().expect("锁未中毒");
        self.ensure_tenant_alive(tenant_id)?;
        let before = members.len();
        members.retain(|m| !(m.tenant_id == tenant_id && m.user_id == user_id));
        if members.len() == before {
            return Err(IdmError::NotFound);
        }
        self.outbox.emit(
            "tenant.member_removed",
            tenant_id,
            super::member_payload(tenant_id, user_id, None, None),
        );
        Ok(())
    }

    async fn set_status(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        status: MemberStatus,
        _by: Option<String>,
    ) -> Result<(), IdmError> {
        self.with_member(tenant_id, user_id, |m| m.status = status)?;
        self.outbox.emit(
            "tenant.member_updated",
            tenant_id,
            super::member_payload(tenant_id, user_id, Some(status), None),
        );
        Ok(())
    }

    async fn set_roles(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        role_ids: &[Uuid],
        _by: Option<String>,
    ) -> Result<(), IdmError> {
        self.check_roles_exist(role_ids)?;
        let ids = dedup_ids(role_ids);
        let names = self.tenant_role_names(&ids);
        self.with_member(tenant_id, user_id, |m| m.role_ids = ids)?;
        self.outbox.emit(
            "tenant.member_roles_set",
            tenant_id,
            super::member_payload(tenant_id, user_id, None, Some(&names)),
        );
        Ok(())
    }

    async fn get(&self, tenant_id: Uuid, user_id: Uuid) -> Result<Option<Membership>, IdmError> {
        let members = self.tenants.members.lock().expect("锁未中毒");
        let tenants = self.tenants.tenants.lock().expect("锁未中毒");
        let Some(t) = tenants
            .iter()
            .find(|t| t.id == tenant_id && t.deleted_at.is_none())
        else {
            return Ok(None);
        };
        Ok(members
            .iter()
            .find(|m| m.tenant_id == tenant_id && m.user_id == user_id)
            .map(|m| self.to_membership(t, m)))
    }

    async fn list_by_tenant(
        &self,
        tenant_id: Uuid,
        page: &ListPage,
    ) -> Result<ListResult<Membership>, IdmError> {
        let members = self.tenants.members.lock().expect("锁未中毒");
        let tenants = self.tenants.tenants.lock().expect("锁未中毒");
        let rows = match tenants
            .iter()
            .find(|t| t.id == tenant_id && t.deleted_at.is_none())
        {
            Some(t) => {
                let mut rows: Vec<Membership> = members
                    .iter()
                    .filter(|m| m.tenant_id == tenant_id)
                    .map(|m| self.to_membership(t, m))
                    .collect();
                rows.sort_by_key(|m| m.user_id);
                rows
            }
            None => Vec::new(),
        };
        Ok(paginate(rows, page, |m| m.user_id))
    }

    async fn memberships_for_user(&self, user_id: Uuid) -> Result<Vec<Membership>, IdmError> {
        let members = self.tenants.members.lock().expect("锁未中毒");
        let tenants = self.tenants.tenants.lock().expect("锁未中毒");
        let mut out: Vec<Membership> = members
            .iter()
            .filter(|m| m.user_id == user_id && m.status == MemberStatus::Active)
            .filter_map(|m| {
                tenants
                    .iter()
                    .find(|t| {
                        t.id == m.tenant_id
                            && t.deleted_at.is_none()
                            && t.status == TenantStatus::Active
                    })
                    .map(|t| self.to_membership(t, m))
            })
            .collect();
        // last_used_at 降序、NULL 最后,再按租户 id 升序(镜像 PG ORDER BY)
        out.sort_by(|a, b| {
            match (a.last_used_at, b.last_used_at) {
                (Some(x), Some(y)) => y.cmp(&x),
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (None, None) => Ordering::Equal,
            }
            .then_with(|| a.tenant.id.cmp(&b.tenant.id))
        });
        Ok(out)
    }

    async fn touch_last_used(&self, tenant_id: Uuid, user_id: Uuid) -> Result<(), IdmError> {
        let now = OffsetDateTime::now_utc();
        self.with_member(tenant_id, user_id, |m| m.last_used_at = Some(now))
    }
}

/// 发件箱内存实现:与 `InMemoryUserRepo`/`InMemoryRoleRepo` 可共享同一份 `OutboxStore`
/// (见 [`InMemoryOutboxRepo::sharing_with`]),让 Task 2 起 emit 的行经本 repo 的 poll/mark 可见
/// (镜像 PG "同库不同表" 的语义)。
pub struct InMemoryOutboxRepo {
    inner: Arc<OutboxStore>,
}

impl InMemoryOutboxRepo {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(OutboxStore::default()),
        }
    }

    /// 与给定 `InMemoryUserRepo` **共享**发件箱存储。
    pub fn sharing_with(users: &InMemoryUserRepo) -> Self {
        Self {
            inner: Arc::clone(&users.outbox),
        }
    }
}

impl Default for InMemoryOutboxRepo {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl OutboxRepo for InMemoryOutboxRepo {
    async fn poll_unpublished(&self, limit: i64) -> Result<Vec<OutboxRecord>, IdmError> {
        let rows = self.inner.rows.lock().expect("锁未中毒");
        // 插入序即 id 升序(Vec 只追加),故直接按序取前 limit 条 = ORDER BY id ASC LIMIT。
        Ok(rows
            .iter()
            .filter(|r| r.published_at.is_none())
            .take(limit.max(0) as usize)
            .map(OutboxRow::to_record)
            .collect())
    }

    async fn mark_published(&self, ids: &[i64]) -> Result<(), IdmError> {
        let mut rows = self.inner.rows.lock().expect("锁未中毒");
        let now = OffsetDateTime::now_utc();
        for r in rows.iter_mut() {
            if ids.contains(&r.id) {
                r.published_at.get_or_insert(now);
            }
        }
        Ok(())
    }

    async fn emit(
        &self,
        event_type: &str,
        aggregate_id: Uuid,
        payload: serde_json::Value,
    ) -> Result<(), IdmError> {
        self.inner.emit(event_type, aggregate_id, payload);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// emit → poll 见到(FIFO,按 emit 序)→ mark 第一条 → poll 只剩第二条 → mark 完 → poll 空。
    #[tokio::test]
    async fn outbox_emit_poll_mark_roundtrip() {
        let outbox = InMemoryOutboxRepo::new();
        let a = Uuid::now_v7();
        let b = Uuid::now_v7();
        outbox.inner.emit("user.created", a, json!({"who": "a"}));
        outbox.inner.emit("user.created", b, json!({"who": "b"}));

        let rows = outbox.poll_unpublished(10).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].aggregate_id, a);
        assert_eq!(rows[1].aggregate_id, b);

        outbox.mark_published(&[rows[0].id]).await.unwrap();
        let remaining = outbox.poll_unpublished(10).await.unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].aggregate_id, b);

        outbox.mark_published(&[remaining[0].id]).await.unwrap();
        assert!(outbox.poll_unpublished(10).await.unwrap().is_empty());
    }

    /// 公共 `OutboxRepo::emit`(auth 事件用):emit → poll 立即可见,FIFO 保序。
    #[tokio::test]
    async fn public_emit_appends_pollable_row() {
        let outbox = InMemoryOutboxRepo::new();
        let agg = Uuid::now_v7();
        outbox
            .emit("auth.login_succeeded", agg, json!({"user_id": agg}))
            .await
            .unwrap();

        let rows = outbox.poll_unpublished(10).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].event_type, "auth.login_succeeded");
        assert_eq!(rows[0].aggregate_id, agg);
    }

    /// `InMemoryOutboxRepo::sharing_with` / `InMemoryRoleRepo::sharing_with` 与 `InMemoryUserRepo`
    /// 共享同一个 `Arc<OutboxStore>`(Task 2 的前提:任一侧 emit,三个 repo 视角一致)。
    #[tokio::test]
    async fn outbox_shares_store_with_user_and_role_repo() {
        let users = InMemoryUserRepo::new();
        let roles = InMemoryRoleRepo::sharing_with(&users);
        let outbox = InMemoryOutboxRepo::sharing_with(&users);
        assert!(Arc::ptr_eq(&users.outbox, &roles.outbox));
        assert!(Arc::ptr_eq(&users.outbox, &outbox.inner));

        users.outbox.emit("user.created", Uuid::now_v7(), json!({}));
        assert_eq!(outbox.poll_unpublished(10).await.unwrap().len(), 1);
    }
}
