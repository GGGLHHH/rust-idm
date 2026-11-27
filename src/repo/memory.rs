//! idm 仓储内存实现 —— 脚手架默认,无 DB 即可跑通注册 / 登录全链路 + 写单测。
//! 镜像 PG 的软删过滤、username 唯一、email(有则)唯一、外键,保 parity。
//!
//! 各仓储方法在锁已中毒(别的线程持锁时 panic 过)时 panic,见 `lock`。
//!
//! **共享存储用 `Arc<Mutex<…>>`**:PG 下几个仓储读写同一个库的不同表(外键、跨表查询);内存下要镜像这一点,
//! 各仓储就得共享同一份存储(`new_shared_with(&users)`)。改成借用会让每个仓储带生命周期参数、一路传染到
//! `AuthService` 和消费方的 `AppState`,属于指南「Avoid Rc and Arc」例外里"替代的借用结构过于复杂"的情形。

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};

use async_trait::async_trait;
use serde_json::{json, Value};
use time::OffsetDateTime;
use uuid::Uuid;

use super::event_payload;
use super::list_page::{ListPage, ListResult, SortDirection};
use super::member_repo::MemberRepo;
use super::outbox_repo::{OutboxRecord, OutboxRepo};
use super::role_repo::{NewRole, Role, RoleGrant, RoleRepo};
use super::session_repo::{Session, SessionRepo};
use super::tenant_repo::{NewTenant, TenantRepo};
use super::user_repo::{
    NewUser, User, UserListFilter, UserListRow, UserRepo, UserSortBy, UserWithHash,
};
use crate::idm_error::IdmError;
use crate::tenant::{
    MemberKey, MemberStatus, Membership, RoleScope, Tenant, TenantStatus, DEFAULT_TENANT_ID,
};

/// 用户名 / 邮箱撞存活用户时的冲突消息(与 PG 实现同文)。
const USER_TAKEN: &str = "Username or email already taken";
/// slug 被占用时的冲突消息(与 PG 实现同文)。
const SLUG_TAKEN: &str = "Tenant slug already taken";

/// 取锁。中毒 = 别的线程持锁时 panic 过、状态可能只改了一半 —— 不去读里面的数据(指南「Handling poison」),
/// 直接 panic。
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .expect("内存仓储的锁已中毒:持锁的线程 panic 过")
}

/// 内存内部行:比 `User` 多 password_hash + deleted_at(DTO 不暴露)。
struct UserRow {
    id: Uuid,
    username: String,
    email: Option<String>,
    email_verified: bool,
    password_hash: String,
    created_at: OffsetDateTime,
    deleted_at: Option<OffsetDateTime>,
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

    fn is_alive(&self) -> bool {
        self.deleted_at.is_none()
    }

    /// 是否占用了 `username` / `email`(唯一性只看存活行,镜像两个 partial unique 索引)。
    fn takes(&self, username: &str, email: Option<&str>) -> bool {
        self.is_alive()
            && (self.username == username || (email.is_some() && self.email.as_deref() == email))
    }
}

/// 角色 + 授予关系的**共享**存储:`UserRepo`(create_with_roles / list 读角色名)与 `RoleRepo`
/// (upsert / grant / set_roles / roles_for_user)必须共用同一份,才能镜像 PG 两 repo 共表的语义。
#[derive(Default)]
struct RoleStore {
    /// 存活角色(内存无软删)。
    roles: Mutex<Vec<RoleRecord>>,
    /// 平台角色授予(`user_roles`)。
    grants: Mutex<Vec<RoleGrant>>,
}

struct RoleRecord {
    id: Uuid,
    name: String,
    display_name: String,
    scope: RoleScope,
}

/// 把 role_ids 解到存活角色名(按名排序),供 `user.created` / `user.roles_set` 的 outbox payload 用;
/// 成员仓储的 `add` / `set_roles` 也拿它只做存在性校验。任一 id 查不到存活角色 → `NotFound`
/// (镜像 PG user_roles / member_roles → roles 的 FK:非法 role_id 整体失败)。
fn resolve_role_names(store: &RoleStore, role_ids: &[Uuid]) -> Result<Vec<String>, IdmError> {
    let roles = lock(&store.roles);
    let mut names: Vec<String> = Vec::with_capacity(role_ids.len());
    for role_id in role_ids {
        let role = roles
            .iter()
            .find(|role| role.id == *role_id)
            .ok_or(IdmError::NotFound)?;
        names.push(role.name.clone());
    }
    names.sort();
    Ok(names)
}

/// role_ids 里**租户角色**的名字(按名排序)——`Membership.roles` 与成员事件 payload 共用。
fn tenant_role_names(store: &RoleStore, role_ids: &[Uuid]) -> Vec<String> {
    let roles = lock(&store.roles);
    let mut names: Vec<String> = roles
        .iter()
        .filter(|role| role.scope == RoleScope::Tenant && role_ids.contains(&role.id))
        .map(|role| role.name.clone())
        .collect();
    names.sort();
    names
}

/// 某用户经 `user_roles` 授予的存活**平台**角色名(授予顺序)。
fn platform_role_names(roles: &[RoleRecord], grants: &[RoleGrant], user_id: Uuid) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    let user_grants = grants.iter().filter(|grant| grant.user_id == user_id);
    for grant in user_grants {
        let platform_role = roles
            .iter()
            .find(|role| role.id == grant.role_id && role.scope == RoleScope::Platform);
        if let Some(role) = platform_role {
            names.push(role.name.clone());
        }
    }
    names
}

/// 给 `user_id` 授 `role_ids`(已授的跳过,镜像 PG 主键冲突 do nothing)。
fn grant_all(grants: &mut Vec<RoleGrant>, user_id: Uuid, role_ids: &[Uuid]) {
    for role_id in role_ids {
        let grant = RoleGrant {
            user_id,
            role_id: *role_id,
        };
        if !grants.contains(&grant) {
            grants.push(grant);
        }
    }
}

/// 去重保序(镜像 PG 主键冲突跳过)。
fn dedup_ids(role_ids: &[Uuid]) -> Vec<Uuid> {
    let mut ids: Vec<Uuid> = Vec::with_capacity(role_ids.len());
    for role_id in role_ids {
        if !ids.contains(role_id) {
            ids.push(*role_id);
        }
    }
    ids
}

/// 发件箱内部行:比 `OutboxRecord` 多 `published_at`(是否已发布,对外不暴露 —— poll 只返未发布行)。
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

/// 发件箱的**共享**存储:各仓储写方法内 emit 与 `InMemoryOutboxRepo`(poll / mark)共用同一份,
/// 镜像 PG "同库不同表" 的语义。
#[derive(Default)]
struct OutboxStore {
    rows: Mutex<Vec<OutboxRow>>,
}

impl OutboxStore {
    /// 内部 emit 助手:追加一行(id 递增,未发布)。
    fn emit(&self, event_type: &str, aggregate_id: Uuid, payload: Value) {
        let mut rows = lock(&self.rows);
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

/// 租户 + 成员关系的**共享**存储。构造时就带默认租户(镜像迁移 0004 的插入)。
struct TenantStore {
    /// 含已软删(slug 不复用要看它们)。
    tenants: Mutex<Vec<Tenant>>,
    members: Mutex<Vec<MemberRecord>>,
}

impl Default for TenantStore {
    fn default() -> Self {
        let default_tenant = Tenant::new(
            DEFAULT_TENANT_ID,
            NewTenant {
                slug: "default",
                name: "默认组织",
            },
            OffsetDateTime::now_utc(),
        );
        Self {
            tenants: Mutex::new(vec![default_tenant]),
            members: Mutex::new(Vec::new()),
        }
    }
}

impl TenantStore {
    /// 存活(未软删)的租户。
    fn find_alive(tenants: &[Tenant], id: Uuid) -> Option<&Tenant> {
        tenants
            .iter()
            .find(|tenant| tenant.id == id && tenant.deleted_at.is_none())
    }
}

/// 成员内存行:`role_ids` 即该成员在该租户的 member_roles。
struct MemberRecord {
    key: MemberKey,
    status: MemberStatus,
    last_used_at: Option<OffsetDateTime>,
    role_ids: Vec<Uuid>,
}

/// 排序方向套到一个原始 `Ordering` 上。
fn apply_direction(ordering: Ordering, direction: SortDirection) -> Ordering {
    match direction {
        SortDirection::Ascending => ordering,
        SortDirection::Descending => ordering.reverse(),
    }
}

/// `NULLS LAST` 比较:非空恒排在空之前(与方向无关),两非空按方向比。
fn compare_nulls_last(
    left: Option<&str>,
    right: Option<&str>,
    direction: SortDirection,
) -> Ordering {
    match (left, right) {
        (Some(left), Some(right)) => apply_direction(left.cmp(right), direction),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

/// 单行比较:主键按 `sort_by` × 方向(email `NULLS LAST`),再以 id 兜底(同方向,镜像 PG)。
fn compare_rows(
    left: &UserListRow,
    right: &UserListRow,
    sort_by: UserSortBy,
    direction: SortDirection,
) -> Ordering {
    let primary = match sort_by {
        UserSortBy::Username => apply_direction(left.username.cmp(&right.username), direction),
        UserSortBy::CreatedAt => apply_direction(left.created_at.cmp(&right.created_at), direction),
        UserSortBy::Email => {
            compare_nulls_last(left.email.as_deref(), right.email.as_deref(), direction)
        }
    };
    primary.then_with(|| apply_direction(left.id.cmp(&right.id), direction))
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
            let page_rows: Vec<T> = rows
                .into_iter()
                .skip(offset as usize)
                .take(limit as usize)
                .collect();
            ListResult::new(page_rows, total, None)
        }
        ListPage::Cursor { after, limit } => {
            let kept: Vec<T> = rows
                .into_iter()
                .filter(|row| after.is_none_or(|after| key(row) > after))
                .take(limit as usize + 1)
                .collect();
            ListResult::from_cursor_rows(kept, limit, key)
        }
    }
}

/// 建号三处(create / create_with_roles / create_with_membership)共用:查重 → `precheck` → 写用户行。
/// `precheck` 在查重**之后**、写入**之前**跑(镜像 PG 先撞唯一索引、再撞后续外键的错误优先级),失败则不写;
/// 其返回值原样带回给调用方。
fn insert_user_row<T>(
    store: &mut HashMap<Uuid, UserRow>,
    new_user: NewUser<'_>,
    precheck: impl FnOnce() -> Result<T, IdmError>,
) -> Result<(User, T), IdmError> {
    let taken = store
        .values()
        .any(|row| row.takes(new_user.username, new_user.email));
    if taken {
        return Err(IdmError::Conflict(USER_TAKEN.to_owned()));
    }
    let extra = precheck()?;
    let row = UserRow {
        id: Uuid::now_v7(),
        username: new_user.username.to_owned(),
        email: new_user.email.map(str::to_owned),
        email_verified: false,
        password_hash: new_user.password_hash.to_owned(),
        created_at: OffsetDateTime::now_utc(),
        deleted_at: None,
    };
    let user = row.to_user();
    store.insert(row.id, row);
    Ok((user, extra))
}

/// 用户内存实现。它持有所有共享存储;其它内存仓储经 `new_shared_with(&users)` 共享。
///
/// # Panics
///
/// 各仓储方法在锁已中毒(共享这份存储的某个调用方持锁时 panic 过)时 panic:状态可能只改了一半,
/// 不能接着读(指南「Handling poison」)。
#[derive(Default)]
pub struct InMemoryUserRepo {
    /// 成员仓储也读它,镜像 PG `tenant_members.user_id → users` 的 FK(查用户是否存在)。
    store: Arc<Mutex<HashMap<Uuid, UserRow>>>,
    roles: Arc<RoleStore>,
    outbox: Arc<OutboxStore>,
    tenants: Arc<TenantStore>,
}

impl InMemoryUserRepo {
    /// 一套全新的空存储(只有默认租户)。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl UserRepo for InMemoryUserRepo {
    async fn create(&self, user: NewUser<'_>, _by: Option<&str>) -> Result<User, IdmError> {
        let mut store = lock(&self.store);
        let (created, ()) = insert_user_row(&mut store, user, || Ok(()))?;
        drop(store);
        self.outbox.emit(
            "user.created",
            created.id,
            event_payload::user_created(&created, &[]),
        );
        Ok(created)
    }

    async fn find_by_identifier(&self, identifier: &str) -> Result<Option<UserWithHash>, IdmError> {
        let store = lock(&self.store);
        let found = store.values().find(|row| {
            row.is_alive()
                && (row.username == identifier || row.email.as_deref() == Some(identifier))
        });
        Ok(found.map(|row| UserWithHash::new(row.to_user(), row.password_hash.clone())))
    }

    async fn find_by_id(&self, id: Uuid) -> Result<User, IdmError> {
        lock(&self.store)
            .get(&id)
            .filter(|row| row.is_alive())
            .map(UserRow::to_user)
            .ok_or(IdmError::NotFound)
    }

    async fn find_by_ids(&self, ids: &[Uuid]) -> Result<Vec<User>, IdmError> {
        let store = lock(&self.store);
        // 镜像 PG:只返存活行,查不到的 id 直接缺席(不报错)。
        Ok(ids
            .iter()
            .filter_map(|id| store.get(id))
            .filter(|row| row.is_alive())
            .map(UserRow::to_user)
            .collect())
    }

    async fn update(
        &self,
        id: Uuid,
        username: &str,
        email: Option<&str>,
        _by: Option<&str>,
    ) -> Result<User, IdmError> {
        let mut store = lock(&self.store);
        // 冲突检查(排除自己):username / email 撞别的存活用户
        let taken = store
            .values()
            .any(|row| row.id != id && row.takes(username, email));
        if taken {
            return Err(IdmError::Conflict(USER_TAKEN.to_owned()));
        }
        let row = store
            .get_mut(&id)
            .filter(|row| row.is_alive())
            .ok_or(IdmError::NotFound)?;
        // PUT 全量替换:username 必填、email 总替换(含清空),替换 email 即重置验证。
        row.username = username.to_owned();
        row.email = email.map(str::to_owned);
        row.email_verified = false;
        let user = row.to_user();
        self.outbox
            .emit("user.updated", user.id, event_payload::user_updated(&user));
        Ok(user)
    }

    async fn soft_delete(&self, id: Uuid, _by: Option<&str>) -> Result<(), IdmError> {
        let mut store = lock(&self.store);
        let row = store
            .get_mut(&id)
            .filter(|row| row.is_alive())
            .ok_or(IdmError::NotFound)?;
        row.deleted_at = Some(OffsetDateTime::now_utc());
        self.outbox
            .emit("user.deleted", id, json!({ "user_id": id }));
        Ok(())
    }

    async fn update_password(&self, user_id: Uuid, password_hash: &str) -> Result<(), IdmError> {
        let mut store = lock(&self.store);
        let row = store
            .get_mut(&user_id)
            .filter(|row| row.is_alive())
            .ok_or(IdmError::NotFound)?;
        row.password_hash = password_hash.to_owned();
        Ok(())
    }

    async fn password_hash(&self, user_id: Uuid) -> Result<Option<String>, IdmError> {
        Ok(lock(&self.store)
            .get(&user_id)
            .filter(|row| row.is_alive())
            .map(|row| row.password_hash.clone()))
    }

    async fn create_with_roles(
        &self,
        user: NewUser<'_>,
        role_ids: &[Uuid],
        _by: Option<&str>,
    ) -> Result<User, IdmError> {
        let mut store = lock(&self.store);
        // 查重之后、写入之前校验 role_ids 都是存活角色(镜像 PG user_roles 对 roles 的 FK),否则不动任何存储。
        let (created, role_names) = insert_user_row(&mut store, user, || {
            resolve_role_names(&self.roles, role_ids)
        })?;
        drop(store);
        grant_all(&mut lock(&self.roles.grants), created.id, role_ids);
        self.outbox.emit(
            "user.created",
            created.id,
            event_payload::user_created(&created, &role_names),
        );
        Ok(created)
    }

    async fn create_with_membership(
        &self,
        user: NewUser<'_>,
        tenant_id: Uuid,
        role_ids: &[Uuid],
        _by: Option<&str>,
    ) -> Result<User, IdmError> {
        let mut store = lock(&self.store);
        // 查重之后、写入之前:校验角色(FK)+ 判断租户能不能加入(存活且 active;否则只建账号)。
        let (created, joinable) = insert_user_row(&mut store, user, || {
            resolve_role_names(&self.roles, role_ids)?;
            let tenants = lock(&self.tenants.tenants);
            Ok(TenantStore::find_alive(&tenants, tenant_id)
                .is_some_and(|tenant| tenant.status == TenantStatus::Active))
        })?;
        drop(store);
        self.outbox.emit(
            "user.created",
            created.id,
            event_payload::user_created(&created, &[]),
        );

        if joinable {
            let ids = dedup_ids(role_ids);
            let names = tenant_role_names(&self.roles, &ids);
            lock(&self.tenants.members).push(MemberRecord {
                key: MemberKey {
                    tenant_id,
                    user_id: created.id,
                },
                status: MemberStatus::Active,
                last_used_at: None,
                role_ids: ids,
            });
            self.outbox.emit(
                "tenant.member_added",
                tenant_id,
                event_payload::member(
                    tenant_id,
                    created.id,
                    Some(MemberStatus::Active),
                    Some(&names),
                ),
            );
        }
        Ok(created)
    }

    async fn list(
        &self,
        filter: &UserListFilter,
        sort_by: UserSortBy,
        direction: SortDirection,
        page: &ListPage,
    ) -> Result<ListResult<UserListRow>, IdmError> {
        let store = lock(&self.store);
        let grants = lock(&self.roles.grants);
        let roles = lock(&self.roles.roles);
        let username_query: Option<String> = filter
            .username
            .as_ref()
            .map(|username| username.to_lowercase());
        let mut rows: Vec<UserListRow> = Vec::new();
        let alive_rows = store.values().filter(|row| row.is_alive());
        for row in alive_rows {
            let username_matches = username_query
                .as_ref()
                .is_none_or(|query| row.username.to_lowercase().contains(query));
            let created_in_range = filter
                .created_from
                .is_none_or(|from| row.created_at >= from)
                && filter.created_to.is_none_or(|to| row.created_at <= to);
            if !username_matches || !created_in_range {
                continue;
            }
            // 存活**平台**角色名(按名排序,parity with PG 子查询 ORDER BY r.name)。user_roles 里的租户
            // 作用域行(迁移 0004 复制残留)不算,镜像 PG 的 scope = 'platform' 过滤。
            let mut role_names = platform_role_names(&roles, &grants, row.id);
            role_names.sort();
            let any_matches = filter.roles_any.is_empty()
                || filter
                    .roles_any
                    .iter()
                    .any(|name| role_names.contains(name));
            let none_matches = filter
                .roles_none
                .iter()
                .any(|name| role_names.contains(name));
            if !any_matches || none_matches {
                continue;
            }
            rows.push(UserListRow::new(row.to_user(), role_names));
        }
        rows.sort_by(|left, right| compare_rows(left, right, sort_by, direction));

        match *page {
            ListPage::Offset {
                offset,
                limit,
                with_total,
            } => {
                let total = with_total.then_some(rows.len() as u64);
                let page_rows: Vec<UserListRow> = rows
                    .into_iter()
                    .skip(offset as usize)
                    .take(limit as usize)
                    .collect();
                Ok(ListResult::new(page_rows, total, None))
            }
            ListPage::Cursor { after, limit } => {
                // 镜像 PG:先 WHERE id keyset(相对方向),再 ORDER BY,再取 limit + 1 判下一页。
                let kept: Vec<UserListRow> = rows
                    .into_iter()
                    .filter(|row| {
                        after.is_none_or(|after| match direction {
                            SortDirection::Ascending => row.id > after,
                            SortDirection::Descending => row.id < after,
                        })
                    })
                    .collect();
                Ok(ListResult::from_cursor_rows(kept, limit, |row| row.id))
            }
        }
    }
}

/// 会话内存行。
struct SessionRow {
    session: Session,
    token_hash: String,
    expires_at: OffsetDateTime,
    revoked_at: Option<OffsetDateTime>,
}

/// 会话内存实现。
///
/// # Panics
///
/// 各仓储方法在锁已中毒(共享这份存储的某个调用方持锁时 panic 过)时 panic:状态可能只改了一半,
/// 不能接着读(指南「Handling poison」)。
#[derive(Default)]
pub struct InMemorySessionRepo {
    store: Mutex<Vec<SessionRow>>,
    /// 租户存储(镜像 PG `sessions.tenant_id → tenants` 的外键:建会话时校验租户存在)。
    tenants: Arc<TenantStore>,
}

impl InMemorySessionRepo {
    /// 独立一份租户存储(只有默认租户)。要和别的内存仓储看同一批租户 → [`Self::new_shared_with`]。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 与给定 `InMemoryUserRepo` **共享**租户存储(镜像 PG 外键看的是同一张 tenants 表)。
    #[must_use]
    pub fn new_shared_with(users: &InMemoryUserRepo) -> Self {
        Self {
            store: Mutex::new(Vec::new()),
            tenants: Arc::clone(&users.tenants),
        }
    }

    /// 给满足条件的活跃会话盖 revoked_at(已撤销的不动,幂等)。
    fn revoke_where(&self, predicate: impl Fn(&Session) -> bool) {
        let now = OffsetDateTime::now_utc();
        for row in lock(&self.store).iter_mut() {
            if row.revoked_at.is_none() && predicate(&row.session) {
                row.revoked_at = Some(now);
            }
        }
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
        _by: Option<&str>,
    ) -> Result<Session, IdmError> {
        // 镜像 PG 外键:租户行须存在(已软删的行也还在,外键不拦)。
        if let Some(tenant_id) = tenant_id {
            let exists = lock(&self.tenants.tenants)
                .iter()
                .any(|tenant| tenant.id == tenant_id);
            if !exists {
                return Err(IdmError::NotFound);
            }
        }
        let session = Session::new(user_id, tenant_id);
        lock(&self.store).push(SessionRow {
            session: session.clone(),
            token_hash: token_hash.to_owned(),
            expires_at,
            revoked_at: None,
        });
        Ok(session)
    }

    async fn find_active(
        &self,
        token_hash: &str,
        now: OffsetDateTime,
    ) -> Result<Option<Session>, IdmError> {
        Ok(lock(&self.store)
            .iter()
            .find(|row| {
                row.token_hash == token_hash && row.revoked_at.is_none() && row.expires_at > now
            })
            .map(|row| row.session.clone()))
    }

    async fn revoke(&self, session_id: Uuid) -> Result<bool, IdmError> {
        // 查 + 改在同一把锁里:镜像 PG 的条件更新,并发撤同一会话只有一个拿到 true。
        let mut store = lock(&self.store);
        let active = store
            .iter_mut()
            .find(|row| row.session.id == session_id && row.revoked_at.is_none());
        let Some(row) = active else {
            return Ok(false);
        };
        row.revoked_at = Some(OffsetDateTime::now_utc());
        Ok(true)
    }

    async fn revoke_all(&self, user_id: Uuid, except: Option<Uuid>) -> Result<(), IdmError> {
        self.revoke_where(|session| session.user_id == user_id && Some(session.id) != except);
        Ok(())
    }

    async fn revoke_for_member(&self, member: MemberKey) -> Result<(), IdmError> {
        self.revoke_where(|session| {
            session.tenant_id == Some(member.tenant_id) && session.user_id == member.user_id
        });
        Ok(())
    }

    async fn revoke_for_tenant(&self, tenant_id: Uuid) -> Result<(), IdmError> {
        self.revoke_where(|session| session.tenant_id == Some(tenant_id));
        Ok(())
    }
}

/// 角色内存实现。与 `InMemoryUserRepo` 可共享角色存储(见 [`InMemoryRoleRepo::new_shared_with`]),
/// 从而 `create_with_roles` / `set_roles` 写的授予对 `roles_for_user` / `list` 可见(镜像 PG 共表)。
///
/// # Panics
///
/// 各仓储方法在锁已中毒(共享这份存储的某个调用方持锁时 panic 过)时 panic:状态可能只改了一半,
/// 不能接着读(指南「Handling poison」)。
#[derive(Default)]
pub struct InMemoryRoleRepo {
    inner: Arc<RoleStore>,
    outbox: Arc<OutboxStore>,
}

impl InMemoryRoleRepo {
    /// 独立一份角色 / 发件箱存储。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 与给定 `InMemoryUserRepo` **共享**角色 / 授予 / 发件箱存储 —— 内存模式下让两 repo 语义等价于 PG 共表。
    #[must_use]
    pub fn new_shared_with(users: &InMemoryUserRepo) -> Self {
        Self {
            inner: Arc::clone(&users.roles),
            outbox: Arc::clone(&users.outbox),
        }
    }
}

#[async_trait]
impl RoleRepo for InMemoryRoleRepo {
    async fn upsert(&self, role: NewRole<'_>, _by: Option<&str>) -> Result<Uuid, IdmError> {
        let mut roles = lock(&self.inner.roles);
        if let Some(existing) = roles.iter_mut().find(|existing| existing.name == role.name) {
            existing.scope = role.scope; // 以调用方的代码闭集为准校正 scope
            return Ok(existing.id);
        }
        let id = Uuid::now_v7();
        roles.push(RoleRecord {
            id,
            name: role.name.to_owned(),
            display_name: role.display_name.to_owned(),
            scope: role.scope,
        });
        Ok(id)
    }

    async fn grant(&self, grant: RoleGrant, _by: Option<&str>) -> Result<(), IdmError> {
        grant_all(
            &mut lock(&self.inner.grants),
            grant.user_id,
            &[grant.role_id],
        );
        Ok(())
    }

    async fn roles_for_user(&self, user_id: Uuid) -> Result<Vec<String>, IdmError> {
        let grants = lock(&self.inner.grants);
        let roles = lock(&self.inner.roles);
        // 只回平台角色(镜像 PG 的 scope = 'platform' 过滤)
        Ok(platform_role_names(&roles, &grants, user_id))
    }

    async fn list(&self) -> Result<Vec<Role>, IdmError> {
        let mut list: Vec<Role> = lock(&self.inner.roles)
            .iter()
            .map(|role| Role {
                id: role.id,
                name: role.name.clone(),
                display_name: role.display_name.clone(),
                scope: role.scope,
            })
            .collect();
        list.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(list)
    }

    async fn set_roles(
        &self,
        user_id: Uuid,
        role_ids: &[Uuid],
        _by: Option<&str>,
    ) -> Result<(), IdmError> {
        // 先校验:role_ids 必须都是存活角色,否则不动 grants(镜像 PG FK)。
        let role_names = resolve_role_names(&self.inner, role_ids)?;

        // 全量替换:清该 user 的所有授予,再批量加新(去重)。幂等。
        let mut grants = lock(&self.inner.grants);
        grants.retain(|grant| grant.user_id != user_id);
        grant_all(&mut grants, user_id, role_ids);
        drop(grants);

        self.outbox.emit(
            "user.roles_set",
            user_id,
            json!({ "user_id": user_id, "roles": role_names }),
        );
        Ok(())
    }
}

/// 租户内存实现。
///
/// # Panics
///
/// 各仓储方法在锁已中毒(共享这份存储的某个调用方持锁时 panic 过)时 panic:状态可能只改了一半,
/// 不能接着读(指南「Handling poison」)。
#[derive(Default)]
pub struct InMemoryTenantRepo {
    inner: Arc<TenantStore>,
    outbox: Arc<OutboxStore>,
}

impl InMemoryTenantRepo {
    /// 独立一份租户 / 发件箱存储(只有默认租户)。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 与给定 `InMemoryUserRepo` **共享**租户 / 成员 / 发件箱存储。
    #[must_use]
    pub fn new_shared_with(users: &InMemoryUserRepo) -> Self {
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
        mutate: impl FnOnce(&mut Tenant),
    ) -> Result<Tenant, IdmError> {
        let mut tenants = lock(&self.inner.tenants);
        let tenant = tenants
            .iter_mut()
            .find(|tenant| tenant.id == id && tenant.deleted_at.is_none())
            .ok_or(IdmError::NotFound)?;
        mutate(tenant);
        tenant.updated_at = OffsetDateTime::now_utc();
        let updated = tenant.clone();
        self.outbox
            .emit(event_type, id, event_payload::tenant(&updated));
        Ok(updated)
    }

    /// 插入新租户并发 `tenant.created`;slug 被任何租户占用(含已软删)→ `Conflict`。
    /// 调用方已持租户锁。
    fn insert_new(
        &self,
        tenants: &mut Vec<Tenant>,
        id: Uuid,
        fields: NewTenant<'_>,
    ) -> Result<Tenant, IdmError> {
        // slug 唯一含已软删(镜像不带 deleted_at 条件的唯一索引)
        if tenants.iter().any(|tenant| tenant.slug == fields.slug) {
            return Err(IdmError::Conflict(SLUG_TAKEN.to_owned()));
        }
        let tenant = Tenant::new(id, fields, OffsetDateTime::now_utc());
        tenants.push(tenant.clone());
        self.outbox
            .emit("tenant.created", tenant.id, event_payload::tenant(&tenant));
        Ok(tenant)
    }
}

#[async_trait]
impl TenantRepo for InMemoryTenantRepo {
    async fn create(&self, tenant: NewTenant<'_>, _by: Option<&str>) -> Result<Tenant, IdmError> {
        let mut tenants = lock(&self.inner.tenants);
        self.insert_new(&mut tenants, Uuid::now_v7(), tenant)
    }

    async fn upsert_fixed(
        &self,
        id: Uuid,
        tenant: NewTenant<'_>,
        _by: Option<&str>,
    ) -> Result<Tenant, IdmError> {
        let mut tenants = lock(&self.inner.tenants);
        if let Some(existing) = tenants.iter().find(|existing| existing.id == id) {
            return Ok(existing.clone()); // 已在:原样返回,不改名、不发事件
        }
        self.insert_new(&mut tenants, id, tenant)
    }

    async fn get(&self, id: Uuid) -> Result<Tenant, IdmError> {
        let tenants = lock(&self.inner.tenants);
        TenantStore::find_alive(&tenants, id)
            .cloned()
            .ok_or(IdmError::NotFound)
    }

    async fn get_by_slug(&self, slug: &str) -> Result<Tenant, IdmError> {
        lock(&self.inner.tenants)
            .iter()
            .find(|tenant| tenant.slug == slug && tenant.deleted_at.is_none())
            .cloned()
            .ok_or(IdmError::NotFound)
    }

    async fn list(&self, page: &ListPage) -> Result<ListResult<Tenant>, IdmError> {
        let mut rows: Vec<Tenant> = lock(&self.inner.tenants)
            .iter()
            .filter(|tenant| tenant.deleted_at.is_none())
            .cloned()
            .collect();
        rows.sort_by_key(|tenant| tenant.id);
        Ok(paginate(rows, page, |tenant| tenant.id))
    }

    async fn update_name(
        &self,
        id: Uuid,
        name: &str,
        _by: Option<&str>,
    ) -> Result<Tenant, IdmError> {
        self.mutate_alive(id, "tenant.updated", |tenant| {
            name.clone_into(&mut tenant.name)
        })
    }

    async fn set_status(
        &self,
        id: Uuid,
        status: TenantStatus,
        _by: Option<&str>,
    ) -> Result<Tenant, IdmError> {
        self.mutate_alive(id, "tenant.updated", |tenant| tenant.status = status)
    }

    async fn soft_delete(&self, id: Uuid, _by: Option<&str>) -> Result<(), IdmError> {
        let mut tenants = lock(&self.inner.tenants);
        let tenant = tenants
            .iter_mut()
            .find(|tenant| tenant.id == id && tenant.deleted_at.is_none())
            .ok_or(IdmError::NotFound)?;
        let now = OffsetDateTime::now_utc();
        tenant.deleted_at = Some(now);
        tenant.updated_at = now;
        let payload = json!({ "tenant_id": tenant.id, "slug": tenant.slug });
        self.outbox.emit("tenant.deleted", id, payload);
        Ok(())
    }
}

/// 成员内存实现。与 `InMemoryUserRepo` 共享用户(FK 校验)、角色(名 + scope)、租户、发件箱存储。
///
/// # Panics
///
/// 各仓储方法在锁已中毒(共享这份存储的某个调用方持锁时 panic 过)时 panic:状态可能只改了一半,
/// 不能接着读(指南「Handling poison」)。
#[derive(Default)]
pub struct InMemoryMemberRepo {
    users: Arc<Mutex<HashMap<Uuid, UserRow>>>,
    roles: Arc<RoleStore>,
    tenants: Arc<TenantStore>,
    outbox: Arc<OutboxStore>,
}

impl InMemoryMemberRepo {
    /// 独立一套存储(只有默认租户、没有账号)。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 与给定 `InMemoryUserRepo` **共享**用户 / 角色 / 租户 / 发件箱存储(镜像 PG 共表)。
    #[must_use]
    pub fn new_shared_with(users: &InMemoryUserRepo) -> Self {
        Self {
            users: Arc::clone(&users.store),
            roles: Arc::clone(&users.roles),
            tenants: Arc::clone(&users.tenants),
            outbox: Arc::clone(&users.outbox),
        }
    }

    fn to_membership(&self, tenant: &Tenant, record: &MemberRecord) -> Membership {
        Membership {
            tenant: tenant.clone(),
            user_id: record.key.user_id,
            status: record.status,
            roles: tenant_role_names(&self.roles, &record.role_ids),
            last_used_at: record.last_used_at,
        }
    }

    /// 在成员行上改一下;不是成员 / 租户已软删 → `NotFound`。
    fn with_member<T>(
        &self,
        member: MemberKey,
        mutate: impl FnOnce(&mut MemberRecord) -> T,
    ) -> Result<T, IdmError> {
        let mut members = lock(&self.tenants.members);
        self.ensure_tenant_alive(member.tenant_id)?;
        let record = members
            .iter_mut()
            .find(|record| record.key == member)
            .ok_or(IdmError::NotFound)?;
        Ok(mutate(record))
    }

    /// 租户须存活(未软删),否则 `NotFound` —— 成员写操作对已删租户一律 404(镜像 PG)。
    /// 锁序:调用方已持 members 锁,这里再取 tenants 锁(与 get / list 同序)。
    fn ensure_tenant_alive(&self, tenant_id: Uuid) -> Result<(), IdmError> {
        let tenants = lock(&self.tenants.tenants);
        TenantStore::find_alive(&tenants, tenant_id)
            .map(|_| ())
            .ok_or(IdmError::NotFound)
    }
}

#[async_trait]
impl MemberRepo for InMemoryMemberRepo {
    async fn add(
        &self,
        member: MemberKey,
        role_ids: &[Uuid],
        _by: Option<&str>,
    ) -> Result<Membership, IdmError> {
        // 先校验(各自短暂持锁,避免与 UserRepo::list 的锁序交叉),后改状态。
        // role_ids 都得存在(镜像 PG member_roles → roles 的 FK)。
        resolve_role_names(&self.roles, role_ids)?;
        // 用户须存活:已软删的账号同"不存在"(镜像 PG 的 deleted_at is null 检查)。
        let user_alive = lock(&self.users)
            .get(&member.user_id)
            .is_some_and(UserRow::is_alive);
        if !user_alive {
            return Err(IdmError::NotFound);
        }
        let mut members = lock(&self.tenants.members);
        let tenants = lock(&self.tenants.tenants);
        let tenant =
            TenantStore::find_alive(&tenants, member.tenant_id).ok_or(IdmError::NotFound)?;
        if members.iter().any(|record| record.key == member) {
            return Err(IdmError::Conflict(
                "Already a member of this tenant".to_owned(),
            ));
        }
        let record = MemberRecord {
            key: member,
            status: MemberStatus::Active,
            last_used_at: None,
            role_ids: dedup_ids(role_ids),
        };
        let added = self.to_membership(tenant, &record);
        members.push(record);
        self.outbox.emit(
            "tenant.member_added",
            member.tenant_id,
            event_payload::member(
                member.tenant_id,
                member.user_id,
                Some(added.status),
                Some(&added.roles),
            ),
        );
        Ok(added)
    }

    async fn remove(&self, member: MemberKey, _by: Option<&str>) -> Result<(), IdmError> {
        let mut members = lock(&self.tenants.members);
        self.ensure_tenant_alive(member.tenant_id)?;
        let before = members.len();
        members.retain(|record| record.key != member);
        if members.len() == before {
            return Err(IdmError::NotFound);
        }
        self.outbox.emit(
            "tenant.member_removed",
            member.tenant_id,
            event_payload::member(member.tenant_id, member.user_id, None, None),
        );
        Ok(())
    }

    async fn set_status(
        &self,
        member: MemberKey,
        status: MemberStatus,
        _by: Option<&str>,
    ) -> Result<(), IdmError> {
        self.with_member(member, |record| record.status = status)?;
        self.outbox.emit(
            "tenant.member_updated",
            member.tenant_id,
            event_payload::member(member.tenant_id, member.user_id, Some(status), None),
        );
        Ok(())
    }

    async fn set_roles(
        &self,
        member: MemberKey,
        role_ids: &[Uuid],
        _by: Option<&str>,
    ) -> Result<(), IdmError> {
        resolve_role_names(&self.roles, role_ids)?;
        let ids = dedup_ids(role_ids);
        let names = tenant_role_names(&self.roles, &ids);
        self.with_member(member, |record| record.role_ids = ids)?;
        self.outbox.emit(
            "tenant.member_roles_set",
            member.tenant_id,
            event_payload::member(member.tenant_id, member.user_id, None, Some(&names)),
        );
        Ok(())
    }

    async fn get(&self, member: MemberKey) -> Result<Option<Membership>, IdmError> {
        let members = lock(&self.tenants.members);
        let tenants = lock(&self.tenants.tenants);
        let Some(tenant) = TenantStore::find_alive(&tenants, member.tenant_id) else {
            return Ok(None);
        };
        Ok(members
            .iter()
            .find(|record| record.key == member)
            .map(|record| self.to_membership(tenant, record)))
    }

    async fn list_by_tenant(
        &self,
        tenant_id: Uuid,
        page: &ListPage,
    ) -> Result<ListResult<Membership>, IdmError> {
        // 存活账号快照:先短暂持用户锁再放掉,不和成员 / 租户锁嵌套(建号路径是 用户锁 → 租户锁)。
        let alive_users: HashSet<Uuid> = lock(&self.users)
            .values()
            .filter(|row| row.is_alive())
            .map(|row| row.id)
            .collect();
        let members = lock(&self.tenants.members);
        let tenants = lock(&self.tenants.tenants);
        let mut rows: Vec<Membership> = match TenantStore::find_alive(&tenants, tenant_id) {
            // 已软删账号不进成员列表 / total(镜像 PG 的 users.deleted_at is null 条件)
            Some(tenant) => members
                .iter()
                .filter(|record| {
                    record.key.tenant_id == tenant_id && alive_users.contains(&record.key.user_id)
                })
                .map(|record| self.to_membership(tenant, record))
                .collect(),
            None => Vec::new(),
        };
        rows.sort_by_key(|membership| membership.user_id);
        Ok(paginate(rows, page, |membership| membership.user_id))
    }

    async fn memberships_for_user(&self, user_id: Uuid) -> Result<Vec<Membership>, IdmError> {
        let members = lock(&self.tenants.members);
        let tenants = lock(&self.tenants.tenants);
        let mut effective: Vec<Membership> = Vec::new();
        let active_records = members.iter().filter(|record| {
            record.key.user_id == user_id && record.status == MemberStatus::Active
        });
        for record in active_records {
            let active_tenant = TenantStore::find_alive(&tenants, record.key.tenant_id)
                .filter(|tenant| tenant.status == TenantStatus::Active);
            if let Some(tenant) = active_tenant {
                effective.push(self.to_membership(tenant, record));
            }
        }
        // last_used_at 降序、NULL 最后,再按租户 id 升序(镜像 PG ORDER BY)
        effective.sort_by(|left, right| {
            match (left.last_used_at, right.last_used_at) {
                (Some(left_used), Some(right_used)) => right_used.cmp(&left_used),
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (None, None) => Ordering::Equal,
            }
            .then_with(|| left.tenant.id.cmp(&right.tenant.id))
        });
        Ok(effective)
    }

    async fn touch_last_used(&self, member: MemberKey) -> Result<(), IdmError> {
        let now = OffsetDateTime::now_utc();
        self.with_member(member, |record| record.last_used_at = Some(now))
    }
}

/// 发件箱内存实现:与 `InMemoryUserRepo` 等可共享同一份发件箱存储(见
/// [`InMemoryOutboxRepo::new_shared_with`]),让各仓储写方法内 emit 的行经本 repo 的 poll / mark 可见。
///
/// # Panics
///
/// 各仓储方法在锁已中毒(共享这份存储的某个调用方持锁时 panic 过)时 panic:状态可能只改了一半,
/// 不能接着读(指南「Handling poison」)。
#[derive(Default)]
pub struct InMemoryOutboxRepo {
    inner: Arc<OutboxStore>,
}

impl InMemoryOutboxRepo {
    /// 独立一份发件箱存储。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 与给定 `InMemoryUserRepo` **共享**发件箱存储。
    #[must_use]
    pub fn new_shared_with(users: &InMemoryUserRepo) -> Self {
        Self {
            inner: Arc::clone(&users.outbox),
        }
    }
}

#[async_trait]
impl OutboxRepo for InMemoryOutboxRepo {
    async fn poll_unpublished(&self, limit: i64) -> Result<Vec<OutboxRecord>, IdmError> {
        let rows = lock(&self.inner.rows);
        // 插入序即 id 升序(Vec 只追加),故直接按序取前 limit 条 = ORDER BY id ASC LIMIT。
        Ok(rows
            .iter()
            .filter(|row| row.published_at.is_none())
            .take(limit.max(0) as usize)
            .map(OutboxRow::to_record)
            .collect())
    }

    async fn mark_published(&self, ids: &[i64]) -> Result<(), IdmError> {
        let mut rows = lock(&self.inner.rows);
        let now = OffsetDateTime::now_utc();
        for row in rows.iter_mut() {
            if ids.contains(&row.id) {
                row.published_at.get_or_insert(now);
            }
        }
        Ok(())
    }

    async fn emit(
        &self,
        event_type: &str,
        aggregate_id: Uuid,
        payload: Value,
    ) -> Result<(), IdmError> {
        self.inner.emit(event_type, aggregate_id, payload);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::json;
    use uuid::Uuid;

    use super::{InMemoryOutboxRepo, InMemoryRoleRepo, InMemoryUserRepo};
    use crate::repo::outbox_repo::OutboxRepo;

    /// emit → poll 见到(FIFO,按 emit 序)→ mark 第一条 → poll 只剩第二条 → mark 完 → poll 空。
    #[tokio::test]
    async fn outbox_emit_poll_mark_roundtrip() {
        let outbox = InMemoryOutboxRepo::new();
        let first = Uuid::now_v7();
        let second = Uuid::now_v7();
        outbox
            .inner
            .emit("user.created", first, json!({"who": "a"}));
        outbox
            .inner
            .emit("user.created", second, json!({"who": "b"}));

        let rows = outbox.poll_unpublished(10).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].aggregate_id, first);
        assert_eq!(rows[1].aggregate_id, second);

        outbox.mark_published(&[rows[0].id]).await.unwrap();
        let remaining = outbox.poll_unpublished(10).await.unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].aggregate_id, second);

        outbox.mark_published(&[remaining[0].id]).await.unwrap();
        assert!(outbox.poll_unpublished(10).await.unwrap().is_empty());
    }

    /// 公共 `OutboxRepo::emit`(auth 事件用):emit → poll 立即可见,FIFO 保序。
    #[tokio::test]
    async fn public_emit_appends_pollable_row() {
        let outbox = InMemoryOutboxRepo::new();
        let aggregate = Uuid::now_v7();
        outbox
            .emit(
                "auth.login_succeeded",
                aggregate,
                json!({"user_id": aggregate}),
            )
            .await
            .unwrap();

        let rows = outbox.poll_unpublished(10).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].event_type, "auth.login_succeeded");
        assert_eq!(rows[0].aggregate_id, aggregate);
    }

    /// `InMemoryOutboxRepo::new_shared_with` / `InMemoryRoleRepo::new_shared_with` 与 `InMemoryUserRepo`
    /// 共享同一份发件箱存储(任一侧 emit,三个 repo 视角一致)。
    #[tokio::test]
    async fn outbox_shares_store_with_user_and_role_repo() {
        let users = InMemoryUserRepo::new();
        let roles = InMemoryRoleRepo::new_shared_with(&users);
        let outbox = InMemoryOutboxRepo::new_shared_with(&users);
        assert!(Arc::ptr_eq(&users.outbox, &roles.outbox));
        assert!(Arc::ptr_eq(&users.outbox, &outbox.inner));

        users.outbox.emit("user.created", Uuid::now_v7(), json!({}));
        assert_eq!(outbox.poll_unpublished(10).await.unwrap().len(), 1);
    }
}
