//! idm 仓储:`UserRepo`(users + user_password 凭据分表,同事务)、`SessionRepo`(sessions)、
//! `RoleRepo`(roles + user_roles)、`OutboxRepo`(outbox,事务性发件箱——写方法内 emit 同事务落一行,
//! 本端口只管轮询/标记,不管发布机制)、`TenantRepo`(tenants)、`MemberRepo`(tenant_members + member_roles)。
//! 范式同 widget:trait 端口 + 内存/PG 实现分文件,service 依赖 trait。

mod memory;
mod postgres;

use async_trait::async_trait;
use sea_query::Iden;
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::IdmError;
use crate::tenant::{MemberStatus, Membership, RoleScope, Tenant, TenantStatus};

pub use memory::{
    InMemoryMemberRepo, InMemoryOutboxRepo, InMemoryRoleRepo, InMemorySessionRepo,
    InMemoryTenantRepo, InMemoryUserRepo,
};
pub use postgres::{
    PgMemberRepo, PgOutboxRepo, PgRoleRepo, PgSessionRepo, PgTenantRepo, PgUserRepo,
};

/// 用户内部实体。`FromRow` 供 PG 查映射;读模型 `UserView` 由 service 转,审计字段不进 `UserView`(对外 DTO 归 app)。
#[derive(Clone, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub created_at: OffsetDateTime,
}

/// 用户 + 密码 hash —— **仅** `find_by_email` 返回(登录验密用)。绝不进 DTO / 日志 / 响应。
pub struct UserWithHash {
    pub user: User,
    pub password_hash: String,
}

/// admin 用户列表读模型。比 `User` 多 `created_at` + `roles`(角色名),不含审计写字段。
/// `roles` 映射 PG `text[]`(相关子查询聚合、按名排序);内存实现同样按名排序以保 parity。
#[derive(Clone, sqlx::FromRow)]
pub struct UserListRow {
    pub id: Uuid,
    pub username: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub created_at: OffsetDateTime,
    pub roles: Vec<String>,
}

/// 列表过滤。`None` / 空 `Vec` = 不过滤该维度。
/// `username` 子串模糊(大小写不敏感);`roles_any` = 角色名有交集;`roles_none` = 无交集;
/// `created_from`/`created_to` = 闭区间。
#[derive(Clone, Default)]
pub struct UserListFilter {
    pub username: Option<String>,
    pub roles_any: Vec<String>,
    pub roles_none: Vec<String>,
    pub created_from: Option<OffsetDateTime>,
    pub created_to: Option<OffsetDateTime>,
}

/// 列表排序键。
#[derive(Clone, Copy, Debug)]
pub enum UserSortBy {
    CreatedAt,
    Username,
    Email,
}

/// 排序方向。
#[derive(Clone, Copy, Debug)]
pub enum SortDir {
    Asc,
    Desc,
}

/// 分页模式。`Offset` = 经典页 + 可选总数;`Cursor` = id keyset(v7 全序,默认 created desc 用)。
#[derive(Clone, Copy, Debug)]
pub enum ListPage {
    Offset {
        offset: u64,
        limit: u64,
        with_total: bool,
    },
    Cursor {
        after: Option<Uuid>,
        limit: u64,
    },
}

/// 列表结果。`total` 仅 `Offset { with_total: true }` 时 `Some`;
/// `next_after` 仅 `Cursor` 且还有下一页时 `Some`(下一页游标)。
pub struct UserListResult {
    pub rows: Vec<UserListRow>,
    pub total: Option<u64>,
    pub next_after: Option<Uuid>,
}

/// 通用分页结果(租户列表 / 成员列表)。语义同 [`UserListResult`]:`total` 仅 `Offset { with_total: true }`
/// 时 `Some`;`next_after` 仅 `Cursor` 且还有下一页时 `Some`。
pub struct ListResult<T> {
    pub rows: Vec<T>,
    pub total: Option<u64>,
    pub next_after: Option<Uuid>,
}

/// 角色目录项(`RoleRepo::list` 返回)。`scope` 标明它是平台角色还是租户角色。
#[derive(Clone, sqlx::FromRow)]
pub struct Role {
    pub id: Uuid,
    pub name: String,
    pub display_name: String,
    #[sqlx(try_from = "String")]
    pub scope: RoleScope,
}

/// 会话内部实体。`id` 同时作 JWT 的 `jti`。`tenant_id` = 会话所在租户,`None` = 平台上下文。
#[derive(Clone, Debug, sqlx::FromRow)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub tenant_id: Option<Uuid>,
}

/// 发件箱记录(`OutboxRepo::poll_unpublished` 返回)。不含 `published_at`——返回的行按定义都未发布。
#[derive(Clone, sqlx::FromRow)]
pub struct OutboxRecord {
    pub id: i64,
    pub event_type: String,
    pub aggregate_id: Uuid,
    pub payload: Value,
    pub created_at: OffsetDateTime,
}

/// `user.created` 事件 payload(内存 / PG 三处建号共用,保证形状一致)。`roles` = 建号时授的平台角色名。
pub(crate) fn user_created_payload(user: &User, roles: &[String]) -> Value {
    serde_json::json!({
        "user_id": user.id,
        "username": user.username,
        "email": user.email,
        "email_verified": user.email_verified,
        "created_at": user.created_at,
        "roles": roles,
    })
}

// ── tenant.* 事件 payload(内存 / PG 共用,保证形状一致;都带 tenant_id)──

pub(crate) fn tenant_payload(t: &Tenant) -> Value {
    serde_json::json!({
        "tenant_id": t.id,
        "slug": t.slug,
        "name": t.name,
        "status": t.status.as_str(),
    })
}

pub(crate) fn member_payload(
    tenant_id: Uuid,
    user_id: Uuid,
    status: Option<MemberStatus>,
    roles: Option<&[String]>,
) -> Value {
    let mut v = serde_json::json!({ "tenant_id": tenant_id, "user_id": user_id });
    if let Some(s) = status {
        v["status"] = Value::from(s.as_str());
    }
    if let Some(r) = roles {
        v["roles"] = serde_json::json!(r);
    }
    v
}

/// 内存 / PG 共用的 cursor 分页收尾:`rows` 已按 key 升序且多取了一条(limit + 1)。
pub(crate) fn finish_cursor_page<T>(
    mut rows: Vec<T>,
    limit: u64,
    key: impl Fn(&T) -> Uuid,
) -> ListResult<T> {
    let has_more = rows.len() as u64 > limit;
    rows.truncate(limit as usize);
    let next_after = if has_more {
        rows.last().map(&key)
    } else {
        None
    };
    ListResult {
        rows,
        total: None,
        next_after,
    }
}

// ── sea-query 表/列标识(snake_case:`Users::Table` -> "users"、`EmailVerified` -> "email_verified")──
#[derive(Iden)]
pub(crate) enum Users {
    Table,
    Id,
    Username,
    Email,
    EmailVerified,
    CreatedAt, // 表里已有此列(0001 迁移);list 排序/返回用
    CreatedBy,
    UpdatedBy,
    DeletedAt,
}
#[derive(Iden)]
pub(crate) enum UserPassword {
    Table,
    UserId,
    PasswordHash,
    PasswordUpdatedAt,
}
#[derive(Iden)]
pub(crate) enum Sessions {
    Table,
    Id,
    UserId,
    TokenHash,
    ExpiresAt,
    RevokedAt,
    TenantId,
    CreatedBy,
    UpdatedBy,
}
#[derive(Iden)]
pub(crate) enum Roles {
    Table,
    Id,
    Name,
    DisplayName,
    Scope,
    CreatedBy,
    UpdatedBy,
    DeletedAt,
}
#[derive(Iden)]
pub(crate) enum UserRoles {
    Table,
    UserId,
    RoleId,
    GrantedBy,
}
#[derive(Iden)]
pub(crate) enum Tenants {
    Table,
    Id,
    Slug,
    Name,
    Status,
    CreatedBy,
    CreatedAt,
    UpdatedBy,
    UpdatedAt,
    DeletedAt,
}
#[derive(Iden)]
pub(crate) enum TenantMembers {
    Table,
    TenantId,
    UserId,
    Status,
    LastUsedAt,
    AddedBy,
}
#[derive(Iden)]
pub(crate) enum MemberRoles {
    Table,
    TenantId,
    UserId,
    RoleId,
    GrantedBy,
}
#[derive(Iden)]
pub(crate) enum Outbox {
    Table,
    Id,
    EventType,
    AggregateId,
    Payload,
    CreatedAt,
    PublishedAt,
}

/// 用户仓储端口。写操作的 `by` = 审计主体(created_by),由调用方(app)传入。
#[async_trait]
pub trait UserRepo: Send + Sync {
    /// 同事务建 user + user_password(凭据分表)。username 或 email 已被存活用户占用 → `Conflict`(409)。
    async fn create(
        &self,
        username: &str,
        email: Option<&str>,
        password_hash: &str,
        by: Option<String>,
    ) -> Result<User, IdmError>;

    /// 按 identifier(username 或 email)查存活用户 + 密码 hash(登录用)。
    /// 不存在 → `None`(防枚举,由 service 统一成 401)。
    async fn find_by_identifier(&self, identifier: &str) -> Result<Option<UserWithHash>, IdmError>;

    /// 按 id 查存活用户。不存在 / 已软删 → `NotFound`。
    async fn find_by_id(&self, id: Uuid) -> Result<User, IdmError>;

    /// 按 id **批量**查存活用户(跨模块富化的根原语:如 widget 列表补 created_by 的 username)。
    /// 一条 SQL(`WHERE id IN ...`)解 N+1;查不到的 id 不在结果里(交调用方降级)。
    async fn find_by_ids(&self, ids: &[Uuid]) -> Result<Vec<User>, IdmError>;

    /// **全量更新** username/email(PUT 语义:都替换;`username` 必填,`email=None` 即清空)。
    /// 替换 email 会把 email_verified 置 false。冲突 → `Conflict`;已软删 → `NotFound`。
    async fn update(
        &self,
        id: Uuid,
        username: &str,
        email: Option<&str>,
        by: Option<String>,
    ) -> Result<User, IdmError>;

    /// 软删用户(注销)。幂等(已删/不存在 → NotFound)。
    async fn soft_delete(&self, id: Uuid, by: Option<String>) -> Result<(), IdmError>;

    /// 更新密码 hash(改密)。
    async fn update_password(&self, user_id: Uuid, password_hash: &str) -> Result<(), IdmError>;

    /// 取存活用户的密码 hash(改密/删号验密用)。
    async fn password_hash(&self, user_id: Uuid) -> Result<Option<String>, IdmError>;

    /// admin 列表:过滤(username 模糊 / roles_any / roles_none / created 区间)+ 排序
    /// (`sort_by`×`dir`,email `NULLS LAST`,id 兜底)+ 分页(offset+可选总数 或 cursor keyset)。
    /// **只见存活用户**;`roles` 列 = 该用户存活角色名(按名排序)。
    async fn list(
        &self,
        filter: &UserListFilter,
        sort_by: UserSortBy,
        dir: SortDir,
        page: &ListPage,
    ) -> Result<UserListResult, IdmError>;

    /// 原子建号 + 授角色(**一个事务**:users + user_password + user_roles)。
    /// username/email 已被存活用户占用 → `Conflict`;任一步失败整体回滚(不留半截)。
    async fn create_with_roles(
        &self,
        username: &str,
        email: Option<&str>,
        password_hash: &str,
        role_ids: &[Uuid],
        by: Option<String>,
    ) -> Result<User, IdmError>;

    /// **注册的原子单元**(一个事务:users + user_password + tenant_members + member_roles)。
    /// 租户存活且 active → 建号并把账号加为该租户 active 成员、授 `role_ids`(发 `user.created` +
    /// `tenant.member_added`);租户不存在 / 已软删 / 停用 → **只建账号**(只发 `user.created`,不报错)。
    /// username/email 已被占用 → `Conflict`;任一 role_id 不存在 → `NotFound`;失败整体回滚(不留账号)。
    async fn create_with_membership(
        &self,
        username: &str,
        email: Option<&str>,
        password_hash: &str,
        tenant_id: Uuid,
        role_ids: &[Uuid],
        by: Option<String>,
    ) -> Result<User, IdmError>;
}

/// 会话仓储端口。
#[async_trait]
pub trait SessionRepo: Send + Sync {
    /// 建会话(refresh token 只落 SHA-256 hash,明文不入库)。返回的 `Session.id` 即 JWT `jti`。
    /// `tenant_id` = 会话所在租户(`None` = 平台上下文);租户行不存在 → `NotFound`(FK;已软删的行仍在,不拦 ——
    /// 能否进入由 service 判断)。内存实现要和租户仓储看同一批租户须用 `InMemorySessionRepo::sharing_with`。
    async fn create(
        &self,
        user_id: Uuid,
        tenant_id: Option<Uuid>,
        token_hash: &str,
        expires_at: OffsetDateTime,
        by: Option<String>,
    ) -> Result<Session, IdmError>;

    /// 按 refresh token hash 查**活跃**会话(未撤销、未过期)。
    async fn find_active(
        &self,
        token_hash: &str,
        now: OffsetDateTime,
    ) -> Result<Option<Session>, IdmError>;

    /// 撤销会话(盖 revoked_at)。幂等(已撤销/不存在都 Ok)。
    async fn revoke(&self, session_id: Uuid) -> Result<(), IdmError>;

    /// 撤销用户的所有活跃会话;`except` 排除某会话(改密保留当前)。
    async fn revoke_all(&self, user_id: Uuid, except: Option<Uuid>) -> Result<(), IdmError>;

    /// 撤销某成员**在该租户里**的全部活跃会话(移出 / 停用成员时)。别的租户、平台上下文的会话不动。幂等。
    async fn revoke_for_member(&self, tenant_id: Uuid, user_id: Uuid) -> Result<(), IdmError>;

    /// 撤销某租户里所有人的活跃会话(停用 / 删除租户时)。幂等。
    async fn revoke_for_tenant(&self, tenant_id: Uuid) -> Result<(), IdmError>;
}

/// 角色仓储端口(seed / RBAC 用)。
#[async_trait]
pub trait RoleRepo: Send + Sync {
    /// 幂等:存活同名角色已存在 → 返回其 id(`scope` 与传入不同则校正为传入值 —— 角色归哪类由消费方
    /// 的代码闭集决定,迁移出来的默认 `tenant` 靠 seed 每次 upsert 收敛);否则创建。
    async fn upsert(
        &self,
        name: &str,
        display_name: &str,
        scope: RoleScope,
        by: Option<String>,
    ) -> Result<Uuid, IdmError>;

    /// 幂等授予用户角色(`user_roles` 复合主键冲突即跳过)。
    async fn grant(&self, user_id: Uuid, role_id: Uuid, by: Option<String>)
        -> Result<(), IdmError>;

    /// 查用户的**平台角色**名(经 `user_roles` 授予、存活、`scope = platform`),供 JWT `roles` claim。
    /// 租户角色不在这里(见 [`MemberRepo`] / `Membership.roles`)。
    async fn roles_for_user(&self, user_id: Uuid) -> Result<Vec<String>, IdmError>;

    /// 角色目录:所有存活角色(按 name 排序)。admin 分配角色的候选集。
    async fn list(&self) -> Result<Vec<Role>, IdmError>;

    /// **原子全量替换**用户角色集(一个事务:清旧 + 批量授新)。幂等(重复调用结果稳定)。
    async fn set_roles(
        &self,
        user_id: Uuid,
        role_ids: &[Uuid],
        by: Option<String>,
    ) -> Result<(), IdmError>;
}

/// 租户仓储端口。写方法在自己的事务内同时写 outbox(`tenant.created` / `tenant.updated` / `tenant.deleted`,
/// payload 都带 `tenant_id`,aggregate_id = 租户 id)。读方法**只见存活租户**(软删 → `NotFound`)。
#[async_trait]
pub trait TenantRepo: Send + Sync {
    /// 建租户(id = uuid v7,status = active)。slug 已被任何租户占用(**含已软删**)→ `Conflict`。
    async fn create(&self, slug: &str, name: &str, by: Option<String>) -> Result<Tenant, IdmError>;

    /// 按**固定 id** 幂等建(seed 用,如默认租户)。该 id 已存在 → 原样返回(不改名、不发事件,
    /// 含已软删的行);否则建并发 `tenant.created`。slug 被别的 id 占用 → `Conflict`。
    async fn upsert_fixed(
        &self,
        id: Uuid,
        slug: &str,
        name: &str,
        by: Option<String>,
    ) -> Result<Tenant, IdmError>;

    /// 按 id 查存活租户。不存在 / 已软删 → `NotFound`。
    async fn get(&self, id: Uuid) -> Result<Tenant, IdmError>;

    /// 按 slug 查存活租户。不存在 / 已软删 → `NotFound`。
    async fn get_by_slug(&self, slug: &str) -> Result<Tenant, IdmError>;

    /// 存活租户列表,按 id 升序(v7 = 创建序);`Cursor` 的 `after` 是上一页最后一个租户 id。
    async fn list(&self, page: &ListPage) -> Result<ListResult<Tenant>, IdmError>;

    /// 改名(slug 不可改)。发 `tenant.updated`。不存在 / 已软删 → `NotFound`。
    async fn update_name(
        &self,
        id: Uuid,
        name: &str,
        by: Option<String>,
    ) -> Result<Tenant, IdmError>;

    /// 停用 / 恢复。发 `tenant.updated`(含 status)。不存在 / 已软删 → `NotFound`。
    /// **不吊销会话**:调用方(service)再调 `SessionRepo::revoke_for_tenant`。
    async fn set_status(
        &self,
        id: Uuid,
        status: TenantStatus,
        by: Option<String>,
    ) -> Result<Tenant, IdmError>;

    /// 软删。slug 继续占用(不复用)。发 `tenant.deleted`。不存在 / 已软删 → `NotFound`。
    async fn soft_delete(&self, id: Uuid, by: Option<String>) -> Result<(), IdmError>;
}

/// 成员仓储端口(tenant_members + member_roles)。写方法在自己的事务内同时写 outbox
/// (`tenant.member_added` / `tenant.member_removed` / `tenant.member_roles_set` / `tenant.member_updated`,
/// payload 都带 `tenant_id` 和 `user_id`,aggregate_id = 租户 id)。
/// `Membership.roles` 只含**存活、scope = tenant** 的角色名(按名排序);写入时只校验角色存在,不校验 scope。
#[async_trait]
pub trait MemberRepo: Send + Sync {
    /// 加成员(status = active)并授租户角色。租户不存在 / 已软删、用户不存在、任一 role_id 不存在
    /// → `NotFound`;已是成员(任何状态)→ `Conflict`。任一步失败整体回滚。
    async fn add(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        role_ids: &[Uuid],
        by: Option<String>,
    ) -> Result<Membership, IdmError>;

    /// 移出成员(删成员关系,连带它在该租户的全部租户角色)。不是成员 / 租户已软删 → `NotFound`。
    /// **不吊销会话**:调用方再调 `SessionRepo::revoke_for_member`。
    async fn remove(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        by: Option<String>,
    ) -> Result<(), IdmError>;

    /// 停用 / 恢复成员。发 `tenant.member_updated`(含 status)。不是成员 / 租户已软删 → `NotFound`。
    async fn set_status(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        status: MemberStatus,
        by: Option<String>,
    ) -> Result<(), IdmError>;

    /// **原子全量替换**该成员在该租户的租户角色。不是成员 / 租户已软删 / 任一 role_id 不存在 → `NotFound`(不动原角色)。
    async fn set_roles(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        role_ids: &[Uuid],
        by: Option<String>,
    ) -> Result<(), IdmError>;

    /// 查成员关系(**任何状态**,租户停用也照样返回,由调用方判断)。不是成员 / 租户已软删 → `None`。
    async fn get(&self, tenant_id: Uuid, user_id: Uuid) -> Result<Option<Membership>, IdmError>;

    /// 某租户的成员列表(任何状态),按 user_id 升序;`Cursor` 的 `after` 是上一页最后一个 user_id。
    async fn list_by_tenant(
        &self,
        tenant_id: Uuid,
        page: &ListPage,
    ) -> Result<ListResult<Membership>, IdmError>;

    /// 某账号**有效**的成员关系:租户 active 且未删 + 成员 active。按 `last_used_at` 降序(NULL 最后),
    /// 再按租户 id 升序 —— 第一个就是登录默认进入的租户。
    async fn memberships_for_user(&self, user_id: Uuid) -> Result<Vec<Membership>, IdmError>;

    /// 记录"刚进入该租户"(登录 / 切换):last_used_at = now。不发事件。不是成员 / 租户已软删 → `NotFound`。
    async fn touch_last_used(&self, tenant_id: Uuid, user_id: Uuid) -> Result<(), IdmError>;
}

/// 发件箱仓储端口(transactional outbox)。只读轮询 + 标记已发布,**不参与写事务**——写事务里的
/// 那一行由各 repo(`UserRepo`/`RoleRepo`/`TenantRepo`/`MemberRepo`)写方法内部的 emit 助手在自己的 `&mut Transaction` 上插入。
#[async_trait]
pub trait OutboxRepo: Send + Sync {
    /// 取最早的未发布记录(按 id 升序,FIFO),最多 `limit` 条。
    async fn poll_unpublished(&self, limit: i64) -> Result<Vec<OutboxRecord>, IdmError>;

    /// 标记已发布(盖 published_at)。幂等(重复标记/标记不存在的 id 都 Ok)。
    async fn mark_published(&self, ids: &[i64]) -> Result<(), IdmError>;

    /// **非事务** emit(auth 审计事件用):不挂任何 domain 写事务,单条 insert 到 outbox。
    /// 与 `emit_outbox` 助手(挂调用方 `&mut Transaction`)互补 —— 后者给"领域写 + 事件同事务"的场景,
    /// 本方法给"无领域写的纯审计事件"(登录成功/失败/登出…),由消费方(app handler)在 HTTP 边界调用。
    async fn emit(
        &self,
        event_type: &str,
        aggregate_id: Uuid,
        payload: serde_json::Value,
    ) -> Result<(), IdmError>;
}
