//! 用户仓储端口 [`UserRepo`] 及其数据类型。

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use super::list_page::{ListPage, ListResult, SortDirection};
use crate::idm_error::IdmError;

/// 建号所需的字段(`create` / `create_with_roles` / `create_with_membership` 共用)。
#[derive(Clone, Copy, Default, PartialEq)]
#[allow(
    clippy::exhaustive_structs,
    reason = "指南 non_exhaustive 结构体条款的 FRU 例外:调用方用 ..Default::default() 构造"
)]
pub struct NewUser<'fields> {
    /// 用户名(调用方已归一;存活用户里唯一)。
    pub username: &'fields str,
    /// 邮箱,可选(存活用户里唯一)。
    pub email: Option<&'fields str>,
    /// 密码的 PHC 串(已哈希)。
    pub password_hash: &'fields str,
}

/// 手写 `Debug`:密码 hash 不进日志。
impl fmt::Debug for NewUser<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NewUser")
            .field("username", &self.username)
            .field("email", &self.email)
            .finish_non_exhaustive()
    }
}

/// 用户内部实体。`FromRow` 供 PG 查映射;读模型 `UserView` 由 service 转,审计字段不进 `UserView`
/// (对外 DTO 归 app)。
#[derive(Clone, Debug, PartialEq, sqlx::FromRow)]
#[non_exhaustive]
pub struct User {
    /// 账号 id(uuid v7)。
    pub id: Uuid,
    /// 用户名。
    pub username: String,
    /// 邮箱。
    pub email: Option<String>,
    /// 邮箱是否已验证(换邮箱即重置)。
    pub email_verified: bool,
    /// 建号时刻。
    pub created_at: OffsetDateTime,
}

impl User {
    /// 新账号:没有邮箱、未验证;按需再改公开字段。给自己实现 [`UserRepo`] 的调用方用。
    #[must_use]
    pub fn new(id: Uuid, username: String, created_at: OffsetDateTime) -> Self {
        Self {
            id,
            username,
            email: None,
            email_verified: false,
            created_at,
        }
    }
}

/// 用户 + 密码 hash —— **仅** `find_by_identifier` 返回(登录验密用)。绝不进 DTO / 日志 / 响应。
#[derive(Clone, PartialEq)]
#[non_exhaustive]
pub struct UserWithHash {
    /// 用户。
    pub user: User,
    /// 密码的 PHC 串。
    pub password_hash: String,
}

impl UserWithHash {
    /// 组装(给自己实现 [`UserRepo`] 的调用方用)。
    #[must_use]
    pub fn new(user: User, password_hash: String) -> Self {
        Self {
            user,
            password_hash,
        }
    }
}

/// 手写 `Debug`:密码 hash 不进日志。
impl fmt::Debug for UserWithHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserWithHash")
            .field("user", &self.user)
            .finish_non_exhaustive()
    }
}

/// admin 用户列表读模型。比 `User` 多 `roles`(平台角色名),不含审计写字段。
/// `roles` 映射 PG `text[]`(相关子查询聚合、按名排序);内存实现同样按名排序以保 parity。
#[derive(Clone, Debug, PartialEq, sqlx::FromRow)]
#[non_exhaustive]
pub struct UserListRow {
    /// 账号 id。
    pub id: Uuid,
    /// 用户名。
    pub username: String,
    /// 邮箱。
    pub email: Option<String>,
    /// 邮箱是否已验证。
    pub email_verified: bool,
    /// 建号时刻。
    pub created_at: OffsetDateTime,
    /// 存活的**平台**角色名(按名排序)。
    pub roles: Vec<String>,
}

impl UserListRow {
    /// 由用户和它的平台角色名组装(给自己实现 [`UserRepo`] 的调用方用)。
    #[must_use]
    pub fn new(user: User, roles: Vec<String>) -> Self {
        Self {
            id: user.id,
            username: user.username,
            email: user.email,
            email_verified: user.email_verified,
            created_at: user.created_at,
            roles,
        }
    }
}

/// 列表过滤。`None` / 空 `Vec` = 不过滤该维度。
#[derive(Clone, Debug, Default, PartialEq)]
#[allow(
    clippy::exhaustive_structs,
    reason = "指南 non_exhaustive 结构体条款的 FRU 例外(也是「Options structs should implement \
              Default」说的选项结构体):调用方用 ..Default::default() 构造"
)]
pub struct UserListFilter {
    /// username 子串模糊(大小写不敏感)。
    pub username: Option<String>,
    /// 平台角色名有交集。
    pub roles_any: Vec<String>,
    /// 平台角色名无交集。
    pub roles_none: Vec<String>,
    /// 建号时刻下界(含)。
    pub created_from: Option<OffsetDateTime>,
    /// 建号时刻上界(含)。
    pub created_to: Option<OffsetDateTime>,
}

/// 列表排序键。
#[derive(Clone, Copy, Debug, PartialEq)]
#[non_exhaustive]
pub enum UserSortBy {
    /// 建号时刻。
    CreatedAt,
    /// 用户名(字节序)。
    Username,
    /// 邮箱(字节序,没有邮箱的排最后)。
    Email,
}

/// 用户仓储端口。写操作的 `by` = 审计主体(created_by / updated_by),由调用方(app)传入。
///
/// 只遍历的参数(`ids` / `role_ids`)用切片而非 `impl IntoIterator`:trait 要保持 dyn 兼容
/// (`Arc<dyn UserRepo>` 运行时二选一实现),泛型方法会破坏 dyn 兼容(指南「Generics versus dyn Trait」);
/// 返回 `Vec`:实现天然从数据库取回成 `Vec`(指南「Iterators vs. owned collections」例外)。
#[async_trait]
pub trait UserRepo: Send + Sync {
    /// 同事务建 user + user_password(凭据分表)。username 或 email 已被存活用户占用 → `Conflict`。
    async fn create(&self, user: NewUser<'_>, by: Option<&str>) -> Result<User, IdmError>;

    /// 按 identifier(username 或 email)查存活用户 + 密码 hash(登录用)。
    /// 不存在 → `None`(防枚举,由 service 统一成 401)。
    async fn find_by_identifier(&self, identifier: &str) -> Result<Option<UserWithHash>, IdmError>;

    /// 按 id 查存活用户。不存在 / 已软删 → `NotFound`。
    async fn find_by_id(&self, id: Uuid) -> Result<User, IdmError>;

    /// 按 id **批量**查存活用户(跨模块富化的根原语:如 widget 列表补 created_by 的 username)。
    /// 一条 SQL(`WHERE id IN ...`)解 N+1;查不到的 id 不在结果里(交调用方降级)。
    async fn find_by_ids(&self, ids: &[Uuid]) -> Result<Vec<User>, IdmError>;

    /// **全量更新** username / email(PUT 语义:都替换;`email = None` 即清空)。
    /// 替换 email 会把 email_verified 置 false。冲突 → `Conflict`;已软删 → `NotFound`。
    async fn update(
        &self,
        id: Uuid,
        username: &str,
        email: Option<&str>,
        by: Option<&str>,
    ) -> Result<User, IdmError>;

    /// 软删用户(注销)。已删 / 不存在 → `NotFound`。
    async fn soft_delete(&self, id: Uuid, by: Option<&str>) -> Result<(), IdmError>;

    /// 更新密码 hash(改密)。
    async fn update_password(&self, user_id: Uuid, password_hash: &str) -> Result<(), IdmError>;

    /// 取存活用户的密码 hash(改密 / 删号验密用)。
    async fn password_hash(&self, user_id: Uuid) -> Result<Option<String>, IdmError>;

    /// admin 列表:过滤(username 模糊 / roles_any / roles_none / created 区间)+ 排序
    /// (`sort_by` × `direction`,email `NULLS LAST`,id 兜底)+ 分页(offset + 可选总数 或 cursor keyset)。
    /// **只见存活用户**;`roles` 列 = 该用户存活的**平台**角色名(按名排序);`roles_any` / `roles_none`
    /// 也只按平台角色判定。`user_roles` 里租户作用域的行(迁移 0004 复制进默认租户后的残留)一概不看。
    async fn list(
        &self,
        filter: &UserListFilter,
        sort_by: UserSortBy,
        direction: SortDirection,
        page: &ListPage,
    ) -> Result<ListResult<UserListRow>, IdmError>;

    /// 原子建号 + 授平台角色(**一个事务**:users + user_password + user_roles)。
    /// username / email 已被存活用户占用 → `Conflict`;任一 role_id 不存在 → `NotFound`;失败整体回滚。
    async fn create_with_roles(
        &self,
        user: NewUser<'_>,
        role_ids: &[Uuid],
        by: Option<&str>,
    ) -> Result<User, IdmError>;

    /// **注册的原子单元**(一个事务:users + user_password + tenant_members + member_roles)。
    /// 租户存活且 active → 建号并把账号加为该租户 active 成员、授 `role_ids`(发 `user.created` +
    /// `tenant.member_added`);租户不存在 / 已软删 / 停用 → **只建账号**(只发 `user.created`,不报错)。
    /// username / email 已被占用 → `Conflict`;任一 role_id 不存在 → `NotFound`;失败整体回滚(不留账号)。
    async fn create_with_membership(
        &self,
        user: NewUser<'_>,
        tenant_id: Uuid,
        role_ids: &[Uuid],
        by: Option<&str>,
    ) -> Result<User, IdmError>;
}

/// 转发实现:`Arc<dyn UserRepo>` / `Arc<具体仓储>` 也是 `UserRepo`(下游运行时二选一实现时用)。
#[async_trait]
impl<T: UserRepo + ?Sized> UserRepo for Arc<T> {
    async fn create(&self, user: NewUser<'_>, by: Option<&str>) -> Result<User, IdmError> {
        (**self).create(user, by).await
    }

    async fn find_by_identifier(&self, identifier: &str) -> Result<Option<UserWithHash>, IdmError> {
        (**self).find_by_identifier(identifier).await
    }

    async fn find_by_id(&self, id: Uuid) -> Result<User, IdmError> {
        (**self).find_by_id(id).await
    }

    async fn find_by_ids(&self, ids: &[Uuid]) -> Result<Vec<User>, IdmError> {
        (**self).find_by_ids(ids).await
    }

    async fn update(
        &self,
        id: Uuid,
        username: &str,
        email: Option<&str>,
        by: Option<&str>,
    ) -> Result<User, IdmError> {
        (**self).update(id, username, email, by).await
    }

    async fn soft_delete(&self, id: Uuid, by: Option<&str>) -> Result<(), IdmError> {
        (**self).soft_delete(id, by).await
    }

    async fn update_password(&self, user_id: Uuid, password_hash: &str) -> Result<(), IdmError> {
        (**self).update_password(user_id, password_hash).await
    }

    async fn password_hash(&self, user_id: Uuid) -> Result<Option<String>, IdmError> {
        (**self).password_hash(user_id).await
    }

    async fn list(
        &self,
        filter: &UserListFilter,
        sort_by: UserSortBy,
        direction: SortDirection,
        page: &ListPage,
    ) -> Result<ListResult<UserListRow>, IdmError> {
        (**self).list(filter, sort_by, direction, page).await
    }

    async fn create_with_roles(
        &self,
        user: NewUser<'_>,
        role_ids: &[Uuid],
        by: Option<&str>,
    ) -> Result<User, IdmError> {
        (**self).create_with_roles(user, role_ids, by).await
    }

    async fn create_with_membership(
        &self,
        user: NewUser<'_>,
        tenant_id: Uuid,
        role_ids: &[Uuid],
        by: Option<&str>,
    ) -> Result<User, IdmError> {
        (**self)
            .create_with_membership(user, tenant_id, role_ids, by)
            .await
    }
}

/// 转发实现:同 `Arc<T>`,给独占所有权的 `Box<dyn UserRepo>` / `Box<具体实现>` 用。**每个方法都转发**。
#[async_trait]
impl<T: UserRepo + ?Sized> UserRepo for Box<T> {
    async fn create(&self, user: NewUser<'_>, by: Option<&str>) -> Result<User, IdmError> {
        (**self).create(user, by).await
    }

    async fn find_by_identifier(&self, identifier: &str) -> Result<Option<UserWithHash>, IdmError> {
        (**self).find_by_identifier(identifier).await
    }

    async fn find_by_id(&self, id: Uuid) -> Result<User, IdmError> {
        (**self).find_by_id(id).await
    }

    async fn find_by_ids(&self, ids: &[Uuid]) -> Result<Vec<User>, IdmError> {
        (**self).find_by_ids(ids).await
    }

    async fn update(
        &self,
        id: Uuid,
        username: &str,
        email: Option<&str>,
        by: Option<&str>,
    ) -> Result<User, IdmError> {
        (**self).update(id, username, email, by).await
    }

    async fn soft_delete(&self, id: Uuid, by: Option<&str>) -> Result<(), IdmError> {
        (**self).soft_delete(id, by).await
    }

    async fn update_password(&self, user_id: Uuid, password_hash: &str) -> Result<(), IdmError> {
        (**self).update_password(user_id, password_hash).await
    }

    async fn password_hash(&self, user_id: Uuid) -> Result<Option<String>, IdmError> {
        (**self).password_hash(user_id).await
    }

    async fn list(
        &self,
        filter: &UserListFilter,
        sort_by: UserSortBy,
        direction: SortDirection,
        page: &ListPage,
    ) -> Result<ListResult<UserListRow>, IdmError> {
        (**self).list(filter, sort_by, direction, page).await
    }

    async fn create_with_roles(
        &self,
        user: NewUser<'_>,
        role_ids: &[Uuid],
        by: Option<&str>,
    ) -> Result<User, IdmError> {
        (**self).create_with_roles(user, role_ids, by).await
    }

    async fn create_with_membership(
        &self,
        user: NewUser<'_>,
        tenant_id: Uuid,
        role_ids: &[Uuid],
        by: Option<&str>,
    ) -> Result<User, IdmError> {
        (**self)
            .create_with_membership(user, tenant_id, role_ids, by)
            .await
    }
}
