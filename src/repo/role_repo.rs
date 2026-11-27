//! 角色仓储端口 [`RoleRepo`] 及其数据类型。

use std::sync::Arc;

use async_trait::async_trait;
use uuid::Uuid;

use crate::idm_error::IdmError;
use crate::tenant::RoleScope;

/// 要 upsert 的角色(`RoleRepo::upsert` 的输入)。
#[derive(Clone, Copy, Debug, PartialEq)]
#[allow(
    clippy::exhaustive_structs,
    reason = "指南 non_exhaustive 结构体条款的 FRU 例外:调用方用 ..Default::default() 构造"
)]
pub struct NewRole<'fields> {
    /// 角色名(唯一,代码里的闭集)。
    pub name: &'fields str,
    /// 展示名称。
    pub display_name: &'fields str,
    /// 平台角色还是租户角色。
    pub scope: RoleScope,
}

impl Default for NewRole<'_> {
    /// 空名字的租户角色(只作 FRU 起点)。`RoleScope` 没有"默认作用域",所以手写:取权限更窄的租户。
    fn default() -> Self {
        Self {
            name: "",
            display_name: "",
            scope: RoleScope::Tenant,
        }
    }
}

/// 一条平台角色授予:`user_roles` 的复合主键(账号 + 角色)。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[allow(
    clippy::exhaustive_structs,
    reason = "指南 non_exhaustive 结构体条款例外:描述既有本体(复合主键 = 账号 + 角色),字段不会变"
)]
pub struct RoleGrant {
    /// 被授予的账号。
    pub user_id: Uuid,
    /// 授予的角色。
    pub role_id: Uuid,
}

/// 角色目录项(`RoleRepo::list` 返回)。
#[derive(Clone, Debug, PartialEq, sqlx::FromRow)]
#[non_exhaustive]
pub struct Role {
    /// 角色 id。
    pub id: Uuid,
    /// 角色名。
    pub name: String,
    /// 展示名称。
    pub display_name: String,
    /// 平台角色还是租户角色。
    #[sqlx(try_from = "String")]
    pub scope: RoleScope,
}

impl Role {
    /// 由 id 与字段组装(给自己实现 [`RoleRepo`] 的调用方用)。
    #[must_use]
    pub fn new(id: Uuid, fields: NewRole<'_>) -> Self {
        Self {
            id,
            name: fields.name.to_owned(),
            display_name: fields.display_name.to_owned(),
            scope: fields.scope,
        }
    }
}

/// 角色仓储端口(seed / RBAC 用)。返回 `Vec`:实现天然从数据库取回成 `Vec`(指南「Iterators vs. owned
/// collections」例外);只遍历的 `role_ids` 用切片保持 dyn 兼容(见 [`UserRepo`](crate::UserRepo))。
#[async_trait]
pub trait RoleRepo: Send + Sync {
    /// 幂等:存活同名角色已存在 → 返回其 id(`scope` 与传入不同则校正为传入值 —— 角色归哪类由消费方
    /// 的代码闭集决定,迁移出来的默认 `tenant` 靠 seed 每次 upsert 收敛);否则创建。
    async fn upsert(&self, role: NewRole<'_>, by: Option<&str>) -> Result<Uuid, IdmError>;

    /// 幂等授予用户平台角色(`user_roles` 复合主键冲突即跳过)。
    async fn grant(&self, grant: RoleGrant, by: Option<&str>) -> Result<(), IdmError>;

    /// 查用户的**平台角色**名(经 `user_roles` 授予、存活、`scope = platform`),供 JWT `roles` claim。
    /// 租户角色不在这里(见 [`MemberRepo`](crate::MemberRepo) / `Membership.roles`)。
    async fn roles_for_user(&self, user_id: Uuid) -> Result<Vec<String>, IdmError>;

    /// 角色目录:所有存活角色(按 name 排序)。admin 分配角色的候选集。
    async fn list(&self) -> Result<Vec<Role>, IdmError>;

    /// **原子全量替换**用户角色集(一个事务:清旧 + 批量授新)。幂等(重复调用结果稳定)。
    /// 任一 role_id 不存在 → `NotFound`(不动原授予)。
    async fn set_roles(
        &self,
        user_id: Uuid,
        role_ids: &[Uuid],
        by: Option<&str>,
    ) -> Result<(), IdmError>;
}

/// 转发实现:`Arc<dyn RoleRepo>` / `Arc<具体仓储>` 也是 `RoleRepo`。
#[async_trait]
impl<T: RoleRepo + ?Sized> RoleRepo for Arc<T> {
    async fn upsert(&self, role: NewRole<'_>, by: Option<&str>) -> Result<Uuid, IdmError> {
        (**self).upsert(role, by).await
    }

    async fn grant(&self, grant: RoleGrant, by: Option<&str>) -> Result<(), IdmError> {
        (**self).grant(grant, by).await
    }

    async fn roles_for_user(&self, user_id: Uuid) -> Result<Vec<String>, IdmError> {
        (**self).roles_for_user(user_id).await
    }

    async fn list(&self) -> Result<Vec<Role>, IdmError> {
        (**self).list().await
    }

    async fn set_roles(
        &self,
        user_id: Uuid,
        role_ids: &[Uuid],
        by: Option<&str>,
    ) -> Result<(), IdmError> {
        (**self).set_roles(user_id, role_ids, by).await
    }
}

/// 转发实现:同 `Arc<T>`,给独占所有权的 `Box<dyn RoleRepo>` / `Box<具体实现>` 用。**每个方法都转发**。
#[async_trait]
impl<T: RoleRepo + ?Sized> RoleRepo for Box<T> {
    async fn upsert(&self, role: NewRole<'_>, by: Option<&str>) -> Result<Uuid, IdmError> {
        (**self).upsert(role, by).await
    }

    async fn grant(&self, grant: RoleGrant, by: Option<&str>) -> Result<(), IdmError> {
        (**self).grant(grant, by).await
    }

    async fn roles_for_user(&self, user_id: Uuid) -> Result<Vec<String>, IdmError> {
        (**self).roles_for_user(user_id).await
    }

    async fn list(&self) -> Result<Vec<Role>, IdmError> {
        (**self).list().await
    }

    async fn set_roles(
        &self,
        user_id: Uuid,
        role_ids: &[Uuid],
        by: Option<&str>,
    ) -> Result<(), IdmError> {
        (**self).set_roles(user_id, role_ids, by).await
    }
}
