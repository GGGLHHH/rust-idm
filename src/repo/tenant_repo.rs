//! 租户仓储端口 [`TenantRepo`]。

use std::sync::Arc;

use async_trait::async_trait;
use uuid::Uuid;

use super::list_page::{ListPage, ListResult};
use crate::idm_error::IdmError;
use crate::tenant::{Tenant, TenantStatus};

/// 建租户所需的字段。
#[derive(Clone, Copy, Debug, Default, PartialEq)]
#[allow(
    clippy::exhaustive_structs,
    reason = "指南 non_exhaustive 结构体条款的 FRU 例外:调用方用 ..Default::default() 构造"
)]
pub struct NewTenant<'fields> {
    /// 全局唯一的短标识(含已软删的租户,不复用)。
    pub slug: &'fields str,
    /// 展示名称。
    pub name: &'fields str,
}

/// 租户仓储端口。写方法在自己的事务内同时写 outbox(`tenant.created` / `tenant.updated` /
/// `tenant.deleted`,payload 都带 `tenant_id`,aggregate_id = 租户 id)。读方法**只见存活租户**
/// (软删 → `NotFound`)。
#[async_trait]
pub trait TenantRepo: Send + Sync {
    /// 建租户(id = uuid v7,status = active)。slug 已被任何租户占用(**含已软删**)→ `Conflict`。
    async fn create(&self, tenant: NewTenant<'_>, by: Option<&str>) -> Result<Tenant, IdmError>;

    /// 按**固定 id** 幂等建(seed 用,如默认租户)。该 id 已存在 → 原样返回(不改名、不发事件,
    /// 含已软删的行);否则建并发 `tenant.created`。slug 被别的 id 占用 → `Conflict`。
    async fn upsert_fixed(
        &self,
        id: Uuid,
        tenant: NewTenant<'_>,
        by: Option<&str>,
    ) -> Result<Tenant, IdmError>;

    /// 按 id 查存活租户。不存在 / 已软删 → `NotFound`。
    async fn get(&self, id: Uuid) -> Result<Tenant, IdmError>;

    /// 按 slug 查存活租户。不存在 / 已软删 → `NotFound`。
    async fn get_by_slug(&self, slug: &str) -> Result<Tenant, IdmError>;

    /// 存活租户列表,按 id 升序(v7 = 创建序);`Cursor` 的 `after` 是上一页最后一个租户 id。
    async fn list(&self, page: &ListPage) -> Result<ListResult<Tenant>, IdmError>;

    /// 改名(slug 不可改)。发 `tenant.updated`。不存在 / 已软删 → `NotFound`。
    async fn update_name(&self, id: Uuid, name: &str, by: Option<&str>)
        -> Result<Tenant, IdmError>;

    /// 停用 / 恢复。发 `tenant.updated`(含 status)。不存在 / 已软删 → `NotFound`。
    /// **不吊销会话**:调用方(service)再调 `SessionRepo::revoke_for_tenant`。
    async fn set_status(
        &self,
        id: Uuid,
        status: TenantStatus,
        by: Option<&str>,
    ) -> Result<Tenant, IdmError>;

    /// 软删。slug 继续占用(不复用)。发 `tenant.deleted`。不存在 / 已软删 → `NotFound`。
    async fn soft_delete(&self, id: Uuid, by: Option<&str>) -> Result<(), IdmError>;
}

/// 转发实现:`Arc<dyn TenantRepo>` / `Arc<具体仓储>` 也是 `TenantRepo`。
#[async_trait]
impl<T: TenantRepo + ?Sized> TenantRepo for Arc<T> {
    async fn create(&self, tenant: NewTenant<'_>, by: Option<&str>) -> Result<Tenant, IdmError> {
        (**self).create(tenant, by).await
    }

    async fn upsert_fixed(
        &self,
        id: Uuid,
        tenant: NewTenant<'_>,
        by: Option<&str>,
    ) -> Result<Tenant, IdmError> {
        (**self).upsert_fixed(id, tenant, by).await
    }

    async fn get(&self, id: Uuid) -> Result<Tenant, IdmError> {
        (**self).get(id).await
    }

    async fn get_by_slug(&self, slug: &str) -> Result<Tenant, IdmError> {
        (**self).get_by_slug(slug).await
    }

    async fn list(&self, page: &ListPage) -> Result<ListResult<Tenant>, IdmError> {
        (**self).list(page).await
    }

    async fn update_name(
        &self,
        id: Uuid,
        name: &str,
        by: Option<&str>,
    ) -> Result<Tenant, IdmError> {
        (**self).update_name(id, name, by).await
    }

    async fn set_status(
        &self,
        id: Uuid,
        status: TenantStatus,
        by: Option<&str>,
    ) -> Result<Tenant, IdmError> {
        (**self).set_status(id, status, by).await
    }

    async fn soft_delete(&self, id: Uuid, by: Option<&str>) -> Result<(), IdmError> {
        (**self).soft_delete(id, by).await
    }
}

/// 转发实现:同 `Arc<T>`,给独占所有权的 `Box<dyn TenantRepo>` / `Box<具体实现>` 用。**每个方法都转发**。
#[async_trait]
impl<T: TenantRepo + ?Sized> TenantRepo for Box<T> {
    async fn create(&self, tenant: NewTenant<'_>, by: Option<&str>) -> Result<Tenant, IdmError> {
        (**self).create(tenant, by).await
    }

    async fn upsert_fixed(
        &self,
        id: Uuid,
        tenant: NewTenant<'_>,
        by: Option<&str>,
    ) -> Result<Tenant, IdmError> {
        (**self).upsert_fixed(id, tenant, by).await
    }

    async fn get(&self, id: Uuid) -> Result<Tenant, IdmError> {
        (**self).get(id).await
    }

    async fn get_by_slug(&self, slug: &str) -> Result<Tenant, IdmError> {
        (**self).get_by_slug(slug).await
    }

    async fn list(&self, page: &ListPage) -> Result<ListResult<Tenant>, IdmError> {
        (**self).list(page).await
    }

    async fn update_name(
        &self,
        id: Uuid,
        name: &str,
        by: Option<&str>,
    ) -> Result<Tenant, IdmError> {
        (**self).update_name(id, name, by).await
    }

    async fn set_status(
        &self,
        id: Uuid,
        status: TenantStatus,
        by: Option<&str>,
    ) -> Result<Tenant, IdmError> {
        (**self).set_status(id, status, by).await
    }

    async fn soft_delete(&self, id: Uuid, by: Option<&str>) -> Result<(), IdmError> {
        (**self).soft_delete(id, by).await
    }
}
