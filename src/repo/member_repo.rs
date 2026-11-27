//! 成员仓储端口 [`MemberRepo`](tenant_members + member_roles)。

use std::sync::Arc;

use async_trait::async_trait;
use uuid::Uuid;

use super::list_page::{ListPage, ListResult};
use crate::idm_error::IdmError;
use crate::tenant::{MemberKey, MemberStatus, Membership};

/// 成员仓储端口。写方法在自己的事务内同时写 outbox(`tenant.member_added` / `tenant.member_removed` /
/// `tenant.member_roles_set` / `tenant.member_updated`,payload 都带 `tenant_id` 和 `user_id`,
/// aggregate_id = 租户 id)。`Membership.roles` 只含**存活、scope = tenant** 的角色名(按名排序);
/// 写入时只校验角色存在,不校验 scope。
#[async_trait]
pub trait MemberRepo: Send + Sync {
    /// 加成员(status = active)并授租户角色。租户不存在 / 已软删、用户不存在 / 已软删、任一 role_id
    /// 不存在 → `NotFound`;已是成员(任何状态)→ `Conflict`。任一步失败整体回滚。
    async fn add(
        &self,
        member: MemberKey,
        role_ids: &[Uuid],
        by: Option<&str>,
    ) -> Result<Membership, IdmError>;

    /// 移出成员(删成员关系,连带它在该租户的全部租户角色)。不是成员 / 租户已软删 → `NotFound`。
    /// **不吊销会话**:调用方再调 `SessionRepo::revoke_for_member`。
    async fn remove(&self, member: MemberKey, by: Option<&str>) -> Result<(), IdmError>;

    /// 停用 / 恢复成员。发 `tenant.member_updated`(含 status)。不是成员 / 租户已软删 → `NotFound`。
    async fn set_status(
        &self,
        member: MemberKey,
        status: MemberStatus,
        by: Option<&str>,
    ) -> Result<(), IdmError>;

    /// **原子全量替换**该成员在该租户的租户角色。不是成员 / 租户已软删 / 任一 role_id 不存在 →
    /// `NotFound`(不动原角色)。
    async fn set_roles(
        &self,
        member: MemberKey,
        role_ids: &[Uuid],
        by: Option<&str>,
    ) -> Result<(), IdmError>;

    /// 查成员关系(**任何状态**,租户停用也照样返回,由调用方判断)。不是成员 / 租户已软删 → `None`。
    async fn get(&self, member: MemberKey) -> Result<Option<Membership>, IdmError>;

    /// 某租户的成员列表(任何状态;**不含已软删账号**,total 同口径),按 user_id 升序;`Cursor` 的
    /// `after` 是上一页最后一个 user_id。
    async fn list_by_tenant(
        &self,
        tenant_id: Uuid,
        page: &ListPage,
    ) -> Result<ListResult<Membership>, IdmError>;

    /// 某账号**有效**的成员关系:租户 active 且未删 + 成员 active。按 `last_used_at` 降序(NULL 最后),
    /// 再按租户 id 升序 —— 第一个就是登录默认进入的租户。返回 `Vec`:从数据库取回、调用方要按位置取
    /// 第一个(指南「Iterators vs. owned collections」例外)。
    async fn memberships_for_user(&self, user_id: Uuid) -> Result<Vec<Membership>, IdmError>;

    /// 记录"刚进入该租户"(登录 / 切换):last_used_at = now。不发事件。不是成员 / 租户已软删 → `NotFound`。
    async fn touch_last_used(&self, member: MemberKey) -> Result<(), IdmError>;
}

/// 转发实现:`Arc<dyn MemberRepo>` / `Arc<具体仓储>` 也是 `MemberRepo`。
#[async_trait]
impl<T: MemberRepo + ?Sized> MemberRepo for Arc<T> {
    async fn add(
        &self,
        member: MemberKey,
        role_ids: &[Uuid],
        by: Option<&str>,
    ) -> Result<Membership, IdmError> {
        (**self).add(member, role_ids, by).await
    }

    async fn remove(&self, member: MemberKey, by: Option<&str>) -> Result<(), IdmError> {
        (**self).remove(member, by).await
    }

    async fn set_status(
        &self,
        member: MemberKey,
        status: MemberStatus,
        by: Option<&str>,
    ) -> Result<(), IdmError> {
        (**self).set_status(member, status, by).await
    }

    async fn set_roles(
        &self,
        member: MemberKey,
        role_ids: &[Uuid],
        by: Option<&str>,
    ) -> Result<(), IdmError> {
        (**self).set_roles(member, role_ids, by).await
    }

    async fn get(&self, member: MemberKey) -> Result<Option<Membership>, IdmError> {
        (**self).get(member).await
    }

    async fn list_by_tenant(
        &self,
        tenant_id: Uuid,
        page: &ListPage,
    ) -> Result<ListResult<Membership>, IdmError> {
        (**self).list_by_tenant(tenant_id, page).await
    }

    async fn memberships_for_user(&self, user_id: Uuid) -> Result<Vec<Membership>, IdmError> {
        (**self).memberships_for_user(user_id).await
    }

    async fn touch_last_used(&self, member: MemberKey) -> Result<(), IdmError> {
        (**self).touch_last_used(member).await
    }
}

/// 转发实现:同 `Arc<T>`,给独占所有权的 `Box<dyn MemberRepo>` / `Box<具体实现>` 用。**每个方法都转发**。
#[async_trait]
impl<T: MemberRepo + ?Sized> MemberRepo for Box<T> {
    async fn add(
        &self,
        member: MemberKey,
        role_ids: &[Uuid],
        by: Option<&str>,
    ) -> Result<Membership, IdmError> {
        (**self).add(member, role_ids, by).await
    }

    async fn remove(&self, member: MemberKey, by: Option<&str>) -> Result<(), IdmError> {
        (**self).remove(member, by).await
    }

    async fn set_status(
        &self,
        member: MemberKey,
        status: MemberStatus,
        by: Option<&str>,
    ) -> Result<(), IdmError> {
        (**self).set_status(member, status, by).await
    }

    async fn set_roles(
        &self,
        member: MemberKey,
        role_ids: &[Uuid],
        by: Option<&str>,
    ) -> Result<(), IdmError> {
        (**self).set_roles(member, role_ids, by).await
    }

    async fn get(&self, member: MemberKey) -> Result<Option<Membership>, IdmError> {
        (**self).get(member).await
    }

    async fn list_by_tenant(
        &self,
        tenant_id: Uuid,
        page: &ListPage,
    ) -> Result<ListResult<Membership>, IdmError> {
        (**self).list_by_tenant(tenant_id, page).await
    }

    async fn memberships_for_user(&self, user_id: Uuid) -> Result<Vec<Membership>, IdmError> {
        (**self).memberships_for_user(user_id).await
    }

    async fn touch_last_used(&self, member: MemberKey) -> Result<(), IdmError> {
        (**self).touch_last_used(member).await
    }
}
