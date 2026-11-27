//! 会话仓储端口 [`SessionRepo`] 及会话实体 [`Session`]。

use std::sync::Arc;

use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::idm_error::IdmError;
use crate::tenant::MemberKey;

/// 会话内部实体。`id` 同时作 JWT 的 `jti`。
#[derive(Clone, Debug, PartialEq, sqlx::FromRow)]
#[non_exhaustive]
pub struct Session {
    /// 会话 id(uuid v7)= access token 的 `jti`。
    pub id: Uuid,
    /// 会话所属账号。
    pub user_id: Uuid,
    /// 会话所在租户,`None` = 平台上下文。
    pub tenant_id: Option<Uuid>,
}

impl Session {
    /// 新会话:生成 uuid v7 作 `id`(读回已有行时再改 `id`)。给自己实现 [`SessionRepo`] 的调用方用。
    #[must_use]
    pub fn new(user_id: Uuid, tenant_id: Option<Uuid>) -> Self {
        Self {
            id: Uuid::now_v7(),
            user_id,
            tenant_id,
        }
    }
}

/// 会话仓储端口。
#[async_trait]
pub trait SessionRepo: Send + Sync {
    /// 建会话(refresh token 只落 SHA-256 hash,明文不入库)。返回的 `Session.id` 即 JWT `jti`。
    /// `tenant_id` = 会话所在租户(`None` = 平台上下文);租户行不存在 → `NotFound`(FK;已软删的行仍在,
    /// 不拦 —— 能否进入由 service 判断)。内存实现要和租户仓储看同一批租户须用
    /// `InMemorySessionRepo::new_shared_with`。
    async fn create(
        &self,
        user_id: Uuid,
        tenant_id: Option<Uuid>,
        token_hash: &str,
        expires_at: OffsetDateTime,
        by: Option<&str>,
    ) -> Result<Session, IdmError>;

    /// 按 refresh token hash 查**活跃**会话(未撤销、未过期)。
    async fn find_active(
        &self,
        token_hash: &str,
        now: OffsetDateTime,
    ) -> Result<Option<Session>, IdmError>;

    /// 撤销会话(盖 revoked_at)。**条件更新**(只动未撤销的行):真撤掉了一行 → `true`;
    /// 已撤销 / 不存在 → `false`(幂等,不报错)。并发撤同一会话只有一个调用方拿到 `true` ——
    /// refresh / 切换租户靠它做轮换闸:拿到 `false` 说明这个 refresh token 已被别人用掉,不能再签新会话。
    async fn revoke(&self, session_id: Uuid) -> Result<bool, IdmError>;

    /// 撤销用户的所有活跃会话;`except` 排除某会话(改密保留当前)。
    async fn revoke_all(&self, user_id: Uuid, except: Option<Uuid>) -> Result<(), IdmError>;

    /// 撤销某成员**在该租户里**的全部活跃会话(移出 / 停用成员时)。别的租户、平台上下文的会话不动。幂等。
    async fn revoke_for_member(&self, member: MemberKey) -> Result<(), IdmError>;

    /// 撤销某租户里所有人的活跃会话(停用 / 删除租户时)。幂等。
    async fn revoke_for_tenant(&self, tenant_id: Uuid) -> Result<(), IdmError>;
}

/// 转发实现:`Arc<dyn SessionRepo>` / `Arc<具体仓储>` 也是 `SessionRepo`。
#[async_trait]
impl<T: SessionRepo + ?Sized> SessionRepo for Arc<T> {
    async fn create(
        &self,
        user_id: Uuid,
        tenant_id: Option<Uuid>,
        token_hash: &str,
        expires_at: OffsetDateTime,
        by: Option<&str>,
    ) -> Result<Session, IdmError> {
        (**self)
            .create(user_id, tenant_id, token_hash, expires_at, by)
            .await
    }

    async fn find_active(
        &self,
        token_hash: &str,
        now: OffsetDateTime,
    ) -> Result<Option<Session>, IdmError> {
        (**self).find_active(token_hash, now).await
    }

    async fn revoke(&self, session_id: Uuid) -> Result<bool, IdmError> {
        (**self).revoke(session_id).await
    }

    async fn revoke_all(&self, user_id: Uuid, except: Option<Uuid>) -> Result<(), IdmError> {
        (**self).revoke_all(user_id, except).await
    }

    async fn revoke_for_member(&self, member: MemberKey) -> Result<(), IdmError> {
        (**self).revoke_for_member(member).await
    }

    async fn revoke_for_tenant(&self, tenant_id: Uuid) -> Result<(), IdmError> {
        (**self).revoke_for_tenant(tenant_id).await
    }
}

/// 转发实现:同 `Arc<T>`,给独占所有权的 `Box<dyn SessionRepo>` / `Box<具体实现>` 用。**每个方法都转发**。
#[async_trait]
impl<T: SessionRepo + ?Sized> SessionRepo for Box<T> {
    async fn create(
        &self,
        user_id: Uuid,
        tenant_id: Option<Uuid>,
        token_hash: &str,
        expires_at: OffsetDateTime,
        by: Option<&str>,
    ) -> Result<Session, IdmError> {
        (**self)
            .create(user_id, tenant_id, token_hash, expires_at, by)
            .await
    }

    async fn find_active(
        &self,
        token_hash: &str,
        now: OffsetDateTime,
    ) -> Result<Option<Session>, IdmError> {
        (**self).find_active(token_hash, now).await
    }

    async fn revoke(&self, session_id: Uuid) -> Result<bool, IdmError> {
        (**self).revoke(session_id).await
    }

    async fn revoke_all(&self, user_id: Uuid, except: Option<Uuid>) -> Result<(), IdmError> {
        (**self).revoke_all(user_id, except).await
    }

    async fn revoke_for_member(&self, member: MemberKey) -> Result<(), IdmError> {
        (**self).revoke_for_member(member).await
    }

    async fn revoke_for_tenant(&self, tenant_id: Uuid) -> Result<(), IdmError> {
        (**self).revoke_for_tenant(tenant_id).await
    }
}
