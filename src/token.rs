//! access token 编解码端口:签发([`TokenSigner`])与验证([`TokenVerifier`])分开。
//!
//! **签发(claim 形状 + 签名算法 / 密钥)与验证全部可拔插**:idm 只提供身份事实([`TokenClaims`])、
//! 只回读核心身份([`VerifiedToken`],含当前租户与租户角色)—— app 可注入自定义 claims(权限位、
//! 密钥 kid…)、RS256 / EdDSA、KMS / HSM 签名。一个端口同时解决"claim 里放什么"与"怎么签",二者本是同一处决定。
//!
//! **分进程最小权限**:签验拆成两个 trait —— idm 进程持 [`TokenSigner`](私钥 / 签发),app 进程只注入
//! [`TokenVerifier`](公钥 / 只验不签)。对称 HS256 时同一把密钥,[`Hs256Tokens`] 同时实现两者。
//!
//! [`Hs256Tokens`]: crate::Hs256Tokens

use std::sync::Arc;

use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::idm_error::IdmError;
use crate::repo::Session;

/// 签发一枚 access token 所需的身份事实(idm 交给 signer)。signer 决定最终 claim 形状。
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct TokenClaims {
    /// 账号 id(默认实现写进 `sub`)。
    pub user_id: Uuid,
    /// 会话 id,落 `jti`(可据此撤销)。
    pub session_id: Uuid,
    /// 用户名。
    pub username: String,
    /// 邮箱。
    pub email: Option<String>,
    /// 邮箱是否已验证。
    pub email_verified: bool,
    /// **平台角色**(租户角色见 `tenant_roles`)。
    pub roles: Vec<String>,
    /// 当前租户;`None` = 平台上下文(token 里缺省该 claim)。
    pub tenant_id: Option<Uuid>,
    /// 当前租户内的角色。
    pub tenant_roles: Vec<String>,
    /// 当前租户的 slug(给前端展示「当前组织」用;app 进程只验 JWT、不查 idm 库,只能从 token 里拿)。
    /// 平台上下文 → `None`。默认 `Hs256Tokens` 不写进 token;要不要写由 signer 决定。
    pub tenant_slug: Option<String>,
    /// 当前租户的名称(同 `tenant_slug`)。
    pub tenant_name: Option<String>,
    /// 签发时刻(`iat`)。
    pub issued_at: OffsetDateTime,
    /// 过期时刻(`exp`)。
    pub expires_at: OffsetDateTime,
}

impl TokenClaims {
    /// 为 `session` 签发的最小身份事实:账号、会话、租户取自会话,有效期 `[issued_at, issued_at + ttl)`;
    /// 邮箱 / 角色 / 租户展示信息为空,按需再填公开字段。
    #[must_use]
    pub fn new(
        session: &Session,
        username: String,
        issued_at: OffsetDateTime,
        ttl: Duration,
    ) -> Self {
        Self {
            user_id: session.user_id,
            session_id: session.id,
            username,
            email: None,
            email_verified: false,
            roles: Vec::new(),
            tenant_id: session.tenant_id,
            tenant_roles: Vec::new(),
            tenant_slug: None,
            tenant_name: None,
            issued_at,
            expires_at: issued_at + ttl,
        }
    }
}

/// 从 access token 验出的**核心身份**(idm 据此建 `AuthUser`)。自定义 claims 不在此 —— app 自取。
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct VerifiedToken {
    /// 账号 id。
    pub user_id: Uuid,
    /// 用户名。
    pub username: String,
    /// 平台角色。
    pub roles: Vec<String>,
    /// 当前租户;旧 token / 平台上下文 → `None`。
    pub tenant_id: Option<Uuid>,
    /// 当前租户内的角色;旧 token → 空。
    pub tenant_roles: Vec<String>,
}

impl VerifiedToken {
    /// 平台上下文的核心身份。带租户再接 [`Self::in_tenant`]。
    #[must_use]
    pub fn new(user_id: Uuid, username: String, roles: Vec<String>) -> Self {
        Self {
            user_id,
            username,
            roles,
            tenant_id: None,
            tenant_roles: Vec::new(),
        }
    }

    /// 把身份放进 `tenant_id` 租户,带该租户内的角色。
    #[must_use]
    pub fn in_tenant(self, tenant_id: Uuid, tenant_roles: Vec<String>) -> Self {
        Self {
            tenant_id: Some(tenant_id),
            tenant_roles,
            ..self
        }
    }
}

/// 签发端口(idm 进程):把身份事实签成 access token。实现决定 claim 形状 + 算法 + 密钥源。
pub trait TokenSigner: Send + Sync {
    /// 把 `claims` 签成 access token 串。
    ///
    /// # Errors
    ///
    /// 签名失败 → `IdmError::Internal`。
    fn sign(&self, claims: &TokenClaims) -> Result<String, IdmError>;
}

/// 转发实现:让 `Arc<dyn TokenSigner>` / `Arc<具体实现>` 也能直接注入(和别处共享同一个 signer)。
impl<T: TokenSigner + ?Sized> TokenSigner for Arc<T> {
    fn sign(&self, claims: &TokenClaims) -> Result<String, IdmError> {
        (**self).sign(claims)
    }
}

/// 转发实现:同 `Arc<T>`,给独占所有权的 `Box<dyn TokenSigner>` / `Box<具体实现>` 用。**每个方法都转发**。
impl<T: TokenSigner + ?Sized> TokenSigner for Box<T> {
    fn sign(&self, claims: &TokenClaims) -> Result<String, IdmError> {
        (**self).sign(claims)
    }
}

/// 验证端口(app 进程):验签 + 校验过期 → 核心身份。
pub trait TokenVerifier: Send + Sync {
    /// 验 `token` 并取出核心身份。
    ///
    /// # Errors
    ///
    /// 任何失败(验签 / 过期 / 格式)→ `IdmError::Unauthorized`,不泄露原因。
    fn verify(&self, token: &str) -> Result<VerifiedToken, IdmError>;
}

/// 转发实现:让 `Arc<dyn TokenVerifier>` / `Arc<具体实现>` 也能直接注入(鉴权中间件与 service 共用)。
impl<T: TokenVerifier + ?Sized> TokenVerifier for Arc<T> {
    fn verify(&self, token: &str) -> Result<VerifiedToken, IdmError> {
        (**self).verify(token)
    }
}

/// 转发实现:同 `Arc<T>`,给独占所有权的 `Box<dyn TokenVerifier>` / `Box<具体实现>` 用。**每个方法都转发**。
impl<T: TokenVerifier + ?Sized> TokenVerifier for Box<T> {
    fn verify(&self, token: &str) -> Result<VerifiedToken, IdmError> {
        (**self).verify(token)
    }
}

#[cfg(test)]
mod tests {
    use time::{Duration, OffsetDateTime};
    use uuid::Uuid;

    use super::{TokenClaims, VerifiedToken};
    use crate::repo::Session;

    #[test]
    fn claims_take_identity_and_tenant_from_session() {
        let mut session = Session::new(Uuid::from_u128(1), Some(Uuid::from_u128(9)));
        session.id = Uuid::from_u128(2);
        let now = OffsetDateTime::now_utc();
        let claims = TokenClaims::new(&session, "alice".to_owned(), now, Duration::minutes(15));
        assert_eq!(claims.user_id, Uuid::from_u128(1));
        assert_eq!(claims.session_id, Uuid::from_u128(2));
        assert_eq!(claims.tenant_id, Some(Uuid::from_u128(9)));
        assert_eq!(claims.expires_at - claims.issued_at, Duration::minutes(15));
        assert!(claims.roles.is_empty() && claims.tenant_roles.is_empty());
    }

    #[test]
    fn verified_token_constructors() {
        let token = VerifiedToken::new(Uuid::from_u128(1), "alice".to_owned(), Vec::new());
        assert_eq!(token.tenant_id, None);
        let token = token.in_tenant(Uuid::from_u128(9), vec!["admin".to_owned()]);
        assert_eq!(token.tenant_id, Some(Uuid::from_u128(9)));
        assert_eq!(token.tenant_roles, vec!["admin".to_owned()]);
    }
}
