//! access token 编解码端口 + refresh token 原语。
//!
//! **签发(claim 形状 + 签名算法/密钥)与验证全部可拔插**:idm 只提供身份事实(`TokenClaims`)、
//! 只回读核心身份(`VerifiedToken`,含当前租户与租户角色)—— app 可注入自定义 claims(tenant_id/权限位…)、RS256/EdDSA、
//! KMS/HSM 签名。一个端口同时解决"claim 里放什么"与"怎么签",二者本是同一处决定。
//!
//! **分进程最小权限**:签验拆成两个 trait —— idm 进程持 [`TokenSigner`](私钥/签发),app 进程只注入
//! [`TokenVerifier`](公钥/只验不签)。对称 HS256 时同一把密钥,[`Hs256Tokens`] 同时实现两者。

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::IdmError;

/// 签发一枚 access token 所需的身份事实(idm 交给 signer)。signer 决定最终 claim 形状。
pub struct TokenClaims {
    pub user_id: Uuid,
    /// 会话 id,落 `jti`(可据此撤销)。
    pub session_id: Uuid,
    pub username: String,
    pub email: Option<String>,
    pub email_verified: bool,
    /// **平台角色**(含义从"全部角色"收窄为"平台角色";租户角色见 `tenant_roles`)。
    pub roles: Vec<String>,
    /// 当前租户;`None` = 平台上下文(token 里缺省该 claim)。
    pub tenant_id: Option<Uuid>,
    /// 当前租户内的角色。
    pub tenant_roles: Vec<String>,
    /// 当前租户的 slug / 名称(给前端展示「当前组织」用;app 进程只验 JWT、不查 idm 库,只能从 token 里拿)。
    /// 平台上下文 → `None`。默认 `Hs256Tokens` 不写进 token;要不要写由 signer 决定。
    pub tenant_slug: Option<String>,
    pub tenant_name: Option<String>,
    pub issued_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

/// 从 access token 验出的**核心身份**(idm 据此建 `AuthUser`)。自定义 claims 不在此 —— app 自取。
pub struct VerifiedToken {
    pub user_id: Uuid,
    pub username: String,
    /// 平台角色。
    pub roles: Vec<String>,
    /// 当前租户;旧 token / 平台上下文 → `None`。
    pub tenant_id: Option<Uuid>,
    /// 当前租户内的角色;旧 token → 空。
    pub tenant_roles: Vec<String>,
}

/// 签发端口(idm 进程):把身份事实签成 access token。实现决定 claim 形状 + 算法 + 密钥源。
pub trait TokenSigner: Send + Sync {
    fn sign(&self, claims: &TokenClaims) -> Result<String, IdmError>;
}

/// 验证端口(app 进程):验签 + 校验过期 → 核心身份。任何失败(验签/过期/格式)→ `Unauthorized`,不泄露原因。
pub trait TokenVerifier: Send + Sync {
    fn verify(&self, token: &str) -> Result<VerifiedToken, IdmError>;
}

/// 默认实现:HS256 对称密钥,同时是 signer 与 verifier(签验同一把密钥)。
/// 复刻历史 claim:`sub`=user_id、`jti`=session_id,+ username/email/email_verified/roles/iat/exp。
pub struct Hs256Tokens {
    encoding: jsonwebtoken::EncodingKey,
    decoding: jsonwebtoken::DecodingKey,
}

impl Hs256Tokens {
    pub fn new(secret: &str) -> Self {
        Self {
            encoding: jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
            decoding: jsonwebtoken::DecodingKey::from_secret(secret.as_bytes()),
        }
    }
}

/// HS256 的内部 claim 形状(序列化进 token)。`#[serde(default)]`:旧 token(无 roles / 无租户 claim)解码不失败。
#[derive(Serialize, Deserialize)]
struct Hs256Claims {
    sub: String,
    jti: String,
    username: String,
    email: Option<String>,
    email_verified: bool,
    #[serde(default)]
    roles: Vec<String>,
    /// 当前租户;平台上下文时**缺省**(不写 null)。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tenant_id: Option<Uuid>,
    #[serde(default)]
    tenant_roles: Vec<String>,
    iat: i64,
    exp: i64,
}

impl TokenSigner for Hs256Tokens {
    fn sign(&self, c: &TokenClaims) -> Result<String, IdmError> {
        let claims = Hs256Claims {
            sub: c.user_id.to_string(),
            jti: c.session_id.to_string(),
            username: c.username.clone(),
            email: c.email.clone(),
            email_verified: c.email_verified,
            roles: c.roles.clone(),
            tenant_id: c.tenant_id,
            tenant_roles: c.tenant_roles.clone(),
            iat: c.issued_at.unix_timestamp(),
            exp: c.expires_at.unix_timestamp(),
        };
        jsonwebtoken::encode(&jsonwebtoken::Header::default(), &claims, &self.encoding)
            .map_err(|e| IdmError::Internal(anyhow::anyhow!("JWT 签发失败: {e}")))
    }
}

impl TokenVerifier for Hs256Tokens {
    fn verify(&self, token: &str) -> Result<VerifiedToken, IdmError> {
        let validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        let claims = jsonwebtoken::decode::<Hs256Claims>(token, &self.decoding, &validation)
            .map(|d| d.claims)
            .map_err(|_| IdmError::Unauthorized)?;
        let user_id = claims
            .sub
            .parse::<Uuid>()
            .map_err(|_| IdmError::Unauthorized)?;
        Ok(VerifiedToken {
            user_id,
            username: claims.username,
            roles: claims.roles,
            tenant_id: claims.tenant_id,
            tenant_roles: claims.tenant_roles,
        })
    }
}

/// 生成不透明 refresh token:32B CSPRNG → base64url。返回 (明文给客户端, SHA-256 hash 落库)。
pub(crate) fn generate_refresh() -> (String, String) {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let token = URL_SAFE_NO_PAD.encode(bytes);
    let hash = hash_refresh(&token);
    (token, hash)
}

/// refresh token 的 SHA-256(base64url)。**只存 hash**:明文一旦发出不再可从库反推。
pub(crate) fn hash_refresh(token: &str) -> String {
    use sha2::{Digest, Sha256};
    URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::Duration;

    fn sample(user_id: Uuid, expires_at: OffsetDateTime) -> TokenClaims {
        TokenClaims {
            user_id,
            session_id: Uuid::from_u128(2),
            username: "alice".into(),
            email: None,
            email_verified: false,
            roles: vec!["admin".into()],
            tenant_id: None,
            tenant_roles: vec![],
            tenant_slug: None,
            tenant_name: None,
            issued_at: OffsetDateTime::now_utc(),
            expires_at,
        }
    }

    #[test]
    fn hs256_round_trip_recovers_core_identity() {
        let t = Hs256Tokens::new("secret");
        let uid = Uuid::from_u128(1);
        let token = t
            .sign(&sample(uid, OffsetDateTime::now_utc() + Duration::hours(1)))
            .unwrap();
        let v = t.verify(&token).unwrap();
        assert_eq!(v.user_id, uid);
        assert_eq!(v.username, "alice");
        assert_eq!(v.roles, vec!["admin".to_string()]);
    }

    #[test]
    fn expired_token_is_unauthorized() {
        let t = Hs256Tokens::new("secret");
        let token = t
            .sign(&sample(
                Uuid::from_u128(1),
                OffsetDateTime::now_utc() - Duration::hours(1),
            ))
            .unwrap();
        assert!(matches!(t.verify(&token), Err(IdmError::Unauthorized)));
    }

    #[test]
    fn wrong_key_or_garbage_is_unauthorized() {
        let signer = Hs256Tokens::new("secret-a");
        let token = signer
            .sign(&sample(
                Uuid::from_u128(1),
                OffsetDateTime::now_utc() + Duration::hours(1),
            ))
            .unwrap();
        // 换密钥验签失败(模拟 app 公钥 ≠ 签名私钥的非法 token);乱码同样失败。
        assert!(matches!(
            Hs256Tokens::new("secret-b").verify(&token),
            Err(IdmError::Unauthorized)
        ));
        assert!(matches!(
            signer.verify("garbage"),
            Err(IdmError::Unauthorized)
        ));
    }
    /// 旧 token(Task 2 之前签的,没有 tenant_id / tenant_roles)仍能验过:租户字段缺省为 None / 空。
    #[test]
    fn old_token_without_tenant_claims_still_verifies() {
        #[derive(Serialize)]
        struct OldClaims {
            sub: String,
            jti: String,
            username: String,
            email: Option<String>,
            email_verified: bool,
            roles: Vec<String>,
            iat: i64,
            exp: i64,
        }
        let now = OffsetDateTime::now_utc();
        let old = OldClaims {
            sub: Uuid::from_u128(1).to_string(),
            jti: Uuid::from_u128(2).to_string(),
            username: "alice".into(),
            email: None,
            email_verified: false,
            roles: vec!["superadmin".into()],
            iat: now.unix_timestamp(),
            exp: (now + Duration::hours(1)).unix_timestamp(),
        };
        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &old,
            &jsonwebtoken::EncodingKey::from_secret(b"secret"),
        )
        .unwrap();
        let v = Hs256Tokens::new("secret").verify(&token).unwrap();
        assert_eq!(v.user_id, Uuid::from_u128(1));
        assert_eq!(v.roles, vec!["superadmin".to_string()]);
        assert_eq!(v.tenant_id, None);
        assert!(v.tenant_roles.is_empty());
    }

    /// 新 claim 往返:tenant_id / tenant_roles 完整穿越;平台上下文(None)不写 tenant_id 字段。
    #[test]
    fn tenant_claims_round_trip() {
        let t = Hs256Tokens::new("secret");
        let mut c = sample(
            Uuid::from_u128(1),
            OffsetDateTime::now_utc() + Duration::hours(1),
        );
        c.tenant_id = Some(Uuid::from_u128(9));
        c.tenant_roles = vec!["admin".into()];
        let v = t.verify(&t.sign(&c).unwrap()).unwrap();
        assert_eq!(v.tenant_id, Some(Uuid::from_u128(9)));
        assert_eq!(v.tenant_roles, vec!["admin".to_string()]);

        c.tenant_id = None;
        c.tenant_roles = vec![];
        let token = t.sign(&c).unwrap();
        let payload = token.split('.').nth(1).unwrap();
        let json: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
        assert!(
            json.get("tenant_id").is_none(),
            "平台上下文缺省 tenant_id: {json}"
        );
        assert_eq!(t.verify(&token).unwrap().tenant_id, None);
    }
}
