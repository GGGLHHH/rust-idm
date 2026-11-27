//! 默认 token 端口实现:HS256 对称密钥,同时是 signer 与 verifier。

use std::fmt;

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::idm_error::IdmError;
use crate::token::{TokenClaims, TokenSigner, TokenVerifier, VerifiedToken};

/// 默认实现:HS256 对称密钥,同时是 signer 与 verifier(签验同一把密钥)。
/// 复刻历史 claim:`sub` = user_id、`jti` = session_id,+ username / email / email_verified / roles /
/// tenant_id / tenant_roles / iat / exp。
#[derive(Clone)]
pub struct Hs256Tokens {
    encoding: EncodingKey,
    decoding: DecodingKey,
}

impl Hs256Tokens {
    /// 用对称密钥 `secret` 建签验端口。
    #[must_use]
    pub fn new(secret: &str) -> Self {
        Self {
            encoding: EncodingKey::from_secret(secret.as_bytes()),
            decoding: DecodingKey::from_secret(secret.as_bytes()),
        }
    }
}

/// 手写 `Debug`:密钥不进日志。
impl fmt::Debug for Hs256Tokens {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hs256Tokens").finish_non_exhaustive()
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
    fn sign(&self, claims: &TokenClaims) -> Result<String, IdmError> {
        let wire = Hs256Claims {
            sub: claims.user_id.to_string(),
            jti: claims.session_id.to_string(),
            username: claims.username.clone(),
            email: claims.email.clone(),
            email_verified: claims.email_verified,
            roles: claims.roles.clone(),
            tenant_id: claims.tenant_id,
            tenant_roles: claims.tenant_roles.clone(),
            iat: claims.issued_at.unix_timestamp(),
            exp: claims.expires_at.unix_timestamp(),
        };
        jsonwebtoken::encode(&Header::default(), &wire, &self.encoding)
            .map_err(|e| IdmError::Internal(anyhow::anyhow!("JWT 签发失败: {e}")))
    }
}

impl TokenVerifier for Hs256Tokens {
    fn verify(&self, token: &str) -> Result<VerifiedToken, IdmError> {
        let validation = Validation::new(Algorithm::HS256);
        let token_data: TokenData<Hs256Claims> =
            jsonwebtoken::decode(token, &self.decoding, &validation)
                .map_err(|_| IdmError::Unauthorized)?;
        let claims = token_data.claims;
        let user_id: Uuid = claims.sub.parse().map_err(|_| IdmError::Unauthorized)?;
        Ok(VerifiedToken {
            user_id,
            username: claims.username,
            roles: claims.roles,
            tenant_id: claims.tenant_id,
            tenant_roles: claims.tenant_roles,
        })
    }
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use jsonwebtoken::{EncodingKey, Header};
    use serde::Serialize;
    use serde_json::Value;
    use time::{Duration, OffsetDateTime};
    use uuid::Uuid;

    use super::Hs256Tokens;
    use crate::idm_error::IdmError;
    use crate::repo::Session;
    use crate::token::{TokenClaims, TokenSigner, TokenVerifier};

    fn sample(user_id: Uuid, expires_in: Duration) -> TokenClaims {
        let mut session = Session::new(user_id, None);
        session.id = Uuid::from_u128(2);
        let mut claims = TokenClaims::new(
            &session,
            "alice".to_owned(),
            OffsetDateTime::now_utc(),
            expires_in,
        );
        claims.roles = vec!["admin".to_owned()];
        claims
    }

    #[test]
    fn hs256_round_trip_recovers_core_identity() {
        let tokens = Hs256Tokens::new("secret");
        let user_id = Uuid::from_u128(1);
        let token = tokens.sign(&sample(user_id, Duration::hours(1))).unwrap();
        let verified = tokens.verify(&token).unwrap();
        assert_eq!(verified.user_id, user_id);
        assert_eq!(verified.username, "alice");
        assert_eq!(verified.roles, vec!["admin".to_owned()]);
    }

    #[test]
    fn expired_token_is_unauthorized() {
        let tokens = Hs256Tokens::new("secret");
        let token = tokens
            .sign(&sample(Uuid::from_u128(1), Duration::hours(-2)))
            .unwrap();
        assert!(matches!(tokens.verify(&token), Err(IdmError::Unauthorized)));
    }

    #[test]
    fn wrong_key_or_garbage_is_unauthorized() {
        let signer = Hs256Tokens::new("secret-a");
        let token = signer
            .sign(&sample(Uuid::from_u128(1), Duration::hours(1)))
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

    /// 旧 token(多租户之前签的,没有 tenant_id / tenant_roles)仍能验过:租户字段缺省为 None / 空。
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
            username: "alice".to_owned(),
            email: None,
            email_verified: false,
            roles: vec!["superadmin".to_owned()],
            iat: now.unix_timestamp(),
            exp: (now + Duration::hours(1)).unix_timestamp(),
        };
        let token = jsonwebtoken::encode(
            &Header::default(),
            &old,
            &EncodingKey::from_secret(b"secret"),
        )
        .unwrap();
        let verified = Hs256Tokens::new("secret").verify(&token).unwrap();
        assert_eq!(verified.user_id, Uuid::from_u128(1));
        assert_eq!(verified.roles, vec!["superadmin".to_owned()]);
        assert_eq!(verified.tenant_id, None);
        assert!(verified.tenant_roles.is_empty());
    }

    /// 新 claim 往返:tenant_id / tenant_roles 完整穿越;平台上下文(None)不写 tenant_id 字段。
    #[test]
    fn tenant_claims_round_trip() {
        let tokens = Hs256Tokens::new("secret");
        let mut claims = sample(Uuid::from_u128(1), Duration::hours(1));
        claims.tenant_id = Some(Uuid::from_u128(9));
        claims.tenant_roles = vec!["admin".to_owned()];
        let verified = tokens.verify(&tokens.sign(&claims).unwrap()).unwrap();
        assert_eq!(verified.tenant_id, Some(Uuid::from_u128(9)));
        assert_eq!(verified.tenant_roles, vec!["admin".to_owned()]);

        claims.tenant_id = None;
        claims.tenant_roles = Vec::new();
        let token = tokens.sign(&claims).unwrap();
        let payload = token.split('.').nth(1).unwrap();
        let json: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
        assert!(
            json.get("tenant_id").is_none(),
            "平台上下文缺省 tenant_id: {json}"
        );
        assert_eq!(tokens.verify(&token).unwrap().tenant_id, None);
    }

    /// 密钥不进 Debug 输出。
    #[test]
    fn debug_hides_keys() {
        assert_eq!(
            format!("{:?}", Hs256Tokens::new("secret")),
            "Hs256Tokens { .. }"
        );
    }
}
