//! access token 编解码端口 + refresh token 原语。
//!
//! **签发(claim 形状 + 签名算法/密钥)与验证全部可拔插**:idm 只提供身份事实(`TokenClaims`)、
//! 只回读核心身份(`VerifiedToken`)—— app 可注入自定义 claims(tenant_id/权限位…)、RS256/EdDSA、
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
    pub roles: Vec<String>,
    /// **app 注入的自定义 claims**(tenant_id / 权限位 / 功能开关…),由
    /// [`ClaimsExtender`] 在铸币时填;没装端口 = `Value::Null`。
    ///
    /// idm **不解释**它的内容,只负责原样运到 signer 手里 —— 形状归 app,
    /// 因为只有 app 知道自己要放什么。
    ///
    /// **为什么必须有这个字段**:`TokenSigner::sign` 是同步的,拿不到 `&self` 之外的
    /// 任何东西,更不能 await 一次查库。没有它,app 想往 claim 里塞任何身份之外的
    /// 事实,唯一的缝隙就是把它编码进 `roles: Vec<String>` —— 一个字符串走私通道,
    /// 会污染角色闭集、绕过所有按角色判定的授权闸。本字段就是那条缝的正门。
    pub extra: serde_json::Value,
    pub issued_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

/// 从 access token 验出的**核心身份**(idm 据此建 `AuthUser`)。自定义 claims 不在此 —— app 自取。
pub struct VerifiedToken {
    pub user_id: Uuid,
    pub username: String,
    pub roles: Vec<String>,
}

/// **自定义 claims 端口**(app 注入,可选):铸币时问一次「这个人还有什么该进 claim」。
///
/// 位置与 [`RoleRepo::roles_for_user`](crate::RoleRepo::roles_for_user) **对称** —— 同在
/// `issue_session` 里、同按 user_id 问、同在每条铸币路径(register / login / refresh)上跑一次。
/// 区别只是:roles 是 idm 认得的身份事实,extra 是 idm 不认得、只负责运输的 app 事实。
///
/// 不装 = `TokenClaims::extra` 恒 `Null`,行为与 v0.5.0 完全一致。
#[async_trait::async_trait]
pub trait ClaimsExtender: Send + Sync {
    /// 返回该用户这一刻的自定义 claims。**Err 会让整条铸币失败** —— 这是有意的:
    /// 自定义 claim 常是授权输入(如 tenant_id),读不到就签一枚「没有它」的 token
    /// 等于静默降权/越权,宁可让登录炸。不想炸就在实现里自己兜底成 `Null`。
    async fn extra_for(&self, user_id: Uuid) -> Result<serde_json::Value, IdmError>;
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

/// HS256 的内部 claim 形状(序列化进 token)。`#[serde(default)]` roles:旧 token(无 roles)解码不失败。
#[derive(Serialize, Deserialize)]
struct Hs256Claims {
    sub: String,
    jti: String,
    username: String,
    email: Option<String>,
    email_verified: bool,
    #[serde(default)]
    roles: Vec<String>,
    /// app 的自定义 claims 原样落进 token。**装了 `ClaimsExtender` 却在这儿丢掉,
    /// 等于 extender 白装且无人知晓** —— 所以便捷实现也必须运它。`Null` 时不出现在
    /// token 里(skip_serializing_if),旧 token 无此键也能解(default)。
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    extra: serde_json::Value,
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
            extra: c.extra.clone(),
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
            extra: serde_json::Value::Null,
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
}
