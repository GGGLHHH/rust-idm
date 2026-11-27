//! refresh token 原语:不透明随机串 + 落库用的 SHA-256。

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

/// 刚生成的 refresh token:明文给客户端,`hash` 落库。
pub(crate) struct RefreshToken {
    /// 明文(只发给客户端一次,不入库)。
    pub(crate) token: String,
    /// `token` 的 SHA-256(base64url),落 `sessions.token_hash`。
    pub(crate) hash: String,
}

impl RefreshToken {
    /// 32B CSPRNG → base64url 明文,并算好它的 hash。
    pub(crate) fn generate() -> Self {
        use rand::rngs::OsRng;
        use rand::RngCore as _;

        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let token = URL_SAFE_NO_PAD.encode(bytes);
        let hash = hash_token(&token);
        Self { token, hash }
    }
}

/// refresh token 的 SHA-256(base64url)。**只存 hash**:明文一旦发出不再可从库反推。
pub(crate) fn hash_token(token: &str) -> String {
    use sha2::{Digest as _, Sha256};

    URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::RefreshToken;

    #[test]
    fn generated_hash_matches_token_and_tokens_differ() {
        let first = RefreshToken::generate();
        let second = RefreshToken::generate();
        assert_eq!(super::hash_token(&first.token), first.hash);
        assert_ne!(first.token, second.token, "每次生成都是新的随机串");
        assert_ne!(first.token, first.hash, "落库的是 hash,不是明文");
    }
}
