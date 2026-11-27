//! 密码哈希端口(可拔插)。
//!
//! 解耦的理由是**具体需求**,不是"argon2 是外部库":
//! ① 测试躲开 argon2 的 ~100ms(否则每个 register / login 用例都拖慢);② 实现可换。
//! 注:**换算法**主要靠 PHC 串自描述(verify 按串前缀选算法),trait 管的是"换实现 / 测试替身"。

use std::sync::Arc;

use crate::idm_error::IdmError;

/// 密码哈希端口。和 RustCrypto 的 `argon2::password_hash::PasswordHasher` 同名:本模块里用到那个
/// trait 时一律 `use … as _` 局部匿名导入,不会撞名。
pub trait PasswordHasher: Send + Sync {
    /// 明文 → PHC 串(自带算法标识 + 盐 + 参数)。
    ///
    /// # Errors
    ///
    /// 哈希实现失败 → `IdmError::Internal`。
    fn hash(&self, password: &str) -> Result<String, IdmError>;

    /// 校验明文与 PHC 串是否匹配。串自描述算法 → 天然支持多算法共存(迁移)。
    ///
    /// # Errors
    ///
    /// PHC 串本身解析不了(库里存了坏串)→ `IdmError::Internal`;密码不匹配是 `Ok(false)`。
    fn verify(&self, password: &str, phc_string: &str) -> Result<bool, IdmError>;
}

/// 转发实现:让 `Arc<dyn PasswordHasher>` / `Arc<具体实现>` 也能直接注入。
impl<H: PasswordHasher + ?Sized> PasswordHasher for Arc<H> {
    fn hash(&self, password: &str) -> Result<String, IdmError> {
        (**self).hash(password)
    }

    fn verify(&self, password: &str, phc_string: &str) -> Result<bool, IdmError> {
        (**self).verify(password, phc_string)
    }
}

/// 转发实现:同 `Arc<H>`,给独占所有权的 `Box<dyn PasswordHasher>` / `Box<具体实现>` 用。**每个方法都转发**。
impl<H: PasswordHasher + ?Sized> PasswordHasher for Box<H> {
    fn hash(&self, password: &str) -> Result<String, IdmError> {
        (**self).hash(password)
    }

    fn verify(&self, password: &str, phc_string: &str) -> Result<bool, IdmError> {
        (**self).verify(password, phc_string)
    }
}

/// 生产实现:argon2id(默认参数)。
/// **CPU 密集(~100ms)**:`AuthService` 内部已用 `tokio::task::spawn_blocking` 包起来;
/// 直接调用时也要放到阻塞线程池,否则阻塞 tokio worker 线程、饿死其它请求。
#[derive(Clone, Copy, Debug, Default)]
#[allow(
    clippy::exhaustive_structs,
    reason = "单元结构体没有公开字段,不在指南「Apply #[non_exhaustive] to public structs with public \
              fields」的范围内"
)]
pub struct Argon2Hasher;

impl PasswordHasher for Argon2Hasher {
    fn hash(&self, password: &str) -> Result<String, IdmError> {
        use argon2::password_hash::rand_core::OsRng;
        use argon2::password_hash::{PasswordHasher as _, SaltString};
        use argon2::Argon2;

        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|e| IdmError::Internal(anyhow::anyhow!("argon2 hash 失败: {e}")))
    }

    fn verify(&self, password: &str, phc_string: &str) -> Result<bool, IdmError> {
        use argon2::password_hash::{PasswordHash, PasswordVerifier as _};
        use argon2::Argon2;

        // PHC 解析失败 = 库里存了坏串 → Internal(原始措辞进日志);密码不匹配 → Ok(false)。
        let parsed = PasswordHash::new(phc_string)
            .map_err(|e| IdmError::Internal(anyhow::anyhow!("PHC 串解析失败: {e}")))?;
        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok())
    }
}

/// 测试实现:前缀标记 + 明文比对,不做真哈希 → 躲开 argon2 的 ~100ms。
///
/// 故意**不**加 `#[cfg(test)]`:集成测试(`tests/`)和下游测试是独立 crate,需要能从外部构造它、
/// 经 builder 的 `hasher` 端口注入 `AuthService`。仅供测试装配使用,生产装配永远注入 `Argon2Hasher`。
#[derive(Clone, Copy, Debug, Default)]
#[allow(
    clippy::exhaustive_structs,
    reason = "单元结构体没有公开字段,不在指南「Apply #[non_exhaustive] to public structs with public \
              fields」的范围内"
)]
pub struct FakeHasher;

/// `FakeHasher` 产出的"PHC 串"前缀。
const FAKE_PREFIX: &str = "fake$";

impl PasswordHasher for FakeHasher {
    fn hash(&self, password: &str) -> Result<String, IdmError> {
        Ok(format!("{FAKE_PREFIX}{password}"))
    }

    fn verify(&self, password: &str, phc_string: &str) -> Result<bool, IdmError> {
        Ok(phc_string.strip_prefix(FAKE_PREFIX) == Some(password))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{Argon2Hasher, FakeHasher, PasswordHasher};

    #[test]
    fn argon2_round_trip_and_phc_self_describes() {
        let hasher = Argon2Hasher;
        let phc = hasher.hash("hunter42").unwrap();
        // PHC 串自描述:前缀即算法标识(迁移 / 验证靠它,不靠 trait)
        assert!(phc.starts_with("$argon2id$"), "应是 argon2id PHC 串: {phc}");
        assert!(hasher.verify("hunter42", &phc).unwrap());
        assert!(!hasher.verify("wrong", &phc).unwrap());
    }

    #[test]
    fn fake_round_trip_is_fast_and_correct() {
        let hasher = FakeHasher;
        let phc = hasher.hash("pw").unwrap();
        assert!(hasher.verify("pw", &phc).unwrap());
        assert!(!hasher.verify("nope", &phc).unwrap());
        assert!(!hasher.verify("pw", "pw").unwrap(), "没有前缀的串不算匹配");
    }

    /// 端口可拔插:两个实现都满足同一 trait,可经 `Arc<dyn PasswordHasher>` 互换注入。
    #[test]
    fn both_satisfy_the_port() {
        let impls: Vec<Arc<dyn PasswordHasher>> =
            vec![Arc::new(Argon2Hasher), Arc::new(FakeHasher)];
        for hasher in impls {
            let phc = hasher.hash("secret-pw").unwrap();
            assert!(hasher.verify("secret-pw", &phc).unwrap());
            assert!(!hasher.verify("other", &phc).unwrap());
        }
    }
}
