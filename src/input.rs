//! idm 服务的领域输入(纯数据:无 HTTP / 序列化 / 校验)。
//! HTTP 边界的反序列化 + 校验由消费方(app)做完,再 `.into()` 成这些结构传进 service。
//! 审计主体(created_by / updated_by)不在输入里 —— 由 service 方法的 `by: Option<&str>` 参数单独传。
//!
//! 这些结构刻意**不**加 `#[non_exhaustive]`,而是实现 `Default`:消费方用字面量 + FRU
//! (`RegisterInput { username, password, ..Default::default() }`)构造,落在指南
//! 「Apply #[non_exhaustive] to public structs with public fields」的 FRU 例外里。
//! `Debug` 手写:明文密码一律打成 `<redacted>`,不进日志 / panic 输出。

use std::fmt;

/// 日志里代替明文密码的占位。
const REDACTED: &str = "<redacted>";

/// 注册输入。username 必填、唯一;email 可选;password 明文(service 负责 hash)。
#[derive(Clone, Default, PartialEq)]
#[allow(
    clippy::exhaustive_structs,
    reason = "指南 non_exhaustive 结构体条款的 FRU 例外:调用方用 ..Default::default() 构造"
)]
pub struct RegisterInput {
    /// 用户名(service 会去空白 + 转小写)。
    pub username: String,
    /// 邮箱,可选(同样归一)。
    pub email: Option<String>,
    /// 明文密码。
    pub password: String,
}

impl fmt::Debug for RegisterInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegisterInput")
            .field("username", &self.username)
            .field("email", &self.email)
            .field("password", &REDACTED)
            .finish()
    }
}

/// 登录输入。`identifier` = username 或 email,由 service 自动识别。
#[derive(Clone, Default, PartialEq)]
#[allow(
    clippy::exhaustive_structs,
    reason = "指南 non_exhaustive 结构体条款的 FRU 例外:调用方用 ..Default::default() 构造"
)]
pub struct LoginInput {
    /// 用户名或邮箱。
    pub identifier: String,
    /// 明文密码。
    pub password: String,
}

impl fmt::Debug for LoginInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginInput")
            .field("identifier", &self.identifier)
            .field("password", &REDACTED)
            .finish()
    }
}

/// **全量更新**当前用户(PUT 语义)。username 必填;email 给值 = 设置、给 `None` = 清空。
#[derive(Clone, Debug, Default, PartialEq)]
#[allow(
    clippy::exhaustive_structs,
    reason = "指南 non_exhaustive 结构体条款的 FRU 例外:调用方用 ..Default::default() 构造"
)]
pub struct UpdateMeInput {
    /// 新用户名。
    pub username: String,
    /// 新邮箱;`None` = 清空。
    pub email: Option<String>,
}

/// 改密输入。
#[derive(Clone, Default, PartialEq)]
#[allow(
    clippy::exhaustive_structs,
    reason = "指南 non_exhaustive 结构体条款的 FRU 例外:调用方用 ..Default::default() 构造"
)]
pub struct ChangePasswordInput {
    /// 当前密码(明文,先校验)。
    pub current_password: String,
    /// 新密码(明文)。
    pub new_password: String,
}

impl fmt::Debug for ChangePasswordInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChangePasswordInput")
            .field("current_password", &REDACTED)
            .field("new_password", &REDACTED)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{ChangePasswordInput, LoginInput, RegisterInput};

    /// 明文密码不进 `Debug` 输出(日志 / panic 信息里看不到)。
    #[test]
    fn debug_redacts_passwords() {
        let register = RegisterInput {
            username: "alice".to_owned(),
            password: "hunter42".to_owned(),
            ..RegisterInput::default()
        };
        let login = LoginInput {
            identifier: "alice".to_owned(),
            password: "hunter42".to_owned(),
        };
        let change = ChangePasswordInput {
            current_password: "hunter42".to_owned(),
            new_password: "hunter43".to_owned(),
        };
        for printed in [
            format!("{register:?}"),
            format!("{login:?}"),
            format!("{change:?}"),
        ] {
            assert!(!printed.contains("hunter4"), "密码泄露进 Debug: {printed}");
            assert!(printed.contains("<redacted>"), "{printed}");
        }
        assert!(
            format!("{register:?}").contains("alice"),
            "非敏感字段照常打印"
        );
    }
}
