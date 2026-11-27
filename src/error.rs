//! idm 的领域错误类型(**零 HTTP**)。HTTP 状态码 / 机器码 / wire 形状一律由消费方(app)在
//! `From<IdmError> for AppError` 的边界决定 —— 本库只暴露"出了哪类错"。
//!
//! 防枚举:`login` 返回携带原因的 `InvalidCredentials`(`CredentialFailure::UnknownUser` /
//! `BadPassword`),原因**仅供审计**;HTTP 收口由消费方 app 统一返 401,原因绝不进响应体。
//! 改密 / 注销的密码确认错同样是 `InvalidCredentials(BadPassword)`(凭据错,会话仍有效),
//! 与会话失效的 `Unauthorized` 分开 —— 消费方据此给两个不同的机器码。
//!
//! `Internal` 的原始 source chain 不在这里记日志(无 HTTP 层),由 app 的错误响应处统一落日志。

/// 登录凭据失败的具体原因。**仅供审计**——HTTP 层仍统一 401(防枚举由消费方 app 收口)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialFailure {
    /// identifier 查无存活用户。
    UnknownUser,
    /// 用户存在但密码不匹配。
    BadPassword,
}

#[derive(Debug, thiserror::Error)]
pub enum IdmError {
    /// 资源不存在 / 已软删。
    #[error("resource not found")]
    NotFound,

    /// 未认证 / 凭据无效。**绝不区分"用户不存在"与"密码错误"**(防枚举)。
    #[error("authentication failed")]
    Unauthorized,

    /// 凭据无效(登录 / 改密旧密码 / 注销密码确认),携带失败原因**供审计**。消费方**必须**仍统一返 401(防枚举),
    /// 原因只进审计事件、绝不进响应体。
    #[error("invalid credentials")]
    InvalidCredentials(CredentialFailure),

    /// 已认证但无权做这件事(如切换到自己不是有效成员的租户)。消费方映射成 403。
    #[error("forbidden")]
    Forbidden,

    /// 资源冲突(用户名/邮箱已占用)。消息写给用户、可回传。
    #[error("conflict: {0}")]
    Conflict(String),

    /// 兜底:任何 anyhow 错误(DB / IO / 依赖)。原始细节交 app 落日志、绝不进响应体。
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}
