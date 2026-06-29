//! idm 的领域错误类型(**零 HTTP**)。HTTP 状态码 / 机器码 / wire 形状一律由消费方(app)在
//! `From<IdmError> for AppError` 的边界决定 —— 本库只暴露"出了哪类错"。
//!
//! 防枚举:`login` 对"用户不存在"与"密码错"返回**同一个** `Unauthorized` 变体(在 service 里保证),
//! 客户端无法区分;具体安全文案由 app 写。
//!
//! `Internal` 的原始 source chain 不在这里记日志(无 HTTP 层),由 app 的错误响应处统一落日志。

#[derive(Debug, thiserror::Error)]
pub enum IdmError {
    /// 资源不存在 / 已软删。
    #[error("resource not found")]
    NotFound,

    /// 未认证 / 凭据无效。**绝不区分"用户不存在"与"密码错误"**(防枚举)。
    #[error("authentication failed")]
    Unauthorized,

    /// 资源冲突(用户名/邮箱已占用)。消息写给用户、可回传。
    #[error("conflict: {0}")]
    Conflict(String),

    /// 兜底:任何 anyhow 错误(DB / IO / 依赖)。原始细节交 app 落日志、绝不进响应体。
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}
