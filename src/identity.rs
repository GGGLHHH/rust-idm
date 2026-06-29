//! 鉴权身份:`AuthService::authenticate_token` 验过 JWT 后产出的已认证用户(含角色,供 RBAC)。
//!
//! 消费方(app)的鉴权中间件拿它塞进 `request.extensions`,再由 app 自己的提取器
//! (`CurrentUser` / `AuditContext`)读出来 —— 那些提取器是 HTTP 关注点,归 app,不在本库。

use uuid::Uuid;

/// 已认证身份(含角色名,供权限判定)。token 校验是唯一真相源(`authenticate_token`),此结构只承载结果。
#[derive(Clone, Debug)]
pub struct AuthUser {
    pub id: Uuid,
    pub username: String,
    pub roles: Vec<String>,
}
