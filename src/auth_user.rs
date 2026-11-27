//! 鉴权身份:`AuthService::authenticate_token` 验过 access token 后产出的已认证用户(含角色,供 RBAC)。
//!
//! 消费方(app)的鉴权中间件拿它塞进 `request.extensions`,再由 app 自己的提取器
//! (`CurrentUser` / `AuditContext`)读出来 —— 那些提取器是 HTTP 关注点,归 app,不在本库。

use uuid::Uuid;

use crate::token::VerifiedToken;

/// 已认证身份(含角色名,供权限判定)。token 校验是唯一真相源(`authenticate_token`),此结构只承载结果。
///
/// `#[non_exhaustive]`:库外不能用字面量构造,用 [`AuthUser::new`] + [`AuthUser::in_tenant`],
/// 或从 [`VerifiedToken`] 转换。
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct AuthUser {
    /// 账号 id(= token 的 `sub`)。
    pub id: Uuid,
    /// 用户名(登录时归一过的小写形式)。
    pub username: String,
    /// **平台角色**(经 `user_roles` 授予,如 superadmin)。
    pub roles: Vec<String>,
    /// 当前租户;`None` = 平台上下文(没有有效成员关系 / 旧 token)。
    pub tenant_id: Option<Uuid>,
    /// 当前租户内的角色(`tenant_id` 为 `None` 时为空)。
    pub tenant_roles: Vec<String>,
}

impl AuthUser {
    /// 平台上下文的身份(不带租户)。要进租户再接 [`Self::in_tenant`]。
    #[must_use]
    pub fn new(id: Uuid, username: String, roles: Vec<String>) -> Self {
        Self {
            id,
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

    /// 由验过的 token 建身份(字段一一对应)。同 `From<VerifiedToken>`。
    #[must_use]
    pub fn from_verified_token(token: VerifiedToken) -> Self {
        Self {
            id: token.user_id,
            username: token.username,
            roles: token.roles,
            tenant_id: token.tenant_id,
            tenant_roles: token.tenant_roles,
        }
    }
}

impl From<VerifiedToken> for AuthUser {
    fn from(token: VerifiedToken) -> Self {
        Self::from_verified_token(token)
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::AuthUser;
    use crate::token::VerifiedToken;

    #[test]
    fn constructors_set_platform_then_tenant_context() {
        let id = Uuid::from_u128(1);
        let platform = AuthUser::new(id, "alice".to_owned(), vec!["superadmin".to_owned()]);
        assert_eq!(platform.tenant_id, None);
        assert!(platform.tenant_roles.is_empty());

        let tenant = Uuid::from_u128(9);
        let member = platform.in_tenant(tenant, vec!["admin".to_owned()]);
        assert_eq!(member.tenant_id, Some(tenant));
        assert_eq!(member.tenant_roles, vec!["admin".to_owned()]);
        assert_eq!(
            member.roles,
            vec!["superadmin".to_owned()],
            "平台角色不受进租户影响"
        );
    }

    #[test]
    fn from_verified_token_copies_every_field() {
        let token =
            VerifiedToken::new(Uuid::from_u128(1), "alice".to_owned(), vec!["a".to_owned()])
                .in_tenant(Uuid::from_u128(9), vec!["b".to_owned()]);
        let user = AuthUser::from(token);
        let expected = AuthUser::new(Uuid::from_u128(1), "alice".to_owned(), vec!["a".to_owned()])
            .in_tenant(Uuid::from_u128(9), vec!["b".to_owned()]);
        assert_eq!(user, expected);
    }
}
