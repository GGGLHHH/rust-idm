//! idm 认证业务 [`AuthService`]:持仓储 / 哈希 / token / 时钟端口,编排注册 / 登录 / 发会话。
//! 依赖 trait 而非实现,在此做归一 / 编排 / 审计下传。
//! **入参是领域结构(`input` 模块),已由 app 在 HTTP 边界校验完**;审计主体经 `by: Option<&str>` 传。
//!
//! **多租户**(成员仓储是必填端口,没有关闭开关):会话 / access token 带**一个当前租户**。登录进
//! `last_used_at` 最近的有效成员关系(没有 → 平台上下文,`tenant_id = None`);refresh 沿用会话上的租户并
//! 重新校验成员关系与租户状态(失效 → `Unauthorized`,绝不落到别的租户);`switch_tenant` 换租户(非有效成员
//! → `Forbidden`);注册在同一事务里加入 `signup_tenant`。
//!
//! **端口怎么持有**:四个仓储是类型参数(指南「Generics versus dyn Trait」:库优先泛型);下游要运行时二选一
//! 实现,就用 `AuthService<Arc<dyn UserRepo>, Arc<dyn SessionRepo>, …>` 实例化(各端口有 `Arc<T>` / `Box<T>` 转发实现)。
//! 哈希 / 签发 / 验证 / 时钟四个策略端口经 builder 的泛型参数传入、内部存成 trait 对象:若也做成类型参数,
//! `AuthService` 会有 8 个类型参数、builder 每个 setter 都得换类型,下游的类型签名不可读;它们每次调用只走
//! 一次虚调用,开销相对 argon2 / 验签可忽略。

use std::fmt;
use std::sync::Arc;

use time::Duration;
use tokio::task;
use uuid::Uuid;

use crate::auth_user::AuthUser;
use crate::clock::{Clock, SystemClock};
use crate::hs256_tokens::Hs256Tokens;
use crate::idm_error::{CredentialFailure, IdmError};
use crate::input::{ChangePasswordInput, LoginInput, RegisterInput, UpdateMeInput};
use crate::password_hasher::{Argon2Hasher, PasswordHasher};
use crate::refresh_token::{self, RefreshToken};
use crate::repo::{MemberRepo, NewUser, RoleRepo, Session, SessionRepo, User, UserRepo};
use crate::tenant::{MemberKey, Membership, RoleScope, DEFAULT_TENANT_ID};
use crate::token::{TokenClaims, TokenSigner, TokenVerifier};

/// 默认的注册租户角色。
const DEFAULT_SIGNUP_ROLE: &str = "user";
/// 默认 access token 有效期:15 分钟。
const DEFAULT_ACCESS_TTL: Duration = Duration::minutes(15);
/// 默认 refresh token 有效期:7 天。
const DEFAULT_REFRESH_TTL: Duration = Duration::days(7);

/// 用户读模型(域投影):`User` 实体 + 平台角色名。`me` / `update_me` / `AuthOutcome.user` 的返回。
/// app 把它映射成自己的对外响应 DTO(审计字段不在此)。
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct UserView {
    /// 账号 id。
    pub id: Uuid,
    /// 用户名。
    pub username: String,
    /// 邮箱。
    pub email: Option<String>,
    /// 邮箱是否已验证。
    pub email_verified: bool,
    /// 平台角色名。
    pub roles: Vec<String>,
}

impl UserView {
    fn new(user: &User, roles: Vec<String>) -> Self {
        Self {
            id: user.id,
            username: user.username.clone(),
            email: user.email.clone(),
            email_verified: user.email_verified,
            roles,
        }
    }
}

/// 认证结果(**纯数据**):用户视图 + 待写进 cookie 的 token + cookie 有效期。
/// app 把 token 写进 httponly `Set-Cookie`、body 返 `user`;token 不进响应体。
/// `Debug` 手写:access / refresh token 明文打成 `<redacted>`,不进日志 / panic 输出。
#[derive(Clone, PartialEq)]
#[non_exhaustive]
pub struct AuthOutcome {
    /// 用户视图(`roles` 是平台角色)。
    pub user: UserView,
    /// 本次登录 / 注册 / 刷新所建会话的 id(= `sessions.id` = JWT `jti`)。审计 / 设备管理用。
    pub session_id: Uuid,
    /// access token 明文。
    pub access_token: String,
    /// refresh token 明文。
    pub refresh_token: String,
    /// access token 的有效期(cookie Max-Age)。
    pub access_max_age: Duration,
    /// refresh token 的有效期(cookie Max-Age)。
    pub refresh_max_age: Duration,
    /// 本次会话所在租户(= token 的 `tenant_id` claim);`None` = 平台上下文。
    pub tenant_id: Option<Uuid>,
    /// 本次会话在当前租户内的角色(= token 的 `tenant_roles` claim)。
    pub tenant_roles: Vec<String>,
}

impl fmt::Debug for AuthOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const REDACTED: &str = "<redacted>";
        f.debug_struct("AuthOutcome")
            .field("user", &self.user)
            .field("session_id", &self.session_id)
            .field("access_token", &REDACTED)
            .field("refresh_token", &REDACTED)
            .field("access_max_age", &self.access_max_age)
            .field("refresh_max_age", &self.refresh_max_age)
            .field("tenant_id", &self.tenant_id)
            .field("tenant_roles", &self.tenant_roles)
            .finish()
    }
}

/// 登录进哪里(消费方按自己的授权规则挑,见 [`AuthService::login_with`])。
#[derive(Clone, Copy, Debug, PartialEq)]
#[non_exhaustive]
pub enum LoginEntry {
    /// 进这个租户:必须是候选里的有效成员关系之一,否则 `Forbidden`。
    Tenant(Uuid),
    /// 平台上下文(不带租户,只有平台角色)。
    Platform,
}

/// 验密通过后交给挑选函数的材料:账号、平台角色、有效成员关系(租户 active + 成员 active,
/// `last_used_at` 最近的在前,同 [`AuthService::my_tenants`])。
#[derive(Clone, Copy, Debug, PartialEq)]
#[non_exhaustive]
pub struct LoginCandidates<'login> {
    /// 验密通过的账号。
    pub user_id: Uuid,
    /// 平台角色名。
    pub platform_roles: &'login [String],
    /// 有效成员关系,最近用过的在前。
    pub memberships: &'login [Membership],
}

/// 认证服务。`U` / `S` / `R` / `M` = 用户 / 会话 / 角色 / 成员仓储。
///
/// 不实现 `Clone`:库内唯一所有权(指南「Avoid Rc and Arc」),要在多处共享(如 axum 的 `AppState`)
/// 由消费方包一层 `Arc<AuthService<…>>`。
pub struct AuthService<U, S, R, M> {
    users: U,
    sessions: S,
    roles: R,
    members: M,
    signup_tenant: Option<Uuid>,
    signup_roles: Vec<String>,
    /// `Arc` 而非 `Box`:哈希在 `spawn_blocking` 里跑,闭包要 `'static`、借不了 `&self`,只能共享所有权
    /// (指南「Avoid Rc and Arc」例外:借用结构做不到)。
    hasher: Arc<dyn PasswordHasher>,
    signer: Box<dyn TokenSigner>,
    verifier: Box<dyn TokenVerifier>,
    clock: Box<dyn Clock>,
    access_ttl: Duration,
    refresh_ttl: Duration,
}

impl<U, S, R, M> AuthService<U, S, R, M>
where
    U: UserRepo,
    S: SessionRepo,
    R: RoleRepo,
    M: MemberRepo,
{
    /// 建 builder:只设要 override 的端口,其余取默认(Argon2 / `SystemClock` / 15 分钟 / 7 天)。
    /// 四个仓储没有默认,必须传(含成员仓储:多租户恒开,没有"不启用租户"的降级);签验端口没有安全默认 ——
    /// 必须经 [`AuthServiceBuilder::hs256_secret`] 或 `signer` + `verifier` 给出,否则
    /// [`AuthServiceBuilder::build`] panic。
    pub fn builder(users: U, sessions: S, roles: R, members: M) -> AuthServiceBuilder<U, S, R, M> {
        AuthServiceBuilder {
            users,
            sessions,
            roles,
            members,
            signup_tenant: Some(DEFAULT_TENANT_ID),
            signup_roles: vec![DEFAULT_SIGNUP_ROLE.to_owned()],
            hasher: Arc::new(Argon2Hasher),
            signer: None,
            verifier: None,
            clock: Box::new(SystemClock),
            access_ttl: DEFAULT_ACCESS_TTL,
            refresh_ttl: DEFAULT_REFRESH_TTL,
        }
    }

    /// 注册:归一 username / email → hash 密码 → 建账号 → 发会话。`by` = 审计主体。
    /// 配了 `signup_tenant`(默认)时,**同一事务**里把账号加入该租户(存活且 active 才加)并授
    /// `signup_roles`(必须都是存活的租户角色,否则 `Internal`,什么都不建);随后像登录一样进入它。
    ///
    /// # Errors
    ///
    /// username / email 已占用 → `Conflict`;注册角色配错 → `Internal`;仓储 / 哈希失败 → `Internal`。
    pub async fn register(
        &self,
        input: RegisterInput,
        by: Option<&str>,
    ) -> Result<AuthOutcome, IdmError> {
        let username = normalize_identifier(&input.username);
        let email: Option<String> = input.email.as_deref().map(normalize_identifier);
        let password_hash = self.hash_password(input.password).await?;
        let new_user = NewUser {
            username: &username,
            email: email.as_deref(),
            password_hash: &password_hash,
        };
        let user = match self.signup_tenant {
            Some(tenant_id) => {
                let role_ids = self.signup_role_ids().await?;
                self.users
                    .create_with_membership(new_user, tenant_id, &role_ids, by)
                    .await?
            }
            None => self.users.create(new_user, by).await?,
        };
        let tenant = self.enter_default_tenant(user.id).await?;
        self.issue_session(&user, tenant.as_ref(), by).await
    }

    /// 登录:查用户(identifier = username 或 email)→ 验密 → 进 `last_used_at` 最近的有效租户
    /// (没有 → 平台上下文)→ 发会话。
    ///
    /// # Errors
    ///
    /// 查无此人 / 密码错 → `InvalidCredentials`(原因**仅供审计**,HTTP 401 收口由消费方统一,防枚举)。
    pub async fn login(&self, input: LoginInput) -> Result<AuthOutcome, IdmError> {
        let user = self.check_credentials(input).await?;
        let tenant = self.enter_default_tenant(user.id).await?;
        self.issue_session(&user, tenant.as_ref(), None).await
    }

    /// 登录,但**进哪里由消费方挑**(如后台登录:挑第一个有后台权限的租户,没有再看平台权限)。
    /// 验密(失败同 [`Self::login`])→ 把平台角色 + 有效成员关系交给 `choose` →
    /// `Some(Tenant(id))` 进该租户并记 `last_used_at`;`Some(Platform)` 进平台上下文;
    /// `None` → `Forbidden`,**不建会话、不记 last_used_at**。授权规则(哪个角色给后台权限)在消费方,
    /// 本库不认识权限。
    ///
    /// # Errors
    ///
    /// 凭据错 → `InvalidCredentials`(不调用 `choose`);`choose` 返回 `None`、挑了不在候选里的租户,或刚好
    /// 被并发移出 → `Forbidden`(不像 `login` 那样退回平台上下文:消费方挑租户是有授权含义的)。
    pub async fn login_with<F>(&self, input: LoginInput, choose: F) -> Result<AuthOutcome, IdmError>
    where
        F: FnOnce(&LoginCandidates<'_>) -> Option<LoginEntry>,
    {
        let user = self.check_credentials(input).await?;
        let platform_roles = self.roles.roles_for_user(user.id).await?;
        let memberships = self.members.memberships_for_user(user.id).await?;
        let candidates = LoginCandidates {
            user_id: user.id,
            platform_roles: &platform_roles,
            memberships: &memberships,
        };
        let entry = choose(&candidates).ok_or(IdmError::Forbidden)?;
        let tenant: Option<&Membership> = match entry {
            LoginEntry::Platform => None,
            LoginEntry::Tenant(tenant_id) => {
                let membership = memberships
                    .iter()
                    .find(|membership| membership.tenant.id == tenant_id)
                    .ok_or(IdmError::Forbidden)?;
                match self.members.touch_last_used(membership.key()).await {
                    Err(IdmError::NotFound) => return Err(IdmError::Forbidden),
                    other => other?,
                }
                Some(membership)
            }
        };
        self.issue_session(&user, tenant, None).await
    }

    /// 验 access token → 已认证身份(平台角色 + 当前租户 + 租户角色)。
    ///
    /// # Errors
    ///
    /// 验签 / 过期 / 格式任一失败 → `Unauthorized`。
    pub fn authenticate_token(&self, token: &str) -> Result<AuthUser, IdmError> {
        let verified = self.verifier.verify(token)?;
        Ok(AuthUser::from_verified_token(verified))
    }

    /// 当前用户资料(GET /me):查存活用户 + 平台角色 → `UserView`。
    ///
    /// # Errors
    ///
    /// 已软删 / 不存在 → `NotFound`。
    pub async fn me(&self, user_id: Uuid) -> Result<UserView, IdmError> {
        let user = self.users.find_by_id(user_id).await?;
        let roles = self.roles.roles_for_user(user_id).await?;
        Ok(UserView::new(&user, roles))
    }

    /// 刷新:验 refresh hash → 轮换(撤旧会话、发新会话)。同一 refresh token 并发使用:撤销是条件更新,
    /// 只有撤到行的那一个继续签发。**沿用会话上的租户**,重新读成员关系和租户角色;平台上下文的会话刷新后
    /// 仍是平台上下文。
    ///
    /// # Errors
    ///
    /// refresh 无效 / 过期 / 已撤销(含被并发用掉)→ `Unauthorized`;成员被移出 / 停用、租户停用 / 删除 →
    /// `Unauthorized`(旧会话照样作废,绝不悄悄落到别的租户)。
    pub async fn refresh(&self, refresh_token: &str) -> Result<AuthOutcome, IdmError> {
        let session = self.active_session(refresh_token).await?;
        // 轮换:旧 refresh 一次性,撤销后发新会话(防 refresh 重放)。先撤:后面任何一步失败旧会话都已作废。
        // 撤到 0 行 = 已被并发的另一次 refresh / 切换用掉 → Unauthorized,绝不再分出第二个会话。
        self.consume_session(session.id).await?;
        let user = self.users.find_by_id(session.user_id).await?;
        let tenant: Option<Membership> = match session.tenant_id {
            None => None,
            Some(tenant_id) => {
                let member = MemberKey {
                    tenant_id,
                    user_id: user.id,
                };
                Some(
                    self.effective_membership(member)
                        .await?
                        .ok_or(IdmError::Unauthorized)?,
                )
            }
        };
        self.issue_session(&user, tenant.as_ref(), None).await
    }

    /// 切换当前租户:凭 refresh token 认会话 → 校验 `member.user_id` 在 `member.tenant_id` 是**有效成员**
    /// (成员 active + 租户 active)→ 吊销旧会话 → 建带新租户的会话 → 记 `last_used_at`(下次登录默认进它)。
    ///
    /// `member.user_id` = 调用方已认证的当前身份(消费方从 access token 取)。
    ///
    /// # Errors
    ///
    /// refresh 无效(含已被并发的 refresh / 切换用掉)→ `Unauthorized`;refresh 会话不属于 `member.user_id`
    /// → `Unauthorized`、原会话不动(防止拿别人的 refresh cookie 借当前身份切换别人的会话);不是有效成员
    /// (含平台管理员切进自己不是成员的租户)→ `Forbidden`,原会话不动。
    pub async fn switch_tenant(
        &self,
        refresh_token: &str,
        member: MemberKey,
    ) -> Result<AuthOutcome, IdmError> {
        let session = self.active_session(refresh_token).await?;
        if session.user_id != member.user_id {
            return Err(IdmError::Unauthorized);
        }
        let membership = self
            .effective_membership(member)
            .await?
            .ok_or(IdmError::Forbidden)?;
        let user = self.users.find_by_id(session.user_id).await?;
        // 先记 last_used_at 再吊销:刚好被并发移出(NotFound)→ Forbidden,原会话不动。
        match self.members.touch_last_used(member).await {
            Err(IdmError::NotFound) => return Err(IdmError::Forbidden),
            other => other?,
        }
        // 撤销是轮换闸(同 refresh):撤到 0 行 = 这个 refresh 已被并发用掉 → Unauthorized,不签新会话。
        self.consume_session(session.id).await?;
        self.issue_session(&user, Some(&membership), None).await
    }

    /// 当前账号的有效成员关系(租户 active + 成员 active),`last_used_at` 最近的在前。
    /// 返回 `Vec`:原样转交仓储取回的 `Vec`(指南「Iterators vs. owned collections」例外)。
    ///
    /// # Errors
    ///
    /// 仓储失败 → `Internal`。
    pub async fn my_tenants(&self, user_id: Uuid) -> Result<Vec<Membership>, IdmError> {
        self.members.memberships_for_user(user_id).await
    }

    /// 登出:撤销该 refresh 对应的会话,返回被撤会话(含 `user_id`,审计用)。幂等(找不到活跃会话,
    /// 或被并发的登出 / 刷新抢先撤掉 → `None`)。
    ///
    /// # Errors
    ///
    /// 仓储失败 → `Internal`。
    pub async fn logout(&self, refresh_token: &str) -> Result<Option<Session>, IdmError> {
        let token_hash = refresh_token::hash_token(refresh_token);
        let active = self
            .sessions
            .find_active(&token_hash, self.clock.now())
            .await?;
        let Some(session) = active else {
            return Ok(None);
        };
        if self.sessions.revoke(session.id).await? {
            Ok(Some(session))
        } else {
            Ok(None)
        }
    }

    /// 登出所有设备:撤销用户全部活跃会话。
    ///
    /// # Errors
    ///
    /// 仓储失败 → `Internal`。
    pub async fn logout_all(&self, user_id: Uuid) -> Result<(), IdmError> {
        self.sessions.revoke_all(user_id, None).await
    }

    /// 改资料(PUT /me,**全量替换**):username 必填,email 给值 = 设 / 给空 = 清空。替换 email 会重置
    /// email_verified。`by` = 审计主体(updated_by)。
    ///
    /// # Errors
    ///
    /// 冲突 → `Conflict`;账号已不在 → `NotFound`。
    pub async fn update_me(
        &self,
        user_id: Uuid,
        input: UpdateMeInput,
        by: Option<&str>,
    ) -> Result<UserView, IdmError> {
        let username = normalize_identifier(&input.username);
        let email: Option<String> = input.email.as_deref().map(normalize_identifier);
        let user = self
            .users
            .update(user_id, &username, email.as_deref(), by)
            .await?;
        let roles = self.roles.roles_for_user(user_id).await?;
        Ok(UserView::new(&user, roles))
    }

    /// 注销(DELETE /me):验密 → 撤销所有会话 → 软删账户。`by` = 审计主体。
    ///
    /// # Errors
    ///
    /// 密码错 → `InvalidCredentials(BadPassword)`(凭据错,会话仍有效);账号已不在 → `Unauthorized`
    /// (会话失效)。
    pub async fn delete_me(
        &self,
        user_id: Uuid,
        password: String,
        by: Option<&str>,
    ) -> Result<(), IdmError> {
        self.confirm_password(user_id, password).await?;
        self.sessions.revoke_all(user_id, None).await?;
        self.users.soft_delete(user_id, by).await
    }

    /// 改密(POST /me/password):验旧密码 → 换 hash → 撤销所有会话(强制重登录)。
    ///
    /// # Errors
    ///
    /// 旧密码错 → `InvalidCredentials(BadPassword)`(凭据错,会话仍有效);账号已不在 → `Unauthorized`
    /// (会话失效)。
    pub async fn change_password(
        &self,
        user_id: Uuid,
        input: ChangePasswordInput,
    ) -> Result<(), IdmError> {
        self.confirm_password(user_id, input.current_password)
            .await?;
        let new_hash = self.hash_password(input.new_password).await?;
        self.users.update_password(user_id, &new_hash).await?;
        self.sessions.revoke_all(user_id, None).await?;
        Ok(())
    }

    /// 查用户(identifier = username 或 email)→ 验密。失败原因只供审计(见 [`CredentialFailure`])。
    async fn check_credentials(&self, input: LoginInput) -> Result<User, IdmError> {
        let identifier = normalize_identifier(&input.identifier);
        let Some(found) = self.users.find_by_identifier(&identifier).await? else {
            return Err(IdmError::InvalidCredentials(CredentialFailure::UnknownUser));
        };
        if !self
            .verify_password(input.password, found.password_hash)
            .await?
        {
            return Err(IdmError::InvalidCredentials(CredentialFailure::BadPassword));
        }
        Ok(found.user)
    }

    /// 已登录账号的密码确认(改密 / 注销):账号已不在 → `Unauthorized`;密码错 →
    /// `InvalidCredentials(BadPassword)`。
    async fn confirm_password(&self, user_id: Uuid, password: String) -> Result<(), IdmError> {
        let password_hash = self
            .users
            .password_hash(user_id)
            .await?
            .ok_or(IdmError::Unauthorized)?;
        if self.verify_password(password, password_hash).await? {
            Ok(())
        } else {
            Err(IdmError::InvalidCredentials(CredentialFailure::BadPassword))
        }
    }

    /// 一次性用掉 refresh 会话(轮换闸):真撤掉了 → `Ok`;已被别人撤掉(并发重放)→ `Unauthorized`。
    async fn consume_session(&self, session_id: Uuid) -> Result<(), IdmError> {
        if self.sessions.revoke(session_id).await? {
            Ok(())
        } else {
            Err(IdmError::Unauthorized)
        }
    }

    /// 按 refresh token 找活跃会话;无效 / 过期 / 已撤销 → `Unauthorized`。
    async fn active_session(&self, refresh_token: &str) -> Result<Session, IdmError> {
        let token_hash = refresh_token::hash_token(refresh_token);
        self.sessions
            .find_active(&token_hash, self.clock.now())
            .await?
            .ok_or(IdmError::Unauthorized)
    }

    /// 在该租户的**有效**成员关系(成员 active + 租户 active 且未删);否则 `None`。
    async fn effective_membership(
        &self,
        member: MemberKey,
    ) -> Result<Option<Membership>, IdmError> {
        let membership = self.members.get(member).await?;
        Ok(membership.filter(Membership::is_effective))
    }

    /// 登录 / 注册时进入的租户:有效成员关系里 `last_used_at` 最近的那个(并记一次 last_used_at);
    /// 没有 → `None`(平台上下文)。
    async fn enter_default_tenant(&self, user_id: Uuid) -> Result<Option<Membership>, IdmError> {
        let memberships = self.members.memberships_for_user(user_id).await?;
        let Some(latest) = memberships.into_iter().next() else {
            return Ok(None);
        };
        match self.members.touch_last_used(latest.key()).await {
            Ok(()) => Ok(Some(latest)),
            // 刚好被并发移出 / 租户刚被删:按平台上下文进,不让登录失败
            Err(IdmError::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// `signup_roles` 的角色名 → id,**只在租户角色里找**(`scope = tenant`;注册是加入租户,平台角色
    /// 绝不能经注册授出)。配置的名字找不到(没 seed、或同名的是平台角色)→ `Internal` 并记 error 日志:
    /// 这是装配 / 数据错误,注册必须响亮失败,不能悄悄建一个没有角色的成员。
    async fn signup_role_ids(&self) -> Result<Vec<Uuid>, IdmError> {
        if self.signup_roles.is_empty() {
            return Ok(Vec::new());
        }
        let catalog = self.roles.list().await?;
        let mut role_ids: Vec<Uuid> = Vec::with_capacity(self.signup_roles.len());
        for name in &self.signup_roles {
            let tenant_role = catalog
                .iter()
                .find(|role| &role.name == name && role.scope == RoleScope::Tenant);
            let Some(role) = tenant_role else {
                tracing::error!(role = %name, "注册角色不是存活的租户角色(没 seed?作用域不对?)");
                return Err(IdmError::Internal(anyhow::anyhow!(
                    "注册角色 {name} 不存在或不是租户角色"
                )));
            };
            role_ids.push(role.id);
        }
        Ok(role_ids)
    }

    /// 发会话:查平台角色 → 生成 refresh + 建会话(带租户)→ 经 signer 签 access token(claim 形状由
    /// signer 决定),组 `AuthOutcome`。`tenant` = 当前租户的成员关系(`None` = 平台上下文)。
    async fn issue_session(
        &self,
        user: &User,
        tenant: Option<&Membership>,
        by: Option<&str>,
    ) -> Result<AuthOutcome, IdmError> {
        let now = self.clock.now();
        let roles = self.roles.roles_for_user(user.id).await?;
        let tenant_id: Option<Uuid> = tenant.map(|membership| membership.tenant.id);
        let tenant_roles: Vec<String> = tenant
            .map(|membership| membership.roles.clone())
            .unwrap_or_default();
        let refresh = RefreshToken::generate();
        let session = self
            .sessions
            .create(
                user.id,
                tenant_id,
                &refresh.hash,
                now + self.refresh_ttl,
                by,
            )
            .await?;
        let mut claims = TokenClaims::new(&session, user.username.clone(), now, self.access_ttl);
        claims.email.clone_from(&user.email);
        claims.email_verified = user.email_verified;
        claims.roles.clone_from(&roles);
        claims.tenant_roles.clone_from(&tenant_roles);
        claims.tenant_slug = tenant.map(|membership| membership.tenant.slug.clone());
        claims.tenant_name = tenant.map(|membership| membership.tenant.name.clone());
        let access_token = self.signer.sign(&claims)?;
        Ok(AuthOutcome {
            user: UserView::new(user, roles),
            session_id: session.id,
            access_token,
            refresh_token: refresh.token,
            access_max_age: self.access_ttl,
            refresh_max_age: self.refresh_ttl,
            tenant_id,
            tenant_roles,
        })
    }

    /// argon2 hash 是 CPU 密集 → `spawn_blocking`,不阻塞 tokio worker 线程。
    async fn hash_password(&self, password: String) -> Result<String, IdmError> {
        let hasher = Arc::clone(&self.hasher);
        task::spawn_blocking(move || hasher.hash(&password))
            .await
            .map_err(|e| IdmError::Internal(anyhow::anyhow!("hash 任务异常: {e}")))?
    }

    async fn verify_password(
        &self,
        password: String,
        phc_string: String,
    ) -> Result<bool, IdmError> {
        let hasher = Arc::clone(&self.hasher);
        task::spawn_blocking(move || hasher.verify(&password, &phc_string))
            .await
            .map_err(|e| IdmError::Internal(anyhow::anyhow!("verify 任务异常: {e}")))?
    }
}

/// [`AuthService`] 的 builder —— 只设要 override 的端口,其余取默认。见 [`AuthService::builder`]。
/// 默认:`hasher` = Argon2、`clock` = `SystemClock`、有效期 15 分钟 / 7 天;签验端口无默认(`build` 前必设)。
#[must_use = "builder 不调 build() 什么也不会发生"]
pub struct AuthServiceBuilder<U, S, R, M> {
    users: U,
    sessions: S,
    roles: R,
    members: M,
    signup_tenant: Option<Uuid>,
    signup_roles: Vec<String>,
    hasher: Arc<dyn PasswordHasher>,
    signer: Option<Box<dyn TokenSigner>>,
    verifier: Option<Box<dyn TokenVerifier>>,
    clock: Box<dyn Clock>,
    access_ttl: Duration,
    refresh_ttl: Duration,
}

impl<U, S, R, M> AuthServiceBuilder<U, S, R, M>
where
    U: UserRepo,
    S: SessionRepo,
    R: RoleRepo,
    M: MemberRepo,
{
    /// 用 HS256 对称密钥设签验端口(签发和验证同一把密钥)。与 `signer` / `verifier` 二选一。
    pub fn hs256_secret(mut self, secret: &str) -> Self {
        let tokens = Hs256Tokens::new(secret);
        self.signer = Some(Box::new(tokens.clone()));
        self.verifier = Some(Box::new(tokens));
        self
    }

    /// 自定义签发端口(RS256 / KMS / 自定义 claims)。分进程时 idm 侧持私钥用。
    pub fn signer(mut self, signer: impl TokenSigner + 'static) -> Self {
        self.signer = Some(Box::new(signer));
        self
    }

    /// 自定义验证端口(只验不签 —— app 侧最小权限,持公钥)。
    pub fn verifier(mut self, verifier: impl TokenVerifier + 'static) -> Self {
        self.verifier = Some(Box::new(verifier));
        self
    }

    /// 公开注册加入的租户(默认 `Some(DEFAULT_TENANT_ID)`)。`None` = 注册只建账号。
    /// 该租户不存在 / 已删 / 停用时同样只建账号。
    pub fn signup_tenant(mut self, tenant_id: Option<Uuid>) -> Self {
        self.signup_tenant = tenant_id;
        self
    }

    /// 注册时在 `signup_tenant` 里授的租户角色名(默认 `["user"]`)。每个名字都必须是存活的**租户角色**,
    /// 否则注册返回 `Internal`(装配错误要响亮);不想授角色就传空集合。
    pub fn signup_roles<I>(mut self, roles: I) -> Self
    where
        I: IntoIterator,
        I::Item: Into<String>,
    {
        self.signup_roles = roles.into_iter().map(Into::into).collect();
        self
    }

    /// 替换密码哈希端口(默认 `Argon2Hasher`;测试用 `FakeHasher`)。
    pub fn hasher(mut self, hasher: impl PasswordHasher + 'static) -> Self {
        self.hasher = Arc::new(hasher);
        self
    }

    /// 替换时间端口(默认 `SystemClock`;测试注入固定时钟可确定性测过期 / 轮换)。
    pub fn clock(mut self, clock: impl Clock + 'static) -> Self {
        self.clock = Box::new(clock);
        self
    }

    /// access token 有效期(默认 15 分钟)。
    pub fn access_ttl(mut self, ttl: Duration) -> Self {
        self.access_ttl = ttl;
        self
    }

    /// refresh token 有效期(默认 7 天)。
    pub fn refresh_ttl(mut self, ttl: Duration) -> Self {
        self.refresh_ttl = ttl;
        self
    }

    /// 组装。
    ///
    /// # Panics
    ///
    /// 没经 `hs256_secret` 或 `signer` + `verifier` 设签验端口 → panic(装配错误,启动期即暴露,不会静默
    /// 跑出无法签发 / 验签的服务)。
    #[must_use]
    pub fn build(self) -> AuthService<U, S, R, M> {
        let signer = self
            .signer
            .expect("AuthServiceBuilder::build: 须先调 hs256_secret 或 signer 设签发端口");
        let verifier = self
            .verifier
            .expect("AuthServiceBuilder::build: 须先调 hs256_secret 或 verifier 设验证端口");
        AuthService {
            users: self.users,
            sessions: self.sessions,
            roles: self.roles,
            members: self.members,
            signup_tenant: self.signup_tenant,
            signup_roles: self.signup_roles,
            hasher: self.hasher,
            signer,
            verifier,
            clock: self.clock,
            access_ttl: self.access_ttl,
            refresh_ttl: self.refresh_ttl,
        }
    }
}

/// 标识符归一:去空白 + 转小写(配合 username / email 存活唯一索引,避免大小写绕过唯一)。
fn normalize_identifier(identifier: &str) -> String {
    identifier.trim().to_lowercase()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use std::time::Duration as StdDuration;

    use async_trait::async_trait;
    use time::{Duration, OffsetDateTime};
    // 「Qualify calls to top-level functions with a module name」例外:模块名 `time` 和 time crate 撞名。
    use tokio::time::sleep;
    use uuid::Uuid;

    use super::{AuthOutcome, AuthService, AuthServiceBuilder, LoginEntry};
    use crate::auth_user::AuthUser;
    use crate::clock::Clock;
    use crate::hs256_tokens::Hs256Tokens;
    use crate::idm_error::{CredentialFailure, IdmError};
    use crate::input::{ChangePasswordInput, LoginInput, RegisterInput};
    use crate::password_hasher::{FakeHasher, PasswordHasher};
    use crate::repo::{
        InMemoryMemberRepo, InMemoryRoleRepo, InMemorySessionRepo, InMemoryTenantRepo,
        InMemoryUserRepo, MemberRepo, NewRole, NewTenant, NewUser, RoleGrant, RoleRepo, Session,
        SessionRepo, TenantRepo, UserRepo,
    };
    use crate::tenant::{MemberKey, MemberStatus, RoleScope, TenantStatus, DEFAULT_TENANT_ID};
    use crate::token::{TokenClaims, TokenSigner, TokenVerifier};

    /// 测试里的内存装配:四个仓储都经 `Arc` 转发实现注入(测试还要直接读写这几个仓储)。
    type MemoryAuthService = AuthService<
        Arc<InMemoryUserRepo>,
        Arc<InMemorySessionRepo>,
        Arc<InMemoryRoleRepo>,
        Arc<InMemoryMemberRepo>,
    >;
    type MemoryAuthServiceBuilder = AuthServiceBuilder<
        Arc<InMemoryUserRepo>,
        Arc<InMemorySessionRepo>,
        Arc<InMemoryRoleRepo>,
        Arc<InMemoryMemberRepo>,
    >;

    /// 不授任何注册角色(`signup_roles` 收任意 `Into<String>` 的迭代器,空集合要在声明上写明元素类型)。
    const NO_SIGNUP_ROLES: [&str; 0] = [];

    /// 成员键(测试里写短一点)。
    fn key(tenant_id: Uuid, user_id: Uuid) -> MemberKey {
        MemberKey { tenant_id, user_id }
    }

    fn register_input(username: &str) -> RegisterInput {
        RegisterInput {
            username: username.to_owned(),
            password: "password123".to_owned(),
            ..RegisterInput::default()
        }
    }

    fn login_input(identifier: &str, password: &str) -> LoginInput {
        LoginInput {
            identifier: identifier.to_owned(),
            password: password.to_owned(),
        }
    }

    /// 各自独立存储的内存装配,注册不授租户角色(配了不存在的角色会响亮失败)。
    fn isolated_service(
    ) -> AuthService<InMemoryUserRepo, InMemorySessionRepo, InMemoryRoleRepo, InMemoryMemberRepo>
    {
        AuthService::builder(
            InMemoryUserRepo::new(),
            InMemorySessionRepo::new(),
            InMemoryRoleRepo::new(),
            InMemoryMemberRepo::new(),
        )
        .hs256_secret("secret")
        .hasher(FakeHasher)
        .signup_roles(NO_SIGNUP_ROLES)
        .build()
    }

    /// 签验端口无默认:builder 未设就 build → panic(装配错误启动期即暴露,不会静默跑出无法验签的服务)。
    #[test]
    #[should_panic(expected = "hs256_secret")]
    fn builder_without_token_ports_panics() {
        let _service = AuthService::builder(
            InMemoryUserRepo::new(),
            InMemorySessionRepo::new(),
            InMemoryRoleRepo::new(),
            InMemoryMemberRepo::new(),
        )
        .build();
    }

    /// 下游运行时二选一实现时的实例化方式。
    type DynAuthService = AuthService<
        Arc<dyn UserRepo>,
        Arc<dyn SessionRepo>,
        Arc<dyn RoleRepo>,
        Arc<dyn MemberRepo>,
    >;

    /// 下游可以用 `Arc<dyn …>` 实例化,运行时二选一实现(`Arc<T>` 转发实现的用途)。
    #[tokio::test]
    async fn service_accepts_trait_objects_for_runtime_choice() {
        let users = InMemoryUserRepo::new();
        let sessions: Arc<dyn SessionRepo> = Arc::new(InMemorySessionRepo::new_shared_with(&users));
        let roles: Arc<dyn RoleRepo> = Arc::new(InMemoryRoleRepo::new_shared_with(&users));
        let members: Arc<dyn MemberRepo> = Arc::new(InMemoryMemberRepo::new_shared_with(&users));
        let users: Arc<dyn UserRepo> = Arc::new(users);
        let tokens: Arc<Hs256Tokens> = Arc::new(Hs256Tokens::new("secret"));
        let service: DynAuthService = AuthService::builder(users, sessions, roles, members)
            .signer(Arc::clone(&tokens))
            .verifier(tokens)
            .hasher(Arc::new(FakeHasher))
            .signup_roles(NO_SIGNUP_ROLES)
            .build();
        let outcome = service
            .register(register_input("alice"), None)
            .await
            .unwrap();
        let who = service.authenticate_token(&outcome.access_token).unwrap();
        assert_eq!(who.username, "alice");
    }

    /// 可变测试时钟:证明注入的 `Clock` 真的驱动会话过期(Clock 端口的存在理由)。
    struct TestClock(Mutex<OffsetDateTime>);

    impl Clock for TestClock {
        fn now(&self) -> OffsetDateTime {
            *self.0.lock().unwrap()
        }
    }

    /// 注入固定时钟 → 会话过期由它**确定性**控制:未过期可 refresh,把时钟推过 refresh 有效期后同一
    /// refresh → 401。不 sleep 真实时间也能测过期 / 轮换(refresh 只比对注入时钟的 `now` 与 `expires_at`)。
    #[tokio::test]
    async fn injected_clock_drives_session_expiry() {
        let start = OffsetDateTime::UNIX_EPOCH + Duration::days(20_000); // 固定,与真实时钟无关
        let clock = Arc::new(TestClock(Mutex::new(start)));
        let service = AuthService::builder(
            InMemoryUserRepo::new(),
            InMemorySessionRepo::new(),
            InMemoryRoleRepo::new(),
            InMemoryMemberRepo::new(),
        )
        .hs256_secret("secret")
        .hasher(FakeHasher)
        .signup_roles(NO_SIGNUP_ROLES)
        .clock(Arc::clone(&clock))
        .refresh_ttl(Duration::seconds(100))
        .build();

        // 用户 A:start 注册(会话 expires = start + 100),start 刷新 → 活跃。
        let alice = service
            .register(register_input("alice"), None)
            .await
            .unwrap();
        assert!(
            service.refresh(&alice.refresh_token).await.is_ok(),
            "未过期会话应可 refresh"
        );

        // 用户 B:start 注册,把时钟推到有效期之后 → 会话过期 → 同一 refresh 报 401。
        let bob = service.register(register_input("bob"), None).await.unwrap();
        *clock.0.lock().unwrap() = start + Duration::seconds(101);
        assert!(
            matches!(
                service.refresh(&bob.refresh_token).await,
                Err(IdmError::Unauthorized)
            ),
            "时钟越过 refresh 有效期后会话应过期 → 401"
        );
    }

    /// 独占所有权的运行时选择(`Box<dyn …>`)时的实例化方式。
    type BoxedAuthService = AuthService<
        Box<dyn UserRepo>,
        Box<dyn SessionRepo>,
        Box<dyn RoleRepo>,
        Box<dyn MemberRepo>,
    >;

    /// 独占所有权的运行时选择:四个仓储和哈希 / 签发 / 验证 / 时钟端口全填 `Box<dyn …>`
    /// (`Box<T>` 转发实现的用途)。注册 + 登录(对 / 错密码)走哈希端口两个方法,验 access token 走签验端口,
    /// 推进时钟后 refresh 失效证明 `Box<dyn Clock>` 把 `now` 转发到了内层时钟。
    #[tokio::test]
    async fn service_accepts_boxed_trait_objects_for_every_port() {
        let users = InMemoryUserRepo::new();
        let sessions: Box<dyn SessionRepo> = Box::new(InMemorySessionRepo::new_shared_with(&users));
        let roles: Box<dyn RoleRepo> = Box::new(InMemoryRoleRepo::new_shared_with(&users));
        let members: Box<dyn MemberRepo> = Box::new(InMemoryMemberRepo::new_shared_with(&users));
        let users: Box<dyn UserRepo> = Box::new(users);
        let tokens = Hs256Tokens::new("secret");
        let signer: Box<dyn TokenSigner> = Box::new(tokens.clone());
        let verifier: Box<dyn TokenVerifier> = Box::new(tokens);
        let hasher: Box<dyn PasswordHasher> = Box::new(FakeHasher);
        // 起点取真实时间:Hs256Tokens 验 exp 用的是系统时钟,固定在过去会让 access token 一签出就过期。
        let start = OffsetDateTime::now_utc();
        let test_clock = Arc::new(TestClock(Mutex::new(start)));
        let clock: Box<dyn Clock> = Box::new(Arc::clone(&test_clock));
        let service: BoxedAuthService = AuthService::builder(users, sessions, roles, members)
            .signer(signer)
            .verifier(verifier)
            .hasher(hasher)
            .clock(clock)
            .refresh_ttl(Duration::seconds(100))
            .signup_roles(NO_SIGNUP_ROLES)
            .build();

        let registered = service
            .register(register_input("alice"), None)
            .await
            .unwrap();
        let who = service
            .authenticate_token(&registered.access_token)
            .unwrap();
        assert_eq!(who.username, "alice", "签验端口经 Box 转发后应能验回本人");
        let logged_in = service
            .login(login_input("alice", "password123"))
            .await
            .unwrap();
        assert_eq!(logged_in.user.id, registered.user.id);
        let wrong = service.login(login_input("alice", "wrong")).await;
        assert!(
            matches!(
                wrong,
                Err(IdmError::InvalidCredentials(CredentialFailure::BadPassword))
            ),
            "哈希端口经 Box 转发后错密码应被拒: {wrong:?}"
        );

        *test_clock.0.lock().unwrap() = start + Duration::seconds(101);
        assert!(
            matches!(
                service.refresh(&logged_in.refresh_token).await,
                Err(IdmError::Unauthorized)
            ),
            "Box<dyn Clock> 应把 now 转发给内层时钟:推过 refresh 有效期后会话应过期"
        );
    }

    /// 改密 / 注销的密码确认错 = 凭据错(`InvalidCredentials(BadPassword)`),不是 `Unauthorized`:
    /// 消费方据此把「密码不对」和「会话失效」分成两个机器码。
    #[tokio::test]
    async fn wrong_password_on_change_password_and_delete_me_is_invalid_credentials() {
        let service = isolated_service();
        let alice = service
            .register(register_input("alice"), None)
            .await
            .unwrap();

        let changed = service
            .change_password(
                alice.user.id,
                ChangePasswordInput {
                    current_password: "wrong".to_owned(),
                    new_password: "newpass456".to_owned(),
                },
            )
            .await;
        assert!(
            matches!(
                changed,
                Err(IdmError::InvalidCredentials(CredentialFailure::BadPassword))
            ),
            "改密旧密码错应为 InvalidCredentials(BadPassword): {changed:?}"
        );

        let deleted = service
            .delete_me(alice.user.id, "wrong".to_owned(), None)
            .await;
        assert!(
            matches!(
                deleted,
                Err(IdmError::InvalidCredentials(CredentialFailure::BadPassword))
            ),
            "注销密码错应为 InvalidCredentials(BadPassword): {deleted:?}"
        );
    }

    #[tokio::test]
    async fn login_reports_distinct_failure_reasons() {
        let service = isolated_service();
        service
            .register(register_input("alice"), None)
            .await
            .unwrap();

        let unknown = service.login(login_input("ghost", "password123")).await;
        assert!(
            matches!(
                unknown,
                Err(IdmError::InvalidCredentials(CredentialFailure::UnknownUser))
            ),
            "查无此人应为 UnknownUser: {unknown:?}"
        );

        let bad = service.login(login_input("alice", "wrong")).await;
        assert!(
            matches!(
                bad,
                Err(IdmError::InvalidCredentials(CredentialFailure::BadPassword))
            ),
            "密码不匹配应为 BadPassword: {bad:?}"
        );
    }

    /// `AuthOutcome` 的 `Debug` 不带 token 明文(日志 / panic 输出安全)。
    #[tokio::test]
    async fn auth_outcome_debug_redacts_tokens() {
        let service = isolated_service();
        let outcome = service
            .register(register_input("alice"), None)
            .await
            .unwrap();
        let printed = format!("{outcome:?}");
        assert!(
            !printed.contains(&outcome.access_token),
            "access token 泄露: {printed}"
        );
        assert!(
            !printed.contains(&outcome.refresh_token),
            "refresh token 泄露: {printed}"
        );
        assert!(printed.contains("alice"), "非敏感字段照常打印: {printed}");
    }

    #[tokio::test]
    async fn auth_outcome_exposes_rotating_session_id_and_ttls() {
        let service = isolated_service();
        let registered = service
            .register(register_input("alice"), None)
            .await
            .unwrap();
        assert!(!registered.session_id.is_nil(), "注册应带非空 session_id");
        assert_eq!(
            registered.access_max_age,
            Duration::minutes(15),
            "默认 access 有效期"
        );
        assert_eq!(
            registered.refresh_max_age,
            Duration::days(7),
            "默认 refresh 有效期"
        );

        // 刷新轮换 → 新会话,session_id 必不同。
        let refreshed = service.refresh(&registered.refresh_token).await.unwrap();
        assert_ne!(
            registered.session_id, refreshed.session_id,
            "refresh 轮换后应是新的 session_id"
        );
    }

    #[tokio::test]
    async fn logout_returns_revoked_session_id_then_none() {
        let service = isolated_service();
        let registered = service
            .register(register_input("alice"), None)
            .await
            .unwrap();
        let revoked = service.logout(&registered.refresh_token).await.unwrap();
        assert!(
            matches!(revoked, Some(ref session) if session.id == registered.session_id),
            "登出应返回被撤会话,且 id 匹配"
        );

        // 幂等:同一 token 再登出 → 无活跃会话 → None。
        assert!(service
            .logout(&registered.refresh_token)
            .await
            .unwrap()
            .is_none());
    }

    // ── 多租户:登录选租户 / 切换 / refresh 沿用租户 / 注册加入默认租户 ──

    /// 模拟并发窗口:`find_active` 返回的是"别人撤销之前"读到的快照 —— 两个请求都先查到活跃会话、再去撤。
    /// 撤销闸(条件更新)得让后到的那个撤到 0 行 → `Unauthorized`,不再签第二个会话。
    struct StaleReadSessions {
        inner: InMemorySessionRepo,
        seen: Mutex<HashMap<String, Session>>,
        stale_hits: AtomicUsize,
        created: AtomicUsize,
    }

    #[async_trait]
    impl SessionRepo for StaleReadSessions {
        async fn create(
            &self,
            user_id: Uuid,
            tenant_id: Option<Uuid>,
            token_hash: &str,
            expires_at: OffsetDateTime,
            by: Option<&str>,
        ) -> Result<Session, IdmError> {
            self.created.fetch_add(1, Ordering::SeqCst);
            self.inner
                .create(user_id, tenant_id, token_hash, expires_at, by)
                .await
        }

        async fn find_active(
            &self,
            token_hash: &str,
            now: OffsetDateTime,
        ) -> Result<Option<Session>, IdmError> {
            if let Some(session) = self.inner.find_active(token_hash, now).await? {
                self.seen
                    .lock()
                    .unwrap()
                    .insert(token_hash.to_owned(), session.clone());
                return Ok(Some(session));
            }
            let stale: Option<Session> = self.seen.lock().unwrap().get(token_hash).cloned();
            if stale.is_some() {
                self.stale_hits.fetch_add(1, Ordering::SeqCst);
            }
            Ok(stale)
        }

        async fn revoke(&self, session_id: Uuid) -> Result<bool, IdmError> {
            self.inner.revoke(session_id).await
        }

        async fn revoke_all(&self, user_id: Uuid, except: Option<Uuid>) -> Result<(), IdmError> {
            self.inner.revoke_all(user_id, except).await
        }

        async fn revoke_for_member(&self, member: MemberKey) -> Result<(), IdmError> {
            self.inner.revoke_for_member(member).await
        }

        async fn revoke_for_tenant(&self, tenant_id: Uuid) -> Result<(), IdmError> {
            self.inner.revoke_for_tenant(tenant_id).await
        }
    }

    /// 同一个 refresh token 第二次使用(refresh 或 switch_tenant)→ `Unauthorized`。
    /// 顺序重放(普通仓储)和并发窗口(find_active 读到撤销前的快照)两种都要挡住。
    #[tokio::test]
    async fn reused_refresh_token_cannot_rotate_twice() {
        // ① 顺序重放
        let env = new_env();
        let alice = env.account("alice").await;
        env.members
            .add(key(DEFAULT_TENANT_ID, alice), &[], None)
            .await
            .unwrap();
        let first = env.login("alice").await;
        env.service.refresh(&first.refresh_token).await.unwrap();
        assert!(matches!(
            env.service.refresh(&first.refresh_token).await,
            Err(IdmError::Unauthorized)
        ));
        assert!(matches!(
            env.service
                .switch_tenant(&first.refresh_token, key(DEFAULT_TENANT_ID, alice))
                .await,
            Err(IdmError::Unauthorized)
        ));

        // ② 并发窗口:find_active 仍"看到"已被轮换掉的会话
        let users = InMemoryUserRepo::new();
        let sessions = Arc::new(StaleReadSessions {
            inner: InMemorySessionRepo::new_shared_with(&users),
            seen: Mutex::default(),
            stale_hits: AtomicUsize::new(0),
            created: AtomicUsize::new(0),
        });
        let roles = InMemoryRoleRepo::new_shared_with(&users);
        let members = InMemoryMemberRepo::new_shared_with(&users);
        let service = AuthService::builder(users, Arc::clone(&sessions), roles, members)
            .hs256_secret("secret")
            .hasher(FakeHasher)
            .signup_roles(NO_SIGNUP_ROLES)
            .build();
        let registered = service.register(register_input("bob"), None).await.unwrap();
        assert_eq!(registered.tenant_id, Some(DEFAULT_TENANT_ID));
        service.refresh(&registered.refresh_token).await.unwrap();
        assert_eq!(sessions.created.load(Ordering::SeqCst), 2);

        assert!(matches!(
            service.refresh(&registered.refresh_token).await,
            Err(IdmError::Unauthorized)
        ));
        assert!(matches!(
            service
                .switch_tenant(
                    &registered.refresh_token,
                    key(DEFAULT_TENANT_ID, registered.user.id)
                )
                .await,
            Err(IdmError::Unauthorized)
        ));
        assert_eq!(
            sessions.stale_hits.load(Ordering::SeqCst),
            2,
            "两次重放都确实走进了并发窗口(find_active 读到旧快照)"
        );
        assert_eq!(
            sessions.created.load(Ordering::SeqCst),
            2,
            "重放没有分出新会话"
        );
        // 被并发抢先撤掉的会话登出 → None(没撤到就不报告撤了)
        assert!(service
            .logout(&registered.refresh_token)
            .await
            .unwrap()
            .is_none());
    }

    /// 一套共享存储的内存仓储 + 接好成员仓储的 AuthService(租户模式)。
    struct Env {
        service: MemoryAuthService,
        users: Arc<InMemoryUserRepo>,
        roles: Arc<InMemoryRoleRepo>,
        tenants: InMemoryTenantRepo,
        members: Arc<InMemoryMemberRepo>,
    }

    fn new_env_with(
        configure: impl FnOnce(MemoryAuthServiceBuilder) -> MemoryAuthServiceBuilder,
    ) -> Env {
        let users = InMemoryUserRepo::new();
        let roles = Arc::new(InMemoryRoleRepo::new_shared_with(&users));
        let tenants = InMemoryTenantRepo::new_shared_with(&users);
        let members = Arc::new(InMemoryMemberRepo::new_shared_with(&users));
        let sessions = Arc::new(InMemorySessionRepo::new_shared_with(&users));
        let users = Arc::new(users);
        let builder = AuthService::builder(
            Arc::clone(&users),
            sessions,
            Arc::clone(&roles),
            Arc::clone(&members),
        )
        .hs256_secret("secret")
        .hasher(FakeHasher);
        Env {
            service: configure(builder).build(),
            users,
            roles,
            tenants,
            members,
        }
    }

    fn new_env() -> Env {
        new_env_with(|builder| builder)
    }

    impl Env {
        /// 直接经仓储建账号(不走 register → 不自动加入任何租户)。hash 按 FakeHasher 的格式写。
        async fn account(&self, name: &str) -> Uuid {
            let new_user = NewUser {
                username: name,
                password_hash: "fake$password123",
                ..NewUser::default()
            };
            self.users.create(new_user, None).await.unwrap().id
        }

        async fn tenant_role(&self, name: &str) -> Uuid {
            self.role(name, RoleScope::Tenant).await
        }

        async fn role(&self, name: &str, scope: RoleScope) -> Uuid {
            let role = NewRole {
                name,
                display_name: name,
                scope,
            };
            self.roles.upsert(role, None).await.unwrap()
        }

        async fn tenant(&self, slug: &str) -> Uuid {
            let fields = NewTenant { slug, name: slug };
            self.tenants.create(fields, None).await.unwrap().id
        }

        async fn login(&self, name: &str) -> AuthOutcome {
            self.service
                .login(login_input(name, "password123"))
                .await
                .unwrap_or_else(|e| panic!("login {name} 失败: {e:?}"))
        }

        /// access token 验出来的身份(tenant claim 以 token 为准,不只看 AuthOutcome)。
        fn claims(&self, outcome: &AuthOutcome) -> AuthUser {
            self.service
                .authenticate_token(&outcome.access_token)
                .unwrap()
        }
    }

    #[tokio::test]
    async fn login_picks_last_used_tenant() {
        let env = new_env();
        let admin = env.tenant_role("admin").await;
        let user = env.tenant_role("user").await;
        let alice = env.account("alice").await;
        let acme = env.tenant("acme").await;
        env.members
            .add(key(DEFAULT_TENANT_ID, alice), &[user], None)
            .await
            .unwrap();
        env.members
            .add(key(acme, alice), &[admin], None)
            .await
            .unwrap();

        // 只有 acme 用过 → 进 acme(用过的排在从没用过的前面)
        env.members.touch_last_used(key(acme, alice)).await.unwrap();
        let outcome = env.login("alice").await;
        assert_eq!(outcome.tenant_id, Some(acme));
        assert_eq!(outcome.tenant_roles, vec!["admin".to_owned()]);
        let claims = env.claims(&outcome);
        assert_eq!(claims.tenant_id, Some(acme));
        assert_eq!(claims.tenant_roles, vec!["admin".to_owned()]);

        // 之后用过默认租户 → 下次登录进默认租户
        sleep(StdDuration::from_millis(20)).await;
        env.members
            .touch_last_used(key(DEFAULT_TENANT_ID, alice))
            .await
            .unwrap();
        let outcome = env.login("alice").await;
        assert_eq!(env.claims(&outcome).tenant_id, Some(DEFAULT_TENANT_ID));
        assert_eq!(env.claims(&outcome).tenant_roles, vec!["user".to_owned()]);

        // 登录本身记 last_used_at:进入的租户排到最前
        let memberships = env.service.my_tenants(alice).await.unwrap();
        assert_eq!(memberships[0].tenant.id, DEFAULT_TENANT_ID);
        assert!(memberships[0].last_used_at.is_some());

        // 停用的成员关系不算:默认租户里被停用 → 登录进 acme
        env.members
            .set_status(key(DEFAULT_TENANT_ID, alice), MemberStatus::Inactive, None)
            .await
            .unwrap();
        assert_eq!(env.claims(&env.login("alice").await).tenant_id, Some(acme));
    }

    /// `login_with`:验密后把平台角色 + 有效成员关系(最近用过的在前)交给消费方挑进哪里 ——
    /// 挑中的租户 → 进它(并记 last_used_at);`Platform` → 平台上下文;`None` → `Forbidden` 且不建会话;
    /// 挑了不在候选里的租户 → `Forbidden`;密码错照旧 `InvalidCredentials`,挑选函数不被调用。
    #[tokio::test]
    async fn login_with_lets_caller_choose_entry() {
        let env = new_env();
        let admin = env.tenant_role("admin").await;
        let user = env.tenant_role("user").await;
        let alice = env.account("alice").await;
        let acme = env.tenant("acme").await;
        env.members
            .add(key(DEFAULT_TENANT_ID, alice), &[user], None)
            .await
            .unwrap();
        env.members
            .add(key(acme, alice), &[admin], None)
            .await
            .unwrap();
        // 最近用过的是默认租户
        env.members.touch_last_used(key(acme, alice)).await.unwrap();
        sleep(StdDuration::from_millis(20)).await;
        env.members
            .touch_last_used(key(DEFAULT_TENANT_ID, alice))
            .await
            .unwrap();
        let input = || login_input("alice", "password123");

        // 挑「租户角色里有 admin」的第一个 → acme(跳过最近用过的默认租户)
        let outcome = env
            .service
            .login_with(input(), |candidates| {
                assert_eq!(candidates.user_id, alice);
                assert!(candidates.platform_roles.is_empty());
                let tenant_ids: Vec<Uuid> = candidates
                    .memberships
                    .iter()
                    .map(|membership| membership.tenant.id)
                    .collect();
                assert_eq!(tenant_ids, vec![DEFAULT_TENANT_ID, acme], "最近用过的在前");
                candidates
                    .memberships
                    .iter()
                    .find(|membership| membership.roles.iter().any(|role| role == "admin"))
                    .map(|membership| LoginEntry::Tenant(membership.tenant.id))
            })
            .await
            .unwrap();
        assert_eq!(outcome.tenant_id, Some(acme));
        assert_eq!(env.claims(&outcome).tenant_roles, vec!["admin".to_owned()]);
        // 进入即记 last_used_at:acme 排到最前,普通登录下次也进它
        assert_eq!(
            env.service.my_tenants(alice).await.unwrap()[0].tenant.id,
            acme
        );

        // 平台上下文
        let outcome = env
            .service
            .login_with(input(), |_| Some(LoginEntry::Platform))
            .await
            .unwrap();
        assert_eq!(outcome.tenant_id, None);
        assert!(env.claims(&outcome).tenant_roles.is_empty());

        // 拒绝 → Forbidden;挑了不在候选里的租户 → Forbidden
        let last_used_before = env.service.my_tenants(alice).await.unwrap()[0].last_used_at;
        assert!(matches!(
            env.service.login_with(input(), |_| None).await,
            Err(IdmError::Forbidden)
        ));
        assert!(matches!(
            env.service
                .login_with(input(), |_| Some(LoginEntry::Tenant(Uuid::now_v7())))
                .await,
            Err(IdmError::Forbidden)
        ));
        assert_eq!(
            env.service.my_tenants(alice).await.unwrap()[0].last_used_at,
            last_used_before,
            "被拒不记 last_used_at"
        );

        // 密码错:挑选函数不被调用
        let bad = env
            .service
            .login_with(login_input("alice", "wrong"), |_| {
                panic!("密码错不该走到挑选")
            })
            .await;
        assert!(matches!(
            bad,
            Err(IdmError::InvalidCredentials(CredentialFailure::BadPassword))
        ));
    }

    #[tokio::test]
    async fn login_without_membership_has_no_tenant() {
        let env = new_env();
        let bob = env.account("bob").await;
        let superadmin = env.role("superadmin", RoleScope::Platform).await;
        let grant = RoleGrant {
            user_id: bob,
            role_id: superadmin,
        };
        env.roles.grant(grant, None).await.unwrap();

        let outcome = env.login("bob").await;
        assert_eq!(outcome.tenant_id, None);
        assert!(outcome.tenant_roles.is_empty());
        let claims = env.claims(&outcome);
        assert_eq!(claims.tenant_id, None);
        assert!(claims.tenant_roles.is_empty());
        assert_eq!(claims.roles, vec!["superadmin".to_owned()]); // 平台角色照常
        assert!(env.service.my_tenants(bob).await.unwrap().is_empty());

        // 唯一的租户被停用 → 同样是平台上下文
        let acme = env.tenant("acme").await;
        env.members.add(key(acme, bob), &[], None).await.unwrap();
        env.tenants
            .set_status(acme, TenantStatus::Suspended, None)
            .await
            .unwrap();
        assert_eq!(env.claims(&env.login("bob").await).tenant_id, None);
    }

    #[tokio::test]
    async fn switch_tenant_reissues_with_new_tenant_roles() {
        let env = new_env();
        let admin = env.tenant_role("admin").await;
        let user = env.tenant_role("user").await;
        let alice = env.account("alice").await;
        let acme = env.tenant("acme").await;
        env.members
            .add(key(DEFAULT_TENANT_ID, alice), &[user], None)
            .await
            .unwrap();
        env.members
            .add(key(acme, alice), &[admin], None)
            .await
            .unwrap();

        // 都没用过 → 按租户 id 取第一个 = 默认租户
        let first = env.login("alice").await;
        assert_eq!(first.tenant_id, Some(DEFAULT_TENANT_ID));

        let switched = env
            .service
            .switch_tenant(&first.refresh_token, key(acme, alice))
            .await
            .unwrap_or_else(|e| panic!("switch 失败: {e:?}"));
        assert_ne!(switched.session_id, first.session_id);
        assert_eq!(switched.tenant_id, Some(acme));
        assert_eq!(switched.tenant_roles, vec!["admin".to_owned()]);
        let claims = env.claims(&switched);
        assert_eq!(claims.tenant_id, Some(acme));
        assert_eq!(claims.tenant_roles, vec!["admin".to_owned()]);

        // 旧会话已吊销
        assert!(matches!(
            env.service.refresh(&first.refresh_token).await,
            Err(IdmError::Unauthorized)
        ));
        // 新会话 refresh 留在 acme
        let refreshed = env.service.refresh(&switched.refresh_token).await.unwrap();
        assert_eq!(env.claims(&refreshed).tenant_id, Some(acme));
        // 切换记了 last_used_at → 下次登录直接进 acme
        let membership = env.members.get(key(acme, alice)).await.unwrap().unwrap();
        assert!(membership.last_used_at.is_some());
        assert_eq!(env.claims(&env.login("alice").await).tenant_id, Some(acme));
    }

    #[tokio::test]
    async fn switch_to_non_member_tenant_is_forbidden() {
        let env = new_env();
        let alice = env.account("alice").await;
        let superadmin = env.role("superadmin", RoleScope::Platform).await;
        // 平台管理员也不能切进非成员租户
        let grant = RoleGrant {
            user_id: alice,
            role_id: superadmin,
        };
        env.roles.grant(grant, None).await.unwrap();
        env.members
            .add(key(DEFAULT_TENANT_ID, alice), &[], None)
            .await
            .unwrap();
        let other = env.tenant("other").await;
        let suspended = env.tenant("susp").await;
        env.members
            .add(key(suspended, alice), &[], None)
            .await
            .unwrap();
        env.tenants
            .set_status(suspended, TenantStatus::Suspended, None)
            .await
            .unwrap();
        let inactive = env.tenant("inact").await;
        env.members
            .add(key(inactive, alice), &[], None)
            .await
            .unwrap();
        env.members
            .set_status(key(inactive, alice), MemberStatus::Inactive, None)
            .await
            .unwrap();

        let outcome = env.login("alice").await;
        assert_eq!(outcome.tenant_id, Some(DEFAULT_TENANT_ID));
        for tenant_id in [other, suspended, inactive, Uuid::now_v7()] {
            assert!(
                matches!(
                    env.service
                        .switch_tenant(&outcome.refresh_token, key(tenant_id, alice))
                        .await,
                    Err(IdmError::Forbidden)
                ),
                "切到 {tenant_id} 应 Forbidden"
            );
        }
        // 被拒不动原会话:还能 refresh,仍在默认租户
        let refreshed = env.service.refresh(&outcome.refresh_token).await.unwrap();
        assert_eq!(env.claims(&refreshed).tenant_id, Some(DEFAULT_TENANT_ID));
        // 无效 refresh → Unauthorized(不是 Forbidden)
        assert!(matches!(
            env.service
                .switch_tenant("garbage", key(DEFAULT_TENANT_ID, alice))
                .await,
            Err(IdmError::Unauthorized)
        ));
    }

    /// refresh 会话属于 A、调用方身份是 B → `Unauthorized`,A 的会话不动(不吊销、不记 last_used_at)。
    #[tokio::test]
    async fn switch_tenant_with_another_users_session_is_unauthorized() {
        let env = new_env();
        let user = env.tenant_role("user").await;
        let alice = env.account("alice").await;
        let bob = env.account("bob").await;
        let acme = env.tenant("acme").await;
        for who in [alice, bob] {
            env.members
                .add(key(DEFAULT_TENANT_ID, who), &[user], None)
                .await
                .unwrap();
            env.members
                .add(key(acme, who), &[user], None)
                .await
                .unwrap();
        }
        let alice_login = env.login("alice").await;
        assert!(matches!(
            env.service
                .switch_tenant(&alice_login.refresh_token, key(acme, bob))
                .await,
            Err(IdmError::Unauthorized)
        ));
        let membership = env.members.get(key(acme, alice)).await.unwrap().unwrap();
        assert!(membership.last_used_at.is_none());
        let refreshed = env
            .service
            .refresh(&alice_login.refresh_token)
            .await
            .unwrap();
        assert_eq!(env.claims(&refreshed).tenant_id, Some(DEFAULT_TENANT_ID));
    }

    #[tokio::test]
    async fn refresh_keeps_tenant() {
        let env = new_env();
        let admin = env.tenant_role("admin").await;
        let user = env.tenant_role("user").await;
        let alice = env.account("alice").await;
        let acme = env.tenant("acme").await;
        env.members
            .add(key(DEFAULT_TENANT_ID, alice), &[user], None)
            .await
            .unwrap();
        env.members
            .add(key(acme, alice), &[user], None)
            .await
            .unwrap();
        let first = env.login("alice").await;
        let switched = env
            .service
            .switch_tenant(&first.refresh_token, key(acme, alice))
            .await
            .unwrap();

        // 默认租户后来被"用过"也不影响:refresh 沿用会话上的租户,不重新挑
        sleep(StdDuration::from_millis(20)).await;
        env.members
            .touch_last_used(key(DEFAULT_TENANT_ID, alice))
            .await
            .unwrap();
        // 租户角色重新读:改了角色,refresh 后 token 带新角色
        env.members
            .set_roles(key(acme, alice), &[admin, user], None)
            .await
            .unwrap();
        let refreshed = env.service.refresh(&switched.refresh_token).await.unwrap();
        assert_eq!(refreshed.tenant_id, Some(acme));
        let claims = env.claims(&refreshed);
        assert_eq!(claims.tenant_id, Some(acme));
        assert_eq!(
            claims.tenant_roles,
            vec!["admin".to_owned(), "user".to_owned()]
        );

        // 平台上下文的会话 refresh 后仍是平台上下文
        env.account("bob").await;
        let bob = env.login("bob").await;
        let bob_refreshed = env.service.refresh(&bob.refresh_token).await.unwrap();
        assert_eq!(env.claims(&bob_refreshed).tenant_id, None);
    }

    #[tokio::test]
    async fn refresh_after_member_removed_is_unauthorized() {
        let env = new_env();
        let alice = env.account("alice").await;
        let acme = env.tenant("acme").await;
        // 另有一个有效租户:失败时绝不能悄悄落到它
        env.members
            .add(key(DEFAULT_TENANT_ID, alice), &[], None)
            .await
            .unwrap();
        env.members.add(key(acme, alice), &[], None).await.unwrap();
        env.members.touch_last_used(key(acme, alice)).await.unwrap();
        let outcome = env.login("alice").await;
        assert_eq!(outcome.tenant_id, Some(acme));

        env.members.remove(key(acme, alice), None).await.unwrap();
        assert!(matches!(
            env.service.refresh(&outcome.refresh_token).await,
            Err(IdmError::Unauthorized)
        ));
        // 会话已作废:再试还是 401
        assert!(matches!(
            env.service.refresh(&outcome.refresh_token).await,
            Err(IdmError::Unauthorized)
        ));

        // 成员被停用同理
        let outcome = env.login("alice").await;
        assert_eq!(outcome.tenant_id, Some(DEFAULT_TENANT_ID));
        env.members
            .set_status(key(DEFAULT_TENANT_ID, alice), MemberStatus::Inactive, None)
            .await
            .unwrap();
        assert!(matches!(
            env.service.refresh(&outcome.refresh_token).await,
            Err(IdmError::Unauthorized)
        ));
    }

    #[tokio::test]
    async fn refresh_after_tenant_suspended_is_unauthorized() {
        let env = new_env();
        let alice = env.account("alice").await;
        let acme = env.tenant("acme").await;
        env.members
            .add(key(DEFAULT_TENANT_ID, alice), &[], None)
            .await
            .unwrap();
        env.members.add(key(acme, alice), &[], None).await.unwrap();
        env.members.touch_last_used(key(acme, alice)).await.unwrap();
        let outcome = env.login("alice").await;
        assert_eq!(outcome.tenant_id, Some(acme));

        env.tenants
            .set_status(acme, TenantStatus::Suspended, None)
            .await
            .unwrap();
        assert!(matches!(
            env.service.refresh(&outcome.refresh_token).await,
            Err(IdmError::Unauthorized)
        ));

        // 软删租户同理
        env.tenants
            .set_status(acme, TenantStatus::Active, None)
            .await
            .unwrap();
        let relogin = env.login("alice").await;
        let outcome = env
            .service
            .switch_tenant(&relogin.refresh_token, key(acme, alice))
            .await
            .unwrap();
        env.tenants.soft_delete(acme, None).await.unwrap();
        assert!(matches!(
            env.service.refresh(&outcome.refresh_token).await,
            Err(IdmError::Unauthorized)
        ));
    }

    #[tokio::test]
    async fn register_joins_default_tenant_as_user() {
        let env = new_env();
        env.tenant_role("user").await;
        env.tenant_role("admin").await; // 不在 signup_roles 里,不授
        let outcome = env
            .service
            .register(register_input("alice"), None)
            .await
            .unwrap();
        assert_eq!(outcome.tenant_id, Some(DEFAULT_TENANT_ID));
        assert_eq!(outcome.tenant_roles, vec!["user".to_owned()]);
        let claims = env.claims(&outcome);
        assert_eq!(claims.tenant_id, Some(DEFAULT_TENANT_ID));
        assert_eq!(claims.tenant_roles, vec!["user".to_owned()]);
        assert!(claims.roles.is_empty()); // 租户角色不进平台角色

        let memberships = env.service.my_tenants(outcome.user.id).await.unwrap();
        assert_eq!(memberships.len(), 1);
        assert_eq!(memberships[0].tenant.id, DEFAULT_TENANT_ID);
        assert_eq!(memberships[0].roles, vec!["user".to_owned()]);

        // 自定义 signup_tenant / signup_roles
        let club_id = Uuid::from_u128(0x77);
        let env = new_env_with(|builder| {
            builder
                .signup_tenant(Some(club_id))
                .signup_roles(["member"])
        });
        let club = NewTenant {
            slug: "club",
            name: "Club",
        };
        env.tenants.upsert_fixed(club_id, club, None).await.unwrap();
        env.tenant_role("member").await;
        let outcome = env
            .service
            .register(register_input("bob"), None)
            .await
            .unwrap();
        assert_eq!(outcome.tenant_id, Some(club_id));
        assert_eq!(outcome.tenant_roles, vec!["member".to_owned()]);
    }

    #[tokio::test]
    async fn register_without_default_tenant_only_creates_account() {
        // 不配注册租户:只建账号,平台上下文
        let env = new_env_with(|builder| builder.signup_tenant(None));
        env.tenant_role("user").await;
        let outcome = env
            .service
            .register(register_input("alice"), None)
            .await
            .unwrap();
        assert_eq!(outcome.tenant_id, None);
        assert!(env.claims(&outcome).tenant_id.is_none());
        assert!(env
            .service
            .my_tenants(outcome.user.id)
            .await
            .unwrap()
            .is_empty());
        let membership = env
            .members
            .get(key(DEFAULT_TENANT_ID, outcome.user.id))
            .await;
        assert!(membership.unwrap().is_none());

        // 默认租户停用:同样只建账号(注册不失败)
        let env = new_env();
        env.tenant_role("user").await;
        env.tenants
            .set_status(DEFAULT_TENANT_ID, TenantStatus::Suspended, None)
            .await
            .unwrap();
        let outcome = env
            .service
            .register(register_input("bob"), None)
            .await
            .unwrap();
        assert_eq!(outcome.tenant_id, None);
        let membership = env
            .members
            .get(key(DEFAULT_TENANT_ID, outcome.user.id))
            .await;
        assert!(membership.unwrap().is_none());
        assert!(env.users.find_by_id(outcome.user.id).await.is_ok());

        // 默认租户已删:同样只建账号
        let env = new_env();
        env.tenant_role("user").await;
        env.tenants
            .soft_delete(DEFAULT_TENANT_ID, None)
            .await
            .unwrap();
        let outcome = env
            .service
            .register(register_input("carol"), None)
            .await
            .unwrap();
        assert_eq!(outcome.tenant_id, None);
    }

    /// 配置的注册角色不存在 → 注册响亮失败(Internal),**什么都不建**(不留没角色的成员 / 孤儿账号)。
    #[tokio::test]
    async fn register_with_missing_signup_role_fails_loudly() {
        let env = new_env(); // 默认 signup_roles = ["user"],但目录里没有 user
        let result = env.service.register(register_input("alice"), None).await;
        assert!(matches!(result, Err(IdmError::Internal(_))));
        assert!(env
            .users
            .find_by_identifier("alice")
            .await
            .unwrap()
            .is_none());
    }

    /// 注册角色只在**租户角色**里找:同名的是平台角色 → 当作不存在(Internal),绝不经注册授出平台角色。
    #[tokio::test]
    async fn register_never_grants_a_platform_role() {
        let env = new_env_with(|builder| builder.signup_roles(["superadmin"]));
        env.role("superadmin", RoleScope::Platform).await;
        let result = env.service.register(register_input("mallory"), None).await;
        assert!(matches!(result, Err(IdmError::Internal(_))));
        assert!(env
            .users
            .find_by_identifier("mallory")
            .await
            .unwrap()
            .is_none());
    }

    /// signer 拿到的身份事实带当前租户的 slug / 名称(app 进程据此回答「当前组织」,不查 idm 库);
    /// 平台上下文为空。
    #[tokio::test]
    async fn token_claims_carry_tenant_slug_and_name() {
        /// 记下每次签发拿到的 (tenant_slug, tenant_name)。
        struct Recording {
            tokens: Hs256Tokens,
            seen: Mutex<Vec<(Option<String>, Option<String>)>>,
        }

        impl TokenSigner for Recording {
            fn sign(&self, claims: &TokenClaims) -> Result<String, IdmError> {
                self.seen
                    .lock()
                    .unwrap()
                    .push((claims.tenant_slug.clone(), claims.tenant_name.clone()));
                self.tokens.sign(claims)
            }
        }

        let recording = Arc::new(Recording {
            tokens: Hs256Tokens::new("secret"),
            seen: Mutex::new(Vec::new()),
        });
        let env = new_env_with(|builder| builder.signer(Arc::clone(&recording)));
        let user = env.tenant_role("user").await;
        let alice = env.account("alice").await;
        env.account("bob").await;
        env.members
            .add(key(DEFAULT_TENANT_ID, alice), &[user], None)
            .await
            .unwrap();
        env.login("alice").await;
        env.login("bob").await; // 不是任何租户的成员 → 平台上下文
        let seen = recording.seen.lock().unwrap().clone();
        assert_eq!(
            seen,
            vec![
                (Some("default".to_owned()), Some("默认组织".to_owned())),
                (None, None)
            ]
        );
    }
}
