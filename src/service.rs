//! idm 认证业务。持 repo/hasher/token/clock 端口,编排注册/登录/发会话。
//! 范式同分层 service:依赖 trait 而非实现,在此做归一/编排/审计下传。
//! **入参是领域结构(`input` 模块),已由 app 在 HTTP 边界校验完**;审计主体经 `by: Option<String>` 传。
//!
//! **多租户**(成员仓储是必填端口,没有关闭开关):会话 / access token 带**一个当前租户**。登录进
//! `last_used_at` 最近的有效成员关系(没有 → 平台上下文,`tenant_id = None`);refresh 沿用会话上的租户并
//! 重新校验成员关系与租户状态(失效 → `Unauthorized`,绝不落到别的租户);`switch_tenant` 换租户(非有效成员
//! → `Forbidden`);注册在同一事务里加入 `signup_tenant`。

use std::sync::Arc;

use time::Duration;
use uuid::Uuid;

use super::clock::{Clock, SystemClock};
use super::input::{ChangePasswordInput, LoginInput, RegisterInput, UpdateMeInput};
use super::repo::{MemberRepo, RoleRepo, Session, SessionRepo, User, UserRepo};
use super::tenant::{MemberStatus, Membership, RoleScope, TenantStatus, DEFAULT_TENANT_ID};
use super::token::{self, Hs256Tokens, TokenClaims, TokenSigner, TokenVerifier};
use super::{Argon2Hasher, PwHasher};
use crate::error::{CredentialFailure, IdmError};
use crate::identity::AuthUser;

/// 用户读模型(域投影):`User` 实体 + 角色名。`me`/`update_me`/`AuthOutcome.user` 的返回。
/// app 把它映射成自己的对外响应 DTO(审计字段不在此)。
#[derive(Clone, Debug)]
pub struct UserView {
    pub id: Uuid,
    pub username: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub roles: Vec<String>,
}

/// 认证结果(**纯数据**):用户视图 + 待写进 cookie 的 token + cookie max-age(秒)。
/// app 把 token 写进 httponly `Set-Cookie`、body 返 `user`;token 不进响应体。
/// **刻意不派生 `Debug`**:持 access/refresh token 明文,Debug 会把密钥打进日志/panic 输出。
pub struct AuthOutcome {
    pub user: UserView,
    /// 本次登录/注册/刷新所建会话的 id(= `sessions.id` = JWT `jti`)。审计/设备管理用。
    pub session_id: Uuid,
    pub access_token: String,
    pub refresh_token: String,
    pub access_max_age_secs: i64,
    pub refresh_max_age_secs: i64,
    /// 本次会话所在租户(= token 的 `tenant_id` claim);`None` = 平台上下文。
    pub tenant_id: Option<Uuid>,
    /// 本次会话在当前租户内的角色(= token 的 `tenant_roles` claim)。`user.roles` 是平台角色。
    pub tenant_roles: Vec<String>,
}

/// 登录进哪里(消费方按自己的授权规则挑,见 [`AuthService::login_with`])。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoginEntry {
    /// 进这个租户:必须是候选里的有效成员关系之一,否则 `Forbidden`。
    Tenant(Uuid),
    /// 平台上下文(不带租户,只有平台角色)。
    Platform,
}

/// 验密通过后交给挑选函数的材料:账号、平台角色、有效成员关系(租户 active + 成员 active,
/// `last_used_at` 最近的在前,同 [`AuthService::my_tenants`])。
#[derive(Debug)]
pub struct LoginCandidates<'a> {
    pub user_id: Uuid,
    pub platform_roles: &'a [String],
    pub memberships: &'a [Membership],
}

/// 认证服务。`Clone` 廉价(全是 Arc),app 直接持有它(放进 `AppState`)。
#[derive(Clone)]
pub struct AuthService {
    inner: Arc<Inner>,
}

struct Inner {
    users: Arc<dyn UserRepo>,
    sessions: Arc<dyn SessionRepo>,
    roles: Arc<dyn RoleRepo>,
    members: Arc<dyn MemberRepo>,
    signup_tenant: Option<Uuid>,
    signup_roles: Vec<String>,
    hasher: Arc<dyn PwHasher>,
    signer: Arc<dyn TokenSigner>,
    verifier: Arc<dyn TokenVerifier>,
    clock: Arc<dyn Clock>,
    access_ttl_secs: i64,
    refresh_ttl_secs: i64,
}

/// 默认的注册租户角色。
const DEFAULT_SIGNUP_ROLE: &str = "user";

/// 默认 access token TTL(秒):15 分钟。
const DEFAULT_ACCESS_TTL_SECS: i64 = 900;
/// 默认 refresh token TTL(秒):7 天。
const DEFAULT_REFRESH_TTL_SECS: i64 = 604_800;

impl AuthService {
    /// **便捷构造**:HS256 对称密钥 + 系统时钟 + Argon2 + 默认 claims(覆盖绝大多数场景,行为同历史)。
    /// 只想 override 个别端口(自定义 claims/RS256/测试时钟/FakeHasher)→ 用 [`AuthService::builder`]。
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        users: Arc<dyn UserRepo>,
        sessions: Arc<dyn SessionRepo>,
        roles: Arc<dyn RoleRepo>,
        members: Arc<dyn MemberRepo>,
        hasher: Arc<dyn PwHasher>,
        jwt_secret: &str,
        access_ttl_secs: i64,
        refresh_ttl_secs: i64,
    ) -> Self {
        Self::builder(users, sessions, roles, members)
            .hasher(hasher)
            .hs256_secret(jwt_secret)
            .access_ttl_secs(access_ttl_secs)
            .refresh_ttl_secs(refresh_ttl_secs)
            .build()
    }

    /// **builder**:只设要 override 的端口,其余取默认(Argon2 / SystemClock / TTL 900·604800)。
    /// 仅 repos 无默认须显式传(含成员仓储 `members`:多租户恒开,没有"不启用租户"的降级);签验端口无安全默认 —— 必须经 `hs256_secret` 或 `signer`+`verifier` 给出,
    /// 否则 `build` panic(wiring 错误,启动期即暴露)。
    pub fn builder(
        users: Arc<dyn UserRepo>,
        sessions: Arc<dyn SessionRepo>,
        roles: Arc<dyn RoleRepo>,
        members: Arc<dyn MemberRepo>,
    ) -> AuthServiceBuilder {
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
            clock: Arc::new(SystemClock),
            access_ttl_secs: DEFAULT_ACCESS_TTL_SECS,
            refresh_ttl_secs: DEFAULT_REFRESH_TTL_SECS,
        }
    }

    /// 注册:归一 username/email → hash 密码 → 建账号 → 发会话。`by` = 审计主体。
    /// 配了 `signup_tenant`(默认)时,**同一事务**里把账号加入该租户(存活且 active 才加)并授
    /// `signup_roles`(必须都是存活的租户角色,否则 `Internal`,什么都不建);随后像登录一样进入它。
    pub async fn register(
        &self,
        input: RegisterInput,
        by: Option<String>,
    ) -> Result<AuthOutcome, IdmError> {
        let username = normalize(&input.username);
        let email = input.email.as_deref().map(normalize);
        let hash = self.hash_password(input.password).await?;
        let user = match self.inner.signup_tenant {
            Some(tenant_id) => {
                let role_ids = self.signup_role_ids().await?;
                self.inner
                    .users
                    .create_with_membership(
                        &username,
                        email.as_deref(),
                        &hash,
                        tenant_id,
                        &role_ids,
                        by.clone(),
                    )
                    .await?
            }
            None => {
                self.inner
                    .users
                    .create(&username, email.as_deref(), &hash, by.clone())
                    .await?
            }
        };
        let tenant = self.enter_default_tenant(user.id).await?;
        self.issue_session(&user, tenant.as_ref(), by).await
    }

    /// 登录:查用户(identifier=username 或 email)→ 验密 → 进 `last_used_at` 最近的有效租户(没有 → 平台上下文)
    /// → 发会话。
    /// 失败原因**仅供审计**(`CredentialFailure`);HTTP 401 收口由消费方 app 统一(防枚举)。
    pub async fn login(&self, input: LoginInput) -> Result<AuthOutcome, IdmError> {
        let user = self.check_credentials(input).await?;
        let tenant = self.enter_default_tenant(user.id).await?;
        self.issue_session(&user, tenant.as_ref(), None).await
    }

    /// 登录,但**进哪里由消费方挑**(如后台登录:挑第一个有后台权限的租户,没有再看平台权限)。
    /// 验密(失败同 [`Self::login`])→ 把平台角色 + 有效成员关系交给 `choose` →
    /// `Some(Tenant(id))` 进该租户并记 `last_used_at`;`Some(Platform)` 进平台上下文;
    /// `None` → `Forbidden`,**不建会话、不记 last_used_at**。挑了不在候选里的租户,或刚好被并发移出 → `Forbidden`
    /// (不像 `login` 那样退回平台上下文:消费方挑租户是有授权含义的,不能悄悄换成别的上下文)。
    /// 授权规则(哪个角色给后台权限)在消费方,本库不认识权限。
    pub async fn login_with<F>(&self, input: LoginInput, choose: F) -> Result<AuthOutcome, IdmError>
    where
        F: FnOnce(&LoginCandidates<'_>) -> Option<LoginEntry>,
    {
        let user = self.check_credentials(input).await?;
        let platform_roles = self.inner.roles.roles_for_user(user.id).await?;
        let memberships = self.inner.members.memberships_for_user(user.id).await?;
        let entry = choose(&LoginCandidates {
            user_id: user.id,
            platform_roles: &platform_roles,
            memberships: &memberships,
        })
        .ok_or(IdmError::Forbidden)?;
        let tenant = match entry {
            LoginEntry::Platform => None,
            LoginEntry::Tenant(tenant_id) => {
                let m = memberships
                    .iter()
                    .find(|m| m.tenant.id == tenant_id)
                    .ok_or(IdmError::Forbidden)?;
                match self.inner.members.touch_last_used(tenant_id, user.id).await {
                    Err(IdmError::NotFound) => return Err(IdmError::Forbidden),
                    other => other?,
                }
                Some(m)
            }
        };
        self.issue_session(&user, tenant, None).await
    }

    /// 查用户(identifier = username 或 email)→ 验密。失败原因只供审计(见 [`CredentialFailure`])。
    async fn check_credentials(&self, input: LoginInput) -> Result<User, IdmError> {
        let identifier = normalize(&input.identifier);
        let Some(found) = self.inner.users.find_by_identifier(&identifier).await? else {
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

    /// 验 access token → 已认证身份(平台角色 + 当前租户 + 租户角色)。失败 → `Unauthorized`。
    pub fn authenticate_token(&self, token: &str) -> Result<AuthUser, IdmError> {
        let v = self.inner.verifier.verify(token)?;
        Ok(AuthUser {
            id: v.user_id,
            username: v.username,
            roles: v.roles,
            tenant_id: v.tenant_id,
            tenant_roles: v.tenant_roles,
        })
    }

    /// 当前用户资料(GET /me):查存活用户 + 角色 → `UserView`。已软删 → `NotFound`。
    pub async fn me(&self, user_id: Uuid) -> Result<UserView, IdmError> {
        let user = self.inner.users.find_by_id(user_id).await?;
        let roles = self.inner.roles.roles_for_user(user_id).await?;
        Ok(to_view(&user, roles))
    }

    /// 刷新:验 refresh hash → 轮换(撤旧 session、发新会话)。无效/过期/已撤销 → `Unauthorized`。
    /// **沿用会话上的租户**,重新读成员关系和租户角色;成员被移出 / 停用、租户停用 / 删除 → `Unauthorized`
    /// (旧会话照样作废,绝不悄悄落到别的租户)。平台上下文的会话刷新后仍是平台上下文。
    pub async fn refresh(&self, refresh_token: &str) -> Result<AuthOutcome, IdmError> {
        let session = self.active_session(refresh_token).await?;
        // 轮换:旧 refresh 一次性,撤销后发新会话(防 refresh 重放)。先撤:后面任何一步失败旧会话都已作废。
        self.inner.sessions.revoke(session.id).await?;
        let user = self.inner.users.find_by_id(session.user_id).await?;
        let tenant = match session.tenant_id {
            None => None,
            Some(tenant_id) => Some(
                self.active_membership(tenant_id, user.id)
                    .await?
                    .ok_or(IdmError::Unauthorized)?,
            ),
        };
        self.issue_session(&user, tenant.as_ref(), None).await
    }

    /// 切换当前租户:凭 refresh token 认会话 → 校验在目标租户是**有效成员**(成员 active + 租户 active)
    /// → 吊销旧会话 → 建带新租户的会话 → 记 `last_used_at`(下次登录默认进它)。
    /// refresh 无效 → `Unauthorized`;不是有效成员(含平台管理员切进自己不是成员的租户)→ `Forbidden`,
    /// 原会话不动。
    ///
    /// `user_id` = 调用方已认证的当前身份(消费方从 access token 取)。refresh 会话不属于他 → `Unauthorized`,
    /// 原会话不动:防止拿别人的 refresh cookie(会话固定 / 偷来的 cookie)借当前登录身份去切换别人的会话。
    pub async fn switch_tenant(
        &self,
        refresh_token: &str,
        user_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<AuthOutcome, IdmError> {
        let session = self.active_session(refresh_token).await?;
        if session.user_id != user_id {
            return Err(IdmError::Unauthorized);
        }
        let membership = self
            .active_membership(tenant_id, session.user_id)
            .await?
            .ok_or(IdmError::Forbidden)?;
        let user = self.inner.users.find_by_id(session.user_id).await?;
        // 先记 last_used_at 再吊销:刚好被并发移出(NotFound)→ Forbidden,原会话不动。
        match self.inner.members.touch_last_used(tenant_id, user.id).await {
            Err(IdmError::NotFound) => return Err(IdmError::Forbidden),
            other => other?,
        }
        self.inner.sessions.revoke(session.id).await?;
        self.issue_session(&user, Some(&membership), None).await
    }

    /// 当前账号的有效成员关系(租户 active + 成员 active),`last_used_at` 最近的在前。
    pub async fn my_tenants(&self, user_id: Uuid) -> Result<Vec<Membership>, IdmError> {
        self.inner.members.memberships_for_user(user_id).await
    }

    /// 登出:撤销该 refresh 对应的会话,返回被撤会话(含 `user_id`,审计用)。幂等(找不到活跃会话 → `None`)。
    pub async fn logout(&self, refresh_token: &str) -> Result<Option<Session>, IdmError> {
        let hash = token::hash_refresh(refresh_token);
        if let Some(session) = self
            .inner
            .sessions
            .find_active(&hash, self.inner.clock.now())
            .await?
        {
            self.inner.sessions.revoke(session.id).await?;
            return Ok(Some(session));
        }
        Ok(None)
    }

    /// 登出所有设备:撤销用户全部活跃会话。
    pub async fn logout_all(&self, user_id: Uuid) -> Result<(), IdmError> {
        self.inner.sessions.revoke_all(user_id, None).await
    }

    /// 改资料(PUT /me,**全量替换**):username 必填,email 给值=设/给空=清空。替换 email 会重置 email_verified。
    /// `by` = 审计主体(updated_by)。
    pub async fn update_me(
        &self,
        user_id: Uuid,
        input: UpdateMeInput,
        by: Option<String>,
    ) -> Result<UserView, IdmError> {
        let username = normalize(&input.username);
        let email = input.email.as_deref().map(normalize);
        let user = self
            .inner
            .users
            .update(user_id, &username, email.as_deref(), by)
            .await?;
        let roles = self.inner.roles.roles_for_user(user_id).await?;
        Ok(to_view(&user, roles))
    }

    /// 注销(DELETE /me):验密 → 撤销所有会话 → 软删账户。密码错 → `Unauthorized`。`by` = 审计主体。
    pub async fn delete_me(
        &self,
        user_id: Uuid,
        password: String,
        by: Option<String>,
    ) -> Result<(), IdmError> {
        let hash = self
            .inner
            .users
            .password_hash(user_id)
            .await?
            .ok_or(IdmError::Unauthorized)?;
        if !self.verify_password(password, hash).await? {
            return Err(IdmError::Unauthorized);
        }
        self.inner.sessions.revoke_all(user_id, None).await?;
        self.inner.users.soft_delete(user_id, by).await
    }

    /// 改密(POST /me/password):验旧密码 → 换 hash → 撤销所有会话(强制重登录)。旧密码错 → `Unauthorized`。
    pub async fn change_password(
        &self,
        user_id: Uuid,
        input: ChangePasswordInput,
    ) -> Result<(), IdmError> {
        let hash = self
            .inner
            .users
            .password_hash(user_id)
            .await?
            .ok_or(IdmError::Unauthorized)?;
        if !self.verify_password(input.current_password, hash).await? {
            return Err(IdmError::Unauthorized);
        }
        let new_hash = self.hash_password(input.new_password).await?;
        self.inner.users.update_password(user_id, &new_hash).await?;
        self.inner.sessions.revoke_all(user_id, None).await?;
        Ok(())
    }

    /// 按 refresh token 找活跃会话;无效 / 过期 / 已撤销 → `Unauthorized`。
    async fn active_session(&self, refresh_token: &str) -> Result<Session, IdmError> {
        let hash = token::hash_refresh(refresh_token);
        self.inner
            .sessions
            .find_active(&hash, self.inner.clock.now())
            .await?
            .ok_or(IdmError::Unauthorized)
    }

    /// 在该租户的**有效**成员关系(成员 active + 租户 active 且未删);否则 `None`。
    async fn active_membership(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<Membership>, IdmError> {
        Ok(self
            .inner
            .members
            .get(tenant_id, user_id)
            .await?
            .filter(|m| {
                m.status == MemberStatus::Active && m.tenant.status == TenantStatus::Active
            }))
    }

    /// 登录 / 注册时进入的租户:有效成员关系里 `last_used_at` 最近的那个(并记一次 last_used_at);
    /// 没有 → `None`(平台上下文)。
    async fn enter_default_tenant(&self, user_id: Uuid) -> Result<Option<Membership>, IdmError> {
        let members = &self.inner.members;
        let Some(m) = members
            .memberships_for_user(user_id)
            .await?
            .into_iter()
            .next()
        else {
            return Ok(None);
        };
        match members.touch_last_used(m.tenant.id, user_id).await {
            Ok(()) => Ok(Some(m)),
            // 刚好被并发移出 / 租户刚被删:按平台上下文进,不让登录失败
            Err(IdmError::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// `signup_roles` 的角色名 → id,**只在租户角色里找**(`scope = tenant`;注册是加入租户,平台角色
    /// 绝不能经注册授出)。配置的名字找不到(没 seed、或同名的是平台角色)→ `Internal` 并记 error 日志:
    /// 这是装配 / 数据错误,注册必须响亮失败,不能悄悄建一个没有角色的成员。
    async fn signup_role_ids(&self) -> Result<Vec<Uuid>, IdmError> {
        if self.inner.signup_roles.is_empty() {
            return Ok(Vec::new());
        }
        let catalog = self.inner.roles.list().await?;
        self.inner
            .signup_roles
            .iter()
            .map(|name| {
                catalog
                    .iter()
                    .find(|r| &r.name == name && r.scope == RoleScope::Tenant)
                    .map(|r| r.id)
                    .ok_or_else(|| {
                        tracing::error!(role = %name, "注册角色不是存活的租户角色(没 seed?作用域不对?)");
                        IdmError::Internal(anyhow::anyhow!(
                            "注册角色 {name} 不存在或不是租户角色"
                        ))
                    })
            })
            .collect()
    }

    /// 发会话:查平台角色 → 生成 refresh + 建会话(带租户)→ 经 signer 签 access token(claim 形状由 signer
    /// 决定),组 `AuthOutcome`。`tenant` = 当前租户的成员关系(`None` = 平台上下文)。
    async fn issue_session(
        &self,
        user: &User,
        tenant: Option<&Membership>,
        by: Option<String>,
    ) -> Result<AuthOutcome, IdmError> {
        let now = self.inner.clock.now();
        let roles = self.inner.roles.roles_for_user(user.id).await?;
        let tenant_id = tenant.map(|m| m.tenant.id);
        let tenant_roles = tenant.map(|m| m.roles.clone()).unwrap_or_default();
        let (refresh, refresh_hash) = token::generate_refresh();
        let refresh_expires_at = now + Duration::seconds(self.inner.refresh_ttl_secs);
        let session = self
            .inner
            .sessions
            .create(user.id, tenant_id, &refresh_hash, refresh_expires_at, by)
            .await?;
        let claims = TokenClaims {
            user_id: user.id,
            session_id: session.id,
            username: user.username.clone(),
            email: user.email.clone(),
            email_verified: user.email_verified,
            roles: roles.clone(),
            tenant_id,
            tenant_roles: tenant_roles.clone(),
            tenant_slug: tenant.map(|m| m.tenant.slug.clone()),
            tenant_name: tenant.map(|m| m.tenant.name.clone()),
            issued_at: now,
            expires_at: now + Duration::seconds(self.inner.access_ttl_secs),
        };
        let access = self.inner.signer.sign(&claims)?;
        Ok(AuthOutcome {
            user: to_view(user, roles),
            session_id: session.id,
            access_token: access,
            refresh_token: refresh,
            access_max_age_secs: self.inner.access_ttl_secs,
            refresh_max_age_secs: self.inner.refresh_ttl_secs,
            tenant_id,
            tenant_roles,
        })
    }

    /// argon2 hash 是 CPU 密集 → `spawn_blocking`,不阻塞 tokio worker 线程。
    async fn hash_password(&self, plain: String) -> Result<String, IdmError> {
        let hasher = self.inner.hasher.clone();
        tokio::task::spawn_blocking(move || hasher.hash(&plain))
            .await
            .map_err(|e| IdmError::Internal(anyhow::anyhow!("hash 任务异常: {e}")))?
    }

    async fn verify_password(&self, plain: String, phc: String) -> Result<bool, IdmError> {
        let hasher = self.inner.hasher.clone();
        tokio::task::spawn_blocking(move || hasher.verify(&plain, &phc))
            .await
            .map_err(|e| IdmError::Internal(anyhow::anyhow!("verify 任务异常: {e}")))?
    }
}

/// [`AuthService`] 的 builder —— 只设要 override 的端口,其余取默认。见 [`AuthService::builder`]。
/// 默认:`hasher`=Argon2、`clock`=SystemClock、TTL=900/604800;签验端口无默认(`build` 前必设)。
pub struct AuthServiceBuilder {
    users: Arc<dyn UserRepo>,
    sessions: Arc<dyn SessionRepo>,
    roles: Arc<dyn RoleRepo>,
    members: Arc<dyn MemberRepo>,
    signup_tenant: Option<Uuid>,
    signup_roles: Vec<String>,
    hasher: Arc<dyn PwHasher>,
    signer: Option<Arc<dyn TokenSigner>>,
    verifier: Option<Arc<dyn TokenVerifier>>,
    clock: Arc<dyn Clock>,
    access_ttl_secs: i64,
    refresh_ttl_secs: i64,
}

impl AuthServiceBuilder {
    /// 用 HS256 对称密钥设默认签验端口(同 `new` 的默认)。与 `signer`/`verifier` 二选一。
    pub fn hs256_secret(mut self, secret: &str) -> Self {
        let tokens = Arc::new(Hs256Tokens::new(secret));
        self.signer = Some(tokens.clone());
        self.verifier = Some(tokens);
        self
    }

    /// 自定义签发端口(RS256/KMS/自定义 claims)。分进程 idm 侧持私钥用。
    pub fn signer(mut self, signer: Arc<dyn TokenSigner>) -> Self {
        self.signer = Some(signer);
        self
    }

    /// 自定义验证端口(只验不签 —— app 侧最小权限,持公钥)。
    pub fn verifier(mut self, verifier: Arc<dyn TokenVerifier>) -> Self {
        self.verifier = Some(verifier);
        self
    }

    /// 公开注册加入的租户(默认 `Some(DEFAULT_TENANT_ID)`)。`None` = 注册只建账号。
    /// 该租户不存在 / 已删 / 停用时同样只建账号。
    pub fn signup_tenant(mut self, tenant_id: Option<Uuid>) -> Self {
        self.signup_tenant = tenant_id;
        self
    }

    /// 注册时在 `signup_tenant` 里授的租户角色名(默认 `["user"]`)。每个名字都必须是存活的**租户角色**,
    /// 否则注册返回 `Internal`(装配错误要响亮);不想授角色就传空 `Vec`。
    pub fn signup_roles(mut self, roles: Vec<String>) -> Self {
        self.signup_roles = roles;
        self
    }

    /// 替换密码哈希端口(默认 `Argon2Hasher`;测试用 `FakeHasher`)。
    pub fn hasher(mut self, hasher: Arc<dyn PwHasher>) -> Self {
        self.hasher = hasher;
        self
    }

    /// 替换时间端口(默认 `SystemClock`;测试注入固定时钟可确定性测过期/轮换)。
    pub fn clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// access token TTL(秒,默认 900)。
    pub fn access_ttl_secs(mut self, secs: i64) -> Self {
        self.access_ttl_secs = secs;
        self
    }

    /// refresh token TTL(秒,默认 604800)。
    pub fn refresh_ttl_secs(mut self, secs: i64) -> Self {
        self.refresh_ttl_secs = secs;
        self
    }

    /// 组装。未经 `hs256_secret` / `signer`+`verifier` 设签验端口 → panic(wiring 错误,启动期即暴露)。
    pub fn build(self) -> AuthService {
        let signer = self
            .signer
            .expect("AuthServiceBuilder::build: 须先调 hs256_secret 或 signer 设签发端口");
        let verifier = self
            .verifier
            .expect("AuthServiceBuilder::build: 须先调 hs256_secret 或 verifier 设验证端口");
        AuthService {
            inner: Arc::new(Inner {
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
                access_ttl_secs: self.access_ttl_secs,
                refresh_ttl_secs: self.refresh_ttl_secs,
            }),
        }
    }
}

fn to_view(user: &User, roles: Vec<String>) -> UserView {
    UserView {
        id: user.id,
        username: user.username.clone(),
        email: user.email.clone(),
        email_verified: user.email_verified,
        roles,
    }
}

/// 标识符归一:去空白 + 转小写(配合 username/email 存活唯一索引,避免大小写绕过唯一)。
fn normalize(s: &str) -> String {
    s.trim().to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::AuthService;
    use crate::clock::Clock;
    use crate::error::IdmError;
    use crate::input::RegisterInput;
    use crate::password::FakeHasher;
    use crate::repo::{
        InMemoryMemberRepo, InMemoryRoleRepo, InMemorySessionRepo, InMemoryUserRepo,
    };
    use std::sync::{Arc, Mutex};
    use time::{Duration, OffsetDateTime};

    /// 签验端口无默认:builder 未设就 build → panic(wiring 错误启动期即暴露,不会静默跑出无法验签的服务)。
    #[test]
    #[should_panic(expected = "hs256_secret")]
    fn builder_without_token_ports_panics() {
        let _ = AuthService::builder(
            Arc::new(InMemoryUserRepo::new()),
            Arc::new(InMemorySessionRepo::new()),
            Arc::new(InMemoryRoleRepo::new()),
            Arc::new(InMemoryMemberRepo::new()),
        )
        .build();
    }

    /// 可变测试时钟:证明注入的 `Clock` 真的驱动会话过期(③ Clock 端口的存在理由)。
    struct TestClock(Mutex<OffsetDateTime>);
    impl Clock for TestClock {
        fn now(&self) -> OffsetDateTime {
            *self.0.lock().unwrap()
        }
    }

    fn register_input(username: &str) -> RegisterInput {
        RegisterInput {
            username: username.into(),
            email: None,
            password: "password123".into(),
        }
    }

    /// 注入固定时钟 → 会话过期由它**确定性**控制:未过期可 refresh,把时钟推过 `refresh_ttl` 后
    /// 同一 refresh → 401。这正是 Clock 端口的价值:不 sleep 真实时间也能测过期/轮换。
    /// (refresh 只查 session repo 比对 `now` vs `expires_at`,纯由注入时钟决定,不碰真实时钟。)
    #[tokio::test]
    async fn injected_clock_drives_session_expiry() {
        let t0 = OffsetDateTime::UNIX_EPOCH + Duration::days(20_000); // 固定,与真实时钟无关
        let clock = Arc::new(TestClock(Mutex::new(t0)));
        let svc = AuthService::builder(
            Arc::new(InMemoryUserRepo::new()),
            Arc::new(InMemorySessionRepo::new()),
            Arc::new(InMemoryRoleRepo::new()),
            Arc::new(InMemoryMemberRepo::new()),
        )
        .hs256_secret("secret")
        .hasher(Arc::new(FakeHasher))
        // 独立的空角色仓储:注册不授租户角色(配了不存在的角色会响亮失败)
        .signup_roles(Vec::new())
        .clock(clock.clone())
        .refresh_ttl_secs(100)
        .build();

        // 用户 A:t0 注册(会话 expires=t0+100),t0 刷新 → 活跃(now < expires)。
        let a = svc.register(register_input("alice"), None).await.unwrap();
        assert!(
            svc.refresh(&a.refresh_token).await.is_ok(),
            "未过期会话应可 refresh"
        );

        // 用户 B:t0 注册,把时钟推到 ttl 之后 → 会话过期 → 同一 refresh 报 401(纯由注入时钟决定)。
        let b = svc.register(register_input("bob"), None).await.unwrap();
        *clock.0.lock().unwrap() = t0 + Duration::seconds(101);
        assert!(
            matches!(
                svc.refresh(&b.refresh_token).await,
                Err(IdmError::Unauthorized)
            ),
            "时钟越过 refresh_ttl 后会话应过期 → 401"
        );
    }

    #[tokio::test]
    async fn login_reports_distinct_failure_reasons() {
        use crate::error::CredentialFailure;
        use crate::input::LoginInput;

        let svc = AuthService::builder(
            Arc::new(InMemoryUserRepo::new()),
            Arc::new(InMemorySessionRepo::new()),
            Arc::new(InMemoryRoleRepo::new()),
            Arc::new(InMemoryMemberRepo::new()),
        )
        .hs256_secret("secret")
        .hasher(Arc::new(FakeHasher))
        // 独立的空角色仓储:注册不授租户角色(配了不存在的角色会响亮失败)
        .signup_roles(Vec::new())
        .build();
        svc.register(register_input("alice"), None).await.unwrap();

        // 未知用户。用 matches! 匹配整个 Result(纯模式匹配,不需 AuthOutcome: Debug —
        // 该类型持 token 明文,故意不派生 Debug;不能用 .unwrap_err() 逼它派生)。
        let unknown = svc
            .login(LoginInput {
                identifier: "ghost".into(),
                password: "password123".into(),
            })
            .await;
        assert!(
            matches!(
                unknown,
                Err(IdmError::InvalidCredentials(CredentialFailure::UnknownUser))
            ),
            "查无此人应为 UnknownUser"
        );

        // 密码错(alice 存在,密码非 password123)
        let bad = svc
            .login(LoginInput {
                identifier: "alice".into(),
                password: "wrong".into(),
            })
            .await;
        assert!(
            matches!(
                bad,
                Err(IdmError::InvalidCredentials(CredentialFailure::BadPassword))
            ),
            "密码不匹配应为 BadPassword"
        );
    }

    #[tokio::test]
    async fn auth_outcome_exposes_rotating_session_id() {
        let svc = AuthService::builder(
            Arc::new(InMemoryUserRepo::new()),
            Arc::new(InMemorySessionRepo::new()),
            Arc::new(InMemoryRoleRepo::new()),
            Arc::new(InMemoryMemberRepo::new()),
        )
        .hs256_secret("secret")
        .hasher(Arc::new(FakeHasher))
        // 独立的空角色仓储:注册不授租户角色(配了不存在的角色会响亮失败)
        .signup_roles(Vec::new())
        .build();

        let reg = svc.register(register_input("alice"), None).await.unwrap();
        assert!(!reg.session_id.is_nil(), "注册应带非空 session_id");

        // 刷新轮换 → 新会话,session_id 必不同。
        let refreshed = svc.refresh(&reg.refresh_token).await.unwrap();
        assert_ne!(
            reg.session_id, refreshed.session_id,
            "refresh 轮换后应是新的 session_id"
        );
    }

    #[tokio::test]
    async fn logout_returns_revoked_session_id_then_none() {
        let svc = AuthService::builder(
            Arc::new(InMemoryUserRepo::new()),
            Arc::new(InMemorySessionRepo::new()),
            Arc::new(InMemoryRoleRepo::new()),
            Arc::new(InMemoryMemberRepo::new()),
        )
        .hs256_secret("secret")
        .hasher(Arc::new(FakeHasher))
        // 独立的空角色仓储:注册不授租户角色(配了不存在的角色会响亮失败)
        .signup_roles(Vec::new())
        .build();

        let reg = svc.register(register_input("alice"), None).await.unwrap();
        let revoked = svc.logout(&reg.refresh_token).await.unwrap();
        assert!(
            matches!(revoked, Some(ref session) if session.id == reg.session_id),
            "登出应返回被撤会话,且 id 匹配"
        );

        // 幂等:同一 token 再登出 → 无活跃会话 → None。
        assert!(svc.logout(&reg.refresh_token).await.unwrap().is_none());
    }
    // ── 多租户:登录选租户 / 切换 / refresh 沿用租户 / 注册加入默认租户 ──

    use crate::input::LoginInput;
    use crate::repo::{InMemoryTenantRepo, MemberRepo, RoleRepo, TenantRepo, UserRepo};
    use crate::tenant::{MemberStatus, RoleScope, TenantStatus, DEFAULT_TENANT_ID};
    use uuid::Uuid;

    /// 一套共享存储的内存仓储 + 接好成员仓储的 AuthService(租户模式)。
    struct Env {
        svc: AuthService,
        users: Arc<InMemoryUserRepo>,
        roles: Arc<InMemoryRoleRepo>,
        tenants: Arc<InMemoryTenantRepo>,
        members: Arc<InMemoryMemberRepo>,
    }

    fn env_with(f: impl FnOnce(super::AuthServiceBuilder) -> super::AuthServiceBuilder) -> Env {
        let users = InMemoryUserRepo::new();
        let roles = Arc::new(InMemoryRoleRepo::sharing_with(&users));
        let tenants = Arc::new(InMemoryTenantRepo::sharing_with(&users));
        let members = Arc::new(InMemoryMemberRepo::sharing_with(&users));
        let sessions = Arc::new(InMemorySessionRepo::sharing_with(&users));
        let users = Arc::new(users);
        let builder = AuthService::builder(users.clone(), sessions, roles.clone(), members.clone())
            .hs256_secret("secret")
            .hasher(Arc::new(FakeHasher));
        Env {
            svc: f(builder).build(),
            users,
            roles,
            tenants,
            members,
        }
    }

    fn env() -> Env {
        env_with(|b| b)
    }

    impl Env {
        /// 直接经仓储建账号(不走 register → 不自动加入任何租户)。hash 按 FakeHasher 的格式写。
        async fn account(&self, name: &str) -> Uuid {
            self.users
                .create(name, None, "fake$password123", None)
                .await
                .unwrap()
                .id
        }

        async fn tenant_role(&self, name: &str) -> Uuid {
            self.roles
                .upsert(name, name, RoleScope::Tenant, None)
                .await
                .unwrap()
        }

        async fn login(&self, name: &str) -> super::AuthOutcome {
            self.svc
                .login(LoginInput {
                    identifier: name.into(),
                    password: "password123".into(),
                })
                .await
                .unwrap_or_else(|e| panic!("login {name} 失败: {e:?}"))
        }

        /// access token 验出来的身份(tenant claim 以 token 为准,不只看 AuthOutcome)。
        fn claims(&self, out: &super::AuthOutcome) -> crate::identity::AuthUser {
            self.svc.authenticate_token(&out.access_token).unwrap()
        }
    }

    #[tokio::test]
    async fn login_picks_last_used_tenant() {
        let e = env();
        let admin = e.tenant_role("admin").await;
        let user = e.tenant_role("user").await;
        let alice = e.account("alice").await;
        let acme = e.tenants.create("acme", "Acme", None).await.unwrap();
        e.members
            .add(DEFAULT_TENANT_ID, alice, &[user], None)
            .await
            .unwrap();
        e.members.add(acme.id, alice, &[admin], None).await.unwrap();

        // 只有 acme 用过 → 进 acme(用过的排在从没用过的前面)
        e.members.touch_last_used(acme.id, alice).await.unwrap();
        let out = e.login("alice").await;
        assert_eq!(out.tenant_id, Some(acme.id));
        assert_eq!(out.tenant_roles, vec!["admin".to_string()]);
        let c = e.claims(&out);
        assert_eq!(c.tenant_id, Some(acme.id));
        assert_eq!(c.tenant_roles, vec!["admin".to_string()]);

        // 之后用过默认租户 → 下次登录进默认租户
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        e.members
            .touch_last_used(DEFAULT_TENANT_ID, alice)
            .await
            .unwrap();
        let out = e.login("alice").await;
        assert_eq!(e.claims(&out).tenant_id, Some(DEFAULT_TENANT_ID));
        assert_eq!(e.claims(&out).tenant_roles, vec!["user".to_string()]);

        // 登录本身记 last_used_at:进入的租户排到最前
        let ms = e.svc.my_tenants(alice).await.unwrap();
        assert_eq!(ms[0].tenant.id, DEFAULT_TENANT_ID);
        assert!(ms[0].last_used_at.is_some());

        // 停用的成员关系不算:默认租户里被停用 → 登录进 acme
        e.members
            .set_status(DEFAULT_TENANT_ID, alice, MemberStatus::Inactive, None)
            .await
            .unwrap();
        assert_eq!(e.claims(&e.login("alice").await).tenant_id, Some(acme.id));
    }

    /// `login_with`:验密后把平台角色 + 有效成员关系(最近用过的在前)交给消费方挑进哪里 ——
    /// 挑中的租户 → 进它(并记 last_used_at);`Platform` → 平台上下文;`None` → `Forbidden` 且不建会话;
    /// 挑了不在候选里的租户 → `Forbidden`;密码错照旧 `InvalidCredentials`,挑选函数不被调用。
    #[tokio::test]
    async fn login_with_lets_caller_choose_entry() {
        use super::LoginEntry;
        let e = env();
        let admin = e.tenant_role("admin").await;
        let user = e.tenant_role("user").await;
        let alice = e.account("alice").await;
        let acme = e.tenants.create("acme", "Acme", None).await.unwrap();
        e.members
            .add(DEFAULT_TENANT_ID, alice, &[user], None)
            .await
            .unwrap();
        e.members.add(acme.id, alice, &[admin], None).await.unwrap();
        // 最近用过的是默认租户
        e.members.touch_last_used(acme.id, alice).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        e.members
            .touch_last_used(DEFAULT_TENANT_ID, alice)
            .await
            .unwrap();
        let input = || LoginInput {
            identifier: "alice".into(),
            password: "password123".into(),
        };

        // 挑「租户角色里有 admin」的第一个 → acme(跳过最近用过的默认租户)
        let out = e
            .svc
            .login_with(input(), |c| {
                assert_eq!(c.user_id, alice);
                assert!(c.platform_roles.is_empty());
                assert_eq!(
                    c.memberships
                        .iter()
                        .map(|m| m.tenant.id)
                        .collect::<Vec<_>>(),
                    vec![DEFAULT_TENANT_ID, acme.id],
                    "最近用过的在前"
                );
                c.memberships
                    .iter()
                    .find(|m| m.roles.iter().any(|r| r == "admin"))
                    .map(|m| LoginEntry::Tenant(m.tenant.id))
            })
            .await
            .unwrap();
        assert_eq!(out.tenant_id, Some(acme.id));
        assert_eq!(e.claims(&out).tenant_roles, vec!["admin".to_string()]);
        // 进入即记 last_used_at:acme 排到最前,普通登录下次也进它
        assert_eq!(e.svc.my_tenants(alice).await.unwrap()[0].tenant.id, acme.id);

        // 平台上下文
        let out = e
            .svc
            .login_with(input(), |_| Some(LoginEntry::Platform))
            .await
            .unwrap();
        assert_eq!(out.tenant_id, None);
        assert!(e.claims(&out).tenant_roles.is_empty());

        // 拒绝 → Forbidden;挑了不在候选里的租户 → Forbidden
        let last_used_before = e.svc.my_tenants(alice).await.unwrap()[0].last_used_at;
        assert!(matches!(
            e.svc.login_with(input(), |_| None).await,
            Err(IdmError::Forbidden)
        ));
        assert!(matches!(
            e.svc
                .login_with(input(), |_| Some(LoginEntry::Tenant(Uuid::now_v7())))
                .await,
            Err(IdmError::Forbidden)
        ));
        assert_eq!(
            e.svc.my_tenants(alice).await.unwrap()[0].last_used_at,
            last_used_before,
            "被拒不记 last_used_at"
        );

        // 密码错:挑选函数不被调用
        let bad = e
            .svc
            .login_with(
                LoginInput {
                    identifier: "alice".into(),
                    password: "wrong".into(),
                },
                |_| panic!("密码错不该走到挑选"),
            )
            .await;
        assert!(matches!(
            bad,
            Err(IdmError::InvalidCredentials(
                crate::error::CredentialFailure::BadPassword
            ))
        ));
    }

    #[tokio::test]
    async fn login_without_membership_has_no_tenant() {
        let e = env();
        let bob = e.account("bob").await;
        let sa = e
            .roles
            .upsert("superadmin", "平台管理员", RoleScope::Platform, None)
            .await
            .unwrap();
        e.roles.grant(bob, sa, None).await.unwrap();

        let out = e.login("bob").await;
        assert_eq!(out.tenant_id, None);
        assert!(out.tenant_roles.is_empty());
        let c = e.claims(&out);
        assert_eq!(c.tenant_id, None);
        assert!(c.tenant_roles.is_empty());
        assert_eq!(c.roles, vec!["superadmin".to_string()]); // 平台角色照常
        assert!(e.svc.my_tenants(bob).await.unwrap().is_empty());

        // 唯一的租户被停用 → 同样是平台上下文
        let t = e.tenants.create("acme", "Acme", None).await.unwrap();
        e.members.add(t.id, bob, &[], None).await.unwrap();
        e.tenants
            .set_status(t.id, TenantStatus::Suspended, None)
            .await
            .unwrap();
        assert_eq!(e.claims(&e.login("bob").await).tenant_id, None);
    }

    #[tokio::test]
    async fn switch_tenant_reissues_with_new_tenant_roles() {
        let e = env();
        let admin = e.tenant_role("admin").await;
        let user = e.tenant_role("user").await;
        let alice = e.account("alice").await;
        let acme = e.tenants.create("acme", "Acme", None).await.unwrap();
        e.members
            .add(DEFAULT_TENANT_ID, alice, &[user], None)
            .await
            .unwrap();
        e.members.add(acme.id, alice, &[admin], None).await.unwrap();

        // 都没用过 → 按租户 id 取第一个 = 默认租户
        let first = e.login("alice").await;
        assert_eq!(first.tenant_id, Some(DEFAULT_TENANT_ID));

        let switched = e
            .svc
            .switch_tenant(&first.refresh_token, alice, acme.id)
            .await
            .unwrap_or_else(|err| panic!("switch 失败: {err:?}"));
        assert_ne!(switched.session_id, first.session_id);
        assert_eq!(switched.tenant_id, Some(acme.id));
        assert_eq!(switched.tenant_roles, vec!["admin".to_string()]);
        let c = e.claims(&switched);
        assert_eq!(c.tenant_id, Some(acme.id));
        assert_eq!(c.tenant_roles, vec!["admin".to_string()]);

        // 旧会话已吊销
        assert!(matches!(
            e.svc.refresh(&first.refresh_token).await,
            Err(IdmError::Unauthorized)
        ));
        // 新会话 refresh 留在 acme
        let r = e.svc.refresh(&switched.refresh_token).await.unwrap();
        assert_eq!(e.claims(&r).tenant_id, Some(acme.id));
        // 切换记了 last_used_at → 下次登录直接进 acme
        assert!(e
            .members
            .get(acme.id, alice)
            .await
            .unwrap()
            .unwrap()
            .last_used_at
            .is_some());
        assert_eq!(e.claims(&e.login("alice").await).tenant_id, Some(acme.id));
    }

    #[tokio::test]
    async fn switch_to_non_member_tenant_is_forbidden() {
        let e = env();
        let alice = e.account("alice").await;
        let sa = e
            .roles
            .upsert("superadmin", "平台管理员", RoleScope::Platform, None)
            .await
            .unwrap();
        e.roles.grant(alice, sa, None).await.unwrap(); // 平台管理员也不能切进非成员租户
        e.members
            .add(DEFAULT_TENANT_ID, alice, &[], None)
            .await
            .unwrap();
        let other = e.tenants.create("other", "Other", None).await.unwrap();
        let suspended = e.tenants.create("susp", "Susp", None).await.unwrap();
        e.members.add(suspended.id, alice, &[], None).await.unwrap();
        e.tenants
            .set_status(suspended.id, TenantStatus::Suspended, None)
            .await
            .unwrap();
        let inactive = e.tenants.create("inact", "Inact", None).await.unwrap();
        e.members.add(inactive.id, alice, &[], None).await.unwrap();
        e.members
            .set_status(inactive.id, alice, MemberStatus::Inactive, None)
            .await
            .unwrap();

        let out = e.login("alice").await;
        assert_eq!(out.tenant_id, Some(DEFAULT_TENANT_ID));
        for t in [other.id, suspended.id, inactive.id, Uuid::now_v7()] {
            assert!(
                matches!(
                    e.svc.switch_tenant(&out.refresh_token, alice, t).await,
                    Err(IdmError::Forbidden)
                ),
                "切到 {t} 应 Forbidden"
            );
        }
        // 被拒不动原会话:还能 refresh,仍在默认租户
        let r = e.svc.refresh(&out.refresh_token).await.unwrap();
        assert_eq!(e.claims(&r).tenant_id, Some(DEFAULT_TENANT_ID));
        // 无效 refresh → Unauthorized(不是 Forbidden)
        assert!(matches!(
            e.svc
                .switch_tenant("garbage", alice, DEFAULT_TENANT_ID)
                .await,
            Err(IdmError::Unauthorized)
        ));
    }

    /// refresh 会话属于 A、调用方身份是 B → `Unauthorized`,A 的会话不动(不吊销、不记 last_used_at)。
    #[tokio::test]
    async fn switch_tenant_with_another_users_session_is_unauthorized() {
        let e = env();
        let user = e.tenant_role("user").await;
        let alice = e.account("alice").await;
        let bob = e.account("bob").await;
        let acme = e.tenants.create("acme", "Acme", None).await.unwrap();
        for who in [alice, bob] {
            e.members
                .add(DEFAULT_TENANT_ID, who, &[user], None)
                .await
                .unwrap();
            e.members.add(acme.id, who, &[user], None).await.unwrap();
        }
        let a = e.login("alice").await;
        assert!(matches!(
            e.svc.switch_tenant(&a.refresh_token, bob, acme.id).await,
            Err(IdmError::Unauthorized)
        ));
        assert!(e
            .members
            .get(acme.id, alice)
            .await
            .unwrap()
            .unwrap()
            .last_used_at
            .is_none());
        let r = e.svc.refresh(&a.refresh_token).await.unwrap();
        assert_eq!(e.claims(&r).tenant_id, Some(DEFAULT_TENANT_ID));
    }

    #[tokio::test]
    async fn refresh_keeps_tenant() {
        let e = env();
        let admin = e.tenant_role("admin").await;
        let user = e.tenant_role("user").await;
        let alice = e.account("alice").await;
        let acme = e.tenants.create("acme", "Acme", None).await.unwrap();
        e.members
            .add(DEFAULT_TENANT_ID, alice, &[user], None)
            .await
            .unwrap();
        e.members.add(acme.id, alice, &[user], None).await.unwrap();
        let first = e.login("alice").await;
        let out = e
            .svc
            .switch_tenant(&first.refresh_token, alice, acme.id)
            .await
            .unwrap();

        // 默认租户后来被"用过"也不影响:refresh 沿用会话上的租户,不重新挑
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        e.members
            .touch_last_used(DEFAULT_TENANT_ID, alice)
            .await
            .unwrap();
        // 租户角色重新读:改了角色,refresh 后 token 带新角色
        e.members
            .set_roles(acme.id, alice, &[admin, user], None)
            .await
            .unwrap();
        let r = e.svc.refresh(&out.refresh_token).await.unwrap();
        assert_eq!(r.tenant_id, Some(acme.id));
        let c = e.claims(&r);
        assert_eq!(c.tenant_id, Some(acme.id));
        assert_eq!(
            c.tenant_roles,
            vec!["admin".to_string(), "user".to_string()]
        );

        // 平台上下文的会话 refresh 后仍是平台上下文
        e.account("bob").await;
        let b = e.login("bob").await;
        let rb = e.svc.refresh(&b.refresh_token).await.unwrap();
        assert_eq!(e.claims(&rb).tenant_id, None);
    }

    #[tokio::test]
    async fn refresh_after_member_removed_is_unauthorized() {
        let e = env();
        let alice = e.account("alice").await;
        let acme = e.tenants.create("acme", "Acme", None).await.unwrap();
        // 另有一个有效租户:失败时绝不能悄悄落到它
        e.members
            .add(DEFAULT_TENANT_ID, alice, &[], None)
            .await
            .unwrap();
        e.members.add(acme.id, alice, &[], None).await.unwrap();
        e.members.touch_last_used(acme.id, alice).await.unwrap();
        let out = e.login("alice").await;
        assert_eq!(out.tenant_id, Some(acme.id));

        e.members.remove(acme.id, alice, None).await.unwrap();
        assert!(matches!(
            e.svc.refresh(&out.refresh_token).await,
            Err(IdmError::Unauthorized)
        ));
        // 会话已作废:再试还是 401
        assert!(matches!(
            e.svc.refresh(&out.refresh_token).await,
            Err(IdmError::Unauthorized)
        ));

        // 成员被停用同理
        let out = e.login("alice").await;
        assert_eq!(out.tenant_id, Some(DEFAULT_TENANT_ID));
        e.members
            .set_status(DEFAULT_TENANT_ID, alice, MemberStatus::Inactive, None)
            .await
            .unwrap();
        assert!(matches!(
            e.svc.refresh(&out.refresh_token).await,
            Err(IdmError::Unauthorized)
        ));
    }

    #[tokio::test]
    async fn refresh_after_tenant_suspended_is_unauthorized() {
        let e = env();
        let alice = e.account("alice").await;
        let acme = e.tenants.create("acme", "Acme", None).await.unwrap();
        e.members
            .add(DEFAULT_TENANT_ID, alice, &[], None)
            .await
            .unwrap();
        e.members.add(acme.id, alice, &[], None).await.unwrap();
        e.members.touch_last_used(acme.id, alice).await.unwrap();
        let out = e.login("alice").await;
        assert_eq!(out.tenant_id, Some(acme.id));

        e.tenants
            .set_status(acme.id, TenantStatus::Suspended, None)
            .await
            .unwrap();
        assert!(matches!(
            e.svc.refresh(&out.refresh_token).await,
            Err(IdmError::Unauthorized)
        ));

        // 软删租户同理
        e.tenants
            .set_status(acme.id, TenantStatus::Active, None)
            .await
            .unwrap();
        let out = e
            .svc
            .switch_tenant(&e.login("alice").await.refresh_token, alice, acme.id)
            .await
            .unwrap();
        e.tenants.soft_delete(acme.id, None).await.unwrap();
        assert!(matches!(
            e.svc.refresh(&out.refresh_token).await,
            Err(IdmError::Unauthorized)
        ));
    }

    #[tokio::test]
    async fn register_joins_default_tenant_as_user() {
        let e = env();
        e.tenant_role("user").await;
        e.tenant_role("admin").await; // 不在 signup_roles 里,不授
        let out = e.svc.register(register_input("alice"), None).await.unwrap();
        assert_eq!(out.tenant_id, Some(DEFAULT_TENANT_ID));
        assert_eq!(out.tenant_roles, vec!["user".to_string()]);
        let c = e.claims(&out);
        assert_eq!(c.tenant_id, Some(DEFAULT_TENANT_ID));
        assert_eq!(c.tenant_roles, vec!["user".to_string()]);
        assert!(c.roles.is_empty()); // 租户角色不进平台角色

        let ms = e.svc.my_tenants(out.user.id).await.unwrap();
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].tenant.id, DEFAULT_TENANT_ID);
        assert_eq!(ms[0].roles, vec!["user".to_string()]);

        // 自定义 signup_tenant / signup_roles
        let e = env_with(|b| {
            b.signup_tenant(Some(Uuid::from_u128(0x77)))
                .signup_roles(vec!["member".into()])
        });
        e.tenants
            .upsert_fixed(Uuid::from_u128(0x77), "club", "Club", None)
            .await
            .unwrap();
        e.tenant_role("member").await;
        let out = e.svc.register(register_input("bob"), None).await.unwrap();
        assert_eq!(out.tenant_id, Some(Uuid::from_u128(0x77)));
        assert_eq!(out.tenant_roles, vec!["member".to_string()]);
    }

    #[tokio::test]
    async fn register_without_default_tenant_only_creates_account() {
        // 不配注册租户:只建账号,平台上下文
        let e = env_with(|b| b.signup_tenant(None));
        e.tenant_role("user").await;
        let out = e.svc.register(register_input("alice"), None).await.unwrap();
        assert_eq!(out.tenant_id, None);
        assert!(e.claims(&out).tenant_id.is_none());
        assert!(e.svc.my_tenants(out.user.id).await.unwrap().is_empty());
        assert!(e
            .members
            .get(DEFAULT_TENANT_ID, out.user.id)
            .await
            .unwrap()
            .is_none());

        // 默认租户停用:同样只建账号(注册不失败)
        let e = env();
        e.tenant_role("user").await;
        e.tenants
            .set_status(DEFAULT_TENANT_ID, TenantStatus::Suspended, None)
            .await
            .unwrap();
        let out = e.svc.register(register_input("bob"), None).await.unwrap();
        assert_eq!(out.tenant_id, None);
        assert!(e
            .members
            .get(DEFAULT_TENANT_ID, out.user.id)
            .await
            .unwrap()
            .is_none());
        assert!(e.users.find_by_id(out.user.id).await.is_ok());

        // 默认租户已删:同样只建账号
        let e = env();
        e.tenant_role("user").await;
        e.tenants
            .soft_delete(DEFAULT_TENANT_ID, None)
            .await
            .unwrap();
        let out = e.svc.register(register_input("carol"), None).await.unwrap();
        assert_eq!(out.tenant_id, None);
    }

    /// 配置的注册角色不存在 → 注册响亮失败(Internal),**什么都不建**(不留没角色的成员 / 孤儿账号)。
    #[tokio::test]
    async fn register_with_missing_signup_role_fails_loudly() {
        let e = env(); // 默认 signup_roles = ["user"],但目录里没有 user
        let res = e.svc.register(register_input("alice"), None).await;
        assert!(matches!(res, Err(IdmError::Internal(_))));
        assert!(e.users.find_by_identifier("alice").await.unwrap().is_none());
    }

    /// 注册角色只在**租户角色**里找:同名的是平台角色 → 当作不存在(Internal),绝不经注册授出平台角色。
    #[tokio::test]
    async fn register_never_grants_a_platform_role() {
        let e = env_with(|b| b.signup_roles(vec!["superadmin".into()]));
        e.roles
            .upsert("superadmin", "超管", RoleScope::Platform, None)
            .await
            .unwrap();
        let res = e.svc.register(register_input("mallory"), None).await;
        assert!(matches!(res, Err(IdmError::Internal(_))));
        assert!(e
            .users
            .find_by_identifier("mallory")
            .await
            .unwrap()
            .is_none());
    }

    /// signer 拿到的身份事实带当前租户的 slug / 名称(app 进程据此回答「当前组织」,不查 idm 库);平台上下文为空。
    #[tokio::test]
    async fn token_claims_carry_tenant_slug_and_name() {
        use crate::token::{Hs256Tokens, TokenClaims, TokenSigner};

        struct Recording(Hs256Tokens, Mutex<Vec<(Option<String>, Option<String>)>>);
        impl TokenSigner for Recording {
            fn sign(&self, c: &TokenClaims) -> Result<String, IdmError> {
                self.1
                    .lock()
                    .unwrap()
                    .push((c.tenant_slug.clone(), c.tenant_name.clone()));
                self.0.sign(c)
            }
        }
        let rec = Arc::new(Recording(Hs256Tokens::new("secret"), Mutex::new(vec![])));
        let e = env_with(|b| b.signer(rec.clone()));
        let user = e.tenant_role("user").await;
        let alice = e.account("alice").await;
        e.account("bob").await;
        e.members
            .add(DEFAULT_TENANT_ID, alice, &[user], None)
            .await
            .unwrap();
        e.login("alice").await;
        e.login("bob").await; // 不是任何租户的成员 → 平台上下文
        let seen = rec.1.lock().unwrap().clone();
        assert_eq!(
            seen,
            vec![
                (Some("default".to_owned()), Some("默认组织".to_owned())),
                (None, None)
            ]
        );
    }
}
