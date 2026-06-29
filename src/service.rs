//! idm 认证业务。持 repo/hasher/token/clock 端口,编排注册/登录/发会话。
//! 范式同分层 service:依赖 trait 而非实现,在此做归一/编排/审计下传。
//! **入参是领域结构(`input` 模块),已由 app 在 HTTP 边界校验完**;审计主体经 `by: Option<String>` 传。

use std::sync::Arc;

use time::Duration;
use uuid::Uuid;

use super::clock::{Clock, SystemClock};
use super::input::{ChangePasswordInput, LoginInput, RegisterInput, UpdateMeInput};
use super::repo::{RoleRepo, SessionRepo, User, UserRepo};
use super::token::{self, Hs256Tokens, TokenClaims, TokenSigner, TokenVerifier};
use super::{Argon2Hasher, PwHasher};
use crate::error::IdmError;
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
pub struct AuthOutcome {
    pub user: UserView,
    pub access_token: String,
    pub refresh_token: String,
    pub access_max_age_secs: i64,
    pub refresh_max_age_secs: i64,
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
    hasher: Arc<dyn PwHasher>,
    signer: Arc<dyn TokenSigner>,
    verifier: Arc<dyn TokenVerifier>,
    clock: Arc<dyn Clock>,
    access_ttl_secs: i64,
    refresh_ttl_secs: i64,
}

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
        hasher: Arc<dyn PwHasher>,
        jwt_secret: &str,
        access_ttl_secs: i64,
        refresh_ttl_secs: i64,
    ) -> Self {
        Self::builder(users, sessions, roles)
            .hasher(hasher)
            .hs256_secret(jwt_secret)
            .access_ttl_secs(access_ttl_secs)
            .refresh_ttl_secs(refresh_ttl_secs)
            .build()
    }

    /// **builder**:只设要 override 的端口,其余取默认(Argon2 / SystemClock / TTL 900·604800)。
    /// 仅 repos 无默认须显式传;签验端口无安全默认 —— 必须经 `hs256_secret` 或 `signer`+`verifier` 给出,
    /// 否则 `build` panic(wiring 错误,启动期即暴露)。
    pub fn builder(
        users: Arc<dyn UserRepo>,
        sessions: Arc<dyn SessionRepo>,
        roles: Arc<dyn RoleRepo>,
    ) -> AuthServiceBuilder {
        AuthServiceBuilder {
            users,
            sessions,
            roles,
            hasher: Arc::new(Argon2Hasher),
            signer: None,
            verifier: None,
            clock: Arc::new(SystemClock),
            access_ttl_secs: DEFAULT_ACCESS_TTL_SECS,
            refresh_ttl_secs: DEFAULT_REFRESH_TTL_SECS,
        }
    }

    /// 注册:归一 username/email → hash 密码 → 同事务建 user/password → 发会话。`by` = 审计主体。
    pub async fn register(
        &self,
        input: RegisterInput,
        by: Option<String>,
    ) -> Result<AuthOutcome, IdmError> {
        let username = normalize(&input.username);
        let email = input.email.as_deref().map(normalize);
        let hash = self.hash_password(input.password).await?;
        let user = self
            .inner
            .users
            .create(&username, email.as_deref(), &hash, by.clone())
            .await?;
        self.issue_session(&user, by).await
    }

    /// 登录:查用户(identifier=username 或 email)→ 验密 → 发会话。
    /// **防枚举**:不存在与密码错均返回同一 `Unauthorized`。
    pub async fn login(&self, input: LoginInput) -> Result<AuthOutcome, IdmError> {
        let identifier = normalize(&input.identifier);
        let Some(found) = self.inner.users.find_by_identifier(&identifier).await? else {
            return Err(IdmError::Unauthorized);
        };
        if !self
            .verify_password(input.password, found.password_hash)
            .await?
        {
            return Err(IdmError::Unauthorized);
        }
        self.issue_session(&found.user, None).await
    }

    /// 验 access token → 已认证身份(含角色,供 require_role)。失败 → `Unauthorized`。
    pub fn authenticate_token(&self, token: &str) -> Result<AuthUser, IdmError> {
        let v = self.inner.verifier.verify(token)?;
        Ok(AuthUser {
            id: v.user_id,
            username: v.username,
            roles: v.roles,
        })
    }

    /// 当前用户资料(GET /me):查存活用户 + 角色 → `UserView`。已软删 → `NotFound`。
    pub async fn me(&self, user_id: Uuid) -> Result<UserView, IdmError> {
        let user = self.inner.users.find_by_id(user_id).await?;
        let roles = self.inner.roles.roles_for_user(user_id).await?;
        Ok(to_view(&user, roles))
    }

    /// 刷新:验 refresh hash → 轮换(撤旧 session、发新会话)。无效/过期/已撤销 → `Unauthorized`。
    pub async fn refresh(&self, refresh_token: &str) -> Result<AuthOutcome, IdmError> {
        let hash = token::hash_refresh(refresh_token);
        let now = self.inner.clock.now();
        let Some(session) = self.inner.sessions.find_active(&hash, now).await? else {
            return Err(IdmError::Unauthorized);
        };
        // 轮换:旧 refresh 一次性,撤销后发新会话(防 refresh 重放)。
        self.inner.sessions.revoke(session.id).await?;
        let user = self.inner.users.find_by_id(session.user_id).await?;
        self.issue_session(&user, None).await
    }

    /// 登出:撤销该 refresh 对应的会话。幂等(找不到也 Ok)。
    pub async fn logout(&self, refresh_token: &str) -> Result<(), IdmError> {
        let hash = token::hash_refresh(refresh_token);
        if let Some(session) = self
            .inner
            .sessions
            .find_active(&hash, self.inner.clock.now())
            .await?
        {
            self.inner.sessions.revoke(session.id).await?;
        }
        Ok(())
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

    /// 发会话:查角色 → 生成 refresh + 经 signer 签 access token(claim 形状由 signer 决定),组 `AuthOutcome`。
    async fn issue_session(
        &self,
        user: &User,
        by: Option<String>,
    ) -> Result<AuthOutcome, IdmError> {
        let now = self.inner.clock.now();
        let roles = self.inner.roles.roles_for_user(user.id).await?;
        let (refresh, refresh_hash) = token::generate_refresh();
        let refresh_expires_at = now + Duration::seconds(self.inner.refresh_ttl_secs);
        let session = self
            .inner
            .sessions
            .create(user.id, &refresh_hash, refresh_expires_at, by)
            .await?;
        let claims = TokenClaims {
            user_id: user.id,
            session_id: session.id,
            username: user.username.clone(),
            email: user.email.clone(),
            email_verified: user.email_verified,
            roles: roles.clone(),
            issued_at: now,
            expires_at: now + Duration::seconds(self.inner.access_ttl_secs),
        };
        let access = self.inner.signer.sign(&claims)?;
        Ok(AuthOutcome {
            user: to_view(user, roles),
            access_token: access,
            refresh_token: refresh,
            access_max_age_secs: self.inner.access_ttl_secs,
            refresh_max_age_secs: self.inner.refresh_ttl_secs,
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
    use crate::repo::{InMemoryRoleRepo, InMemorySessionRepo, InMemoryUserRepo};
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
        )
        .hs256_secret("secret")
        .hasher(Arc::new(FakeHasher))
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
}
