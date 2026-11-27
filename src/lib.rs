//! idm —— 自包含的认证**领域 / 服务库**(零 HTTP)。
//!
//! 暴露:[`AuthService`](编排注册 / 登录 / 会话轮换 / 切换租户 / 改密)、可拔插仓储端口(内存 / PG 两种实现)、
//! 密码哈希端口([`PasswordHasher`])、**token 签验端口**([`TokenSigner`] / [`TokenVerifier`],默认
//! [`Hs256Tokens`] —— claim 形状与签名算法 / 密钥可拔插、分进程可只验不签)、**时间端口**
//! ([`Clock`] / [`SystemClock`],测试可注入固定时钟)、领域类型([`User`] / [`AuthUser`] /
//! [`UserView`] / 多租户的 [`Tenant`] / [`Membership`] / [`RoleScope`])、纯数据契约([`AuthOutcome`])和
//! 领域错误 [`IdmError`]。
//!
//! **不含任何 HTTP**:路由、DTO、校验、cookie、状态码全归消费方(app)—— app 在自己的
//! `features/auth/` 建端点、做校验、写 httponly cookie,并 `From<IdmError> for AppError` 接错误。
//!
//! 分层:`AuthService → 仓储端口(trait + 内存 / PG 实现)→ 领域类型`,service 依赖 trait 而非实现。
//! 迁移表见 `migrations/`(消费方拷进自己的 `migrations/idm` 跑)。
//!
//! # 示例
//!
//! ```
//! use std::sync::Arc;
//!
//! use idm::{
//!     AuthService, FakeHasher, InMemoryMemberRepo, InMemoryRoleRepo, InMemorySessionRepo,
//!     InMemoryUserRepo, RegisterInput,
//! };
//!
//! # tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(async {
//! // 内存仓储共享同一份存储(镜像 PG 同库共表);生产换成 `Pg*Repo`。
//! let users = InMemoryUserRepo::new();
//! let sessions = InMemorySessionRepo::new_shared_with(&users);
//! let roles = InMemoryRoleRepo::new_shared_with(&users);
//! let members = InMemoryMemberRepo::new_shared_with(&users);
//! // 不授注册角色;`signup_roles` 收任意 `Into<String>` 的迭代器,空集合要写明元素类型。
//! let no_signup_roles: [&str; 0] = [];
//! let auth = AuthService::builder(Arc::new(users), sessions, roles, members)
//!     .hs256_secret("dev-secret")
//!     .hasher(FakeHasher)
//!     .signup_roles(no_signup_roles)
//!     .build();
//!
//! let input = RegisterInput {
//!     username: "alice".to_owned(),
//!     password: "password123".to_owned(),
//!     ..RegisterInput::default()
//! };
//! let outcome = auth.register(input, None).await.unwrap();
//! let who = auth.authenticate_token(&outcome.access_token).unwrap();
//! assert_eq!(who.username, "alice");
//! # });
//! ```

// Google Rust 风格指南:必须 panic 时用 expect("原因") 说明不变量,不用 unwrap。
#![warn(clippy::unwrap_used)]

mod auth_service;
mod auth_user;
mod clock;
mod hs256_tokens;
mod idm_error;
mod input;
mod password_hasher;
mod refresh_token;
mod repo;
mod tenant;
mod token;

pub use auth_service::{
    AuthOutcome, AuthService, AuthServiceBuilder, LoginCandidates, LoginEntry, UserView,
};
pub use auth_user::AuthUser;
pub use clock::{Clock, SystemClock};
pub use hs256_tokens::Hs256Tokens;
pub use idm_error::{CredentialFailure, IdmError};
pub use input::{ChangePasswordInput, LoginInput, RegisterInput, UpdateMeInput};
pub use password_hasher::{Argon2Hasher, FakeHasher, PasswordHasher};
pub use repo::{
    InMemoryMemberRepo, InMemoryOutboxRepo, InMemoryRoleRepo, InMemorySessionRepo,
    InMemoryTenantRepo, InMemoryUserRepo, ListPage, ListResult, MemberRepo, NewRole, NewTenant,
    NewUser, OutboxRecord, OutboxRepo, PgMemberRepo, PgOutboxRepo, PgRoleRepo, PgSessionRepo,
    PgTenantRepo, PgUserRepo, Role, RoleGrant, RoleRepo, Session, SessionRepo, SortDirection,
    TenantRepo, User, UserListFilter, UserListRow, UserRepo, UserSortBy, UserWithHash,
};
pub use tenant::{
    MemberKey, MemberStatus, Membership, RoleScope, Tenant, TenantStatus, UnknownValue,
    DEFAULT_TENANT_ID,
};
pub use token::{TokenClaims, TokenSigner, TokenVerifier, VerifiedToken};
