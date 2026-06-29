//! idm —— 自包含的认证**领域/服务库**(零 HTTP)。
//!
//! 暴露:`AuthService`(编排注册/登录/会话轮换/改密)、可拔插仓储端口(内存/PG)、哈希端口
//! (`PwHasher`)、**token 签验端口**(`TokenSigner`/`TokenVerifier`,默认 `Hs256Tokens` —— claim 形状
//! 与签名算法/密钥可拔插、分进程可只验不签)、**时间端口**(`Clock`/`SystemClock`,测试可注入固定时钟)、
//! 领域类型(`User`/`AuthUser`/`UserView`)、纯数据契约(`AuthOutcome`)、领域错误 `IdmError`。
//! **不含任何 HTTP**:路由、DTO、校验、cookie、状态码全归消费方(app)—— app 在自己的
//! `features/auth/` 建端点、做校验、写 httponly cookie,并 `From<IdmError> for AppError` 接错误。
//!
//! 分层范式:`service → repo(trait + memory/postgres)→ 领域类型`,service 依赖 trait 而非实现。
//! 迁移表见 `migrations/`(消费方 copy 进自己的 migrations/idm 跑)。

mod clock;
mod error;
mod identity;
mod input;
pub mod password;
mod repo;
mod service;
mod token;

pub use clock::{Clock, SystemClock};
pub use error::IdmError;
pub use identity::AuthUser;
pub use input::{ChangePasswordInput, LoginInput, RegisterInput, UpdateMeInput};
pub use password::{Argon2Hasher, FakeHasher, PwHasher};
pub use repo::{
    InMemoryRoleRepo, InMemorySessionRepo, InMemoryUserRepo, PgRoleRepo, PgSessionRepo, PgUserRepo,
    RoleRepo, Session, SessionRepo, User, UserRepo, UserWithHash,
};
pub use service::{AuthOutcome, AuthService, AuthServiceBuilder, UserView};
pub use token::{Hs256Tokens, TokenClaims, TokenSigner, TokenVerifier, VerifiedToken};
