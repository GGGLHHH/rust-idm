//! idm 仓储:端口 trait + 内存 / PG 两种实现。
//!
//! - [`UserRepo`] —— users + user_password(凭据分表,同事务);
//! - [`SessionRepo`] —— sessions;
//! - [`RoleRepo`] —— roles + user_roles;
//! - [`TenantRepo`] —— tenants;
//! - [`MemberRepo`] —— tenant_members + member_roles;
//! - [`OutboxRepo`] —— outbox(事务性发件箱 —— 写方法内 emit 同事务落一行,本端口只管轮询 / 标记,不管发布机制)。
//!
//! 每个端口都有 `Arc<T>` 转发实现:`AuthService<Arc<dyn UserRepo>, …>` 可以在运行时二选一实现。

mod event_payload;
mod list_page;
mod member_repo;
mod memory;
mod outbox_repo;
mod postgres;
mod role_repo;
mod schema;
mod session_repo;
mod tenant_repo;
mod user_repo;

pub use list_page::{ListPage, ListResult, SortDirection};
pub use member_repo::MemberRepo;
pub use memory::{
    InMemoryMemberRepo, InMemoryOutboxRepo, InMemoryRoleRepo, InMemorySessionRepo,
    InMemoryTenantRepo, InMemoryUserRepo,
};
pub use outbox_repo::{OutboxRecord, OutboxRepo};
pub use postgres::{
    PgMemberRepo, PgOutboxRepo, PgRoleRepo, PgSessionRepo, PgTenantRepo, PgUserRepo,
};
pub use role_repo::{NewRole, Role, RoleGrant, RoleRepo};
pub use session_repo::{Session, SessionRepo};
pub use tenant_repo::{NewTenant, TenantRepo};
pub use user_repo::{
    NewUser, User, UserListFilter, UserListRow, UserRepo, UserSortBy, UserWithHash,
};
