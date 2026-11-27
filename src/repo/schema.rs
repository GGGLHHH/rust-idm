//! sea-query 表 / 列标识(snake_case:`Users::Table` → "users"、`EmailVerified` → "email_verified")。
//! 只给 PG 实现拼 SQL 用。

use sea_query::Iden;

/// `users` 表。
#[derive(Iden)]
pub(crate) enum Users {
    Table,
    Id,
    Username,
    Email,
    EmailVerified,
    CreatedAt,
    CreatedBy,
    UpdatedBy,
    DeletedAt,
}

/// `user_password` 表(凭据分表)。
#[derive(Iden)]
pub(crate) enum UserPassword {
    Table,
    UserId,
    PasswordHash,
    PasswordUpdatedAt,
}

/// `sessions` 表。
#[derive(Iden)]
pub(crate) enum Sessions {
    Table,
    Id,
    UserId,
    TokenHash,
    ExpiresAt,
    RevokedAt,
    TenantId,
    CreatedBy,
    UpdatedBy,
}

/// `roles` 表。
#[derive(Iden)]
pub(crate) enum Roles {
    Table,
    Id,
    Name,
    DisplayName,
    Scope,
    CreatedBy,
    UpdatedBy,
    DeletedAt,
}

/// `user_roles` 表(平台角色授予)。
#[derive(Iden)]
pub(crate) enum UserRoles {
    Table,
    UserId,
    RoleId,
    GrantedBy,
}

/// `tenants` 表。
#[derive(Iden)]
pub(crate) enum Tenants {
    Table,
    Id,
    Slug,
    Name,
    Status,
    CreatedBy,
    CreatedAt,
    UpdatedBy,
    UpdatedAt,
    DeletedAt,
}

/// `tenant_members` 表。
#[derive(Iden)]
pub(crate) enum TenantMembers {
    Table,
    TenantId,
    UserId,
    Status,
    LastUsedAt,
    AddedBy,
}

/// `member_roles` 表(租户角色授予)。
#[derive(Iden)]
pub(crate) enum MemberRoles {
    Table,
    TenantId,
    UserId,
    RoleId,
    GrantedBy,
}

/// `outbox` 表。
#[derive(Iden)]
pub(crate) enum Outbox {
    Table,
    Id,
    EventType,
    AggregateId,
    Payload,
    CreatedAt,
    PublishedAt,
}
