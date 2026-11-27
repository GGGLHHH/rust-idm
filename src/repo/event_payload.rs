//! outbox 事件 payload 的形状(内存 / PG 两种实现共用,保证形状一致)。

use serde_json::{json, Value};
use uuid::Uuid;

use super::user_repo::User;
use crate::tenant::{MemberStatus, Tenant};

/// `user.created` 事件 payload(三处建号共用)。`roles` = 建号时授的平台角色名。
pub(crate) fn user_created(user: &User, roles: &[String]) -> Value {
    json!({
        "user_id": user.id,
        "username": user.username,
        "email": user.email,
        "email_verified": user.email_verified,
        "created_at": user.created_at,
        "roles": roles,
    })
}

/// `user.updated` 事件 payload。
pub(crate) fn user_updated(user: &User) -> Value {
    json!({
        "user_id": user.id,
        "username": user.username,
        "email": user.email,
        "email_verified": user.email_verified,
    })
}

/// `tenant.created` / `tenant.updated` 事件 payload(带 `tenant_id`)。
pub(crate) fn tenant(tenant: &Tenant) -> Value {
    json!({
        "tenant_id": tenant.id,
        "slug": tenant.slug,
        "name": tenant.name,
        "status": tenant.status.as_str(),
    })
}

/// `tenant.member_*` 事件 payload:总带 `tenant_id` / `user_id`,`status` / `roles` 按事件需要带。
pub(crate) fn member(
    tenant_id: Uuid,
    user_id: Uuid,
    status: Option<MemberStatus>,
    roles: Option<&[String]>,
) -> Value {
    let mut payload = json!({ "tenant_id": tenant_id, "user_id": user_id });
    if let Some(status) = status {
        payload["status"] = Value::from(status.as_str());
    }
    if let Some(roles) = roles {
        payload["roles"] = json!(roles);
    }
    payload
}
