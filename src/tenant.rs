//! 多租户领域类型:租户、成员关系、角色作用域(平台 / 租户)。
//!
//! 身份模型(baserust-stack `docs/superpowers/specs/2026-11-25-multi-tenant-design.md` §4.1):账号全局;租户内的身份 = 成员关系(`tenant_members`)+ 租户角色
//! (`member_roles`);平台角色仍经 `user_roles` 授予。同一角色名只属于一类,由 `roles.scope`
//! 标明 —— 读取时按 scope 过滤(`RoleRepo::roles_for_user` 只回平台角色,`Membership.roles` 只回租户角色)。

use std::error::Error;
use std::fmt;
use std::str::FromStr;

use time::OffsetDateTime;
use uuid::Uuid;

use crate::repo::NewTenant;

/// 默认租户的固定 id(迁移 0004 插入;app / content / search 各有同值常量)。nil UUID 永远不是合法租户。
pub const DEFAULT_TENANT_ID: Uuid = Uuid::from_u128(1);

/// 库里出现了闭集之外的取值(CHECK 约束兜着,理论上走不到)。
#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub struct UnknownValue(String);

impl UnknownValue {
    /// 解析失败的原文。
    #[must_use]
    pub fn value(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for UnknownValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown closed-set value: {}", self.0)
    }
}

impl Error for UnknownValue {}

/// 租户状态。`Suspended` = 停用:成员登录 / 切换 / refresh 都进不去。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[allow(
    clippy::exhaustive_enums,
    reason = "指南「Apply #[non_exhaustive] to publicly-exposed enums」例外:两态、等价于布尔(启用 / 停用)"
)]
pub enum TenantStatus {
    /// 正常。
    Active,
    /// 停用。
    Suspended,
}

impl TenantStatus {
    /// 库里 / 事件 payload 里的文本形式。
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
        }
    }
}

impl fmt::Display for TenantStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for TenantStatus {
    type Err = UnknownValue;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text {
            "active" => Ok(Self::Active),
            "suspended" => Ok(Self::Suspended),
            other => Err(UnknownValue(other.to_owned())),
        }
    }
}

impl TryFrom<String> for TenantStatus {
    type Error = UnknownValue;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        text.parse()
    }
}

/// 成员状态。`Inactive` = 停用成员:关系和角色保留,但不算有效成员。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[allow(
    clippy::exhaustive_enums,
    reason = "指南「Apply #[non_exhaustive] to publicly-exposed enums」例外:两态、等价于布尔(有效 / 停用)"
)]
pub enum MemberStatus {
    /// 有效成员。
    Active,
    /// 停用成员。
    Inactive,
}

impl MemberStatus {
    /// 库里 / 事件 payload 里的文本形式。
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Inactive => "inactive",
        }
    }
}

impl fmt::Display for MemberStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for MemberStatus {
    type Err = UnknownValue;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text {
            "active" => Ok(Self::Active),
            "inactive" => Ok(Self::Inactive),
            other => Err(UnknownValue(other.to_owned())),
        }
    }
}

impl TryFrom<String> for MemberStatus {
    type Error = UnknownValue;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        text.parse()
    }
}

/// 角色作用域。`Platform` 经 `user_roles` 授予(如 superadmin);`Tenant` 经 `member_roles`
/// 按租户授予(如 admin、user)。由消费方的角色闭集决定,`RoleRepo::upsert` 时传入。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[allow(
    clippy::exhaustive_enums,
    reason = "指南「Apply #[non_exhaustive] to publicly-exposed enums」例外:两态(平台 / 租户),身份模型就这两层"
)]
pub enum RoleScope {
    /// 平台角色。
    Platform,
    /// 租户角色。
    Tenant,
}

impl RoleScope {
    /// 库里的文本形式。
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Platform => "platform",
            Self::Tenant => "tenant",
        }
    }
}

impl fmt::Display for RoleScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for RoleScope {
    type Err = UnknownValue;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text {
            "platform" => Ok(Self::Platform),
            "tenant" => Ok(Self::Tenant),
            other => Err(UnknownValue(other.to_owned())),
        }
    }
}

impl TryFrom<String> for RoleScope {
    type Error = UnknownValue;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        text.parse()
    }
}

/// 租户。`slug` 全局唯一且**删除后也不复用**;软删用 `deleted_at`。
#[derive(Clone, Debug, PartialEq, sqlx::FromRow)]
#[non_exhaustive]
pub struct Tenant {
    /// 租户 id(uuid v7;默认租户是 [`DEFAULT_TENANT_ID`])。
    pub id: Uuid,
    /// 全局唯一的短标识(URL / 展示用),不可改、删除后不复用。
    pub slug: String,
    /// 展示名称。
    pub name: String,
    /// 启用 / 停用。
    #[sqlx(try_from = "String")]
    pub status: TenantStatus,
    /// 创建时刻。
    pub created_at: OffsetDateTime,
    /// 最近修改时刻。
    pub updated_at: OffsetDateTime,
    /// 软删时刻;存活租户为 `None`。
    pub deleted_at: Option<OffsetDateTime>,
}

impl Tenant {
    /// 新建的租户:active、未删,`updated_at` = `created_at`。给自己实现 [`TenantRepo`] 的调用方用;
    /// 读回已有行时再按需改 `status` / `updated_at` / `deleted_at`。
    ///
    /// [`TenantRepo`]: crate::TenantRepo
    #[must_use]
    pub fn new(id: Uuid, fields: NewTenant<'_>, created_at: OffsetDateTime) -> Self {
        Self {
            id,
            slug: fields.slug.to_owned(),
            name: fields.name.to_owned(),
            status: TenantStatus::Active,
            created_at,
            updated_at: created_at,
            deleted_at: None,
        }
    }
}

/// 成员关系的键:哪个账号在哪个租户里(`tenant_members` 的复合主键)。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[allow(
    clippy::exhaustive_structs,
    reason = "指南 non_exhaustive 结构体条款例外:描述既有本体(复合主键 = 租户 + 账号),字段不会变"
)]
pub struct MemberKey {
    /// 租户 id。
    pub tenant_id: Uuid,
    /// 账号 id。
    pub user_id: Uuid,
}

/// 成员关系:某账号在某租户里的身份。
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct Membership {
    /// 所在租户(完整行)。
    pub tenant: Tenant,
    /// 账号 id。
    pub user_id: Uuid,
    /// 有效 / 停用。
    pub status: MemberStatus,
    /// 该租户内的**租户角色**名(存活、scope = tenant,按名排序)。
    pub roles: Vec<String>,
    /// 最近一次进入该租户(登录 / 切换)的时刻;登录默认进最近的那个。从没进过 = `None`。
    pub last_used_at: Option<OffsetDateTime>,
}

impl Membership {
    /// 成员关系:没有角色、从没进入过;按需再改 `roles` / `last_used_at`。给自己实现
    /// [`MemberRepo`] 的调用方用。
    ///
    /// [`MemberRepo`]: crate::MemberRepo
    #[must_use]
    pub fn new(tenant: Tenant, user_id: Uuid, status: MemberStatus) -> Self {
        Self {
            tenant,
            user_id,
            status,
            roles: Vec::new(),
            last_used_at: None,
        }
    }

    /// 这条成员关系的键。
    #[must_use]
    pub fn key(&self) -> MemberKey {
        MemberKey {
            tenant_id: self.tenant.id,
            user_id: self.user_id,
        }
    }

    /// 是否**有效**:成员 active 且租户 active(存活由仓储保证:已删租户的成员关系读不出来)。
    #[must_use]
    pub fn is_effective(&self) -> bool {
        self.status == MemberStatus::Active && self.tenant.status == TenantStatus::Active
    }
}

#[cfg(test)]
mod tests {
    use time::OffsetDateTime;
    use uuid::Uuid;

    use super::{
        MemberKey, MemberStatus, Membership, RoleScope, Tenant, TenantStatus, DEFAULT_TENANT_ID,
    };
    use crate::repo::NewTenant;

    #[test]
    fn closed_sets_round_trip_through_text() {
        use std::str::FromStr;

        for status in [TenantStatus::Active, TenantStatus::Suspended] {
            assert_eq!(TenantStatus::from_str(status.as_str()).unwrap(), status);
        }
        for status in [MemberStatus::Active, MemberStatus::Inactive] {
            assert_eq!(MemberStatus::from_str(status.as_str()).unwrap(), status);
        }
        for scope in [RoleScope::Platform, RoleScope::Tenant] {
            assert_eq!(
                RoleScope::try_from(scope.as_str().to_owned()).unwrap(),
                scope
            );
        }
        assert_eq!(
            TenantStatus::Suspended.to_string(),
            "suspended",
            "Display = 库里的文本"
        );
        let error = RoleScope::from_str("nope").unwrap_err();
        assert_eq!(error.value(), "nope");
        assert_eq!(error.to_string(), "unknown closed-set value: nope");
    }

    #[test]
    fn default_tenant_id_is_fixed_and_not_nil() {
        assert_eq!(
            DEFAULT_TENANT_ID.to_string(),
            "00000000-0000-0000-0000-000000000001"
        );
        assert!(!DEFAULT_TENANT_ID.is_nil());
    }

    #[test]
    fn constructors_build_fresh_tenant_and_membership() {
        let now = OffsetDateTime::now_utc();
        let fields = NewTenant {
            slug: "acme",
            name: "Acme",
        };
        let tenant = Tenant::new(Uuid::from_u128(7), fields, now);
        assert_eq!(tenant.status, TenantStatus::Active);
        assert_eq!(tenant.updated_at, now);
        assert_eq!(tenant.deleted_at, None);

        let user_id = Uuid::from_u128(8);
        let mut membership = Membership::new(tenant, user_id, MemberStatus::Active);
        assert_eq!(
            membership.key(),
            MemberKey {
                tenant_id: Uuid::from_u128(7),
                user_id,
            }
        );
        assert!(membership.is_effective());
        membership.tenant.status = TenantStatus::Suspended;
        assert!(!membership.is_effective(), "租户停用 → 成员关系无效");
    }
}
