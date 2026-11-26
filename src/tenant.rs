//! 多租户领域类型:租户、成员关系、角色作用域(平台 / 租户)。
//!
//! 身份模型(spec §4.1):账号全局;租户内的身份 = 成员关系(`tenant_members`)+ 租户角色
//! (`member_roles`);平台角色仍经 `user_roles` 授予。同一角色名只属于一类,由 `roles.scope`
//! 标明 —— 读取时按 scope 过滤(`RoleRepo::roles_for_user` 只回平台角色,`Membership.roles` 只回租户角色)。

use std::fmt;
use std::str::FromStr;

use time::OffsetDateTime;
use uuid::Uuid;

/// 默认租户的固定 id(迁移 0004 插入;app / content / search 各有同值常量)。nil UUID 永远不是合法租户。
pub const DEFAULT_TENANT_ID: Uuid = Uuid::from_u128(1);

/// 库里出现了闭集之外的取值(CHECK 约束兜着,理论上走不到)。
#[derive(Debug)]
pub struct UnknownValue(pub String);

impl fmt::Display for UnknownValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown closed-set value: {}", self.0)
    }
}

impl std::error::Error for UnknownValue {}

/// 闭集字符串枚举的 as_str / FromStr / TryFrom<String> 三件套(库里存小写文本)。
macro_rules! text_enum {
    ($ty:ident { $($variant:ident => $s:literal),* $(,)? }) => {
        impl $ty {
            /// 库里 / 事件 payload 里的文本形式。
            pub fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $s,)*
                }
            }
        }

        impl FromStr for $ty {
            type Err = UnknownValue;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    $($s => Ok(Self::$variant),)*
                    other => Err(UnknownValue(other.to_owned())),
                }
            }
        }

        impl TryFrom<String> for $ty {
            type Error = UnknownValue;
            fn try_from(s: String) -> Result<Self, Self::Error> {
                s.parse()
            }
        }
    };
}

/// 租户状态。`Suspended` = 停用:成员登录 / 切换 / refresh 都进不去。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TenantStatus {
    Active,
    Suspended,
}
text_enum!(TenantStatus { Active => "active", Suspended => "suspended" });

/// 成员状态。`Inactive` = 停用成员:关系和角色保留,但不算有效成员。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MemberStatus {
    Active,
    Inactive,
}
text_enum!(MemberStatus { Active => "active", Inactive => "inactive" });

/// 角色作用域。`Platform` 经 `user_roles` 授予(如 superadmin);`Tenant` 经 `member_roles`
/// 按租户授予(如 admin、user)。由消费方的角色闭集决定,`RoleRepo::upsert` 时传入。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RoleScope {
    Platform,
    Tenant,
}
text_enum!(RoleScope { Platform => "platform", Tenant => "tenant" });

/// 租户。`slug` 全局唯一且**删除后也不复用**;软删用 `deleted_at`。
#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow)]
pub struct Tenant {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    #[sqlx(try_from = "String")]
    pub status: TenantStatus,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub deleted_at: Option<OffsetDateTime>,
}

/// 成员关系:某账号在某租户里的身份。`roles` = 该租户内的**租户角色**名(存活、scope=tenant,按名排序)。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Membership {
    pub tenant: Tenant,
    pub user_id: Uuid,
    pub status: MemberStatus,
    pub roles: Vec<String>,
    /// 最近一次进入该租户(登录 / 切换)的时刻;登录默认进最近的那个。从没进过 = `None`。
    pub last_used_at: Option<OffsetDateTime>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_sets_round_trip_through_text() {
        for s in [TenantStatus::Active, TenantStatus::Suspended] {
            assert_eq!(s.as_str().parse::<TenantStatus>().unwrap(), s);
        }
        for s in [MemberStatus::Active, MemberStatus::Inactive] {
            assert_eq!(s.as_str().parse::<MemberStatus>().unwrap(), s);
        }
        for s in [RoleScope::Platform, RoleScope::Tenant] {
            assert_eq!(RoleScope::try_from(s.as_str().to_owned()).unwrap(), s);
        }
        assert!("nope".parse::<RoleScope>().is_err());
    }

    #[test]
    fn default_tenant_id_is_fixed_and_not_nil() {
        assert_eq!(
            DEFAULT_TENANT_ID.to_string(),
            "00000000-0000-0000-0000-000000000001"
        );
        assert!(!DEFAULT_TENANT_ID.is_nil());
    }
}
