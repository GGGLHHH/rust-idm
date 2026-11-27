//! idm repo 契约一致性:**同一批断言对内存与 PG 的仓储各跑一遍**,钉死行为 parity。
//! 覆盖 user(create/find/update/soft_delete/password/list)、session(create/find_active/revoke)、
//! role(upsert/grant/roles)、outbox,以及多租户的 tenant / member(见 `idm_tenant_contract`)。
//! "内存绿不保证 PG 绿"的漂移,全靠这套契约抓。
//!
//! 内存入口:默认 `cargo test` 就跑(零 DB)。
//! PG 入口:`just test-pg`(需 DATABASE_URL 连 idm role + 跑着的 pg)。

use idm::{
    IdmError, ListPage, ListResult, MemberKey, MemberRepo, MemberStatus, Membership, NewRole,
    NewTenant, NewUser, OutboxRecord, OutboxRepo, RoleGrant, RoleRepo, RoleScope, SessionRepo,
    SortDirection, TenantRepo, TenantStatus, UserListFilter, UserListRow, UserRepo, UserSortBy,
    DEFAULT_TENANT_ID,
};
use serde_json::Value;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

/// 契约唯一真相源。三个 repo 协作(user → session → role),内存与 PG 都调它。
/// PG 有 FK(sessions/user_roles → users),故必须先建 user 再建 session/grant。
async fn idm_repo_contract(
    users: &(impl UserRepo + ?Sized),
    sessions: &(impl SessionRepo + ?Sized),
    roles: &(impl RoleRepo + ?Sized),
) {
    // ── user:create + find(username/email)+ 重复 → Conflict + password_hash ──
    let alice = users
        .create(
            NewUser {
                username: "alice",
                email: Some("a@b.com"),
                password_hash: "hash1",
            },
            Some("sys"),
        )
        .await
        .unwrap();
    assert_eq!(alice.username, "alice");
    assert!(users.find_by_identifier("alice").await.unwrap().is_some());
    assert!(users.find_by_identifier("a@b.com").await.unwrap().is_some());
    assert!(users.find_by_identifier("nobody").await.unwrap().is_none());
    assert_eq!(users.find_by_id(alice.id).await.unwrap().username, "alice");
    assert!(matches!(
        users
            .create(
                NewUser {
                    username: "alice",
                    email: None,
                    password_hash: "h"
                },
                None
            )
            .await,
        Err(IdmError::Conflict(_))
    ));
    assert_eq!(
        users.password_hash(alice.id).await.unwrap().as_deref(),
        Some("hash1")
    );

    // ── find_by_ids:批量富化根原语,内存↔PG parity(命中 + 缺席 + 空集 + 软删过滤)──
    let bob = users
        .create(
            NewUser {
                username: "bob",
                email: None,
                password_hash: "h2",
            },
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        users.find_by_ids(&[alice.id, bob.id]).await.unwrap().len(),
        2
    );
    let missing = Uuid::now_v7();
    assert_eq!(
        users.find_by_ids(&[alice.id, missing]).await.unwrap().len(),
        1
    ); // 不存在的缺席
    assert!(users.find_by_ids(&[]).await.unwrap().is_empty()); // 空集 → 空
    users.soft_delete(bob.id, None).await.unwrap();
    assert!(users.find_by_ids(&[bob.id]).await.unwrap().is_empty()); // 软删后消失(富化降级依据)

    // ── role:upsert 幂等 + grant 幂等 + roles_for_user ──
    let admin_role_id = roles
        .upsert(
            NewRole {
                name: "admin",
                display_name: "管理员",
                scope: RoleScope::Platform,
            },
            Some("sys"),
        )
        .await
        .unwrap();
    assert_eq!(
        roles
            .upsert(
                NewRole {
                    name: "admin",
                    display_name: "管理员",
                    scope: RoleScope::Platform
                },
                None
            )
            .await
            .unwrap(),
        admin_role_id
    ); // 幂等返同 id
    assert!(roles.roles_for_user(alice.id).await.unwrap().is_empty());
    roles
        .grant(
            RoleGrant {
                user_id: alice.id,
                role_id: admin_role_id,
            },
            Some("sys"),
        )
        .await
        .unwrap();
    roles
        .grant(
            RoleGrant {
                user_id: alice.id,
                role_id: admin_role_id,
            },
            None,
        )
        .await
        .unwrap(); // 幂等:不重复授予
    assert_eq!(
        roles.roles_for_user(alice.id).await.unwrap(),
        vec!["admin".to_string()]
    );

    // ── session:create + find_active + 过期 + revoke + revoke_all ──
    let now = OffsetDateTime::now_utc();
    let future = now + Duration::days(7);
    let session = sessions
        .create(alice.id, None, "tokhash1", future, Some("sys"))
        .await
        .unwrap();
    assert!(sessions
        .find_active("tokhash1", now)
        .await
        .unwrap()
        .is_some());
    // 过期(now 推到 expires 之后)→ 不活跃
    assert!(sessions
        .find_active("tokhash1", future + Duration::seconds(1))
        .await
        .unwrap()
        .is_none());
    // revoke → 不活跃
    sessions.revoke(session.id).await.unwrap();
    assert!(sessions
        .find_active("tokhash1", now)
        .await
        .unwrap()
        .is_none());
    // revoke_all:撤销该用户全部
    sessions
        .create(alice.id, None, "tokhash2", future, None)
        .await
        .unwrap();
    sessions
        .create(alice.id, None, "tokhash3", future, None)
        .await
        .unwrap();
    sessions.revoke_all(alice.id, None).await.unwrap();
    assert!(sessions
        .find_active("tokhash2", now)
        .await
        .unwrap()
        .is_none());
    assert!(sessions
        .find_active("tokhash3", now)
        .await
        .unwrap()
        .is_none());

    // ── update + update_password + soft_delete(幂等)──
    let updated = users
        .update(alice.id, "alice2", None, Some("sys"))
        .await
        .unwrap();
    assert_eq!(updated.username, "alice2");
    users.update_password(alice.id, "hash2").await.unwrap();
    assert_eq!(
        users.password_hash(alice.id).await.unwrap().as_deref(),
        Some("hash2")
    );
    users.soft_delete(alice.id, None).await.unwrap();
    assert!(matches!(
        users.find_by_id(alice.id).await,
        Err(IdmError::NotFound)
    ));
    assert!(users.find_by_identifier("alice2").await.unwrap().is_none()); // 软删后查不到
    assert!(matches!(
        users.soft_delete(alice.id, None).await,
        Err(IdmError::NotFound)
    )); // 二次删幂等
}

/// user-admin 原语契约(list 过滤/排序/分页 + create_with_roles 原子/409 + RoleRepo list/set_roles）。
/// 内存与 PG 各跑一遍。断言只用**稳定属性**(username / 计数 / 角色成员),不比跨实现的 id 值。
/// 前提:`users` 与 `roles` **共享**角色/授予状态(内存用 `new_shared_with`,PG 天然共表)。
async fn idm_user_admin_contract(
    users: &(impl UserRepo + ?Sized),
    roles: &(impl RoleRepo + ?Sized),
) {
    fn names(listed: &ListResult<UserListRow>) -> Vec<&str> {
        listed.rows.iter().map(|u| u.username.as_str()).collect()
    }
    let offset = |offset: u64, limit: u64, with_total: bool| ListPage::Offset {
        offset,
        limit,
        with_total,
    };

    // ── 种子:3 角色 + 4 用户(经 create_with_roles,插入序 = id/created 序)──
    let admin = roles
        .upsert(
            NewRole {
                name: "admin",
                display_name: "Admin",
                scope: RoleScope::Platform,
            },
            None,
        )
        .await
        .unwrap();
    let editor = roles
        .upsert(
            NewRole {
                name: "editor",
                display_name: "Editor",
                scope: RoleScope::Platform,
            },
            None,
        )
        .await
        .unwrap();
    let viewer = roles
        .upsert(
            NewRole {
                name: "viewer",
                display_name: "Viewer",
                scope: RoleScope::Platform,
            },
            None,
        )
        .await
        .unwrap();

    let alice = users
        .create_with_roles(
            NewUser {
                username: "alice",
                email: Some("a@x.io"),
                password_hash: "h",
            },
            &[admin],
            None,
        )
        .await
        .unwrap();
    let bob = users
        .create_with_roles(
            NewUser {
                username: "bob",
                email: None,
                password_hash: "h",
            },
            &[editor],
            None,
        )
        .await
        .unwrap();
    let carol = users
        .create_with_roles(
            NewUser {
                username: "carol",
                email: Some("c@x.io"),
                password_hash: "h",
            },
            &[admin, editor],
            None,
        )
        .await
        .unwrap();
    let _dave = users
        .create_with_roles(
            NewUser {
                username: "dave",
                email: None,
                password_hash: "h",
            },
            &[],
            None,
        )
        .await
        .unwrap();

    // ── create_with_roles:唯一冲突 → Conflict;角色确实被关联 ──
    assert!(matches!(
        users
            .create_with_roles(
                NewUser {
                    username: "alice",
                    email: None,
                    password_hash: "h"
                },
                &[],
                None
            )
            .await,
        Err(IdmError::Conflict(_))
    ));
    let mut carol_roles = roles.roles_for_user(carol.id).await.unwrap();
    carol_roles.sort();
    assert_eq!(carol_roles, vec!["admin".to_string(), "editor".to_string()]);

    // ── username 模糊(含 "a",大小写不敏感)→ alice, carol, dave(bob 无 a)──
    let filter = UserListFilter {
        username: Some("A".into()),
        ..Default::default()
    };
    let listed = users
        .list(
            &filter,
            UserSortBy::Username,
            SortDirection::Ascending,
            &offset(0, 10, true),
        )
        .await
        .unwrap();
    assert_eq!(names(&listed), ["alice", "carol", "dave"]);
    assert_eq!(listed.total, Some(3));
    // roles 列:alice 的 roles = [admin]
    assert_eq!(listed.rows[0].roles, vec!["admin".to_string()]);

    // ── roles_any = [admin] → alice, carol ──
    let filter = UserListFilter {
        roles_any: vec!["admin".into()],
        ..Default::default()
    };
    let listed = users
        .list(
            &filter,
            UserSortBy::Username,
            SortDirection::Ascending,
            &offset(0, 10, false),
        )
        .await
        .unwrap();
    assert_eq!(names(&listed), ["alice", "carol"]);
    assert!(listed.total.is_none());

    // ── roles_none = [admin] → bob, dave ──
    let filter = UserListFilter {
        roles_none: vec!["admin".into()],
        ..Default::default()
    };
    let listed = users
        .list(
            &filter,
            UserSortBy::Username,
            SortDirection::Ascending,
            &offset(0, 10, false),
        )
        .await
        .unwrap();
    assert_eq!(names(&listed), ["bob", "dave"]);

    // ── sort Email Ascending NULLS LAST:非空升序(a@x.io<c@x.io)后接空(id 升序:bob<dave)──
    let listed = users
        .list(
            &UserListFilter::default(),
            UserSortBy::Email,
            SortDirection::Ascending,
            &offset(0, 10, false),
        )
        .await
        .unwrap();
    assert_eq!(names(&listed), ["alice", "carol", "bob", "dave"]);
    // Email Descending NULLS LAST:非空降序(carol,alice)后接空(id 降序:dave,bob)
    let listed = users
        .list(
            &UserListFilter::default(),
            UserSortBy::Email,
            SortDirection::Descending,
            &offset(0, 10, false),
        )
        .await
        .unwrap();
    assert_eq!(names(&listed), ["carol", "alice", "dave", "bob"]);

    // ── sort CreatedAt:asc = 插入序,desc = 逆序 ──
    let listed = users
        .list(
            &UserListFilter::default(),
            UserSortBy::CreatedAt,
            SortDirection::Ascending,
            &offset(0, 10, false),
        )
        .await
        .unwrap();
    assert_eq!(names(&listed), ["alice", "bob", "carol", "dave"]);
    let listed = users
        .list(
            &UserListFilter::default(),
            UserSortBy::CreatedAt,
            SortDirection::Descending,
            &offset(0, 10, false),
        )
        .await
        .unwrap();
    assert_eq!(names(&listed), ["dave", "carol", "bob", "alice"]);

    // ── offset 分页:username asc, offset=1 limit=2, with_total ──
    let listed = users
        .list(
            &UserListFilter::default(),
            UserSortBy::Username,
            SortDirection::Ascending,
            &offset(1, 2, true),
        )
        .await
        .unwrap();
    assert_eq!(names(&listed), ["bob", "carol"]);
    assert_eq!(listed.total, Some(4));

    // ── cursor(created desc ≈ id desc):首页 limit=2 → dave, carol + next_after=Some ──
    let first_page = users
        .list(
            &UserListFilter::default(),
            UserSortBy::CreatedAt,
            SortDirection::Descending,
            &ListPage::Cursor {
                after: None,
                limit: 2,
            },
        )
        .await
        .unwrap();
    assert_eq!(names(&first_page), ["dave", "carol"]);
    let after = first_page.next_after.expect("首页应有下一页游标");
    // 次页:after=carol 游标 → bob, alice + 无更多
    let second_page = users
        .list(
            &UserListFilter::default(),
            UserSortBy::CreatedAt,
            SortDirection::Descending,
            &ListPage::Cursor {
                after: Some(after),
                limit: 2,
            },
        )
        .await
        .unwrap();
    assert_eq!(names(&second_page), ["bob", "alice"]);
    assert!(second_page.next_after.is_none());

    // ── RoleRepo::list:3 存活角色,按 name 排序 ──
    let role_list = roles.list().await.unwrap();
    let role_names: Vec<&str> = role_list.iter().map(|role| role.name.as_str()).collect();
    assert_eq!(role_names, ["admin", "editor", "viewer"]);
    assert_eq!(role_list[0].display_name, "Admin");

    // ── set_roles:全量替换(alice: admin → editor+viewer),幂等 ──
    roles
        .set_roles(alice.id, &[editor, viewer], None)
        .await
        .unwrap();
    let mut got = roles.roles_for_user(alice.id).await.unwrap();
    got.sort();
    assert_eq!(got, vec!["editor".to_string(), "viewer".to_string()]);
    // 幂等:再设一次相同,结果稳定
    roles
        .set_roles(alice.id, &[editor, viewer], None)
        .await
        .unwrap();
    let mut got_again = roles.roles_for_user(alice.id).await.unwrap();
    got_again.sort();
    assert_eq!(got_again, vec!["editor".to_string(), "viewer".to_string()]);

    // set_roles 反映到 list:roles_any=[admin] 现在只剩 carol(alice 已去 admin)
    let filter = UserListFilter {
        roles_any: vec!["admin".into()],
        ..Default::default()
    };
    let listed = users
        .list(
            &filter,
            UserSortBy::Username,
            SortDirection::Ascending,
            &offset(0, 10, false),
        )
        .await
        .unwrap();
    assert_eq!(names(&listed), ["carol"]);

    // ── LIKE 元字符转义:username 过滤按字面匹配(_ / % 非通配),内存↔PG parity ──
    // 造 a_b / axb / a%b / ayb:未转义时 "a_b"(_=任意单字符)会误命中全部四个。
    for username in ["a_b", "axb", "a%b", "ayb"] {
        users
            .create_with_roles(
                NewUser {
                    username,
                    email: None,
                    password_hash: "h",
                },
                &[],
                None,
            )
            .await
            .unwrap();
    }
    let filter = UserListFilter {
        username: Some("a_b".into()),
        ..Default::default()
    };
    let listed = users
        .list(
            &filter,
            UserSortBy::Username,
            SortDirection::Ascending,
            &offset(0, 10, false),
        )
        .await
        .unwrap();
    assert_eq!(names(&listed), ["a_b"]); // 字面下划线:只命中 a_b,不含 axb/ayb/a%b
    let filter = UserListFilter {
        username: Some("a%b".into()),
        ..Default::default()
    };
    let listed = users
        .list(
            &filter,
            UserSortBy::Username,
            SortDirection::Ascending,
            &offset(0, 10, false),
        )
        .await
        .unwrap();
    assert_eq!(names(&listed), ["a%b"]); // 字面百分号:只命中 a%b

    // ── 排序 collation parity:混合大小写按字节序(C collation),内存↔PG 必须同序 ──
    // expected 由 Rust str Ord 现算(= 字节序 = COLLATE "C"),两后端都须等于它 → 真 parity。
    // 无 COLLATE "C" 时 PG 按库默认 collation(可能大小写不敏感)会漂移、断言挂。
    let mixed = ["Mx-Bob", "Mx-alice", "Mx-Carol", "Mx-dave"];
    for username in mixed {
        users
            .create_with_roles(
                NewUser {
                    username,
                    email: None,
                    password_hash: "h",
                },
                &[],
                None,
            )
            .await
            .unwrap();
    }
    let filter = UserListFilter {
        username: Some("Mx-".into()),
        ..Default::default()
    };
    let listed = users
        .list(
            &filter,
            UserSortBy::Username,
            SortDirection::Ascending,
            &offset(0, 10, false),
        )
        .await
        .unwrap();
    let mut expected = mixed.to_vec();
    expected.sort_unstable();
    assert_eq!(names(&listed), expected);

    let _ = bob;
}

/// outbox 事件契约:每个写方法在自己的事务/锁内 emit 一条领域事件,payload 形状正确,
/// 失败路径(唯一冲突 / 非法 role_id)不留残留行。内存(三件套共享存储)与 PG(天然共表)各跑一遍。
async fn idm_outbox_contract(
    users: &(impl UserRepo + ?Sized),
    roles: &(impl RoleRepo + ?Sized),
    outbox: &(impl OutboxRepo + ?Sized),
) {
    assert!(outbox.poll_unpublished(100).await.unwrap().is_empty());

    let editor = roles
        .upsert(
            NewRole {
                name: "editor",
                display_name: "Editor",
                scope: RoleScope::Platform,
            },
            None,
        )
        .await
        .unwrap();
    let viewer = roles
        .upsert(
            NewRole {
                name: "viewer",
                display_name: "Viewer",
                scope: RoleScope::Platform,
            },
            None,
        )
        .await
        .unwrap();

    // ── create_with_roles → 恰一条 user.created,payload 含正确角色名 ──
    let dana = users
        .create_with_roles(
            NewUser {
                username: "dana",
                email: Some("dana@x.io"),
                password_hash: "h",
            },
            &[editor],
            None,
        )
        .await
        .unwrap();
    let rows = outbox.poll_unpublished(100).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].event_type, "user.created");
    assert_eq!(rows[0].aggregate_id, dana.id);
    let payload = &rows[0].payload;
    assert_eq!(payload["user_id"], serde_json::to_value(dana.id).unwrap());
    assert_eq!(payload["username"], "dana");
    assert_eq!(payload["email"], "dana@x.io");
    assert_eq!(payload["email_verified"], false);
    assert_eq!(
        payload["created_at"],
        serde_json::to_value(dana.created_at).unwrap()
    );
    assert_eq!(payload["roles"], serde_json::json!(["editor"]));
    outbox.mark_published(&[rows[0].id]).await.unwrap();

    // ── create(无角色)→ user.created,roles = [] ──
    let erin = users
        .create(
            NewUser {
                username: "erin",
                email: None,
                password_hash: "h",
            },
            None,
        )
        .await
        .unwrap();
    let rows = outbox.poll_unpublished(100).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].event_type, "user.created");
    assert_eq!(rows[0].aggregate_id, erin.id);
    assert_eq!(rows[0].payload["roles"], serde_json::json!([]));
    assert_eq!(rows[0].payload["email"], Value::Null);
    outbox.mark_published(&[rows[0].id]).await.unwrap();

    // ── update → 恰一条 user.updated ──
    users
        .update(dana.id, "dana2", Some("dana2@x.io"), None)
        .await
        .unwrap();
    let rows = outbox.poll_unpublished(100).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].event_type, "user.updated");
    assert_eq!(rows[0].aggregate_id, dana.id);
    assert_eq!(rows[0].payload["username"], "dana2");
    assert_eq!(rows[0].payload["email"], "dana2@x.io");
    assert_eq!(rows[0].payload["email_verified"], false);
    outbox.mark_published(&[rows[0].id]).await.unwrap();

    // ── update_password → 不 emit ──
    users.update_password(dana.id, "h2").await.unwrap();
    assert!(outbox.poll_unpublished(100).await.unwrap().is_empty());

    // ── set_roles → 恰一条 user.roles_set,roles = 替换后的结果 ──
    roles.set_roles(dana.id, &[viewer], None).await.unwrap();
    let rows = outbox.poll_unpublished(100).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].event_type, "user.roles_set");
    assert_eq!(rows[0].aggregate_id, dana.id);
    assert_eq!(rows[0].payload["roles"], serde_json::json!(["viewer"]));
    outbox.mark_published(&[rows[0].id]).await.unwrap();

    // ── soft_delete → 恰一条 user.deleted ──
    users.soft_delete(dana.id, None).await.unwrap();
    let rows = outbox.poll_unpublished(100).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].event_type, "user.deleted");
    assert_eq!(rows[0].aggregate_id, dana.id);
    assert_eq!(
        rows[0].payload["user_id"],
        serde_json::to_value(dana.id).unwrap()
    );
    outbox.mark_published(&[rows[0].id]).await.unwrap();

    // ── 回滚:重名 create_with_roles 失败 → 无残留 ──
    assert!(users
        .create_with_roles(
            NewUser {
                username: "erin",
                email: None,
                password_hash: "h"
            },
            &[],
            None
        )
        .await
        .is_err());
    assert!(outbox.poll_unpublished(100).await.unwrap().is_empty());

    // ── 回滚:非法 role_id 的 create_with_roles 失败 → 无残留,且两后端同一 NotFound 变体 ──
    let bogus_role = Uuid::now_v7();
    let error = users
        .create_with_roles(
            NewUser {
                username: "frank",
                email: None,
                password_hash: "h",
            },
            &[bogus_role],
            None,
        )
        .await
        .err()
        .unwrap();
    assert!(
        matches!(error, IdmError::NotFound),
        "invalid role_id must be NotFound, got {error:?}"
    );
    assert!(outbox.poll_unpublished(100).await.unwrap().is_empty());

    // ── 回滚:非法 role_id 的 set_roles 失败 → 无残留,且两后端同一 NotFound 变体 ──
    let error = roles
        .set_roles(erin.id, &[bogus_role], None)
        .await
        .unwrap_err();
    assert!(
        matches!(error, IdmError::NotFound),
        "invalid role_id must be NotFound, got {error:?}"
    );
    assert!(outbox.poll_unpublished(100).await.unwrap().is_empty());
}

/// 多租户数据层契约:租户 / 成员 / 租户角色 / 平台角色过滤 / 按租户吊销会话 / tenant.* 事件。
/// 每个用例一个 async fn,内存(全部 repo 共享存储)与 PG(天然共表)各跑一遍。
/// **两边都有默认租户**:PG 由迁移 0004 插入,内存实现构造时镜像插入 —— 断言据此写。
mod idm_tenant_contract {
    #[cfg(feature = "pg-conformance")]
    use sqlx::PgPool;

    use super::*;

    /// 一个用例要用到的全部仓储(内存侧共享存储,PG 侧共一个库)。
    pub(crate) struct Repos {
        pub users: Box<dyn UserRepo>,
        pub roles: Box<dyn RoleRepo>,
        pub sessions: Box<dyn SessionRepo>,
        pub tenants: Box<dyn TenantRepo>,
        pub members: Box<dyn MemberRepo>,
        pub outbox: Box<dyn OutboxRepo>,
    }

    impl Repos {
        fn memory() -> Self {
            use idm::{
                InMemoryMemberRepo, InMemoryOutboxRepo, InMemoryRoleRepo, InMemorySessionRepo,
                InMemoryTenantRepo, InMemoryUserRepo,
            };

            let users = InMemoryUserRepo::new();
            Self {
                roles: Box::new(InMemoryRoleRepo::new_shared_with(&users)),
                sessions: Box::new(InMemorySessionRepo::new_shared_with(&users)),
                tenants: Box::new(InMemoryTenantRepo::new_shared_with(&users)),
                members: Box::new(InMemoryMemberRepo::new_shared_with(&users)),
                outbox: Box::new(InMemoryOutboxRepo::new_shared_with(&users)),
                users: Box::new(users),
            }
        }

        #[cfg(feature = "pg-conformance")]
        pub(crate) fn pg(pool: PgPool) -> Self {
            use idm::{
                PgMemberRepo, PgOutboxRepo, PgRoleRepo, PgSessionRepo, PgTenantRepo, PgUserRepo,
            };

            Self {
                users: Box::new(PgUserRepo::new(pool.clone())),
                roles: Box::new(PgRoleRepo::new(pool.clone())),
                sessions: Box::new(PgSessionRepo::new(pool.clone())),
                tenants: Box::new(PgTenantRepo::new(pool.clone())),
                members: Box::new(PgMemberRepo::new(pool.clone())),
                outbox: Box::new(PgOutboxRepo::new(pool)),
            }
        }

        /// 把发件箱里已有的行全标已发布(建用户等前置动作会 emit user.*,事件用例只看之后的)。
        async fn drain_outbox(&self) {
            let ids: Vec<i64> = self
                .outbox
                .poll_unpublished(1000)
                .await
                .unwrap()
                .iter()
                .map(|r| r.id)
                .collect();
            self.outbox.mark_published(&ids).await.unwrap();
        }
    }

    fn tenant_ids(memberships: &[Membership]) -> Vec<Uuid> {
        memberships.iter().map(|m| m.tenant.id).collect()
    }

    pub(crate) async fn add_member_then_memberships_for_user_lists_it(repos: Repos) {
        let alice = repos
            .users
            .create(
                NewUser {
                    username: "alice",
                    email: None,
                    password_hash: "h",
                },
                None,
            )
            .await
            .unwrap();
        let bob = repos
            .users
            .create(
                NewUser {
                    username: "bob",
                    email: None,
                    password_hash: "h",
                },
                None,
            )
            .await
            .unwrap();
        let tenant_admin_role = repos
            .roles
            .upsert(
                NewRole {
                    name: "t_admin",
                    display_name: "租户管理员",
                    scope: RoleScope::Tenant,
                },
                None,
            )
            .await
            .unwrap();
        let acme = repos
            .tenants
            .create(
                NewTenant {
                    slug: "acme",
                    name: "Acme",
                },
                Some("sys"),
            )
            .await
            .unwrap();
        assert_eq!(acme.slug, "acme");
        assert_eq!(acme.status, TenantStatus::Active);
        assert!(acme.deleted_at.is_none());
        assert!(repos
            .members
            .memberships_for_user(alice.id)
            .await
            .unwrap()
            .is_empty());

        let membership = repos
            .members
            .add(
                MemberKey {
                    tenant_id: acme.id,
                    user_id: alice.id,
                },
                &[tenant_admin_role],
                Some("sys"),
            )
            .await
            .unwrap();
        assert_eq!(membership.tenant.id, acme.id);
        assert_eq!(membership.user_id, alice.id);
        assert_eq!(membership.status, MemberStatus::Active);
        assert_eq!(membership.roles, vec!["t_admin".to_string()]);
        assert!(membership.last_used_at.is_none());

        let memberships = repos.members.memberships_for_user(alice.id).await.unwrap();
        assert_eq!(tenant_ids(&memberships), vec![acme.id]);
        assert_eq!(memberships[0].tenant.slug, "acme");
        assert_eq!(memberships[0].roles, vec!["t_admin".to_string()]);

        // get:成员 Some、非成员 None
        assert!(repos
            .members
            .get(MemberKey {
                tenant_id: acme.id,
                user_id: alice.id
            })
            .await
            .unwrap()
            .is_some());
        assert!(repos
            .members
            .get(MemberKey {
                tenant_id: acme.id,
                user_id: bob.id
            })
            .await
            .unwrap()
            .is_none());

        // 重复加 → Conflict;不存在的租户 → NotFound;非法 role_id → NotFound(且不留半截)
        assert!(matches!(
            repos
                .members
                .add(
                    MemberKey {
                        tenant_id: acme.id,
                        user_id: alice.id
                    },
                    &[],
                    None
                )
                .await,
            Err(IdmError::Conflict(_))
        ));
        assert!(matches!(
            repos
                .members
                .add(
                    MemberKey {
                        tenant_id: Uuid::now_v7(),
                        user_id: alice.id
                    },
                    &[],
                    None
                )
                .await,
            Err(IdmError::NotFound)
        ));
        assert!(matches!(
            repos
                .members
                .add(
                    MemberKey {
                        tenant_id: acme.id,
                        user_id: bob.id
                    },
                    &[Uuid::now_v7()],
                    None
                )
                .await,
            Err(IdmError::NotFound)
        ));
        assert!(repos
            .members
            .get(MemberKey {
                tenant_id: acme.id,
                user_id: bob.id
            })
            .await
            .unwrap()
            .is_none());

        // list_by_tenant:只有 alice
        let page = repos
            .members
            .list_by_tenant(
                acme.id,
                &ListPage::Offset {
                    offset: 0,
                    limit: 10,
                    with_total: true,
                },
            )
            .await
            .unwrap();
        assert_eq!(page.total, Some(1));
        assert_eq!(page.rows.len(), 1);
        assert_eq!(page.rows[0].user_id, alice.id);

        // 多个租户:last_used_at 最近的排最前(登录默认进它),从没用过的(NULL)排最后
        let beta = repos
            .tenants
            .create(
                NewTenant {
                    slug: "beta",
                    name: "Beta",
                },
                None,
            )
            .await
            .unwrap();
        repos
            .members
            .add(
                MemberKey {
                    tenant_id: beta.id,
                    user_id: alice.id,
                },
                &[],
                None,
            )
            .await
            .unwrap();
        repos
            .members
            .touch_last_used(MemberKey {
                tenant_id: beta.id,
                user_id: alice.id,
            })
            .await
            .unwrap();
        let memberships = repos.members.memberships_for_user(alice.id).await.unwrap();
        assert_eq!(tenant_ids(&memberships), vec![beta.id, acme.id]);
        assert!(memberships[0].last_used_at.is_some());
        assert!(memberships[1].last_used_at.is_none());
        // 非成员 touch → NotFound
        assert!(matches!(
            repos
                .members
                .touch_last_used(MemberKey {
                    tenant_id: beta.id,
                    user_id: bob.id
                })
                .await,
            Err(IdmError::NotFound)
        ));
    }

    pub(crate) async fn suspended_tenant_excluded_from_memberships(repos: Repos) {
        let alice = repos
            .users
            .create(
                NewUser {
                    username: "alice",
                    email: None,
                    password_hash: "h",
                },
                None,
            )
            .await
            .unwrap();
        let tenant1 = repos
            .tenants
            .create(
                NewTenant {
                    slug: "t1",
                    name: "T1",
                },
                None,
            )
            .await
            .unwrap();
        let tenant2 = repos
            .tenants
            .create(
                NewTenant {
                    slug: "t2",
                    name: "T2",
                },
                None,
            )
            .await
            .unwrap();
        repos
            .members
            .add(
                MemberKey {
                    tenant_id: tenant1.id,
                    user_id: alice.id,
                },
                &[],
                None,
            )
            .await
            .unwrap();
        repos
            .members
            .add(
                MemberKey {
                    tenant_id: tenant2.id,
                    user_id: alice.id,
                },
                &[],
                None,
            )
            .await
            .unwrap();
        let mut both = tenant_ids(&repos.members.memberships_for_user(alice.id).await.unwrap());
        both.sort();
        assert_eq!(both, vec![tenant1.id, tenant2.id]);

        let suspended = repos
            .tenants
            .set_status(tenant1.id, TenantStatus::Suspended, None)
            .await
            .unwrap();
        assert_eq!(suspended.status, TenantStatus::Suspended);
        assert_eq!(
            repos.tenants.get(tenant1.id).await.unwrap().status,
            TenantStatus::Suspended
        );
        assert_eq!(
            tenant_ids(&repos.members.memberships_for_user(alice.id).await.unwrap()),
            vec![tenant2.id]
        );
        // 停用租户的成员关系本身还在(get 不过滤状态,由调用方判断)
        let membership = repos
            .members
            .get(MemberKey {
                tenant_id: tenant1.id,
                user_id: alice.id,
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(membership.tenant.status, TenantStatus::Suspended);

        // 恢复 → 又回来
        repos
            .tenants
            .set_status(tenant1.id, TenantStatus::Active, None)
            .await
            .unwrap();
        assert_eq!(
            repos
                .members
                .memberships_for_user(alice.id)
                .await
                .unwrap()
                .len(),
            2
        );

        // 软删租户 → 也不在列表里;get / get_by_slug → NotFound;改它 → NotFound
        repos.tenants.soft_delete(tenant2.id, None).await.unwrap();
        assert_eq!(
            tenant_ids(&repos.members.memberships_for_user(alice.id).await.unwrap()),
            vec![tenant1.id]
        );
        assert!(matches!(
            repos.tenants.get(tenant2.id).await,
            Err(IdmError::NotFound)
        ));
        assert!(matches!(
            repos.tenants.get_by_slug("t2").await,
            Err(IdmError::NotFound)
        ));
        assert!(matches!(
            repos
                .tenants
                .set_status(tenant2.id, TenantStatus::Active, None)
                .await,
            Err(IdmError::NotFound)
        ));
        assert!(matches!(
            repos.tenants.soft_delete(tenant2.id, None).await,
            Err(IdmError::NotFound)
        ));
        assert!(matches!(
            repos
                .tenants
                .set_status(Uuid::now_v7(), TenantStatus::Active, None)
                .await,
            Err(IdmError::NotFound)
        ));
    }

    pub(crate) async fn inactive_member_excluded(repos: Repos) {
        let alice = repos
            .users
            .create(
                NewUser {
                    username: "alice",
                    email: None,
                    password_hash: "h",
                },
                None,
            )
            .await
            .unwrap();
        let bob = repos
            .users
            .create(
                NewUser {
                    username: "bob",
                    email: None,
                    password_hash: "h",
                },
                None,
            )
            .await
            .unwrap();
        let tenant = repos
            .tenants
            .create(
                NewTenant {
                    slug: "acme",
                    name: "Acme",
                },
                None,
            )
            .await
            .unwrap();
        repos
            .members
            .add(
                MemberKey {
                    tenant_id: tenant.id,
                    user_id: alice.id,
                },
                &[],
                None,
            )
            .await
            .unwrap();
        repos
            .members
            .add(
                MemberKey {
                    tenant_id: tenant.id,
                    user_id: bob.id,
                },
                &[],
                None,
            )
            .await
            .unwrap();

        repos
            .members
            .set_status(
                MemberKey {
                    tenant_id: tenant.id,
                    user_id: alice.id,
                },
                MemberStatus::Inactive,
                None,
            )
            .await
            .unwrap();
        assert!(repos
            .members
            .memberships_for_user(alice.id)
            .await
            .unwrap()
            .is_empty());
        // 只影响 alice
        assert_eq!(
            repos
                .members
                .memberships_for_user(bob.id)
                .await
                .unwrap()
                .len(),
            1
        );
        // get 仍能看到(带状态),list_by_tenant 也列出(管理端要看停用成员)
        let membership = repos
            .members
            .get(MemberKey {
                tenant_id: tenant.id,
                user_id: alice.id,
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(membership.status, MemberStatus::Inactive);
        let page = repos
            .members
            .list_by_tenant(
                tenant.id,
                &ListPage::Offset {
                    offset: 0,
                    limit: 10,
                    with_total: true,
                },
            )
            .await
            .unwrap();
        assert_eq!(page.total, Some(2));

        // 恢复
        repos
            .members
            .set_status(
                MemberKey {
                    tenant_id: tenant.id,
                    user_id: alice.id,
                },
                MemberStatus::Active,
                None,
            )
            .await
            .unwrap();
        assert_eq!(
            repos
                .members
                .memberships_for_user(alice.id)
                .await
                .unwrap()
                .len(),
            1
        );
        // 非成员 → NotFound
        assert!(matches!(
            repos
                .members
                .set_status(
                    MemberKey {
                        tenant_id: Uuid::now_v7(),
                        user_id: alice.id
                    },
                    MemberStatus::Inactive,
                    None
                )
                .await,
            Err(IdmError::NotFound)
        ));
    }

    pub(crate) async fn slug_not_reusable_after_delete(repos: Repos) {
        let tenant = repos
            .tenants
            .create(
                NewTenant {
                    slug: "acme",
                    name: "Acme",
                },
                None,
            )
            .await
            .unwrap();
        assert_eq!(
            repos.tenants.get_by_slug("acme").await.unwrap().id,
            tenant.id
        );
        assert!(matches!(
            repos
                .tenants
                .create(
                    NewTenant {
                        slug: "acme",
                        name: "Other"
                    },
                    None
                )
                .await,
            Err(IdmError::Conflict(_))
        ));
        repos.tenants.soft_delete(tenant.id, None).await.unwrap();
        assert!(matches!(
            repos.tenants.get_by_slug("acme").await,
            Err(IdmError::NotFound)
        ));
        // 删除后 slug 仍占着:不复用
        assert!(matches!(
            repos
                .tenants
                .create(
                    NewTenant {
                        slug: "acme",
                        name: "Again"
                    },
                    None
                )
                .await,
            Err(IdmError::Conflict(_))
        ));

        // upsert_fixed:默认租户两边都已在(PG 迁移 / 内存构造),幂等返回同一行
        let default_tenant = repos
            .tenants
            .upsert_fixed(
                DEFAULT_TENANT_ID,
                NewTenant {
                    slug: "default",
                    name: "默认组织",
                },
                None,
            )
            .await
            .unwrap();
        assert_eq!(default_tenant.id, DEFAULT_TENANT_ID);
        assert_eq!(default_tenant.slug, "default");
        let default_again = repos
            .tenants
            .upsert_fixed(
                DEFAULT_TENANT_ID,
                NewTenant {
                    slug: "default",
                    name: "默认组织",
                },
                None,
            )
            .await
            .unwrap();
        assert_eq!(default_again.id, DEFAULT_TENANT_ID);
        // 新的固定 id:建出来;再调幂等
        let fixed = Uuid::from_u128(0x42);
        let fixed_tenant = repos
            .tenants
            .upsert_fixed(
                fixed,
                NewTenant {
                    slug: "fixed",
                    name: "Fixed",
                },
                None,
            )
            .await
            .unwrap();
        assert_eq!(
            (fixed_tenant.id, fixed_tenant.slug.as_str()),
            (fixed, "fixed")
        );
        assert_eq!(
            repos
                .tenants
                .upsert_fixed(
                    fixed,
                    NewTenant {
                        slug: "fixed",
                        name: "Fixed"
                    },
                    None
                )
                .await
                .unwrap()
                .id,
            fixed
        );
        // slug 被别的 id 占了 → Conflict(含已删的 acme)
        assert!(matches!(
            repos
                .tenants
                .upsert_fixed(
                    Uuid::from_u128(0x43),
                    NewTenant {
                        slug: "acme",
                        name: "X"
                    },
                    None
                )
                .await,
            Err(IdmError::Conflict(_))
        ));

        // update_name
        let renamed = repos
            .tenants
            .update_name(fixed, "Fixed 2", None)
            .await
            .unwrap();
        assert_eq!(renamed.name, "Fixed 2");
        assert_eq!(renamed.slug, "fixed");

        // list:只见存活(default + fixed;acme 已删),按 id 升序;cursor 翻页
        let all = repos
            .tenants
            .list(&ListPage::Offset {
                offset: 0,
                limit: 10,
                with_total: true,
            })
            .await
            .unwrap();
        assert_eq!(all.total, Some(2));
        let tenant_ids: Vec<Uuid> = all.rows.iter().map(|tenant| tenant.id).collect();
        assert_eq!(tenant_ids, vec![DEFAULT_TENANT_ID, fixed]);
        let first_page = repos
            .tenants
            .list(&ListPage::Cursor {
                after: None,
                limit: 1,
            })
            .await
            .unwrap();
        assert_eq!(first_page.rows[0].id, DEFAULT_TENANT_ID);
        let second_page = repos
            .tenants
            .list(&ListPage::Cursor {
                after: first_page.next_after,
                limit: 1,
            })
            .await
            .unwrap();
        assert_eq!(second_page.rows[0].id, fixed);
        assert!(second_page.next_after.is_none());
    }

    pub(crate) async fn roles_for_user_returns_platform_scope_only(repos: Repos) {
        let alice = repos
            .users
            .create(
                NewUser {
                    username: "alice",
                    email: None,
                    password_hash: "h",
                },
                None,
            )
            .await
            .unwrap();
        let platform_role = repos
            .roles
            .upsert(
                NewRole {
                    name: "sa",
                    display_name: "平台管理员",
                    scope: RoleScope::Platform,
                },
                None,
            )
            .await
            .unwrap();
        let tenant_role = repos
            .roles
            .upsert(
                NewRole {
                    name: "ta",
                    display_name: "租户角色",
                    scope: RoleScope::Tenant,
                },
                None,
            )
            .await
            .unwrap();
        repos
            .roles
            .grant(
                RoleGrant {
                    user_id: alice.id,
                    role_id: platform_role,
                },
                None,
            )
            .await
            .unwrap();
        repos
            .roles
            .grant(
                RoleGrant {
                    user_id: alice.id,
                    role_id: tenant_role,
                },
                None,
            )
            .await
            .unwrap();
        assert_eq!(
            repos.roles.roles_for_user(alice.id).await.unwrap(),
            vec!["sa".to_string()]
        );
        // 目录带 scope
        let list = repos.roles.list().await.unwrap();
        let scope_of = |name: &str| list.iter().find(|x| x.name == name).unwrap().scope;
        assert_eq!(scope_of("sa"), RoleScope::Platform);
        assert_eq!(scope_of("ta"), RoleScope::Tenant);

        // 成员角色读取同样按 scope 过滤:平台角色挂进 member_roles 也不算租户角色
        let tenant = repos
            .tenants
            .create(
                NewTenant {
                    slug: "acme",
                    name: "Acme",
                },
                None,
            )
            .await
            .unwrap();
        let membership = repos
            .members
            .add(
                MemberKey {
                    tenant_id: tenant.id,
                    user_id: alice.id,
                },
                &[platform_role, tenant_role],
                None,
            )
            .await
            .unwrap();
        assert_eq!(membership.roles, vec!["ta".to_string()]);

        // upsert 以调用方 scope 为准(代码闭集是真相源):同名再 upsert 成 platform → 改 scope、id 不变
        assert_eq!(
            repos
                .roles
                .upsert(
                    NewRole {
                        name: "ta",
                        display_name: "租户角色",
                        scope: RoleScope::Platform
                    },
                    None
                )
                .await
                .unwrap(),
            tenant_role
        );
        let mut got = repos.roles.roles_for_user(alice.id).await.unwrap();
        got.sort();
        assert_eq!(got, vec!["sa".to_string(), "ta".to_string()]);
        assert!(repos
            .members
            .get(MemberKey {
                tenant_id: tenant.id,
                user_id: alice.id
            })
            .await
            .unwrap()
            .unwrap()
            .roles
            .is_empty());
    }

    pub(crate) async fn member_roles_are_per_tenant(repos: Repos) {
        let alice = repos
            .users
            .create(
                NewUser {
                    username: "alice",
                    email: None,
                    password_hash: "h",
                },
                None,
            )
            .await
            .unwrap();
        let admin = repos
            .roles
            .upsert(
                NewRole {
                    name: "t_admin",
                    display_name: "A",
                    scope: RoleScope::Tenant,
                },
                None,
            )
            .await
            .unwrap();
        let user = repos
            .roles
            .upsert(
                NewRole {
                    name: "t_user",
                    display_name: "U",
                    scope: RoleScope::Tenant,
                },
                None,
            )
            .await
            .unwrap();
        let tenant1 = repos
            .tenants
            .create(
                NewTenant {
                    slug: "t1",
                    name: "T1",
                },
                None,
            )
            .await
            .unwrap();
        let tenant2 = repos
            .tenants
            .create(
                NewTenant {
                    slug: "t2",
                    name: "T2",
                },
                None,
            )
            .await
            .unwrap();
        repos
            .members
            .add(
                MemberKey {
                    tenant_id: tenant1.id,
                    user_id: alice.id,
                },
                &[admin],
                None,
            )
            .await
            .unwrap();
        repos
            .members
            .add(
                MemberKey {
                    tenant_id: tenant2.id,
                    user_id: alice.id,
                },
                &[user],
                None,
            )
            .await
            .unwrap();

        let roles_in = |tenant_id: Uuid| {
            let members = &repos.members;
            let user_id = alice.id;
            async move {
                members
                    .get(MemberKey { tenant_id, user_id })
                    .await
                    .unwrap()
                    .unwrap()
                    .roles
            }
        };
        assert_eq!(roles_in(tenant1.id).await, vec!["t_admin".to_string()]);
        assert_eq!(roles_in(tenant2.id).await, vec!["t_user".to_string()]);
        // 租户角色不进平台角色
        assert!(repos
            .roles
            .roles_for_user(alice.id)
            .await
            .unwrap()
            .is_empty());

        // set_roles 全量替换只动 t1;结果按名排序
        repos
            .members
            .set_roles(
                MemberKey {
                    tenant_id: tenant1.id,
                    user_id: alice.id,
                },
                &[user, admin],
                None,
            )
            .await
            .unwrap();
        assert_eq!(
            roles_in(tenant1.id).await,
            vec!["t_admin".to_string(), "t_user".to_string()]
        );
        assert_eq!(roles_in(tenant2.id).await, vec!["t_user".to_string()]);
        // 幂等
        repos
            .members
            .set_roles(
                MemberKey {
                    tenant_id: tenant1.id,
                    user_id: alice.id,
                },
                &[user, admin],
                None,
            )
            .await
            .unwrap();
        assert_eq!(roles_in(tenant1.id).await.len(), 2);
        // memberships_for_user 每个租户带各自角色
        let memberships = repos.members.memberships_for_user(alice.id).await.unwrap();
        let roles_of = |tenant_id: Uuid| {
            memberships
                .iter()
                .find(|m| m.tenant.id == tenant_id)
                .unwrap()
                .roles
                .clone()
        };
        assert_eq!(roles_of(tenant1.id).len(), 2);
        assert_eq!(roles_of(tenant2.id), vec!["t_user".to_string()]);

        // 非法 role_id → NotFound 且原角色不变;非成员 → NotFound
        assert!(matches!(
            repos
                .members
                .set_roles(
                    MemberKey {
                        tenant_id: tenant2.id,
                        user_id: alice.id
                    },
                    &[Uuid::now_v7()],
                    None
                )
                .await,
            Err(IdmError::NotFound)
        ));
        assert_eq!(roles_in(tenant2.id).await, vec!["t_user".to_string()]);
        assert!(matches!(
            repos
                .members
                .set_roles(
                    MemberKey {
                        tenant_id: tenant2.id,
                        user_id: Uuid::now_v7()
                    },
                    &[user],
                    None
                )
                .await,
            Err(IdmError::NotFound)
        ));

        // remove:只移出 t1,连带清掉它的租户角色;再移 → NotFound
        repos
            .members
            .remove(
                MemberKey {
                    tenant_id: tenant1.id,
                    user_id: alice.id,
                },
                None,
            )
            .await
            .unwrap();
        assert!(repos
            .members
            .get(MemberKey {
                tenant_id: tenant1.id,
                user_id: alice.id
            })
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            tenant_ids(&repos.members.memberships_for_user(alice.id).await.unwrap()),
            vec![tenant2.id]
        );
        assert!(matches!(
            repos
                .members
                .remove(
                    MemberKey {
                        tenant_id: tenant1.id,
                        user_id: alice.id
                    },
                    None
                )
                .await,
            Err(IdmError::NotFound)
        ));
        // 重新加入:旧角色不复活
        repos
            .members
            .add(
                MemberKey {
                    tenant_id: tenant1.id,
                    user_id: alice.id,
                },
                &[],
                None,
            )
            .await
            .unwrap();
        assert!(roles_in(tenant1.id).await.is_empty());
    }

    pub(crate) async fn revoke_for_member_revokes_only_that_tenant_sessions(repos: Repos) {
        let alice = repos
            .users
            .create(
                NewUser {
                    username: "alice",
                    email: None,
                    password_hash: "h",
                },
                None,
            )
            .await
            .unwrap();
        let bob = repos
            .users
            .create(
                NewUser {
                    username: "bob",
                    email: None,
                    password_hash: "h",
                },
                None,
            )
            .await
            .unwrap();
        let tenant1 = repos
            .tenants
            .create(
                NewTenant {
                    slug: "t1",
                    name: "T1",
                },
                None,
            )
            .await
            .unwrap();
        let tenant2 = repos
            .tenants
            .create(
                NewTenant {
                    slug: "t2",
                    name: "T2",
                },
                None,
            )
            .await
            .unwrap();
        let now = OffsetDateTime::now_utc();
        let expires_at = now + Duration::days(1);
        let session1 = repos
            .sessions
            .create(alice.id, Some(tenant1.id), "a-t1", expires_at, None)
            .await
            .unwrap();
        assert_eq!(session1.tenant_id, Some(tenant1.id));
        repos
            .sessions
            .create(alice.id, Some(tenant2.id), "a-t2", expires_at, None)
            .await
            .unwrap();
        repos
            .sessions
            .create(alice.id, None, "a-platform", expires_at, None)
            .await
            .unwrap();
        repos
            .sessions
            .create(bob.id, Some(tenant1.id), "b-t1", expires_at, None)
            .await
            .unwrap();

        let active = |token_hash: &'static str| {
            let sessions = &repos.sessions;
            async move { sessions.find_active(token_hash, now).await.unwrap() }
        };
        // find_active 带回 tenant_id(平台上下文 = None)
        assert_eq!(active("a-t2").await.unwrap().tenant_id, Some(tenant2.id));
        assert_eq!(active("a-platform").await.unwrap().tenant_id, None);

        repos
            .sessions
            .revoke_for_member(MemberKey {
                tenant_id: tenant1.id,
                user_id: alice.id,
            })
            .await
            .unwrap();
        assert!(active("a-t1").await.is_none());
        assert!(active("a-t2").await.is_some());
        assert!(active("a-platform").await.is_some());
        assert!(active("b-t1").await.is_some());

        repos.sessions.revoke_for_tenant(tenant2.id).await.unwrap();
        assert!(active("a-t2").await.is_none());
        assert!(active("a-platform").await.is_some());
        assert!(active("b-t1").await.is_some());
        repos.sessions.revoke_for_tenant(tenant1.id).await.unwrap();
        assert!(active("b-t1").await.is_none());
        assert!(active("a-platform").await.is_some());
        // 幂等
        repos.sessions.revoke_for_tenant(tenant1.id).await.unwrap();
        repos
            .sessions
            .revoke_for_member(MemberKey {
                tenant_id: tenant1.id,
                user_id: alice.id,
            })
            .await
            .unwrap();
    }

    pub(crate) async fn member_ops_emit_outbox_events(repos: Repos) {
        let alice = repos
            .users
            .create(
                NewUser {
                    username: "alice",
                    email: None,
                    password_hash: "h",
                },
                None,
            )
            .await
            .unwrap();
        let admin = repos
            .roles
            .upsert(
                NewRole {
                    name: "t_admin",
                    display_name: "A",
                    scope: RoleScope::Tenant,
                },
                None,
            )
            .await
            .unwrap();
        let user = repos
            .roles
            .upsert(
                NewRole {
                    name: "t_user",
                    display_name: "U",
                    scope: RoleScope::Tenant,
                },
                None,
            )
            .await
            .unwrap();
        repos.drain_outbox().await;

        // 取出全部未发布事件并标已发布,断言每条的 aggregate_id 都是租户、payload 带 tenant_id
        let take = |tenant_id: Uuid| {
            let outbox = &repos.outbox;
            async move {
                let rows = outbox.poll_unpublished(100).await.unwrap();
                let ids: Vec<i64> = rows.iter().map(|x| x.id).collect();
                outbox.mark_published(&ids).await.unwrap();
                for row in &rows {
                    assert_eq!(
                        row.aggregate_id, tenant_id,
                        "{} 的 aggregate 应是租户",
                        row.event_type
                    );
                    assert_eq!(
                        row.payload["tenant_id"],
                        serde_json::to_value(tenant_id).unwrap(),
                        "{} payload 应带 tenant_id",
                        row.event_type
                    );
                }
                rows
            }
        };
        let types = |rows: &[OutboxRecord]| -> Vec<String> {
            rows.iter().map(|row| row.event_type.clone()).collect()
        };

        let tenant = repos
            .tenants
            .create(
                NewTenant {
                    slug: "acme",
                    name: "Acme",
                },
                None,
            )
            .await
            .unwrap();
        let rows = take(tenant.id).await;
        assert_eq!(types(&rows), ["tenant.created"]);
        assert_eq!(rows[0].payload["slug"], "acme");
        assert_eq!(rows[0].payload["name"], "Acme");
        assert_eq!(rows[0].payload["status"], "active");

        repos
            .tenants
            .update_name(tenant.id, "Acme 2", None)
            .await
            .unwrap();
        let rows = take(tenant.id).await;
        assert_eq!(types(&rows), ["tenant.updated"]);
        assert_eq!(rows[0].payload["name"], "Acme 2");
        assert_eq!(rows[0].payload["status"], "active");

        repos
            .tenants
            .set_status(tenant.id, TenantStatus::Suspended, None)
            .await
            .unwrap();
        let rows = take(tenant.id).await;
        assert_eq!(types(&rows), ["tenant.updated"]);
        assert_eq!(rows[0].payload["status"], "suspended");

        repos
            .members
            .add(
                MemberKey {
                    tenant_id: tenant.id,
                    user_id: alice.id,
                },
                &[admin],
                None,
            )
            .await
            .unwrap();
        let rows = take(tenant.id).await;
        assert_eq!(types(&rows), ["tenant.member_added"]);
        assert_eq!(
            rows[0].payload["user_id"],
            serde_json::to_value(alice.id).unwrap()
        );
        assert_eq!(rows[0].payload["roles"], serde_json::json!(["t_admin"]));
        assert_eq!(rows[0].payload["status"], "active");

        repos
            .members
            .set_roles(
                MemberKey {
                    tenant_id: tenant.id,
                    user_id: alice.id,
                },
                &[user, admin],
                None,
            )
            .await
            .unwrap();
        let rows = take(tenant.id).await;
        assert_eq!(types(&rows), ["tenant.member_roles_set"]);
        assert_eq!(
            rows[0].payload["roles"],
            serde_json::json!(["t_admin", "t_user"])
        );

        repos
            .members
            .set_status(
                MemberKey {
                    tenant_id: tenant.id,
                    user_id: alice.id,
                },
                MemberStatus::Inactive,
                None,
            )
            .await
            .unwrap();
        let rows = take(tenant.id).await;
        assert_eq!(types(&rows), ["tenant.member_updated"]);
        assert_eq!(rows[0].payload["status"], "inactive");

        // touch_last_used / upsert_fixed 命中已有 / 失败的写 → 不发事件
        repos
            .members
            .touch_last_used(MemberKey {
                tenant_id: tenant.id,
                user_id: alice.id,
            })
            .await
            .unwrap();
        assert!(repos
            .members
            .add(
                MemberKey {
                    tenant_id: tenant.id,
                    user_id: alice.id
                },
                &[],
                None
            )
            .await
            .is_err());
        assert!(repos
            .members
            .set_roles(
                MemberKey {
                    tenant_id: tenant.id,
                    user_id: alice.id
                },
                &[Uuid::now_v7()],
                None
            )
            .await
            .is_err());
        assert!(repos
            .tenants
            .create(
                NewTenant {
                    slug: "acme",
                    name: "dup"
                },
                None
            )
            .await
            .is_err());
        assert!(take(tenant.id).await.is_empty());
        repos
            .tenants
            .upsert_fixed(
                DEFAULT_TENANT_ID,
                NewTenant {
                    slug: "default",
                    name: "默认组织",
                },
                None,
            )
            .await
            .unwrap();
        assert!(take(DEFAULT_TENANT_ID).await.is_empty());

        repos
            .members
            .remove(
                MemberKey {
                    tenant_id: tenant.id,
                    user_id: alice.id,
                },
                None,
            )
            .await
            .unwrap();
        let rows = take(tenant.id).await;
        assert_eq!(types(&rows), ["tenant.member_removed"]);
        assert_eq!(
            rows[0].payload["user_id"],
            serde_json::to_value(alice.id).unwrap()
        );

        repos.tenants.soft_delete(tenant.id, None).await.unwrap();
        let rows = take(tenant.id).await;
        assert_eq!(types(&rows), ["tenant.deleted"]);
    }

    /// 注册原子单元:`UserRepo::create_with_membership` 一个事务建账号 + 加入租户 + 授租户角色。
    /// 租户不存在 / 停用 / 已删 → 只建账号;任一步失败(角色不存在、用户名冲突)→ 什么都不留。
    pub(crate) async fn create_with_membership_is_atomic(repos: Repos) {
        let tenant_user_role = repos
            .roles
            .upsert(
                NewRole {
                    name: "t_user",
                    display_name: "成员",
                    scope: RoleScope::Tenant,
                },
                None,
            )
            .await
            .unwrap();
        repos.drain_outbox().await;

        let alice = repos
            .users
            .create_with_membership(
                NewUser {
                    username: "alice",
                    email: Some("a@x.com"),
                    password_hash: "h",
                },
                DEFAULT_TENANT_ID,
                &[tenant_user_role],
                Some("sys"),
            )
            .await
            .unwrap();
        assert_eq!(alice.username, "alice");
        let memberships = repos.members.memberships_for_user(alice.id).await.unwrap();
        assert_eq!(tenant_ids(&memberships), vec![DEFAULT_TENANT_ID]);
        assert_eq!(memberships[0].roles, vec!["t_user".to_string()]);
        assert_eq!(memberships[0].status, MemberStatus::Active);
        // 事件:user.created 在前,tenant.member_added 在后(同一事务)
        let rows = repos.outbox.poll_unpublished(100).await.unwrap();
        let types: Vec<&str> = rows.iter().map(|x| x.event_type.as_str()).collect();
        assert_eq!(types, ["user.created", "tenant.member_added"]);
        assert_eq!(rows[1].aggregate_id, DEFAULT_TENANT_ID);
        assert_eq!(rows[1].payload["roles"], serde_json::json!(["t_user"]));
        repos.drain_outbox().await;

        // 停用的租户 → 只建账号,不加入,只发 user.created
        let acme = repos
            .tenants
            .create(
                NewTenant {
                    slug: "acme",
                    name: "Acme",
                },
                None,
            )
            .await
            .unwrap();
        repos
            .tenants
            .set_status(acme.id, TenantStatus::Suspended, None)
            .await
            .unwrap();
        repos.drain_outbox().await;
        let bob = repos
            .users
            .create_with_membership(
                NewUser {
                    username: "bob",
                    email: None,
                    password_hash: "h",
                },
                acme.id,
                &[tenant_user_role],
                None,
            )
            .await
            .unwrap();
        assert!(repos
            .members
            .get(MemberKey {
                tenant_id: acme.id,
                user_id: bob.id
            })
            .await
            .unwrap()
            .is_none());
        let rows = repos.outbox.poll_unpublished(100).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].event_type, "user.created");
        repos.drain_outbox().await;

        // 不存在 / 已删的租户 → 只建账号
        let carol = repos
            .users
            .create_with_membership(
                NewUser {
                    username: "carol",
                    email: None,
                    password_hash: "h",
                },
                Uuid::now_v7(),
                &[tenant_user_role],
                None,
            )
            .await
            .unwrap();
        assert!(repos
            .members
            .memberships_for_user(carol.id)
            .await
            .unwrap()
            .is_empty());
        let gone = repos
            .tenants
            .create(
                NewTenant {
                    slug: "gone",
                    name: "Gone",
                },
                None,
            )
            .await
            .unwrap();
        repos.tenants.soft_delete(gone.id, None).await.unwrap();
        let dave = repos
            .users
            .create_with_membership(
                NewUser {
                    username: "dave",
                    email: None,
                    password_hash: "h",
                },
                gone.id,
                &[],
                None,
            )
            .await
            .unwrap();
        assert!(repos
            .members
            .memberships_for_user(dave.id)
            .await
            .unwrap()
            .is_empty());
        repos.drain_outbox().await;

        // 角色不存在 → NotFound,账号也不留、不发事件
        assert!(matches!(
            repos
                .users
                .create_with_membership(
                    NewUser {
                        username: "erin",
                        email: None,
                        password_hash: "h"
                    },
                    DEFAULT_TENANT_ID,
                    &[Uuid::now_v7()],
                    None
                )
                .await,
            Err(IdmError::NotFound)
        ));
        assert!(repos
            .users
            .find_by_identifier("erin")
            .await
            .unwrap()
            .is_none());
        // 用户名冲突 → Conflict,不留成员关系
        assert!(matches!(
            repos
                .users
                .create_with_membership(
                    NewUser {
                        username: "alice",
                        email: None,
                        password_hash: "h"
                    },
                    DEFAULT_TENANT_ID,
                    &[tenant_user_role],
                    None
                )
                .await,
            Err(IdmError::Conflict(_))
        ));
        assert!(repos.outbox.poll_unpublished(100).await.unwrap().is_empty());
        let page = repos
            .members
            .list_by_tenant(
                DEFAULT_TENANT_ID,
                &ListPage::Offset {
                    offset: 0,
                    limit: 10,
                    with_total: true,
                },
            )
            .await
            .unwrap();
        assert_eq!(page.total, Some(1)); // 只有 alice
    }

    /// 会话的租户须存在(PG 靠外键,内存共享租户存储校验):不存在 → NotFound;已删的租户行仍在,外键不拦。
    pub(crate) async fn session_create_rejects_unknown_tenant(repos: Repos) {
        let alice = repos
            .users
            .create(
                NewUser {
                    username: "alice",
                    email: None,
                    password_hash: "h",
                },
                None,
            )
            .await
            .unwrap();
        let future = OffsetDateTime::now_utc() + Duration::days(1);
        assert!(matches!(
            repos
                .sessions
                .create(alice.id, Some(Uuid::now_v7()), "h-unknown", future, None)
                .await,
            Err(IdmError::NotFound)
        ));
        assert!(repos
            .sessions
            .find_active("h-unknown", OffsetDateTime::now_utc())
            .await
            .unwrap()
            .is_none());
        let session = repos
            .sessions
            .create(alice.id, Some(DEFAULT_TENANT_ID), "h-default", future, None)
            .await
            .unwrap();
        assert_eq!(session.tenant_id, Some(DEFAULT_TENANT_ID));
        let tenant = repos
            .tenants
            .create(
                NewTenant {
                    slug: "acme",
                    name: "Acme",
                },
                None,
            )
            .await
            .unwrap();
        let session = repos
            .sessions
            .create(alice.id, Some(tenant.id), "h-acme", future, None)
            .await
            .unwrap();
        assert_eq!(
            repos
                .sessions
                .find_active("h-acme", OffsetDateTime::now_utc())
                .await
                .unwrap()
                .map(|x| x.tenant_id),
            Some(Some(tenant.id))
        );
        assert_eq!(session.tenant_id, Some(tenant.id));
        repos.tenants.soft_delete(tenant.id, None).await.unwrap();
        assert!(repos
            .sessions
            .create(alice.id, Some(tenant.id), "h-deleted", future, None)
            .await
            .is_ok());
    }

    /// 租户软删后,对其成员关系的写(set_status / set_roles / touch_last_used / remove)一律 NotFound,
    /// 不改数据、不发事件(和 get / list 看不见已删租户的成员一致)。
    pub(crate) async fn member_writes_on_deleted_tenant_are_not_found(repos: Repos) {
        let alice = repos
            .users
            .create(
                NewUser {
                    username: "alice",
                    email: None,
                    password_hash: "h",
                },
                None,
            )
            .await
            .unwrap();
        let role = repos
            .roles
            .upsert(
                NewRole {
                    name: "t_user",
                    display_name: "成员",
                    scope: RoleScope::Tenant,
                },
                None,
            )
            .await
            .unwrap();
        let tenant = repos
            .tenants
            .create(
                NewTenant {
                    slug: "acme",
                    name: "Acme",
                },
                None,
            )
            .await
            .unwrap();
        repos
            .members
            .add(
                MemberKey {
                    tenant_id: tenant.id,
                    user_id: alice.id,
                },
                &[role],
                None,
            )
            .await
            .unwrap();
        repos.tenants.soft_delete(tenant.id, None).await.unwrap();
        repos.drain_outbox().await;

        assert!(matches!(
            repos
                .members
                .set_status(
                    MemberKey {
                        tenant_id: tenant.id,
                        user_id: alice.id
                    },
                    MemberStatus::Inactive,
                    None
                )
                .await,
            Err(IdmError::NotFound)
        ));
        assert!(matches!(
            repos
                .members
                .set_roles(
                    MemberKey {
                        tenant_id: tenant.id,
                        user_id: alice.id
                    },
                    &[],
                    None
                )
                .await,
            Err(IdmError::NotFound)
        ));
        assert!(matches!(
            repos
                .members
                .touch_last_used(MemberKey {
                    tenant_id: tenant.id,
                    user_id: alice.id
                })
                .await,
            Err(IdmError::NotFound)
        ));
        assert!(matches!(
            repos
                .members
                .remove(
                    MemberKey {
                        tenant_id: tenant.id,
                        user_id: alice.id
                    },
                    None
                )
                .await,
            Err(IdmError::NotFound)
        ));
        assert!(repos.outbox.poll_unpublished(100).await.unwrap().is_empty());
        // 存活租户上的同样操作照常(对照:证明 NotFound 是因为租户已删)
        let tenant2 = repos
            .tenants
            .create(
                NewTenant {
                    slug: "beta",
                    name: "Beta",
                },
                None,
            )
            .await
            .unwrap();
        repos
            .members
            .add(
                MemberKey {
                    tenant_id: tenant2.id,
                    user_id: alice.id,
                },
                &[role],
                None,
            )
            .await
            .unwrap();
        repos
            .members
            .set_roles(
                MemberKey {
                    tenant_id: tenant2.id,
                    user_id: alice.id,
                },
                &[],
                None,
            )
            .await
            .unwrap();
        repos
            .members
            .touch_last_used(MemberKey {
                tenant_id: tenant2.id,
                user_id: alice.id,
            })
            .await
            .unwrap();
        repos
            .members
            .set_status(
                MemberKey {
                    tenant_id: tenant2.id,
                    user_id: alice.id,
                },
                MemberStatus::Inactive,
                None,
            )
            .await
            .unwrap();
        repos
            .members
            .remove(
                MemberKey {
                    tenant_id: tenant2.id,
                    user_id: alice.id,
                },
                None,
            )
            .await
            .unwrap();
    }

    /// `MemberRepo::add` 对已软删账号 → `NotFound`(trait 文档「用户不存在」),不留成员行、不发事件;
    /// 账号软删后,成员列表(offset / cursor)和 total 都不再含他。
    pub(crate) async fn soft_deleted_user_not_addable_nor_listed_as_member(repos: Repos) {
        let alice = repos
            .users
            .create(
                NewUser {
                    username: "alice",
                    email: None,
                    password_hash: "h",
                },
                None,
            )
            .await
            .unwrap();
        let bob = repos
            .users
            .create(
                NewUser {
                    username: "bob",
                    email: None,
                    password_hash: "h",
                },
                None,
            )
            .await
            .unwrap();
        let carol = repos
            .users
            .create(
                NewUser {
                    username: "carol",
                    email: None,
                    password_hash: "h",
                },
                None,
            )
            .await
            .unwrap();
        let tenant = repos
            .tenants
            .create(
                NewTenant {
                    slug: "acme",
                    name: "Acme",
                },
                None,
            )
            .await
            .unwrap();

        // carol 先软删,再加 → NotFound,且看不到半截成员行
        repos.users.soft_delete(carol.id, None).await.unwrap();
        repos.drain_outbox().await;
        assert!(matches!(
            repos
                .members
                .add(
                    MemberKey {
                        tenant_id: tenant.id,
                        user_id: carol.id
                    },
                    &[],
                    None
                )
                .await,
            Err(IdmError::NotFound)
        ));
        assert!(repos
            .members
            .get(MemberKey {
                tenant_id: tenant.id,
                user_id: carol.id
            })
            .await
            .unwrap()
            .is_none());
        assert!(repos.outbox.poll_unpublished(100).await.unwrap().is_empty());

        // alice、bob 都是成员;bob 之后软删 → 列表与 total 只剩 alice
        repos
            .members
            .add(
                MemberKey {
                    tenant_id: tenant.id,
                    user_id: alice.id,
                },
                &[],
                None,
            )
            .await
            .unwrap();
        repos
            .members
            .add(
                MemberKey {
                    tenant_id: tenant.id,
                    user_id: bob.id,
                },
                &[],
                None,
            )
            .await
            .unwrap();
        let offset = ListPage::Offset {
            offset: 0,
            limit: 10,
            with_total: true,
        };
        assert_eq!(
            repos
                .members
                .list_by_tenant(tenant.id, &offset)
                .await
                .unwrap()
                .total,
            Some(2)
        );
        repos.users.soft_delete(bob.id, None).await.unwrap();
        let page = repos
            .members
            .list_by_tenant(tenant.id, &offset)
            .await
            .unwrap();
        assert_eq!(page.total, Some(1));
        let ids: Vec<Uuid> = page.rows.iter().map(|m| m.user_id).collect();
        assert_eq!(ids, vec![alice.id]);
        let cursor = repos
            .members
            .list_by_tenant(
                tenant.id,
                &ListPage::Cursor {
                    after: None,
                    limit: 10,
                },
            )
            .await
            .unwrap();
        let ids: Vec<Uuid> = cursor.rows.iter().map(|m| m.user_id).collect();
        assert_eq!(ids, vec![alice.id]);
        assert!(cursor.next_after.is_none());
    }

    /// 迁移 0004 之后 user_roles 里还留着租户作用域角色(老账号的 admin / user)。
    /// `UserRepo::list` 的 roles 列与 roles_any / roles_none 只看**平台**角色:租户角色不显示、按它筛选不命中。
    pub(crate) async fn user_list_sees_platform_roles_only(repos: Repos) {
        let alice = repos
            .users
            .create(
                NewUser {
                    username: "alice",
                    email: None,
                    password_hash: "h",
                },
                None,
            )
            .await
            .unwrap();
        let bob = repos
            .users
            .create(
                NewUser {
                    username: "bob",
                    email: None,
                    password_hash: "h",
                },
                None,
            )
            .await
            .unwrap();
        let platform_role = repos
            .roles
            .upsert(
                NewRole {
                    name: "sa",
                    display_name: "平台管理员",
                    scope: RoleScope::Platform,
                },
                None,
            )
            .await
            .unwrap();
        let tenant_role = repos
            .roles
            .upsert(
                NewRole {
                    name: "ta",
                    display_name: "租户角色",
                    scope: RoleScope::Tenant,
                },
                None,
            )
            .await
            .unwrap();
        // 模拟迁移残留:租户角色也挂在 user_roles 上
        repos
            .roles
            .grant(
                RoleGrant {
                    user_id: alice.id,
                    role_id: platform_role,
                },
                None,
            )
            .await
            .unwrap();
        repos
            .roles
            .grant(
                RoleGrant {
                    user_id: alice.id,
                    role_id: tenant_role,
                },
                None,
            )
            .await
            .unwrap();
        repos
            .roles
            .grant(
                RoleGrant {
                    user_id: bob.id,
                    role_id: tenant_role,
                },
                None,
            )
            .await
            .unwrap();

        async fn list(
            users: &(impl UserRepo + ?Sized),
            filter: UserListFilter,
        ) -> ListResult<UserListRow> {
            let page = ListPage::Offset {
                offset: 0,
                limit: 10,
                with_total: true,
            };
            users
                .list(
                    &filter,
                    UserSortBy::Username,
                    SortDirection::Ascending,
                    &page,
                )
                .await
                .unwrap()
        }

        let all = list(&*repos.users, UserListFilter::default()).await;
        let roles_of = |name: &str| {
            all.rows
                .iter()
                .find(|u| u.username == name)
                .unwrap()
                .roles
                .clone()
        };
        assert_eq!(roles_of("alice"), vec!["sa".to_string()]);
        assert!(roles_of("bob").is_empty());

        // roles_any = 租户角色 → 谁都不命中
        let matching_tenant_role = list(
            &*repos.users,
            UserListFilter {
                roles_any: vec!["ta".into()],
                ..Default::default()
            },
        )
        .await;
        assert!(matching_tenant_role.rows.is_empty());
        assert_eq!(matching_tenant_role.total, Some(0));
        // roles_none = 租户角色 → 不排除任何人
        let excluding_tenant_role = list(
            &*repos.users,
            UserListFilter {
                roles_none: vec!["ta".into()],
                ..Default::default()
            },
        )
        .await;
        assert_eq!(excluding_tenant_role.total, Some(2));
        // 平台角色筛选照常
        let matching_platform_role = list(
            &*repos.users,
            UserListFilter {
                roles_any: vec!["sa".into()],
                ..Default::default()
            },
        )
        .await;
        let names: Vec<&str> = matching_platform_role
            .rows
            .iter()
            .map(|u| u.username.as_str())
            .collect();
        assert_eq!(names, vec!["alice"]);
    }

    /// `SessionRepo::revoke` 是条件更新,告诉调用方是否真撤掉了一行(refresh 轮换靠它防并发重放)。
    pub(crate) async fn session_revoke_reports_whether_it_revoked(repos: Repos) {
        let alice = repos
            .users
            .create(
                NewUser {
                    username: "alice",
                    email: None,
                    password_hash: "h",
                },
                None,
            )
            .await
            .unwrap();
        let now = OffsetDateTime::now_utc();
        let session = repos
            .sessions
            .create(alice.id, None, "h-revoke", now + Duration::days(1), None)
            .await
            .unwrap();
        assert!(
            repos.sessions.revoke(session.id).await.unwrap(),
            "首次撤销 → true"
        );
        assert!(
            !repos.sessions.revoke(session.id).await.unwrap(),
            "已撤销再撤 → false(幂等,不报错)"
        );
        assert!(
            !repos.sessions.revoke(Uuid::now_v7()).await.unwrap(),
            "不存在 → false"
        );
        assert!(repos
            .sessions
            .find_active("h-revoke", now)
            .await
            .unwrap()
            .is_none());
    }

    /// 同一批用例生成内存入口(默认 cargo test)和 PG 入口(pg-conformance)。
    macro_rules! both_backends {
        ($($case:ident),* $(,)?) => {
            mod memory {
                $(
                    #[tokio::test]
                    async fn $case() {
                        super::$case(super::Repos::memory()).await;
                    }
                )*
            }

            #[cfg(feature = "pg-conformance")]
            mod pg {
                $(
                    #[sqlx::test(migrations = false)]
                    async fn $case(pool: sqlx::PgPool) -> sqlx::Result<()> {
                        crate::pg::bootstrap_idm(&pool)
                            .await
                            .expect("bootstrap idm schema + 跑 migrations");
                        super::$case(super::Repos::pg(pool)).await;
                        Ok(())
                    }
                )*
            }
        };
    }

    both_backends!(
        add_member_then_memberships_for_user_lists_it,
        suspended_tenant_excluded_from_memberships,
        inactive_member_excluded,
        slug_not_reusable_after_delete,
        roles_for_user_returns_platform_scope_only,
        member_roles_are_per_tenant,
        revoke_for_member_revokes_only_that_tenant_sessions,
        member_ops_emit_outbox_events,
        create_with_membership_is_atomic,
        session_create_rejects_unknown_tenant,
        member_writes_on_deleted_tenant_are_not_found,
        soft_deleted_user_not_addable_nor_listed_as_member,
        user_list_sees_platform_roles_only,
        session_revoke_reports_whether_it_revoked,
    );
}

// ── 入口 1:内存(零 DB,默认 cargo test 就编译+跑)──
#[tokio::test]
async fn memory_satisfies_idm_contract() {
    use idm::{InMemoryRoleRepo, InMemorySessionRepo, InMemoryUserRepo};
    idm_repo_contract(
        &InMemoryUserRepo::new(),
        &InMemorySessionRepo::new(),
        &InMemoryRoleRepo::new(),
    )
    .await;
}

// ── 入口 1b:内存 user-admin 契约(users↔roles 共享角色/授予状态)──
#[tokio::test]
async fn memory_satisfies_user_admin_contract() {
    use idm::{InMemoryRoleRepo, InMemoryUserRepo};
    let users = InMemoryUserRepo::new();
    let roles = InMemoryRoleRepo::new_shared_with(&users);
    idm_user_admin_contract(&users, &roles).await;
}

// ── 入口 1c:内存 outbox 契约(users↔roles↔outbox 三件套共享存储)──
#[tokio::test]
async fn memory_satisfies_outbox_contract() {
    use idm::{InMemoryOutboxRepo, InMemoryRoleRepo, InMemoryUserRepo};
    let users = InMemoryUserRepo::new();
    let roles = InMemoryRoleRepo::new_shared_with(&users);
    let outbox = InMemoryOutboxRepo::new_shared_with(&users);
    idm_outbox_contract(&users, &roles, &outbox).await;
}

// ── 入口 1d:同三份契约,仓储全包成 `Box<dyn …>` 再传:泛型参数是 `Box<dyn …>` 本身,
// 每个方法都经 `Box<T>` 转发实现(租户 / 成员仓储的转发由下面 `idm_tenant_contract` 覆盖:
// `Repos` 字段是 `Box<dyn …>`,方法解析先命中 `&Box<dyn …>` 的转发实现)──
#[tokio::test]
async fn memory_satisfies_contracts_through_box_forwarding() {
    use idm::{InMemoryOutboxRepo, InMemoryRoleRepo, InMemorySessionRepo, InMemoryUserRepo};

    let users: Box<dyn UserRepo> = Box::new(InMemoryUserRepo::new());
    let sessions: Box<dyn SessionRepo> = Box::new(InMemorySessionRepo::new());
    let roles: Box<dyn RoleRepo> = Box::new(InMemoryRoleRepo::new());
    idm_repo_contract(&users, &sessions, &roles).await;

    let shared = InMemoryUserRepo::new();
    let roles: Box<dyn RoleRepo> = Box::new(InMemoryRoleRepo::new_shared_with(&shared));
    let users: Box<dyn UserRepo> = Box::new(shared);
    idm_user_admin_contract(&users, &roles).await;

    let shared = InMemoryUserRepo::new();
    let roles: Box<dyn RoleRepo> = Box::new(InMemoryRoleRepo::new_shared_with(&shared));
    let outbox: Box<dyn OutboxRepo> = Box::new(InMemoryOutboxRepo::new_shared_with(&shared));
    let users: Box<dyn UserRepo> = Box::new(shared);
    idm_outbox_contract(&users, &roles, &outbox).await;
    // 契约没覆盖的非事务 emit 也要经 Box 转发
    let aggregate_id = Uuid::now_v7();
    outbox
        .emit("box.forwarded", aggregate_id, Value::Null)
        .await
        .unwrap();
    let pending: Vec<OutboxRecord> = outbox.poll_unpublished(1000).await.unwrap();
    assert!(
        pending
            .iter()
            .any(|record| record.event_type == "box.forwarded"
                && record.aggregate_id == aggregate_id),
        "emit 应经 Box<dyn OutboxRepo> 转发写进发件箱: {pending:?}"
    );
}

// ── 入口 2:PG(需 --features pg-conformance + DATABASE_URL 连 idm role + 跑着的 pg)──
// bootstrap 内联在本文件(不走 #[path] include):sqlx::migrate! 在被 include 的文件里会按
// "相对当前文件目录"解析路径(sqlx 不支持),内联后它相对 idm crate 的 CARGO_MANIFEST_DIR、稳。
#[cfg(feature = "pg-conformance")]
mod pg {
    use idm::{
        MemberKey, NewRole, NewTenant, NewUser, OutboxRepo, PgMemberRepo, PgOutboxRepo, PgRoleRepo,
        PgSessionRepo, PgTenantRepo, PgUserRepo, RoleGrant,
    };
    use sqlx::migrate::Migrator;
    use sqlx::PgPool;
    use uuid::Uuid;

    use super::idm_repo_contract;

    /// 编译期内嵌 idm crate 的 migrations/(相对 idm crate 的 CARGO_MANIFEST_DIR)。
    static IDM_MIGRATOR: Migrator = sqlx::migrate!("./migrations");

    /// #[sqlx::test] 的干净临时库:建 idm schema + 跑 idm crate 自带 migrations。
    pub(crate) async fn bootstrap_idm(pool: &PgPool) -> anyhow::Result<()> {
        sqlx::query("create schema if not exists idm")
            .execute(pool)
            .await?;
        IDM_MIGRATOR.run(pool).await?;
        Ok(())
    }

    #[sqlx::test(migrations = false)]
    async fn pg_satisfies_idm_contract(pool: PgPool) -> sqlx::Result<()> {
        bootstrap_idm(&pool)
            .await
            .expect("bootstrap idm schema + 跑 migrations");
        let users = PgUserRepo::new(pool.clone());
        let sessions = PgSessionRepo::new(pool.clone());
        let roles = PgRoleRepo::new(pool);
        idm_repo_contract(&users, &sessions, &roles).await;
        Ok(())
    }

    #[sqlx::test(migrations = false)]
    async fn pg_satisfies_user_admin_contract(pool: PgPool) -> sqlx::Result<()> {
        bootstrap_idm(&pool)
            .await
            .expect("bootstrap idm schema + 跑 migrations");
        let users = PgUserRepo::new(pool.clone());
        let roles = PgRoleRepo::new(pool);
        super::idm_user_admin_contract(&users, &roles).await;
        Ok(())
    }

    #[sqlx::test(migrations = false)]
    async fn pg_satisfies_outbox_contract(pool: PgPool) -> sqlx::Result<()> {
        bootstrap_idm(&pool)
            .await
            .expect("bootstrap idm schema + 跑 migrations");
        let users = PgUserRepo::new(pool.clone());
        let roles = PgRoleRepo::new(pool.clone());
        let outbox = PgOutboxRepo::new(pool);
        super::idm_outbox_contract(&users, &roles, &outbox).await;
        Ok(())
    }

    /// 审计主体按借用传(`by: Option<&str>`)后照样落库:每条写路径把 `by` 写进对应的审计列
    /// (users / roles / tenants 的 created_by / updated_by、user_roles / member_roles 的 granted_by、
    /// tenant_members 的 added_by、sessions 的 created_by),`None` 落成 NULL。内存实现不存审计列,故只在 PG 断言。
    #[sqlx::test(migrations = false)]
    async fn pg_audit_by_is_persisted(pool: PgPool) -> sqlx::Result<()> {
        use idm::{MemberRepo, RoleRepo, RoleScope, SessionRepo, TenantRepo, UserRepo};
        use time::{Duration, OffsetDateTime};

        bootstrap_idm(&pool)
            .await
            .expect("bootstrap idm schema + 跑 migrations");
        let users = PgUserRepo::new(pool.clone());
        let sessions = PgSessionRepo::new(pool.clone());
        let roles = PgRoleRepo::new(pool.clone());
        let tenants = PgTenantRepo::new(pool.clone());
        let members = PgMemberRepo::new(pool.clone());

        let alice = users
            .create(
                NewUser {
                    username: "alice",
                    email: None,
                    password_hash: "hash",
                },
                Some("creator"),
            )
            .await
            .expect("create alice");
        let (created_by, updated_by): (Option<String>, Option<String>) =
            sqlx::query_as("select created_by, updated_by from users where id = $1")
                .bind(alice.id)
                .fetch_one(&pool)
                .await?;
        assert_eq!(created_by.as_deref(), Some("creator"));
        assert_eq!(updated_by.as_deref(), Some("creator"));

        users
            .update(alice.id, "alice2", None, Some("updater"))
            .await
            .expect("update alice");
        let updated_by: Option<String> =
            sqlx::query_scalar("select updated_by from users where id = $1")
                .bind(alice.id)
                .fetch_one(&pool)
                .await?;
        assert_eq!(updated_by.as_deref(), Some("updater"));

        let anonymous = users
            .create(
                NewUser {
                    username: "anonymous",
                    email: None,
                    password_hash: "hash",
                },
                None,
            )
            .await
            .expect("create anonymous");
        let (created_by, updated_by): (Option<String>, Option<String>) =
            sqlx::query_as("select created_by, updated_by from users where id = $1")
                .bind(anonymous.id)
                .fetch_one(&pool)
                .await?;
        assert_eq!(
            (created_by, updated_by),
            (None, None),
            "by = None 落成 NULL"
        );

        users
            .soft_delete(anonymous.id, Some("deleter"))
            .await
            .expect("soft delete anonymous");
        let updated_by: Option<String> =
            sqlx::query_scalar("select updated_by from users where id = $1")
                .bind(anonymous.id)
                .fetch_one(&pool)
                .await?;
        assert_eq!(updated_by.as_deref(), Some("deleter"));

        let platform_role_id = roles
            .upsert(
                NewRole {
                    name: "auditor",
                    display_name: "审计员",
                    scope: RoleScope::Platform,
                },
                Some("role-creator"),
            )
            .await
            .expect("upsert platform role");
        let (created_by, updated_by): (Option<String>, Option<String>) =
            sqlx::query_as("select created_by, updated_by from roles where id = $1")
                .bind(platform_role_id)
                .fetch_one(&pool)
                .await?;
        assert_eq!(created_by.as_deref(), Some("role-creator"));
        assert_eq!(updated_by.as_deref(), Some("role-creator"));

        roles
            .grant(
                RoleGrant {
                    user_id: alice.id,
                    role_id: platform_role_id,
                },
                Some("granter"),
            )
            .await
            .expect("grant platform role");
        let granted_by: Option<String> = sqlx::query_scalar(
            "select granted_by from user_roles where user_id = $1 and role_id = $2",
        )
        .bind(alice.id)
        .bind(platform_role_id)
        .fetch_one(&pool)
        .await?;
        assert_eq!(granted_by.as_deref(), Some("granter"));

        let tenant = tenants
            .create(
                NewTenant {
                    slug: "acme",
                    name: "Acme",
                },
                Some("tenant-creator"),
            )
            .await
            .expect("create tenant");
        let (created_by, updated_by): (Option<String>, Option<String>) =
            sqlx::query_as("select created_by, updated_by from tenants where id = $1")
                .bind(tenant.id)
                .fetch_one(&pool)
                .await?;
        assert_eq!(created_by.as_deref(), Some("tenant-creator"));
        assert_eq!(updated_by.as_deref(), Some("tenant-creator"));

        tenants
            .update_name(tenant.id, "Acme Inc", Some("tenant-updater"))
            .await
            .expect("rename tenant");
        let updated_by: Option<String> =
            sqlx::query_scalar("select updated_by from tenants where id = $1")
                .bind(tenant.id)
                .fetch_one(&pool)
                .await?;
        assert_eq!(updated_by.as_deref(), Some("tenant-updater"));

        let tenant_role_id = roles
            .upsert(
                NewRole {
                    name: "editor",
                    display_name: "编辑",
                    scope: RoleScope::Tenant,
                },
                None,
            )
            .await
            .expect("upsert tenant role");
        let member = MemberKey {
            tenant_id: tenant.id,
            user_id: alice.id,
        };
        members
            .add(member, &[tenant_role_id], Some("member-adder"))
            .await
            .expect("add member");
        let added_by: Option<String> = sqlx::query_scalar(
            "select added_by from tenant_members where tenant_id = $1 and user_id = $2",
        )
        .bind(tenant.id)
        .bind(alice.id)
        .fetch_one(&pool)
        .await?;
        assert_eq!(added_by.as_deref(), Some("member-adder"));
        let granted_by: Option<String> = sqlx::query_scalar(
            "select granted_by from member_roles where tenant_id = $1 and user_id = $2",
        )
        .bind(tenant.id)
        .bind(alice.id)
        .fetch_one(&pool)
        .await?;
        assert_eq!(granted_by.as_deref(), Some("member-adder"));

        members
            .set_roles(member, &[tenant_role_id], Some("role-setter"))
            .await
            .expect("set member roles");
        let granted_by: Option<String> = sqlx::query_scalar(
            "select granted_by from member_roles where tenant_id = $1 and user_id = $2",
        )
        .bind(tenant.id)
        .bind(alice.id)
        .fetch_one(&pool)
        .await?;
        assert_eq!(granted_by.as_deref(), Some("role-setter"));

        let expires_at = OffsetDateTime::now_utc() + Duration::days(7);
        let session = sessions
            .create(
                alice.id,
                Some(tenant.id),
                "audit-token-hash",
                expires_at,
                Some("session-creator"),
            )
            .await
            .expect("create session");
        let created_by: Option<String> =
            sqlx::query_scalar("select created_by from sessions where id = $1")
                .bind(session.id)
                .fetch_one(&pool)
                .await?;
        assert_eq!(created_by.as_deref(), Some("session-creator"));
        Ok(())
    }

    /// 迁移 0004 回填:在只跑到 0003 的库里塞两个存活用户 + 一个软删用户和 user_roles,再跑 0004 ——
    /// 两个存活用户都成为默认租户 active 成员,user_roles 复制进默认租户的 member_roles(原行保留);
    /// superadmin 改为平台角色并在默认租户兼任 admin(baserust-stack `docs/superpowers/specs/2026-11-25-multi-tenant-design.md` §4.7);软删用户不加;
    /// 有效会话(账号是默认租户成员)回填默认租户,已吊销 / 非成员的会话保持 NULL。
    #[sqlx::test(migrations = false)]
    async fn migration_backfills_default_tenant(pool: PgPool) -> sqlx::Result<()> {
        use idm::{MemberRepo, RoleRepo, DEFAULT_TENANT_ID};

        sqlx::query("create schema if not exists idm")
            .execute(&pool)
            .await?;
        IDM_MIGRATOR.run_to(3, &pool).await.expect("跑到 0003");

        let (user1, user2, gone) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
        for (id, name) in [(user1, "u1"), (user2, "u2"), (gone, "gone")] {
            sqlx::query("insert into users (id, username) values ($1, $2)")
                .bind(id)
                .bind(name)
                .execute(&pool)
                .await?;
        }
        sqlx::query("update users set deleted_at = now() where id = $1")
            .bind(gone)
            .execute(&pool)
            .await?;
        let (superadmin_role, admin_role, user_role) =
            (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
        for (id, name) in [
            (superadmin_role, "superadmin"),
            (admin_role, "admin"),
            (user_role, "user"),
        ] {
            sqlx::query("insert into roles (id, name, display_name) values ($1, $2, $2)")
                .bind(id)
                .bind(name)
                .execute(&pool)
                .await?;
        }
        for (user, role) in [
            (user1, superadmin_role),
            (user2, user_role),
            (user2, admin_role),
            (gone, user_role),
        ] {
            sqlx::query("insert into user_roles (user_id, role_id) values ($1, $2)")
                .bind(user)
                .bind(role)
                .execute(&pool)
                .await?;
        }

        // 升级前的会话:u1 有效、u2 已吊销、软删用户 gone 的有效会话(不是成员)
        let (live_session, revoked_session, gone_session) =
            (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
        for (session_id, user_id, revoked) in [
            (live_session, user1, false),
            (revoked_session, user2, true),
            (gone_session, gone, false),
        ] {
            sqlx::query(
                "insert into sessions (id, user_id, token_hash, expires_at, revoked_at)
                 values ($1, $2, $3, now() + interval '1 day',
                         case when $4 then now() else null end)",
            )
            .bind(session_id)
            .bind(user_id)
            .bind(session_id.to_string())
            .bind(revoked)
            .execute(&pool)
            .await?;
        }

        IDM_MIGRATOR.run(&pool).await.expect("跑 0004");

        // 有效会话且仍是默认租户成员 → 回填默认租户;已吊销 / 非成员的保持 NULL
        let sessions: Vec<(Uuid, Option<Uuid>)> =
            sqlx::query_as("select id, tenant_id from sessions order by id")
                .fetch_all(&pool)
                .await?;
        let mut expect = vec![
            (live_session, Some(DEFAULT_TENANT_ID)),
            (revoked_session, None),
            (gone_session, None),
        ];
        expect.sort();
        assert_eq!(sessions, expect);

        // 两个存活用户都是默认租户的 active 成员;软删的不加
        let members: Vec<(Uuid, String)> = sqlx::query_as(
            "select user_id, status from tenant_members where tenant_id = $1 order by user_id",
        )
        .bind(DEFAULT_TENANT_ID)
        .fetch_all(&pool)
        .await?;
        let mut expect = vec![(user1, "active".to_owned()), (user2, "active".to_owned())];
        expect.sort();
        assert_eq!(members, expect);

        // member_roles:u2 的 admin/user 原样复制;u1 的 superadmin 复制 + 兼任 admin
        let member_roles: Vec<(Uuid, Uuid)> = sqlx::query_as(
            "select user_id, role_id from member_roles where tenant_id = $1 order by user_id, role_id",
        )
        .bind(DEFAULT_TENANT_ID)
        .fetch_all(&pool)
        .await?;
        let mut expect = vec![
            (user1, superadmin_role),
            (user1, admin_role),
            (user2, admin_role),
            (user2, user_role),
        ];
        expect.sort();
        assert_eq!(member_roles, expect);
        // user_roles 原行保留(复制不是搬)
        let user_role_count: i64 = sqlx::query_scalar("select count(*) from user_roles")
            .fetch_one(&pool)
            .await?;
        assert_eq!(user_role_count, 4);

        // 经仓储读:平台角色只剩 superadmin;默认租户的租户角色按 scope 过滤
        let roles = PgRoleRepo::new(pool.clone());
        assert_eq!(
            roles.roles_for_user(user1).await.unwrap(),
            vec!["superadmin"]
        );
        let members = PgMemberRepo::new(pool.clone());
        let user1_memberships = members.memberships_for_user(user1).await.unwrap();
        assert_eq!(user1_memberships.len(), 1);
        assert_eq!(user1_memberships[0].tenant.id, DEFAULT_TENANT_ID);
        assert_eq!(user1_memberships[0].tenant.slug, "default");
        assert_eq!(user1_memberships[0].roles, vec!["admin"]);
        let user2_memberships = members.memberships_for_user(user2).await.unwrap();
        assert_eq!(user2_memberships[0].roles, vec!["admin", "user"]);
        Ok(())
    }

    /// 并发:同一个 refresh token 被并发使用 N 次,只能有一次成功(其余 Unauthorized),
    /// 且最终该用户只有一个活跃会话。find_active → revoke 若不是原子的,会分出多个都有效的会话。
    #[sqlx::test(migrations = false)]
    async fn pg_concurrent_refresh_with_same_token_rotates_once(pool: PgPool) -> sqlx::Result<()> {
        use idm::{AuthService, FakeHasher, IdmError, RegisterInput};
        use std::sync::Arc;

        bootstrap_idm(&pool)
            .await
            .expect("bootstrap idm schema + 跑 migrations");
        let no_signup_roles: Vec<String> = Vec::new();
        let service = Arc::new(
            AuthService::builder(
                PgUserRepo::new(pool.clone()),
                PgSessionRepo::new(pool.clone()),
                PgRoleRepo::new(pool.clone()),
                PgMemberRepo::new(pool.clone()),
            )
            .hs256_secret("secret")
            .hasher(FakeHasher)
            .signup_roles(no_signup_roles)
            .build(),
        );
        let registered = service
            .register(
                RegisterInput {
                    username: "alice".into(),
                    email: None,
                    password: "password123".into(),
                },
                None,
            )
            .await
            .expect("register");

        // 同时起 N 个任务:每个都先 find_active(都看到活跃会话)再撤销 —— 正是非原子轮换会出错的竞态窗口。
        const N: usize = 16;
        let mut handles = Vec::new();
        for i in 0..N {
            let service = Arc::clone(&service);
            let token = registered.refresh_token.clone();
            let tenant = registered.tenant_id;
            let user_id = registered.user.id;
            handles.push(tokio::spawn(async move {
                // 一半走 refresh、一半走 switch_tenant(切回同一个租户):两条路径共用同一把撤销闸
                let result = match tenant {
                    Some(tenant_id) if i % 2 == 1 => {
                        service
                            .switch_tenant(&token, MemberKey { tenant_id, user_id })
                            .await
                    }
                    _ => service.refresh(&token).await,
                };
                result.map(|outcome| outcome.session_id)
            }));
        }
        let mut successes = 0;
        for handle in handles {
            match handle.await.expect("task") {
                Ok(_) => successes += 1,
                Err(IdmError::Unauthorized) => {}
                Err(error) => panic!("并发使用同一 refresh 只该得到 Unauthorized,得到 {error:?}"),
            }
        }
        assert_eq!(
            successes, 1,
            "同一 refresh token 并发使用只能轮换出一个新会话"
        );
        let active: i64 = sqlx::query_scalar(
            "select count(*) from sessions where user_id = $1 and revoked_at is null",
        )
        .bind(registered.user.id)
        .fetch_one(&pool)
        .await?;
        assert_eq!(active, 1, "最终只剩一个活跃会话");
        Ok(())
    }

    /// 回滚 0004 不丢升级后授出的租户角色 —— 默认租户 **active 成员**的 member_roles 里**租户作用域**的行
    /// 写回 user_roles(已有的不重复);平台角色、别的租户的角色不写回;表与列都被删掉。
    /// 写回前先对账:user_roles 里租户作用域、但默认租户 active 成员的 member_roles 里没有的行删掉 ——
    /// 升级后被撤权 / 停用 / 移出的人回滚后不复活。
    #[sqlx::test(migrations = false)]
    async fn migration_0004_down_restores_default_tenant_roles(pool: PgPool) -> sqlx::Result<()> {
        use idm::{
            MemberRepo, MemberStatus, RoleRepo, RoleScope, TenantRepo, UserRepo, DEFAULT_TENANT_ID,
        };

        bootstrap_idm(&pool)
            .await
            .expect("bootstrap idm schema + 跑 migrations");
        let users = PgUserRepo::new(pool.clone());
        let roles = PgRoleRepo::new(pool.clone());
        let tenants = PgTenantRepo::new(pool.clone());
        let members = PgMemberRepo::new(pool.clone());

        let user_role = roles
            .upsert(
                NewRole {
                    name: "user",
                    display_name: "成员",
                    scope: RoleScope::Tenant,
                },
                None,
            )
            .await
            .unwrap();
        let admin_role = roles
            .upsert(
                NewRole {
                    name: "admin",
                    display_name: "管理员",
                    scope: RoleScope::Tenant,
                },
                None,
            )
            .await
            .unwrap();
        let superadmin_role = roles
            .upsert(
                NewRole {
                    name: "superadmin",
                    display_name: "平台管理员",
                    scope: RoleScope::Platform,
                },
                None,
            )
            .await
            .unwrap();
        // 升级后注册的新账号:默认租户 user 角色,只在 member_roles 里
        let newbie = users
            .create_with_membership(
                NewUser {
                    username: "newbie",
                    email: None,
                    password_hash: "h",
                },
                DEFAULT_TENANT_ID,
                &[user_role],
                None,
            )
            .await
            .unwrap();
        // 老账号:user_roles 已有 admin(迁移复制来的),默认租户里又被授了 user
        let old = users
            .create(
                NewUser {
                    username: "old",
                    email: None,
                    password_hash: "h",
                },
                None,
            )
            .await
            .unwrap();
        roles
            .grant(
                RoleGrant {
                    user_id: old.id,
                    role_id: admin_role,
                },
                None,
            )
            .await
            .unwrap();
        members
            .add(
                MemberKey {
                    tenant_id: DEFAULT_TENANT_ID,
                    user_id: old.id,
                },
                &[admin_role, user_role],
                None,
            )
            .await
            .unwrap();
        // 平台角色挂进 member_roles(写入只校验存在):不写回
        let platform_user = users
            .create(
                NewUser {
                    username: "plat",
                    email: None,
                    password_hash: "h",
                },
                None,
            )
            .await
            .unwrap();
        members
            .add(
                MemberKey {
                    tenant_id: DEFAULT_TENANT_ID,
                    user_id: platform_user.id,
                },
                &[superadmin_role],
                None,
            )
            .await
            .unwrap();
        // 别的租户的角色:不写回
        let acme = tenants
            .create(
                NewTenant {
                    slug: "acme",
                    name: "Acme",
                },
                None,
            )
            .await
            .unwrap();
        let other = users
            .create(
                NewUser {
                    username: "other",
                    email: None,
                    password_hash: "h",
                },
                None,
            )
            .await
            .unwrap();
        members
            .add(
                MemberKey {
                    tenant_id: acme.id,
                    user_id: other.id,
                },
                &[admin_role],
                None,
            )
            .await
            .unwrap();

        // 先对账再写回 —— 升级后在默认租户里被撤权 / 停用 / 移出的人,回滚后不能靠 user_roles 里
        // 迁移前遗留的租户角色行(或写回)复活。user_roles 里的租户角色行模拟 0004 之前的授予(up 只复制不搬)。
        // 撤权:老账号原有 admin(user_roles 遗留),升级后在默认租户被撤成只剩 user → 回滚后只有 user
        let demoted = users
            .create(
                NewUser {
                    username: "demoted",
                    email: None,
                    password_hash: "h",
                },
                None,
            )
            .await
            .unwrap();
        roles
            .grant(
                RoleGrant {
                    user_id: demoted.id,
                    role_id: admin_role,
                },
                None,
            )
            .await
            .unwrap();
        roles
            .grant(
                RoleGrant {
                    user_id: demoted.id,
                    role_id: superadmin_role,
                },
                None,
            )
            .await
            .unwrap(); // 平台角色:不受对账影响
        members
            .add(
                MemberKey {
                    tenant_id: DEFAULT_TENANT_ID,
                    user_id: demoted.id,
                },
                &[admin_role],
                None,
            )
            .await
            .unwrap();
        members
            .set_roles(
                MemberKey {
                    tenant_id: DEFAULT_TENANT_ID,
                    user_id: demoted.id,
                },
                &[user_role],
                None,
            )
            .await
            .unwrap();
        // 停用:关系与角色保留,但 status = inactive → 不写回,遗留的 admin 也删掉
        let paused = users
            .create(
                NewUser {
                    username: "paused",
                    email: None,
                    password_hash: "h",
                },
                None,
            )
            .await
            .unwrap();
        roles
            .grant(
                RoleGrant {
                    user_id: paused.id,
                    role_id: admin_role,
                },
                None,
            )
            .await
            .unwrap();
        members
            .add(
                MemberKey {
                    tenant_id: DEFAULT_TENANT_ID,
                    user_id: paused.id,
                },
                &[admin_role, user_role],
                None,
            )
            .await
            .unwrap();
        members
            .set_status(
                MemberKey {
                    tenant_id: DEFAULT_TENANT_ID,
                    user_id: paused.id,
                },
                MemberStatus::Inactive,
                None,
            )
            .await
            .unwrap();
        // 移出:成员行连同 member_roles 删掉 → 遗留的 admin 也删掉
        let gone = users
            .create(
                NewUser {
                    username: "gone",
                    email: None,
                    password_hash: "h",
                },
                None,
            )
            .await
            .unwrap();
        roles
            .grant(
                RoleGrant {
                    user_id: gone.id,
                    role_id: admin_role,
                },
                None,
            )
            .await
            .unwrap();
        members
            .add(
                MemberKey {
                    tenant_id: DEFAULT_TENANT_ID,
                    user_id: gone.id,
                },
                &[admin_role],
                None,
            )
            .await
            .unwrap();
        members
            .remove(
                MemberKey {
                    tenant_id: DEFAULT_TENANT_ID,
                    user_id: gone.id,
                },
                None,
            )
            .await
            .unwrap();

        IDM_MIGRATOR.undo(&pool, 3).await.expect("回滚 0004");

        let user_roles: Vec<(Uuid, Uuid)> =
            sqlx::query_as("select user_id, role_id from user_roles order by user_id, role_id")
                .fetch_all(&pool)
                .await?;
        let mut expect = vec![
            (newbie.id, user_role),
            (old.id, admin_role),
            (old.id, user_role),
            (demoted.id, user_role),
            (demoted.id, superadmin_role),
        ];
        expect.sort();
        assert_eq!(
            user_roles, expect,
            "撤权的只剩现有角色、停用 / 移出的租户角色不复活、平台角色不动"
        );

        // 0004 建的表 / 列都没了
        let left: i64 = sqlx::query_scalar(
            "select count(*) from information_schema.tables \
             where table_schema = current_schema() \
               and table_name in ('tenants', 'tenant_members', 'member_roles')",
        )
        .fetch_one(&pool)
        .await?;
        assert_eq!(left, 0);
        let column_count: i64 = sqlx::query_scalar(
            "select count(*) from information_schema.columns \
             where table_schema = current_schema() \
               and ((table_name = 'roles' and column_name = 'scope') \
                 or (table_name = 'sessions' and column_name = 'tenant_id'))",
        )
        .fetch_one(&pool)
        .await?;
        assert_eq!(column_count, 0);

        // 再升回去照常(down 之后 up 可重放)
        IDM_MIGRATOR.run(&pool).await.expect("重新跑 0004");
        Ok(())
    }

    /// outbox:仓储写方法同事务落行用的 `emit_outbox` 是 postgres 模块的私有函数,外部集成测试够不着,
    /// 改直插 SQL 模拟写方法落行的效果 → poll_unpublished 见到(FIFO,按 id 升序)→ mark 第一条 → 只剩第二条 → mark 完 → 空。
    #[sqlx::test(migrations = false)]
    async fn pg_outbox_poll_and_mark(pool: PgPool) -> sqlx::Result<()> {
        use serde_json::json;

        bootstrap_idm(&pool)
            .await
            .expect("bootstrap idm schema + 跑 migrations");

        for who in ["a", "b"] {
            sqlx::query(
                "insert into outbox (event_type, aggregate_id, payload) values ($1, $2, $3)",
            )
            .bind("user.created")
            .bind(Uuid::now_v7())
            .bind(json!({ "who": who }))
            .execute(&pool)
            .await?;
        }

        let outbox = PgOutboxRepo::new(pool.clone());
        let rows = outbox.poll_unpublished(10).await.expect("poll");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].payload["who"], "a"); // FIFO:id 升序
        assert_eq!(rows[1].payload["who"], "b");

        outbox
            .mark_published(&[rows[0].id])
            .await
            .expect("mark first");
        let remaining = outbox.poll_unpublished(10).await.expect("poll again");
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].payload["who"], "b");

        outbox
            .mark_published(&[remaining[0].id])
            .await
            .expect("mark second");
        assert!(outbox
            .poll_unpublished(10)
            .await
            .expect("poll empty")
            .is_empty());
        Ok(())
    }
}
