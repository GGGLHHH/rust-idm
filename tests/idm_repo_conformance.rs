//! idm repo 契约一致性:**同一批断言对内存与 PG 的三个 repo 各跑一遍**,钉死行为 parity。
//! user(create/find/update/soft_delete/password)+ session(create/find_active/revoke)+ role(upsert/grant/roles)。
//! "内存绿不保证 PG 绿"的漂移,全靠这套契约抓。
//!
//! 内存入口:默认 `cargo test` 就跑(零 DB)。
//! PG 入口:`just test-pg`(需 DATABASE_URL 连 idm role + 跑着的 pg)。

use idm::IdmError;
use idm::{
    ListPage, MemberRepo, MemberStatus, OutboxRepo, RoleRepo, RoleScope, SessionRepo, SortDir,
    TenantRepo, TenantStatus, UserListFilter, UserRepo, UserSortBy, DEFAULT_TENANT_ID,
};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

/// 契约唯一真相源。三个 repo 协作(user → session → role),内存与 PG 都调它。
/// PG 有 FK(sessions/user_roles → users),故必须先建 user 再建 session/grant。
async fn idm_repo_contract(users: &dyn UserRepo, sessions: &dyn SessionRepo, roles: &dyn RoleRepo) {
    // ── user:create + find(username/email)+ 重复 → Conflict + password_hash ──
    let u = users
        .create("alice", Some("a@b.com"), "hash1", Some("sys".into()))
        .await
        .unwrap();
    assert_eq!(u.username, "alice");
    assert!(users.find_by_identifier("alice").await.unwrap().is_some());
    assert!(users.find_by_identifier("a@b.com").await.unwrap().is_some());
    assert!(users.find_by_identifier("nobody").await.unwrap().is_none());
    assert_eq!(users.find_by_id(u.id).await.unwrap().username, "alice");
    assert!(matches!(
        users.create("alice", None, "h", None).await,
        Err(IdmError::Conflict(_))
    ));
    assert_eq!(
        users.password_hash(u.id).await.unwrap().as_deref(),
        Some("hash1")
    );

    // ── find_by_ids:批量富化根原语,内存↔PG parity(命中 + 缺席 + 空集 + 软删过滤)──
    let bob = users.create("bob", None, "h2", None).await.unwrap();
    assert_eq!(users.find_by_ids(&[u.id, bob.id]).await.unwrap().len(), 2);
    let missing = Uuid::now_v7();
    assert_eq!(users.find_by_ids(&[u.id, missing]).await.unwrap().len(), 1); // 不存在的缺席
    assert!(users.find_by_ids(&[]).await.unwrap().is_empty()); // 空集 → 空
    users.soft_delete(bob.id, None).await.unwrap();
    assert!(users.find_by_ids(&[bob.id]).await.unwrap().is_empty()); // 软删后消失(富化降级依据)

    // ── role:upsert 幂等 + grant 幂等 + roles_for_user ──
    let rid = roles
        .upsert("admin", "管理员", RoleScope::Platform, Some("sys".into()))
        .await
        .unwrap();
    assert_eq!(
        roles
            .upsert("admin", "管理员", RoleScope::Platform, None)
            .await
            .unwrap(),
        rid
    ); // 幂等返同 id
    assert!(roles.roles_for_user(u.id).await.unwrap().is_empty());
    roles.grant(u.id, rid, Some("sys".into())).await.unwrap();
    roles.grant(u.id, rid, None).await.unwrap(); // 幂等:不重复授予
    assert_eq!(
        roles.roles_for_user(u.id).await.unwrap(),
        vec!["admin".to_string()]
    );

    // ── session:create + find_active + 过期 + revoke + revoke_all ──
    let now = OffsetDateTime::now_utc();
    let future = now + Duration::days(7);
    let s = sessions
        .create(u.id, None, "tokhash1", future, Some("sys".into()))
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
    sessions.revoke(s.id).await.unwrap();
    assert!(sessions
        .find_active("tokhash1", now)
        .await
        .unwrap()
        .is_none());
    // revoke_all:撤销该用户全部
    sessions
        .create(u.id, None, "tokhash2", future, None)
        .await
        .unwrap();
    sessions
        .create(u.id, None, "tokhash3", future, None)
        .await
        .unwrap();
    sessions.revoke_all(u.id, None).await.unwrap();
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
    let upd = users
        .update(u.id, "alice2", None, Some("sys".into()))
        .await
        .unwrap();
    assert_eq!(upd.username, "alice2");
    users.update_password(u.id, "hash2").await.unwrap();
    assert_eq!(
        users.password_hash(u.id).await.unwrap().as_deref(),
        Some("hash2")
    );
    users.soft_delete(u.id, None).await.unwrap();
    assert!(matches!(
        users.find_by_id(u.id).await,
        Err(IdmError::NotFound)
    ));
    assert!(users.find_by_identifier("alice2").await.unwrap().is_none()); // 软删后查不到
    assert!(matches!(
        users.soft_delete(u.id, None).await,
        Err(IdmError::NotFound)
    )); // 二次删幂等
}

/// user-admin 原语契约(list 过滤/排序/分页 + create_with_roles 原子/409 + RoleRepo list/set_roles）。
/// 内存与 PG 各跑一遍。断言只用**稳定属性**(username / 计数 / 角色成员),不比跨实现的 id 值。
/// 前提:`users` 与 `roles` **共享**角色/授予状态(内存用 `sharing_with`,PG 天然共表)。
async fn idm_user_admin_contract(users: &dyn UserRepo, roles: &dyn RoleRepo) {
    fn names(r: &idm::UserListResult) -> Vec<&str> {
        r.rows.iter().map(|u| u.username.as_str()).collect()
    }
    let offset = |o: u64, l: u64, t: bool| ListPage::Offset {
        offset: o,
        limit: l,
        with_total: t,
    };

    // ── 种子:3 角色 + 4 用户(经 create_with_roles,插入序 = id/created 序)──
    let admin = roles
        .upsert("admin", "Admin", RoleScope::Platform, None)
        .await
        .unwrap();
    let editor = roles
        .upsert("editor", "Editor", RoleScope::Platform, None)
        .await
        .unwrap();
    let viewer = roles
        .upsert("viewer", "Viewer", RoleScope::Platform, None)
        .await
        .unwrap();

    let alice = users
        .create_with_roles("alice", Some("a@x.io"), "h", &[admin], None)
        .await
        .unwrap();
    let bob = users
        .create_with_roles("bob", None, "h", &[editor], None)
        .await
        .unwrap();
    let carol = users
        .create_with_roles("carol", Some("c@x.io"), "h", &[admin, editor], None)
        .await
        .unwrap();
    let _dave = users
        .create_with_roles("dave", None, "h", &[], None)
        .await
        .unwrap();

    // ── create_with_roles:唯一冲突 → Conflict;角色确实被关联 ──
    assert!(matches!(
        users.create_with_roles("alice", None, "h", &[], None).await,
        Err(IdmError::Conflict(_))
    ));
    let mut carol_roles = roles.roles_for_user(carol.id).await.unwrap();
    carol_roles.sort();
    assert_eq!(carol_roles, vec!["admin".to_string(), "editor".to_string()]);

    // ── username 模糊(含 "a",大小写不敏感)→ alice, carol, dave(bob 无 a)──
    let f = UserListFilter {
        username: Some("A".into()),
        ..Default::default()
    };
    let r = users
        .list(&f, UserSortBy::Username, SortDir::Asc, &offset(0, 10, true))
        .await
        .unwrap();
    assert_eq!(names(&r), ["alice", "carol", "dave"]);
    assert_eq!(r.total, Some(3));
    // roles 列:alice 的 roles = [admin]
    assert_eq!(r.rows[0].roles, vec!["admin".to_string()]);

    // ── roles_any = [admin] → alice, carol ──
    let f = UserListFilter {
        roles_any: vec!["admin".into()],
        ..Default::default()
    };
    let r = users
        .list(
            &f,
            UserSortBy::Username,
            SortDir::Asc,
            &offset(0, 10, false),
        )
        .await
        .unwrap();
    assert_eq!(names(&r), ["alice", "carol"]);
    assert!(r.total.is_none());

    // ── roles_none = [admin] → bob, dave ──
    let f = UserListFilter {
        roles_none: vec!["admin".into()],
        ..Default::default()
    };
    let r = users
        .list(
            &f,
            UserSortBy::Username,
            SortDir::Asc,
            &offset(0, 10, false),
        )
        .await
        .unwrap();
    assert_eq!(names(&r), ["bob", "dave"]);

    // ── sort Email Asc NULLS LAST:非空升序(a@x.io<c@x.io)后接空(id 升序:bob<dave)──
    let r = users
        .list(
            &UserListFilter::default(),
            UserSortBy::Email,
            SortDir::Asc,
            &offset(0, 10, false),
        )
        .await
        .unwrap();
    assert_eq!(names(&r), ["alice", "carol", "bob", "dave"]);
    // Email Desc NULLS LAST:非空降序(carol,alice)后接空(id 降序:dave,bob)
    let r = users
        .list(
            &UserListFilter::default(),
            UserSortBy::Email,
            SortDir::Desc,
            &offset(0, 10, false),
        )
        .await
        .unwrap();
    assert_eq!(names(&r), ["carol", "alice", "dave", "bob"]);

    // ── sort CreatedAt:asc = 插入序,desc = 逆序 ──
    let r = users
        .list(
            &UserListFilter::default(),
            UserSortBy::CreatedAt,
            SortDir::Asc,
            &offset(0, 10, false),
        )
        .await
        .unwrap();
    assert_eq!(names(&r), ["alice", "bob", "carol", "dave"]);
    let r = users
        .list(
            &UserListFilter::default(),
            UserSortBy::CreatedAt,
            SortDir::Desc,
            &offset(0, 10, false),
        )
        .await
        .unwrap();
    assert_eq!(names(&r), ["dave", "carol", "bob", "alice"]);

    // ── offset 分页:username asc, offset=1 limit=2, with_total ──
    let r = users
        .list(
            &UserListFilter::default(),
            UserSortBy::Username,
            SortDir::Asc,
            &offset(1, 2, true),
        )
        .await
        .unwrap();
    assert_eq!(names(&r), ["bob", "carol"]);
    assert_eq!(r.total, Some(4));

    // ── cursor(created desc ≈ id desc):首页 limit=2 → dave, carol + next_after=Some ──
    let p1 = users
        .list(
            &UserListFilter::default(),
            UserSortBy::CreatedAt,
            SortDir::Desc,
            &ListPage::Cursor {
                after: None,
                limit: 2,
            },
        )
        .await
        .unwrap();
    assert_eq!(names(&p1), ["dave", "carol"]);
    let after = p1.next_after.expect("首页应有下一页游标");
    // 次页:after=carol 游标 → bob, alice + 无更多
    let p2 = users
        .list(
            &UserListFilter::default(),
            UserSortBy::CreatedAt,
            SortDir::Desc,
            &ListPage::Cursor {
                after: Some(after),
                limit: 2,
            },
        )
        .await
        .unwrap();
    assert_eq!(names(&p2), ["bob", "alice"]);
    assert!(p2.next_after.is_none());

    // ── RoleRepo::list:3 存活角色,按 name 排序 ──
    let rl = roles.list().await.unwrap();
    assert_eq!(
        rl.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
        ["admin", "editor", "viewer"]
    );
    assert_eq!(rl[0].display_name, "Admin");

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
    let mut got2 = roles.roles_for_user(alice.id).await.unwrap();
    got2.sort();
    assert_eq!(got2, vec!["editor".to_string(), "viewer".to_string()]);

    // set_roles 反映到 list:roles_any=[admin] 现在只剩 carol(alice 已去 admin)
    let f = UserListFilter {
        roles_any: vec!["admin".into()],
        ..Default::default()
    };
    let r = users
        .list(
            &f,
            UserSortBy::Username,
            SortDir::Asc,
            &offset(0, 10, false),
        )
        .await
        .unwrap();
    assert_eq!(names(&r), ["carol"]);

    // ── LIKE 元字符转义:username 过滤按字面匹配(_ / % 非通配),内存↔PG parity ──
    // 造 a_b / axb / a%b / ayb:未转义时 "a_b"(_=任意单字符)会误命中全部四个。
    for u in ["a_b", "axb", "a%b", "ayb"] {
        users
            .create_with_roles(u, None, "h", &[], None)
            .await
            .unwrap();
    }
    let f = UserListFilter {
        username: Some("a_b".into()),
        ..Default::default()
    };
    let r = users
        .list(
            &f,
            UserSortBy::Username,
            SortDir::Asc,
            &offset(0, 10, false),
        )
        .await
        .unwrap();
    assert_eq!(names(&r), ["a_b"]); // 字面下划线:只命中 a_b,不含 axb/ayb/a%b
    let f = UserListFilter {
        username: Some("a%b".into()),
        ..Default::default()
    };
    let r = users
        .list(
            &f,
            UserSortBy::Username,
            SortDir::Asc,
            &offset(0, 10, false),
        )
        .await
        .unwrap();
    assert_eq!(names(&r), ["a%b"]); // 字面百分号:只命中 a%b

    // ── 排序 collation parity:混合大小写按字节序(C collation),内存↔PG 必须同序 ──
    // expected 由 Rust str Ord 现算(= 字节序 = COLLATE "C"),两后端都须等于它 → 真 parity。
    // 无 COLLATE "C" 时 PG 按库默认 collation(可能大小写不敏感)会漂移、断言挂。
    let mixed = ["Mx-Bob", "Mx-alice", "Mx-Carol", "Mx-dave"];
    for m in mixed {
        users
            .create_with_roles(m, None, "h", &[], None)
            .await
            .unwrap();
    }
    let f = UserListFilter {
        username: Some("Mx-".into()),
        ..Default::default()
    };
    let r = users
        .list(
            &f,
            UserSortBy::Username,
            SortDir::Asc,
            &offset(0, 10, false),
        )
        .await
        .unwrap();
    let mut expected = mixed.to_vec();
    expected.sort_unstable();
    assert_eq!(names(&r), expected);

    let _ = bob;
}

/// outbox 事件契约(Task 2):每个写方法在自己的事务/锁内 emit 一条领域事件,payload 形状正确,
/// 失败路径(唯一冲突 / 非法 role_id)不留残留行。内存(三件套共享存储)与 PG(天然共表)各跑一遍。
async fn idm_outbox_contract(users: &dyn UserRepo, roles: &dyn RoleRepo, outbox: &dyn OutboxRepo) {
    assert!(outbox.poll_unpublished(100).await.unwrap().is_empty());

    let editor = roles
        .upsert("editor", "Editor", RoleScope::Platform, None)
        .await
        .unwrap();
    let viewer = roles
        .upsert("viewer", "Viewer", RoleScope::Platform, None)
        .await
        .unwrap();

    // ── create_with_roles → 恰一条 user.created,payload 含正确角色名 ──
    let dana = users
        .create_with_roles("dana", Some("dana@x.io"), "h", &[editor], None)
        .await
        .unwrap();
    let rows = outbox.poll_unpublished(100).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].event_type, "user.created");
    assert_eq!(rows[0].aggregate_id, dana.id);
    let p = &rows[0].payload;
    assert_eq!(p["user_id"], serde_json::to_value(dana.id).unwrap());
    assert_eq!(p["username"], "dana");
    assert_eq!(p["email"], "dana@x.io");
    assert_eq!(p["email_verified"], false);
    assert_eq!(
        p["created_at"],
        serde_json::to_value(dana.created_at).unwrap()
    );
    assert_eq!(p["roles"], serde_json::json!(["editor"]));
    outbox.mark_published(&[rows[0].id]).await.unwrap();

    // ── create(无角色)→ user.created,roles = [] ──
    let erin = users.create("erin", None, "h", None).await.unwrap();
    let rows = outbox.poll_unpublished(100).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].event_type, "user.created");
    assert_eq!(rows[0].aggregate_id, erin.id);
    assert_eq!(rows[0].payload["roles"], serde_json::json!([]));
    assert_eq!(rows[0].payload["email"], serde_json::Value::Null);
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
        .create_with_roles("erin", None, "h", &[], None)
        .await
        .is_err());
    assert!(outbox.poll_unpublished(100).await.unwrap().is_empty());

    // ── 回滚:非法 role_id 的 create_with_roles 失败 → 无残留,且两后端同一 NotFound 变体 ──
    let bogus_role = Uuid::now_v7();
    let err = users
        .create_with_roles("frank", None, "h", &[bogus_role], None)
        .await
        .err()
        .unwrap();
    assert!(
        matches!(err, IdmError::NotFound),
        "invalid role_id must be NotFound, got {err:?}"
    );
    assert!(outbox.poll_unpublished(100).await.unwrap().is_empty());

    // ── 回滚:非法 role_id 的 set_roles 失败 → 无残留,且两后端同一 NotFound 变体 ──
    let err = roles
        .set_roles(erin.id, &[bogus_role], None)
        .await
        .unwrap_err();
    assert!(
        matches!(err, IdmError::NotFound),
        "invalid role_id must be NotFound, got {err:?}"
    );
    assert!(outbox.poll_unpublished(100).await.unwrap().is_empty());
}

/// 多租户数据层契约(Task 1):租户 / 成员 / 租户角色 / 平台角色过滤 / 按租户吊销会话 / tenant.* 事件。
/// 每个用例一个 async fn,内存(全部 repo 共享存储)与 PG(天然共表)各跑一遍。
/// **两边都有默认租户**:PG 由迁移 0004 插入,内存实现构造时镜像插入 —— 断言据此写。
mod idm_tenant_contract {
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
            let users = idm::InMemoryUserRepo::new();
            Self {
                roles: Box::new(idm::InMemoryRoleRepo::sharing_with(&users)),
                sessions: Box::new(idm::InMemorySessionRepo::sharing_with(&users)),
                tenants: Box::new(idm::InMemoryTenantRepo::sharing_with(&users)),
                members: Box::new(idm::InMemoryMemberRepo::sharing_with(&users)),
                outbox: Box::new(idm::InMemoryOutboxRepo::sharing_with(&users)),
                users: Box::new(users),
            }
        }

        #[cfg(feature = "pg-conformance")]
        pub(crate) fn pg(pool: sqlx::PgPool) -> Self {
            Self {
                users: Box::new(idm::PgUserRepo::new(pool.clone())),
                roles: Box::new(idm::PgRoleRepo::new(pool.clone())),
                sessions: Box::new(idm::PgSessionRepo::new(pool.clone())),
                tenants: Box::new(idm::PgTenantRepo::new(pool.clone())),
                members: Box::new(idm::PgMemberRepo::new(pool.clone())),
                outbox: Box::new(idm::PgOutboxRepo::new(pool)),
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

    fn tenant_ids(ms: &[idm::Membership]) -> Vec<Uuid> {
        ms.iter().map(|m| m.tenant.id).collect()
    }

    pub(crate) async fn add_member_then_memberships_for_user_lists_it(r: Repos) {
        let alice = r.users.create("alice", None, "h", None).await.unwrap();
        let bob = r.users.create("bob", None, "h", None).await.unwrap();
        let t_admin = r
            .roles
            .upsert("t_admin", "租户管理员", RoleScope::Tenant, None)
            .await
            .unwrap();
        let acme = r
            .tenants
            .create("acme", "Acme", Some("sys".into()))
            .await
            .unwrap();
        assert_eq!(acme.slug, "acme");
        assert_eq!(acme.status, TenantStatus::Active);
        assert!(acme.deleted_at.is_none());
        assert!(r
            .members
            .memberships_for_user(alice.id)
            .await
            .unwrap()
            .is_empty());

        let m = r
            .members
            .add(acme.id, alice.id, &[t_admin], Some("sys".into()))
            .await
            .unwrap();
        assert_eq!(m.tenant.id, acme.id);
        assert_eq!(m.user_id, alice.id);
        assert_eq!(m.status, MemberStatus::Active);
        assert_eq!(m.roles, vec!["t_admin".to_string()]);
        assert!(m.last_used_at.is_none());

        let ms = r.members.memberships_for_user(alice.id).await.unwrap();
        assert_eq!(tenant_ids(&ms), vec![acme.id]);
        assert_eq!(ms[0].tenant.slug, "acme");
        assert_eq!(ms[0].roles, vec!["t_admin".to_string()]);

        // get:成员 Some、非成员 None
        assert!(r.members.get(acme.id, alice.id).await.unwrap().is_some());
        assert!(r.members.get(acme.id, bob.id).await.unwrap().is_none());

        // 重复加 → Conflict;不存在的租户 → NotFound;非法 role_id → NotFound(且不留半截)
        assert!(matches!(
            r.members.add(acme.id, alice.id, &[], None).await,
            Err(IdmError::Conflict(_))
        ));
        assert!(matches!(
            r.members.add(Uuid::now_v7(), alice.id, &[], None).await,
            Err(IdmError::NotFound)
        ));
        assert!(matches!(
            r.members
                .add(acme.id, bob.id, &[Uuid::now_v7()], None)
                .await,
            Err(IdmError::NotFound)
        ));
        assert!(r.members.get(acme.id, bob.id).await.unwrap().is_none());

        // list_by_tenant:只有 alice
        let page = r
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
        let beta = r.tenants.create("beta", "Beta", None).await.unwrap();
        r.members.add(beta.id, alice.id, &[], None).await.unwrap();
        r.members.touch_last_used(beta.id, alice.id).await.unwrap();
        let ms = r.members.memberships_for_user(alice.id).await.unwrap();
        assert_eq!(tenant_ids(&ms), vec![beta.id, acme.id]);
        assert!(ms[0].last_used_at.is_some());
        assert!(ms[1].last_used_at.is_none());
        // 非成员 touch → NotFound
        assert!(matches!(
            r.members.touch_last_used(beta.id, bob.id).await,
            Err(IdmError::NotFound)
        ));
    }

    pub(crate) async fn suspended_tenant_excluded_from_memberships(r: Repos) {
        let alice = r.users.create("alice", None, "h", None).await.unwrap();
        let t1 = r.tenants.create("t1", "T1", None).await.unwrap();
        let t2 = r.tenants.create("t2", "T2", None).await.unwrap();
        r.members.add(t1.id, alice.id, &[], None).await.unwrap();
        r.members.add(t2.id, alice.id, &[], None).await.unwrap();
        let mut both = tenant_ids(&r.members.memberships_for_user(alice.id).await.unwrap());
        both.sort();
        assert_eq!(both, vec![t1.id, t2.id]);

        let s = r
            .tenants
            .set_status(t1.id, TenantStatus::Suspended, None)
            .await
            .unwrap();
        assert_eq!(s.status, TenantStatus::Suspended);
        assert_eq!(
            r.tenants.get(t1.id).await.unwrap().status,
            TenantStatus::Suspended
        );
        assert_eq!(
            tenant_ids(&r.members.memberships_for_user(alice.id).await.unwrap()),
            vec![t2.id]
        );
        // 停用租户的成员关系本身还在(get 不过滤状态,由调用方判断)
        let m = r.members.get(t1.id, alice.id).await.unwrap().unwrap();
        assert_eq!(m.tenant.status, TenantStatus::Suspended);

        // 恢复 → 又回来
        r.tenants
            .set_status(t1.id, TenantStatus::Active, None)
            .await
            .unwrap();
        assert_eq!(
            r.members
                .memberships_for_user(alice.id)
                .await
                .unwrap()
                .len(),
            2
        );

        // 软删租户 → 也不在列表里;get / get_by_slug → NotFound;改它 → NotFound
        r.tenants.soft_delete(t2.id, None).await.unwrap();
        assert_eq!(
            tenant_ids(&r.members.memberships_for_user(alice.id).await.unwrap()),
            vec![t1.id]
        );
        assert!(matches!(
            r.tenants.get(t2.id).await,
            Err(IdmError::NotFound)
        ));
        assert!(matches!(
            r.tenants.get_by_slug("t2").await,
            Err(IdmError::NotFound)
        ));
        assert!(matches!(
            r.tenants
                .set_status(t2.id, TenantStatus::Active, None)
                .await,
            Err(IdmError::NotFound)
        ));
        assert!(matches!(
            r.tenants.soft_delete(t2.id, None).await,
            Err(IdmError::NotFound)
        ));
        assert!(matches!(
            r.tenants
                .set_status(Uuid::now_v7(), TenantStatus::Active, None)
                .await,
            Err(IdmError::NotFound)
        ));
    }

    pub(crate) async fn inactive_member_excluded(r: Repos) {
        let alice = r.users.create("alice", None, "h", None).await.unwrap();
        let bob = r.users.create("bob", None, "h", None).await.unwrap();
        let t = r.tenants.create("acme", "Acme", None).await.unwrap();
        r.members.add(t.id, alice.id, &[], None).await.unwrap();
        r.members.add(t.id, bob.id, &[], None).await.unwrap();

        r.members
            .set_status(t.id, alice.id, MemberStatus::Inactive, None)
            .await
            .unwrap();
        assert!(r
            .members
            .memberships_for_user(alice.id)
            .await
            .unwrap()
            .is_empty());
        // 只影响 alice
        assert_eq!(
            r.members.memberships_for_user(bob.id).await.unwrap().len(),
            1
        );
        // get 仍能看到(带状态),list_by_tenant 也列出(管理端要看停用成员)
        let m = r.members.get(t.id, alice.id).await.unwrap().unwrap();
        assert_eq!(m.status, MemberStatus::Inactive);
        let page = r
            .members
            .list_by_tenant(
                t.id,
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
        r.members
            .set_status(t.id, alice.id, MemberStatus::Active, None)
            .await
            .unwrap();
        assert_eq!(
            r.members
                .memberships_for_user(alice.id)
                .await
                .unwrap()
                .len(),
            1
        );
        // 非成员 → NotFound
        assert!(matches!(
            r.members
                .set_status(Uuid::now_v7(), alice.id, MemberStatus::Inactive, None)
                .await,
            Err(IdmError::NotFound)
        ));
    }

    pub(crate) async fn slug_not_reusable_after_delete(r: Repos) {
        let t = r.tenants.create("acme", "Acme", None).await.unwrap();
        assert_eq!(r.tenants.get_by_slug("acme").await.unwrap().id, t.id);
        assert!(matches!(
            r.tenants.create("acme", "Other", None).await,
            Err(IdmError::Conflict(_))
        ));
        r.tenants.soft_delete(t.id, None).await.unwrap();
        assert!(matches!(
            r.tenants.get_by_slug("acme").await,
            Err(IdmError::NotFound)
        ));
        // 删除后 slug 仍占着:不复用
        assert!(matches!(
            r.tenants.create("acme", "Again", None).await,
            Err(IdmError::Conflict(_))
        ));

        // upsert_fixed:默认租户两边都已在(PG 迁移 / 内存构造),幂等返回同一行
        let d = r
            .tenants
            .upsert_fixed(DEFAULT_TENANT_ID, "default", "默认组织", None)
            .await
            .unwrap();
        assert_eq!(d.id, DEFAULT_TENANT_ID);
        assert_eq!(d.slug, "default");
        let d2 = r
            .tenants
            .upsert_fixed(DEFAULT_TENANT_ID, "default", "默认组织", None)
            .await
            .unwrap();
        assert_eq!(d2.id, DEFAULT_TENANT_ID);
        // 新的固定 id:建出来;再调幂等
        let fixed = Uuid::from_u128(0x42);
        let f = r
            .tenants
            .upsert_fixed(fixed, "fixed", "Fixed", None)
            .await
            .unwrap();
        assert_eq!((f.id, f.slug.as_str()), (fixed, "fixed"));
        assert_eq!(
            r.tenants
                .upsert_fixed(fixed, "fixed", "Fixed", None)
                .await
                .unwrap()
                .id,
            fixed
        );
        // slug 被别的 id 占了 → Conflict(含已删的 acme)
        assert!(matches!(
            r.tenants
                .upsert_fixed(Uuid::from_u128(0x43), "acme", "X", None)
                .await,
            Err(IdmError::Conflict(_))
        ));

        // update_name
        let renamed = r.tenants.update_name(fixed, "Fixed 2", None).await.unwrap();
        assert_eq!(renamed.name, "Fixed 2");
        assert_eq!(renamed.slug, "fixed");

        // list:只见存活(default + fixed;acme 已删),按 id 升序;cursor 翻页
        let all = r
            .tenants
            .list(&ListPage::Offset {
                offset: 0,
                limit: 10,
                with_total: true,
            })
            .await
            .unwrap();
        assert_eq!(all.total, Some(2));
        assert_eq!(
            all.rows.iter().map(|t| t.id).collect::<Vec<_>>(),
            vec![DEFAULT_TENANT_ID, fixed]
        );
        let p1 = r
            .tenants
            .list(&ListPage::Cursor {
                after: None,
                limit: 1,
            })
            .await
            .unwrap();
        assert_eq!(p1.rows[0].id, DEFAULT_TENANT_ID);
        let p2 = r
            .tenants
            .list(&ListPage::Cursor {
                after: p1.next_after,
                limit: 1,
            })
            .await
            .unwrap();
        assert_eq!(p2.rows[0].id, fixed);
        assert!(p2.next_after.is_none());
    }

    pub(crate) async fn roles_for_user_returns_platform_scope_only(r: Repos) {
        let alice = r.users.create("alice", None, "h", None).await.unwrap();
        let sa = r
            .roles
            .upsert("sa", "平台管理员", RoleScope::Platform, None)
            .await
            .unwrap();
        let ta = r
            .roles
            .upsert("ta", "租户角色", RoleScope::Tenant, None)
            .await
            .unwrap();
        r.roles.grant(alice.id, sa, None).await.unwrap();
        r.roles.grant(alice.id, ta, None).await.unwrap();
        assert_eq!(
            r.roles.roles_for_user(alice.id).await.unwrap(),
            vec!["sa".to_string()]
        );
        // 目录带 scope
        let list = r.roles.list().await.unwrap();
        let scope_of = |n: &str| list.iter().find(|x| x.name == n).unwrap().scope;
        assert_eq!(scope_of("sa"), RoleScope::Platform);
        assert_eq!(scope_of("ta"), RoleScope::Tenant);

        // 成员角色读取同样按 scope 过滤:平台角色挂进 member_roles 也不算租户角色
        let t = r.tenants.create("acme", "Acme", None).await.unwrap();
        let m = r
            .members
            .add(t.id, alice.id, &[sa, ta], None)
            .await
            .unwrap();
        assert_eq!(m.roles, vec!["ta".to_string()]);

        // upsert 以调用方 scope 为准(代码闭集是真相源):同名再 upsert 成 platform → 改 scope、id 不变
        assert_eq!(
            r.roles
                .upsert("ta", "租户角色", RoleScope::Platform, None)
                .await
                .unwrap(),
            ta
        );
        let mut got = r.roles.roles_for_user(alice.id).await.unwrap();
        got.sort();
        assert_eq!(got, vec!["sa".to_string(), "ta".to_string()]);
        assert!(r
            .members
            .get(t.id, alice.id)
            .await
            .unwrap()
            .unwrap()
            .roles
            .is_empty());
    }

    pub(crate) async fn member_roles_are_per_tenant(r: Repos) {
        let alice = r.users.create("alice", None, "h", None).await.unwrap();
        let admin = r
            .roles
            .upsert("t_admin", "A", RoleScope::Tenant, None)
            .await
            .unwrap();
        let user = r
            .roles
            .upsert("t_user", "U", RoleScope::Tenant, None)
            .await
            .unwrap();
        let t1 = r.tenants.create("t1", "T1", None).await.unwrap();
        let t2 = r.tenants.create("t2", "T2", None).await.unwrap();
        r.members
            .add(t1.id, alice.id, &[admin], None)
            .await
            .unwrap();
        r.members.add(t2.id, alice.id, &[user], None).await.unwrap();

        let roles_in = |t: Uuid| {
            let members = &r.members;
            let uid = alice.id;
            async move { members.get(t, uid).await.unwrap().unwrap().roles }
        };
        assert_eq!(roles_in(t1.id).await, vec!["t_admin".to_string()]);
        assert_eq!(roles_in(t2.id).await, vec!["t_user".to_string()]);
        // 租户角色不进平台角色
        assert!(r.roles.roles_for_user(alice.id).await.unwrap().is_empty());

        // set_roles 全量替换只动 t1;结果按名排序
        r.members
            .set_roles(t1.id, alice.id, &[user, admin], None)
            .await
            .unwrap();
        assert_eq!(
            roles_in(t1.id).await,
            vec!["t_admin".to_string(), "t_user".to_string()]
        );
        assert_eq!(roles_in(t2.id).await, vec!["t_user".to_string()]);
        // 幂等
        r.members
            .set_roles(t1.id, alice.id, &[user, admin], None)
            .await
            .unwrap();
        assert_eq!(roles_in(t1.id).await.len(), 2);
        // memberships_for_user 每个租户带各自角色
        let ms = r.members.memberships_for_user(alice.id).await.unwrap();
        let of = |t: Uuid| ms.iter().find(|m| m.tenant.id == t).unwrap().roles.clone();
        assert_eq!(of(t1.id).len(), 2);
        assert_eq!(of(t2.id), vec!["t_user".to_string()]);

        // 非法 role_id → NotFound 且原角色不变;非成员 → NotFound
        assert!(matches!(
            r.members
                .set_roles(t2.id, alice.id, &[Uuid::now_v7()], None)
                .await,
            Err(IdmError::NotFound)
        ));
        assert_eq!(roles_in(t2.id).await, vec!["t_user".to_string()]);
        assert!(matches!(
            r.members
                .set_roles(t2.id, Uuid::now_v7(), &[user], None)
                .await,
            Err(IdmError::NotFound)
        ));

        // remove:只移出 t1,连带清掉它的租户角色;再移 → NotFound
        r.members.remove(t1.id, alice.id, None).await.unwrap();
        assert!(r.members.get(t1.id, alice.id).await.unwrap().is_none());
        assert_eq!(
            tenant_ids(&r.members.memberships_for_user(alice.id).await.unwrap()),
            vec![t2.id]
        );
        assert!(matches!(
            r.members.remove(t1.id, alice.id, None).await,
            Err(IdmError::NotFound)
        ));
        // 重新加入:旧角色不复活
        r.members.add(t1.id, alice.id, &[], None).await.unwrap();
        assert!(roles_in(t1.id).await.is_empty());
    }

    pub(crate) async fn revoke_for_member_revokes_only_that_tenant_sessions(r: Repos) {
        let alice = r.users.create("alice", None, "h", None).await.unwrap();
        let bob = r.users.create("bob", None, "h", None).await.unwrap();
        let t1 = r.tenants.create("t1", "T1", None).await.unwrap();
        let t2 = r.tenants.create("t2", "T2", None).await.unwrap();
        let now = OffsetDateTime::now_utc();
        let exp = now + Duration::days(1);
        let s1 = r
            .sessions
            .create(alice.id, Some(t1.id), "a-t1", exp, None)
            .await
            .unwrap();
        assert_eq!(s1.tenant_id, Some(t1.id));
        r.sessions
            .create(alice.id, Some(t2.id), "a-t2", exp, None)
            .await
            .unwrap();
        r.sessions
            .create(alice.id, None, "a-platform", exp, None)
            .await
            .unwrap();
        r.sessions
            .create(bob.id, Some(t1.id), "b-t1", exp, None)
            .await
            .unwrap();

        let active = |h: &'static str| {
            let sessions = &r.sessions;
            async move { sessions.find_active(h, now).await.unwrap() }
        };
        // find_active 带回 tenant_id(平台上下文 = None)
        assert_eq!(active("a-t2").await.unwrap().tenant_id, Some(t2.id));
        assert_eq!(active("a-platform").await.unwrap().tenant_id, None);

        r.sessions.revoke_for_member(t1.id, alice.id).await.unwrap();
        assert!(active("a-t1").await.is_none());
        assert!(active("a-t2").await.is_some());
        assert!(active("a-platform").await.is_some());
        assert!(active("b-t1").await.is_some());

        r.sessions.revoke_for_tenant(t2.id).await.unwrap();
        assert!(active("a-t2").await.is_none());
        assert!(active("a-platform").await.is_some());
        assert!(active("b-t1").await.is_some());
        r.sessions.revoke_for_tenant(t1.id).await.unwrap();
        assert!(active("b-t1").await.is_none());
        assert!(active("a-platform").await.is_some());
        // 幂等
        r.sessions.revoke_for_tenant(t1.id).await.unwrap();
        r.sessions.revoke_for_member(t1.id, alice.id).await.unwrap();
    }

    pub(crate) async fn member_ops_emit_outbox_events(r: Repos) {
        let alice = r.users.create("alice", None, "h", None).await.unwrap();
        let admin = r
            .roles
            .upsert("t_admin", "A", RoleScope::Tenant, None)
            .await
            .unwrap();
        let user = r
            .roles
            .upsert("t_user", "U", RoleScope::Tenant, None)
            .await
            .unwrap();
        r.drain_outbox().await;

        // 取出全部未发布事件并标已发布,断言每条的 aggregate_id 都是租户、payload 带 tenant_id
        let take = |tid: Uuid| {
            let outbox = &r.outbox;
            async move {
                let rows = outbox.poll_unpublished(100).await.unwrap();
                let ids: Vec<i64> = rows.iter().map(|x| x.id).collect();
                outbox.mark_published(&ids).await.unwrap();
                for row in &rows {
                    assert_eq!(
                        row.aggregate_id, tid,
                        "{} 的 aggregate 应是租户",
                        row.event_type
                    );
                    assert_eq!(
                        row.payload["tenant_id"],
                        serde_json::to_value(tid).unwrap(),
                        "{} payload 应带 tenant_id",
                        row.event_type
                    );
                }
                rows
            }
        };
        let types = |rows: &[idm::OutboxRecord]| {
            rows.iter()
                .map(|x| x.event_type.clone())
                .collect::<Vec<_>>()
        };

        let t = r.tenants.create("acme", "Acme", None).await.unwrap();
        let rows = take(t.id).await;
        assert_eq!(types(&rows), ["tenant.created"]);
        assert_eq!(rows[0].payload["slug"], "acme");
        assert_eq!(rows[0].payload["name"], "Acme");
        assert_eq!(rows[0].payload["status"], "active");

        r.tenants.update_name(t.id, "Acme 2", None).await.unwrap();
        let rows = take(t.id).await;
        assert_eq!(types(&rows), ["tenant.updated"]);
        assert_eq!(rows[0].payload["name"], "Acme 2");
        assert_eq!(rows[0].payload["status"], "active");

        r.tenants
            .set_status(t.id, TenantStatus::Suspended, None)
            .await
            .unwrap();
        let rows = take(t.id).await;
        assert_eq!(types(&rows), ["tenant.updated"]);
        assert_eq!(rows[0].payload["status"], "suspended");

        r.members.add(t.id, alice.id, &[admin], None).await.unwrap();
        let rows = take(t.id).await;
        assert_eq!(types(&rows), ["tenant.member_added"]);
        assert_eq!(
            rows[0].payload["user_id"],
            serde_json::to_value(alice.id).unwrap()
        );
        assert_eq!(rows[0].payload["roles"], serde_json::json!(["t_admin"]));
        assert_eq!(rows[0].payload["status"], "active");

        r.members
            .set_roles(t.id, alice.id, &[user, admin], None)
            .await
            .unwrap();
        let rows = take(t.id).await;
        assert_eq!(types(&rows), ["tenant.member_roles_set"]);
        assert_eq!(
            rows[0].payload["roles"],
            serde_json::json!(["t_admin", "t_user"])
        );

        r.members
            .set_status(t.id, alice.id, MemberStatus::Inactive, None)
            .await
            .unwrap();
        let rows = take(t.id).await;
        assert_eq!(types(&rows), ["tenant.member_updated"]);
        assert_eq!(rows[0].payload["status"], "inactive");

        // touch_last_used / upsert_fixed 命中已有 / 失败的写 → 不发事件
        r.members.touch_last_used(t.id, alice.id).await.unwrap();
        assert!(r.members.add(t.id, alice.id, &[], None).await.is_err());
        assert!(r
            .members
            .set_roles(t.id, alice.id, &[Uuid::now_v7()], None)
            .await
            .is_err());
        assert!(r.tenants.create("acme", "dup", None).await.is_err());
        assert!(take(t.id).await.is_empty());
        r.tenants
            .upsert_fixed(DEFAULT_TENANT_ID, "default", "默认组织", None)
            .await
            .unwrap();
        assert!(take(DEFAULT_TENANT_ID).await.is_empty());

        r.members.remove(t.id, alice.id, None).await.unwrap();
        let rows = take(t.id).await;
        assert_eq!(types(&rows), ["tenant.member_removed"]);
        assert_eq!(
            rows[0].payload["user_id"],
            serde_json::to_value(alice.id).unwrap()
        );

        r.tenants.soft_delete(t.id, None).await.unwrap();
        let rows = take(t.id).await;
        assert_eq!(types(&rows), ["tenant.deleted"]);
    }

    /// 注册原子单元(Task 2):`UserRepo::create_with_membership` 一个事务建账号 + 加入租户 + 授租户角色。
    /// 租户不存在 / 停用 / 已删 → 只建账号;任一步失败(角色不存在、用户名冲突)→ 什么都不留。
    pub(crate) async fn create_with_membership_is_atomic(r: Repos) {
        let t_user = r
            .roles
            .upsert("t_user", "成员", RoleScope::Tenant, None)
            .await
            .unwrap();
        r.drain_outbox().await;

        let alice = r
            .users
            .create_with_membership(
                "alice",
                Some("a@x.com"),
                "h",
                DEFAULT_TENANT_ID,
                &[t_user],
                Some("sys".into()),
            )
            .await
            .unwrap();
        assert_eq!(alice.username, "alice");
        let ms = r.members.memberships_for_user(alice.id).await.unwrap();
        assert_eq!(tenant_ids(&ms), vec![DEFAULT_TENANT_ID]);
        assert_eq!(ms[0].roles, vec!["t_user".to_string()]);
        assert_eq!(ms[0].status, MemberStatus::Active);
        // 事件:user.created 在前,tenant.member_added 在后(同一事务)
        let rows = r.outbox.poll_unpublished(100).await.unwrap();
        let types: Vec<&str> = rows.iter().map(|x| x.event_type.as_str()).collect();
        assert_eq!(types, ["user.created", "tenant.member_added"]);
        assert_eq!(rows[1].aggregate_id, DEFAULT_TENANT_ID);
        assert_eq!(rows[1].payload["roles"], serde_json::json!(["t_user"]));
        r.drain_outbox().await;

        // 停用的租户 → 只建账号,不加入,只发 user.created
        let acme = r.tenants.create("acme", "Acme", None).await.unwrap();
        r.tenants
            .set_status(acme.id, TenantStatus::Suspended, None)
            .await
            .unwrap();
        r.drain_outbox().await;
        let bob = r
            .users
            .create_with_membership("bob", None, "h", acme.id, &[t_user], None)
            .await
            .unwrap();
        assert!(r.members.get(acme.id, bob.id).await.unwrap().is_none());
        let rows = r.outbox.poll_unpublished(100).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].event_type, "user.created");
        r.drain_outbox().await;

        // 不存在 / 已删的租户 → 只建账号
        let carol = r
            .users
            .create_with_membership("carol", None, "h", Uuid::now_v7(), &[t_user], None)
            .await
            .unwrap();
        assert!(r
            .members
            .memberships_for_user(carol.id)
            .await
            .unwrap()
            .is_empty());
        let gone = r.tenants.create("gone", "Gone", None).await.unwrap();
        r.tenants.soft_delete(gone.id, None).await.unwrap();
        let dave = r
            .users
            .create_with_membership("dave", None, "h", gone.id, &[], None)
            .await
            .unwrap();
        assert!(r
            .members
            .memberships_for_user(dave.id)
            .await
            .unwrap()
            .is_empty());
        r.drain_outbox().await;

        // 角色不存在 → NotFound,账号也不留、不发事件
        assert!(matches!(
            r.users
                .create_with_membership(
                    "erin",
                    None,
                    "h",
                    DEFAULT_TENANT_ID,
                    &[Uuid::now_v7()],
                    None
                )
                .await,
            Err(IdmError::NotFound)
        ));
        assert!(r.users.find_by_identifier("erin").await.unwrap().is_none());
        // 用户名冲突 → Conflict,不留成员关系
        assert!(matches!(
            r.users
                .create_with_membership("alice", None, "h", DEFAULT_TENANT_ID, &[t_user], None)
                .await,
            Err(IdmError::Conflict(_))
        ));
        assert!(r.outbox.poll_unpublished(100).await.unwrap().is_empty());
        let page = r
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
    pub(crate) async fn session_create_rejects_unknown_tenant(r: Repos) {
        let alice = r.users.create("alice", None, "h", None).await.unwrap();
        let future = OffsetDateTime::now_utc() + Duration::days(1);
        assert!(matches!(
            r.sessions
                .create(alice.id, Some(Uuid::now_v7()), "h-unknown", future, None)
                .await,
            Err(IdmError::NotFound)
        ));
        assert!(r
            .sessions
            .find_active("h-unknown", OffsetDateTime::now_utc())
            .await
            .unwrap()
            .is_none());
        let s = r
            .sessions
            .create(alice.id, Some(DEFAULT_TENANT_ID), "h-default", future, None)
            .await
            .unwrap();
        assert_eq!(s.tenant_id, Some(DEFAULT_TENANT_ID));
        let t = r.tenants.create("acme", "Acme", None).await.unwrap();
        let s = r
            .sessions
            .create(alice.id, Some(t.id), "h-acme", future, None)
            .await
            .unwrap();
        assert_eq!(
            r.sessions
                .find_active("h-acme", OffsetDateTime::now_utc())
                .await
                .unwrap()
                .map(|x| x.tenant_id),
            Some(Some(t.id))
        );
        assert_eq!(s.tenant_id, Some(t.id));
        r.tenants.soft_delete(t.id, None).await.unwrap();
        assert!(r
            .sessions
            .create(alice.id, Some(t.id), "h-deleted", future, None)
            .await
            .is_ok());
    }

    /// 租户软删后,对其成员关系的写(set_status / set_roles / touch_last_used / remove)一律 NotFound,
    /// 不改数据、不发事件(和 get / list 看不见已删租户的成员一致)。
    pub(crate) async fn member_writes_on_deleted_tenant_are_not_found(r: Repos) {
        let alice = r.users.create("alice", None, "h", None).await.unwrap();
        let role = r
            .roles
            .upsert("t_user", "成员", RoleScope::Tenant, None)
            .await
            .unwrap();
        let t = r.tenants.create("acme", "Acme", None).await.unwrap();
        r.members.add(t.id, alice.id, &[role], None).await.unwrap();
        r.tenants.soft_delete(t.id, None).await.unwrap();
        r.drain_outbox().await;

        assert!(matches!(
            r.members
                .set_status(t.id, alice.id, MemberStatus::Inactive, None)
                .await,
            Err(IdmError::NotFound)
        ));
        assert!(matches!(
            r.members.set_roles(t.id, alice.id, &[], None).await,
            Err(IdmError::NotFound)
        ));
        assert!(matches!(
            r.members.touch_last_used(t.id, alice.id).await,
            Err(IdmError::NotFound)
        ));
        assert!(matches!(
            r.members.remove(t.id, alice.id, None).await,
            Err(IdmError::NotFound)
        ));
        assert!(r.outbox.poll_unpublished(100).await.unwrap().is_empty());
        // 存活租户上的同样操作照常(对照:证明 NotFound 是因为租户已删)
        let t2 = r.tenants.create("beta", "Beta", None).await.unwrap();
        r.members.add(t2.id, alice.id, &[role], None).await.unwrap();
        r.members
            .set_roles(t2.id, alice.id, &[], None)
            .await
            .unwrap();
        r.members.touch_last_used(t2.id, alice.id).await.unwrap();
        r.members
            .set_status(t2.id, alice.id, MemberStatus::Inactive, None)
            .await
            .unwrap();
        r.members.remove(t2.id, alice.id, None).await.unwrap();
    }

    /// 复审 #1:`MemberRepo::add` 对已软删账号 → `NotFound`(trait 文档「用户不存在」),不留成员行、不发事件;
    /// 账号软删后,成员列表(offset / cursor)和 total 都不再含他。
    pub(crate) async fn soft_deleted_user_not_addable_nor_listed_as_member(r: Repos) {
        let alice = r.users.create("alice", None, "h", None).await.unwrap();
        let bob = r.users.create("bob", None, "h", None).await.unwrap();
        let carol = r.users.create("carol", None, "h", None).await.unwrap();
        let t = r.tenants.create("acme", "Acme", None).await.unwrap();

        // carol 先软删,再加 → NotFound,且看不到半截成员行
        r.users.soft_delete(carol.id, None).await.unwrap();
        r.drain_outbox().await;
        assert!(matches!(
            r.members.add(t.id, carol.id, &[], None).await,
            Err(IdmError::NotFound)
        ));
        assert!(r.members.get(t.id, carol.id).await.unwrap().is_none());
        assert!(r.outbox.poll_unpublished(100).await.unwrap().is_empty());

        // alice、bob 都是成员;bob 之后软删 → 列表与 total 只剩 alice
        r.members.add(t.id, alice.id, &[], None).await.unwrap();
        r.members.add(t.id, bob.id, &[], None).await.unwrap();
        let offset = ListPage::Offset {
            offset: 0,
            limit: 10,
            with_total: true,
        };
        assert_eq!(
            r.members.list_by_tenant(t.id, &offset).await.unwrap().total,
            Some(2)
        );
        r.users.soft_delete(bob.id, None).await.unwrap();
        let page = r.members.list_by_tenant(t.id, &offset).await.unwrap();
        assert_eq!(page.total, Some(1));
        let ids: Vec<Uuid> = page.rows.iter().map(|m| m.user_id).collect();
        assert_eq!(ids, vec![alice.id]);
        let cursor = r
            .members
            .list_by_tenant(
                t.id,
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

    /// 复审 #2:迁移 0004 之后 user_roles 里还留着租户作用域角色(老账号的 admin / user)。
    /// `UserRepo::list` 的 roles 列与 roles_any / roles_none 只看**平台**角色:租户角色不显示、按它筛选不命中。
    pub(crate) async fn user_list_sees_platform_roles_only(r: Repos) {
        let alice = r.users.create("alice", None, "h", None).await.unwrap();
        let bob = r.users.create("bob", None, "h", None).await.unwrap();
        let sa = r
            .roles
            .upsert("sa", "平台管理员", RoleScope::Platform, None)
            .await
            .unwrap();
        let ta = r
            .roles
            .upsert("ta", "租户角色", RoleScope::Tenant, None)
            .await
            .unwrap();
        // 模拟迁移残留:租户角色也挂在 user_roles 上
        r.roles.grant(alice.id, sa, None).await.unwrap();
        r.roles.grant(alice.id, ta, None).await.unwrap();
        r.roles.grant(bob.id, ta, None).await.unwrap();

        async fn list(users: &dyn UserRepo, filter: UserListFilter) -> idm::UserListResult {
            let page = ListPage::Offset {
                offset: 0,
                limit: 10,
                with_total: true,
            };
            users
                .list(&filter, UserSortBy::Username, SortDir::Asc, &page)
                .await
                .unwrap()
        }

        let all = list(&*r.users, UserListFilter::default()).await;
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
        let any_ta = list(
            &*r.users,
            UserListFilter {
                roles_any: vec!["ta".into()],
                ..Default::default()
            },
        )
        .await;
        assert!(any_ta.rows.is_empty());
        assert_eq!(any_ta.total, Some(0));
        // roles_none = 租户角色 → 不排除任何人
        let none_ta = list(
            &*r.users,
            UserListFilter {
                roles_none: vec!["ta".into()],
                ..Default::default()
            },
        )
        .await;
        assert_eq!(none_ta.total, Some(2));
        // 平台角色筛选照常
        let any_sa = list(
            &*r.users,
            UserListFilter {
                roles_any: vec!["sa".into()],
                ..Default::default()
            },
        )
        .await;
        let names: Vec<&str> = any_sa.rows.iter().map(|u| u.username.as_str()).collect();
        assert_eq!(names, vec!["alice"]);
    }

    /// 复审 #3:`SessionRepo::revoke` 是条件更新,告诉调用方是否真撤掉了一行(refresh 轮换靠它防并发重放)。
    pub(crate) async fn session_revoke_reports_whether_it_revoked(r: Repos) {
        let alice = r.users.create("alice", None, "h", None).await.unwrap();
        let now = OffsetDateTime::now_utc();
        let s = r
            .sessions
            .create(alice.id, None, "h-revoke", now + Duration::days(1), None)
            .await
            .unwrap();
        assert!(r.sessions.revoke(s.id).await.unwrap(), "首次撤销 → true");
        assert!(
            !r.sessions.revoke(s.id).await.unwrap(),
            "已撤销再撤 → false(幂等,不报错)"
        );
        assert!(
            !r.sessions.revoke(Uuid::now_v7()).await.unwrap(),
            "不存在 → false"
        );
        assert!(r
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
    let roles = InMemoryRoleRepo::sharing_with(&users);
    idm_user_admin_contract(&users, &roles).await;
}

// ── 入口 1c:内存 outbox 契约(users↔roles↔outbox 三件套共享存储)──
#[tokio::test]
async fn memory_satisfies_outbox_contract() {
    use idm::{InMemoryOutboxRepo, InMemoryRoleRepo, InMemoryUserRepo};
    let users = InMemoryUserRepo::new();
    let roles = InMemoryRoleRepo::sharing_with(&users);
    let outbox = InMemoryOutboxRepo::sharing_with(&users);
    idm_outbox_contract(&users, &roles, &outbox).await;
}

// ── 入口 2:PG(需 --features pg-conformance + DATABASE_URL 连 idm role + 跑着的 pg)──
// bootstrap 内联在本文件(不走 #[path] include):sqlx::migrate! 在被 include 的文件里会按
// "相对当前文件目录"解析路径(sqlx 不支持),内联后它相对 idm crate 的 CARGO_MANIFEST_DIR、稳。
#[cfg(feature = "pg-conformance")]
mod pg {
    use super::idm_repo_contract;
    use idm::OutboxRepo;
    use sqlx::migrate::Migrator;

    /// 编译期内嵌 idm crate 的 migrations/(相对 idm crate 的 CARGO_MANIFEST_DIR)。
    static IDM_MIGRATOR: Migrator = sqlx::migrate!("./migrations");

    /// #[sqlx::test] 的干净临时库:建 idm schema + 跑 idm crate 自带 migrations。
    pub(crate) async fn bootstrap_idm(pool: &sqlx::PgPool) -> anyhow::Result<()> {
        sqlx::query("create schema if not exists idm")
            .execute(pool)
            .await?;
        IDM_MIGRATOR.run(pool).await?;
        Ok(())
    }

    #[sqlx::test(migrations = false)]
    async fn pg_satisfies_idm_contract(pool: sqlx::PgPool) -> sqlx::Result<()> {
        bootstrap_idm(&pool)
            .await
            .expect("bootstrap idm schema + 跑 migrations");
        let users = idm::PgUserRepo::new(pool.clone());
        let sessions = idm::PgSessionRepo::new(pool.clone());
        let roles = idm::PgRoleRepo::new(pool);
        idm_repo_contract(&users, &sessions, &roles).await;
        Ok(())
    }

    #[sqlx::test(migrations = false)]
    async fn pg_satisfies_user_admin_contract(pool: sqlx::PgPool) -> sqlx::Result<()> {
        bootstrap_idm(&pool)
            .await
            .expect("bootstrap idm schema + 跑 migrations");
        let users = idm::PgUserRepo::new(pool.clone());
        let roles = idm::PgRoleRepo::new(pool);
        super::idm_user_admin_contract(&users, &roles).await;
        Ok(())
    }

    #[sqlx::test(migrations = false)]
    async fn pg_satisfies_outbox_contract(pool: sqlx::PgPool) -> sqlx::Result<()> {
        bootstrap_idm(&pool)
            .await
            .expect("bootstrap idm schema + 跑 migrations");
        let users = idm::PgUserRepo::new(pool.clone());
        let roles = idm::PgRoleRepo::new(pool.clone());
        let outbox = idm::PgOutboxRepo::new(pool);
        super::idm_outbox_contract(&users, &roles, &outbox).await;
        Ok(())
    }

    /// 迁移 0004 回填:在只跑到 0003 的库里塞两个存活用户 + 一个软删用户和 user_roles,再跑 0004 ——
    /// 两个存活用户都成为默认租户 active 成员,user_roles 复制进默认租户的 member_roles(原行保留);
    /// superadmin 改为平台角色并在默认租户兼任 admin(spec §4.7);软删用户不加;
    /// 有效会话(账号是默认租户成员)回填默认租户,已吊销 / 非成员的会话保持 NULL。
    #[sqlx::test(migrations = false)]
    async fn migration_backfills_default_tenant(pool: sqlx::PgPool) -> sqlx::Result<()> {
        use super::Uuid;
        use idm::{MemberRepo, RoleRepo, DEFAULT_TENANT_ID};

        sqlx::query("create schema if not exists idm")
            .execute(&pool)
            .await?;
        IDM_MIGRATOR.run_to(3, &pool).await.expect("跑到 0003");

        let (u1, u2, gone) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
        for (id, name) in [(u1, "u1"), (u2, "u2"), (gone, "gone")] {
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
        let (r_sa, r_admin, r_user) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
        for (id, name) in [(r_sa, "superadmin"), (r_admin, "admin"), (r_user, "user")] {
            sqlx::query("insert into roles (id, name, display_name) values ($1, $2, $2)")
                .bind(id)
                .bind(name)
                .execute(&pool)
                .await?;
        }
        for (u, r) in [(u1, r_sa), (u2, r_user), (u2, r_admin), (gone, r_user)] {
            sqlx::query("insert into user_roles (user_id, role_id) values ($1, $2)")
                .bind(u)
                .bind(r)
                .execute(&pool)
                .await?;
        }

        // 升级前的会话:u1 有效、u2 已吊销、软删用户 gone 的有效会话(不是成员)
        let (s_live, s_revoked, s_gone) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
        for (sid, uid, revoked) in [
            (s_live, u1, false),
            (s_revoked, u2, true),
            (s_gone, gone, false),
        ] {
            sqlx::query(
                "insert into sessions (id, user_id, token_hash, expires_at, revoked_at)
                 values ($1, $2, $3, now() + interval '1 day',
                         case when $4 then now() else null end)",
            )
            .bind(sid)
            .bind(uid)
            .bind(sid.to_string())
            .bind(revoked)
            .execute(&pool)
            .await?;
        }

        IDM_MIGRATOR.run(&pool).await.expect("跑 0004");

        // 有效会话且仍是默认租户成员 → 回填默认租户;已吊销 / 非成员的保持 NULL
        let sess: Vec<(Uuid, Option<Uuid>)> =
            sqlx::query_as("select id, tenant_id from sessions order by id")
                .fetch_all(&pool)
                .await?;
        let mut expect = vec![
            (s_live, Some(DEFAULT_TENANT_ID)),
            (s_revoked, None),
            (s_gone, None),
        ];
        expect.sort();
        assert_eq!(sess, expect);

        // 两个存活用户都是默认租户的 active 成员;软删的不加
        let members: Vec<(Uuid, String)> = sqlx::query_as(
            "select user_id, status from tenant_members where tenant_id = $1 order by user_id",
        )
        .bind(DEFAULT_TENANT_ID)
        .fetch_all(&pool)
        .await?;
        let mut expect = vec![(u1, "active".to_owned()), (u2, "active".to_owned())];
        expect.sort();
        assert_eq!(members, expect);

        // member_roles:u2 的 admin/user 原样复制;u1 的 superadmin 复制 + 兼任 admin
        let mr: Vec<(Uuid, Uuid)> = sqlx::query_as(
            "select user_id, role_id from member_roles where tenant_id = $1 order by user_id, role_id",
        )
        .bind(DEFAULT_TENANT_ID)
        .fetch_all(&pool)
        .await?;
        let mut expect = vec![(u1, r_sa), (u1, r_admin), (u2, r_admin), (u2, r_user)];
        expect.sort();
        assert_eq!(mr, expect);
        // user_roles 原行保留(复制不是搬)
        let ur: i64 = sqlx::query_scalar("select count(*) from user_roles")
            .fetch_one(&pool)
            .await?;
        assert_eq!(ur, 4);

        // 经仓储读:平台角色只剩 superadmin;默认租户的租户角色按 scope 过滤
        let roles = idm::PgRoleRepo::new(pool.clone());
        assert_eq!(roles.roles_for_user(u1).await.unwrap(), vec!["superadmin"]);
        let members = idm::PgMemberRepo::new(pool.clone());
        let m1 = members.memberships_for_user(u1).await.unwrap();
        assert_eq!(m1.len(), 1);
        assert_eq!(m1[0].tenant.id, DEFAULT_TENANT_ID);
        assert_eq!(m1[0].tenant.slug, "default");
        assert_eq!(m1[0].roles, vec!["admin"]);
        let m2 = members.memberships_for_user(u2).await.unwrap();
        assert_eq!(m2[0].roles, vec!["admin", "user"]);
        Ok(())
    }

    /// 复审 #3(并发):同一个 refresh token 被并发使用 N 次,只能有一次成功(其余 Unauthorized),
    /// 且最终该用户只有一个活跃会话。修复前 find_active → revoke 非原子,会分出多个都有效的会话。
    #[sqlx::test(migrations = false)]
    async fn pg_concurrent_refresh_with_same_token_rotates_once(
        pool: sqlx::PgPool,
    ) -> sqlx::Result<()> {
        use idm::{AuthService, FakeHasher, IdmError, RegisterInput};
        use std::sync::Arc;

        bootstrap_idm(&pool)
            .await
            .expect("bootstrap idm schema + 跑 migrations");
        let svc = AuthService::builder(
            Arc::new(idm::PgUserRepo::new(pool.clone())),
            Arc::new(idm::PgSessionRepo::new(pool.clone())),
            Arc::new(idm::PgRoleRepo::new(pool.clone())),
            Arc::new(idm::PgMemberRepo::new(pool.clone())),
        )
        .hs256_secret("secret")
        .hasher(Arc::new(FakeHasher))
        .signup_roles(Vec::new())
        .build();
        let reg = svc
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

        // 同时起 N 个任务:每个都先 find_active(都看到活跃会话)再撤销 —— 正是修复前的竞态窗口。
        const N: usize = 16;
        let mut handles = Vec::new();
        for i in 0..N {
            let svc = svc.clone();
            let token = reg.refresh_token.clone();
            let tenant = reg.tenant_id;
            let user_id = reg.user.id;
            handles.push(tokio::spawn(async move {
                // 一半走 refresh、一半走 switch_tenant(切回同一个租户):两条路径共用同一把撤销闸
                let res = match tenant {
                    Some(t) if i % 2 == 1 => svc.switch_tenant(&token, user_id, t).await,
                    _ => svc.refresh(&token).await,
                };
                res.map(|o| o.session_id)
            }));
        }
        let mut ok = 0;
        for h in handles {
            match h.await.expect("task") {
                Ok(_) => ok += 1,
                Err(IdmError::Unauthorized) => {}
                Err(e) => panic!("并发使用同一 refresh 只该得到 Unauthorized,得到 {e:?}"),
            }
        }
        assert_eq!(ok, 1, "同一 refresh token 并发使用只能轮换出一个新会话");
        let active: i64 = sqlx::query_scalar(
            "select count(*) from sessions where user_id = $1 and revoked_at is null",
        )
        .bind(reg.user.id)
        .fetch_one(&pool)
        .await?;
        assert_eq!(active, 1, "最终只剩一个活跃会话");
        Ok(())
    }

    /// 复审 #4:回滚 0004 不丢升级后授出的租户角色 —— 默认租户 **active 成员**的 member_roles 里**租户作用域**的行
    /// 写回 user_roles(已有的不重复);平台角色、别的租户的角色不写回;表与列都被删掉。
    /// 写回前先对账:user_roles 里租户作用域、但默认租户 active 成员的 member_roles 里没有的行删掉 ——
    /// 升级后被撤权 / 停用 / 移出的人回滚后不复活。
    #[sqlx::test(migrations = false)]
    async fn migration_0004_down_restores_default_tenant_roles(
        pool: sqlx::PgPool,
    ) -> sqlx::Result<()> {
        use super::Uuid;
        use idm::{
            MemberRepo, MemberStatus, RoleRepo, RoleScope, TenantRepo, UserRepo, DEFAULT_TENANT_ID,
        };

        bootstrap_idm(&pool)
            .await
            .expect("bootstrap idm schema + 跑 migrations");
        let users = idm::PgUserRepo::new(pool.clone());
        let roles = idm::PgRoleRepo::new(pool.clone());
        let tenants = idm::PgTenantRepo::new(pool.clone());
        let members = idm::PgMemberRepo::new(pool.clone());

        let r_user = roles
            .upsert("user", "成员", RoleScope::Tenant, None)
            .await
            .unwrap();
        let r_admin = roles
            .upsert("admin", "管理员", RoleScope::Tenant, None)
            .await
            .unwrap();
        let r_sa = roles
            .upsert("superadmin", "平台管理员", RoleScope::Platform, None)
            .await
            .unwrap();
        // 升级后注册的新账号:默认租户 user 角色,只在 member_roles 里
        let newbie = users
            .create_with_membership("newbie", None, "h", DEFAULT_TENANT_ID, &[r_user], None)
            .await
            .unwrap();
        // 老账号:user_roles 已有 admin(迁移复制来的),默认租户里又被授了 user
        let old = users.create("old", None, "h", None).await.unwrap();
        roles.grant(old.id, r_admin, None).await.unwrap();
        members
            .add(DEFAULT_TENANT_ID, old.id, &[r_admin, r_user], None)
            .await
            .unwrap();
        // 平台角色挂进 member_roles(写入只校验存在):不写回
        let plat = users.create("plat", None, "h", None).await.unwrap();
        members
            .add(DEFAULT_TENANT_ID, plat.id, &[r_sa], None)
            .await
            .unwrap();
        // 别的租户的角色:不写回
        let acme = tenants.create("acme", "Acme", None).await.unwrap();
        let other = users.create("other", None, "h", None).await.unwrap();
        members
            .add(acme.id, other.id, &[r_admin], None)
            .await
            .unwrap();

        // 复审:先对账再写回 —— 升级后在默认租户里被撤权 / 停用 / 移出的人,回滚后不能靠 user_roles 里
        // 迁移前遗留的租户角色行(或写回)复活。user_roles 里的租户角色行模拟 0004 之前的授予(up 只复制不搬)。
        // 撤权:老账号原有 admin(user_roles 遗留),升级后在默认租户被撤成只剩 user → 回滚后只有 user
        let demoted = users.create("demoted", None, "h", None).await.unwrap();
        roles.grant(demoted.id, r_admin, None).await.unwrap();
        roles.grant(demoted.id, r_sa, None).await.unwrap(); // 平台角色:不受对账影响
        members
            .add(DEFAULT_TENANT_ID, demoted.id, &[r_admin], None)
            .await
            .unwrap();
        members
            .set_roles(DEFAULT_TENANT_ID, demoted.id, &[r_user], None)
            .await
            .unwrap();
        // 停用:关系与角色保留,但 status = inactive → 不写回,遗留的 admin 也删掉
        let paused = users.create("paused", None, "h", None).await.unwrap();
        roles.grant(paused.id, r_admin, None).await.unwrap();
        members
            .add(DEFAULT_TENANT_ID, paused.id, &[r_admin, r_user], None)
            .await
            .unwrap();
        members
            .set_status(DEFAULT_TENANT_ID, paused.id, MemberStatus::Inactive, None)
            .await
            .unwrap();
        // 移出:成员行连同 member_roles 删掉 → 遗留的 admin 也删掉
        let gone = users.create("gone", None, "h", None).await.unwrap();
        roles.grant(gone.id, r_admin, None).await.unwrap();
        members
            .add(DEFAULT_TENANT_ID, gone.id, &[r_admin], None)
            .await
            .unwrap();
        members
            .remove(DEFAULT_TENANT_ID, gone.id, None)
            .await
            .unwrap();

        IDM_MIGRATOR.undo(&pool, 3).await.expect("回滚 0004");

        let ur: Vec<(Uuid, Uuid)> =
            sqlx::query_as("select user_id, role_id from user_roles order by user_id, role_id")
                .fetch_all(&pool)
                .await?;
        let mut expect = vec![
            (newbie.id, r_user),
            (old.id, r_admin),
            (old.id, r_user),
            (demoted.id, r_user),
            (demoted.id, r_sa),
        ];
        expect.sort();
        assert_eq!(
            ur, expect,
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
        let cols: i64 = sqlx::query_scalar(
            "select count(*) from information_schema.columns \
             where table_schema = current_schema() \
               and ((table_name = 'roles' and column_name = 'scope') \
                 or (table_name = 'sessions' and column_name = 'tenant_id'))",
        )
        .fetch_one(&pool)
        .await?;
        assert_eq!(cols, 0);

        // 再升回去照常(down 之后 up 可重放)
        IDM_MIGRATOR.run(&pool).await.expect("重新跑 0004");
        Ok(())
    }

    /// outbox:emit 助手是 `pub(crate)`,本文件是外部集成测试够不着,改直插 SQL 模拟 Task 2 写路径
    /// 落地的效果 → poll_unpublished 见到(FIFO,按 id 升序)→ mark 第一条 → 只剩第二条 → mark 完 → 空。
    #[sqlx::test(migrations = false)]
    async fn pg_outbox_poll_and_mark(pool: sqlx::PgPool) -> sqlx::Result<()> {
        use serde_json::json;

        bootstrap_idm(&pool)
            .await
            .expect("bootstrap idm schema + 跑 migrations");

        for who in ["a", "b"] {
            sqlx::query(
                "insert into outbox (event_type, aggregate_id, payload) values ($1, $2, $3)",
            )
            .bind("user.created")
            .bind(super::Uuid::now_v7())
            .bind(json!({ "who": who }))
            .execute(&pool)
            .await?;
        }

        let outbox = idm::PgOutboxRepo::new(pool.clone());
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
