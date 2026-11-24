//! idm repo 契约一致性:**同一批断言对内存与 PG 的三个 repo 各跑一遍**,钉死行为 parity。
//! user(create/find/update/soft_delete/password)+ session(create/find_active/revoke)+ role(upsert/grant/roles)。
//! "内存绿不保证 PG 绿"的漂移,全靠这套契约抓。
//!
//! 内存入口:默认 `cargo test` 就跑(零 DB)。
//! PG 入口:`just test-pg`(需 DATABASE_URL 连 idm role + 跑着的 pg)。

use idm::IdmError;
use idm::{
    ListPage, OutboxRepo, RoleRepo, SessionRepo, SortDir, UserListFilter, UserRepo, UserSortBy,
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
        .upsert("admin", "管理员", Some("sys".into()))
        .await
        .unwrap();
    assert_eq!(roles.upsert("admin", "管理员", None).await.unwrap(), rid); // 幂等返同 id
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
        .create(u.id, "tokhash1", future, Some("sys".into()))
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
        .create(u.id, "tokhash2", future, None)
        .await
        .unwrap();
    sessions
        .create(u.id, "tokhash3", future, None)
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
    let admin = roles.upsert("admin", "Admin", None).await.unwrap();
    let editor = roles.upsert("editor", "Editor", None).await.unwrap();
    let viewer = roles.upsert("viewer", "Viewer", None).await.unwrap();

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

    let editor = roles.upsert("editor", "Editor", None).await.unwrap();
    let viewer = roles.upsert("viewer", "Viewer", None).await.unwrap();

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
    async fn bootstrap_idm(pool: &sqlx::PgPool) -> anyhow::Result<()> {
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
