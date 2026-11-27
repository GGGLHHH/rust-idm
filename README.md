# idm

自包含的**认证 / 身份(IDM)领域与服务库(零 HTTP)**:`AuthService` + 可替换的仓储 / 密码哈希 / 令牌 / 时钟端口 + 自己的 `IdmError`。
作为库嵌进应用使用,HTTP 边界(路由、DTO、校验、cookie)归消费方。

> 从 **baserust** 脚手架里抽出来的,对应 `simple-idm-slim` ↔ 业务应用的关系(业务应用依赖一个可复用的认证库)。

## 里面有什么

- **领域**:`AuthService`(注册 / 登录 / 会话轮换 / 切换租户 / 改密码)+ 仓储端口 `UserRepo` / `SessionRepo` / `RoleRepo` /
  `TenantRepo` / `MemberRepo`
  (内存和 Postgres 两种实现)+ 发件箱 `OutboxRepo`(transactional outbox,写事务里顺带记事件)+ JWT
  (HS256 访问令牌 + 轮换的不透明刷新令牌)+ `PasswordHasher` 端口后面的 Argon2 密码哈希。
- **令牌和时钟端口**:`TokenSigner` / `TokenVerifier`(默认 `Hs256Tokens`;拆开是为了独立的 idm 进程只签发、
  app 只验签)+ `Clock` / `SystemClock`(注入固定时钟,确定性地测过期和轮换)。
- **领域类型和错误**:`AuthOutcome` / `UserView` / `AuthUser` / `Tenant` / `Membership`(纯数据),`IdmError` 六种:
  `NotFound` / `Unauthorized` / `InvalidCredentials`(带失败原因,只给审计用,对外仍统一 401)/ `Forbidden`
  (已认证但不是目标租户的有效成员)/ `Conflict` / `Internal`。
  HTTP 状态码、错误码和响应格式由消费方经 `From<IdmError> for AppError` 决定。
- **迁移**:在 `migrations/`,拷进应用的 `migrations/idm` 跑。

## 怎么用

```toml
[dependencies]
idm = { git = "https://github.com/GGGLHHH/rust-idm", tag = "v0.7.0" }
```

> `v0.7.0` 这个 tag **发版后**才存在(目前已有的 tag 只到 `v0.5.1`,0.6.0 没打过 tag);发版前要用当前代码,按提交钉住:
> `idm = { git = "https://github.com/GGGLHHH/rust-idm", rev = "<提交>" }`。

实现仓储端口(或直接用自带的 `InMemory*` / `Pg*`),用 builder 建一个 `AuthService`,在自己的 handler 里调用。
`AuthService` 对四个仓储是泛型的、不实现 `Clone`(库内唯一所有权):要放进 `AppState` 就包一层 `Arc`;
要在运行时二选一实现(内存 / PG),用 `Arc<dyn UserRepo>` 等实例化(每个端口都有 `Arc<T>` / `Box<T>` 转发实现;独占所有权时填 `Box<dyn …>`):

```rust
use std::sync::Arc;
use idm::{AuthService, MemberRepo, RoleRepo, SessionRepo, UserRepo};
use time::Duration;

type DynAuthService =
    AuthService<Arc<dyn UserRepo>, Arc<dyn SessionRepo>, Arc<dyn RoleRepo>, Arc<dyn MemberRepo>>;

let auth: Arc<DynAuthService> = Arc::new(
    AuthService::builder(users, sessions, roles, members) // 成员仓储必填:多租户恒开
        .hs256_secret(&jwt_secret)                          // 或 .signer(…) + .verifier(…)
        .access_ttl(Duration::minutes(15))                  // 默认就是 15 分钟 / 7 天
        .refresh_ttl(Duration::days(7))
        .build(),
);

let out = auth.register(register_input, Some(actor)).await?; // -> AuthOutcome { user: UserView, access_token, refresh_token, .. }
let who = auth.authenticate_token(&access_token)?;           // -> AuthUser { id, username, roles, tenant_id, tenant_roles }
```

完整可运行的例子见 crate 文档(`src/lib.rs` 顶部,`cargo test` 会跑它)。

## 服务方法

`AuthService`:`register` · `login` · `login_with` · `refresh` · `switch_tenant` · `my_tenants` · `logout` · `logout_all` · `me` ·
`update_me` · `delete_me` · `change_password` · `authenticate_token`。参数是领域的 `*Input` 结构(部分写方法另带 `by: Option<&str>` 做审计),
返回领域数据(`AuthOutcome` / `UserView` / `AuthUser`);路由、httponly cookie、`{code, error}` 响应格式归消费方。

## 多租户与 token(0.6.0 起)

账号全局一份;租户(`tenants`)、成员关系(`tenant_members`)、租户角色(`member_roles`)由 `TenantRepo` / `MemberRepo` 管。
角色分两类:**平台角色**(`user_roles`,如 superadmin)和**租户角色**(`member_roles`,如 admin、user),由 `roles.scope` 标明。

access token 的 claim(`TokenClaims` / `VerifiedToken` / `AuthUser` 同形):

| claim | 含义 |
|---|---|
| `roles` | **平台角色**(含义从"全部角色"收窄为"平台角色") |
| `tenant_id` | 当前租户;平台上下文时**缺省**(不写 null) |
| `tenant_roles` | 当前租户内的角色 |

只放**一个当前租户**。旧 token(没有 `tenant_id` / `tenant_roles`)靠 `#[serde(default)]` 照样能验,读出来是平台上下文。

`TokenClaims` 另带 `tenant_slug` / `tenant_name`(当前租户的展示信息,平台上下文为 `None`):给只验 JWT、不查 idm 库的
消费方回答「当前组织是哪个」。默认 `Hs256Tokens` 不写它们;要不要写进 token 由消费方的 signer 决定(baserust 写)。

成员仓储是 `AuthService::builder` 的**必填参数**(多租户恒开,没有"单租户 / 关闭租户"开关):

- **登录**:进有效成员关系(成员 active + 租户 active)里 `last_used_at` 最近的那个,并记一次 `last_used_at`;没有 → 平台上下文。
- **`login_with(input, choose)`**:验密同 `login`,但进哪里由消费方挑(本库不认识权限):`choose` 拿到
  `LoginCandidates { user_id, platform_roles, memberships }`(成员关系最近用过的在前),返回 `Some(LoginEntry::Tenant(id))`
  (进该租户并记 `last_used_at`)/ `Some(LoginEntry::Platform)`(平台上下文)/ `None`(→ `Forbidden`,**不建会话、不记 `last_used_at`**)。
  挑了不在候选里的租户或刚好被并发移出 → `Forbidden`(不退回平台上下文)。baserust 的后台登录用它挑「有后台权限的租户」。
- **refresh**:沿用会话上的租户,重新读成员关系和租户角色;成员被移出 / 停用、租户停用 / 删除 → `Unauthorized`
  (旧会话同时作废,绝不落到别的租户)。
- **`switch_tenant(refresh_token, MemberKey { tenant_id, user_id })`**:refresh 会话不属于 `user_id`(当前已认证身份)→ `Unauthorized`;非有效成员 → `Forbidden`(平台管理员也一样,原会话不动);成功则吊销旧会话、
  建带新租户的会话、记 `last_used_at`。
- **`my_tenants(user_id)`**:有效成员关系列表,最近用过的在前。
- **注册**:`UserRepo::create_with_membership` 一个事务建账号 + 加入 `signup_tenant`(默认 `Some(DEFAULT_TENANT_ID)`,
  该租户存活且 active 才加)+ 授 `signup_roles`(默认 `["user"]`;**只认存活的租户角色**,目录里没有或同名的是平台角色 → `IdmError::Internal`,
  什么都不建 —— 装配错误要响亮;不想授角色就配空 `Vec`)。
  `.signup_tenant(None)` = 注册只建账号。
- 内存实现要看同一批租户:`InMemory{Role,Tenant,Member,Session,Outbox}Repo::new_shared_with(&users)`。

已发出的 access token 在过期前仍有效(成员被移出 / 租户停用的最长生效延迟 = access TTL);refresh 立即失败。

## 版本变更

### 0.7.0(按 Google Rust 风格指南修正 API;相对 0.6.x **破坏性**)

0.6.0 没有打 tag,baserust 一直钉在提交 `00f4e4d`(0.6.0 + 多租户复审修复)上;下表把 `00f4e4d` 里已经带上的
不兼容变更(`SessionRepo::revoke` 改返回 `bool` 等)也一并列出,从 `00f4e4d` 升上来的照着改即可。

除「行为变化」一节外只改 API 形状。逐条对照:

| 0.6.x | 0.7.0 |
|---|---|
| `AuthService`(内部 `Arc<dyn …>`,`Clone`) | `AuthService<U, S, R, M>` 对四个仓储泛型、不 `Clone`;共享时包 `Arc`,运行时二选一用 `AuthService<Arc<dyn UserRepo>, …>` |
| `AuthService::new(users, sessions, roles, members, hasher, secret, access_secs, refresh_secs)` | 删除,用 `AuthService::builder(..).hasher(h).hs256_secret(s).access_ttl(d).refresh_ttl(d).build()` |
| `AuthServiceBuilder`(非泛型) | `AuthServiceBuilder<U, S, R, M>`(跟 `AuthService` 同参) |
| builder 收 `Arc<dyn …>`:`.hasher(Arc<dyn PwHasher>)` / `.signer(..)` / `.verifier(..)` / `.clock(..)` | 收 `impl Trait + 'static`(`Arc<T>` 也行,有转发实现) |
| `.access_ttl_secs(i64)` / `.refresh_ttl_secs(i64)`;`AuthOutcome.access_max_age_secs` / `refresh_max_age_secs: i64` | `.access_ttl(Duration)` / `.refresh_ttl(Duration)`;`AuthOutcome.access_max_age` / `refresh_max_age: time::Duration` |
| `.signup_roles(Vec<String>)` | `.signup_roles(impl IntoIterator<Item: Into<String>>)`(空集合要写明元素类型,如 `let no_roles: [&str; 0] = [];`) |
| `switch_tenant(token, user_id, tenant_id)` | `switch_tenant(token, MemberKey { tenant_id, user_id })` |
| `PwHasher`(`hash(plain)` / `verify(plain, phc)`) | `PasswordHasher`(参数名 `password` / `phc_string`) |
| 公开模块 `idm::password`(`idm::password::{Argon2Hasher, FakeHasher, PwHasher}`) | 模块改私有,一律从 crate 根导入:`idm::{Argon2Hasher, FakeHasher, PasswordHasher}` |
| `SortDir::{Asc, Desc}`;`UserRepo::list(.., dir: SortDir, ..)` | `SortDirection::{Ascending, Descending}`;参数名 `direction` |
| `UserListResult` | `ListResult<UserListRow>` |
| `UserRepo::create(username, email, hash, by)` / `create_with_roles(username, email, hash, role_ids, by)` / `create_with_membership(username, email, hash, tenant_id, role_ids, by)` | 前三个参数合成 `NewUser { username, email, password_hash }` |
| `RoleRepo::upsert(name, display_name, scope, by)` / `grant(user_id, role_id, by)` | `upsert(NewRole { name, display_name, scope }, by)` / `grant(RoleGrant { user_id, role_id }, by)` |
| `TenantRepo::create(slug, name, by)` / `upsert_fixed(id, slug, name, by)` | `create(NewTenant { slug, name }, by)` / `upsert_fixed(id, NewTenant { slug, name }, by)` |
| `MemberRepo::{add, remove, set_status, set_roles, get, touch_last_used}(tenant_id, user_id, …)`、`SessionRepo::revoke_for_member(tenant_id, user_id)` | 前两个参数合成 `MemberKey { tenant_id, user_id }` |
| 写方法的审计主体 `by: Option<String>`(`AuthService::register` / `update_me` / `delete_me` 和五个仓储 trait 的全部写方法) | `by: Option<&str>`(和 rust-content 0.5.0 一致);调用方传 `Some("…")` / `.as_deref()`,不再 `clone` 出 `String`。自己实现了仓储端口的照改签名 |
| `SessionRepo::revoke(id) -> Result<(), IdmError>`(`00f4e4d` 起) | `-> Result<bool, IdmError>`:条件更新,真撤掉一行 → `true`,已撤销 / 不存在 → `false`。自己实现了 `SessionRepo` 的要照此返回(refresh / 切换租户靠它做轮换闸) |
| `InMemory*Repo::sharing_with(&users)` | `InMemory*Repo::new_shared_with(&users)` |
| 公开结构体 / 枚举可穷尽 | 加了 `#[non_exhaustive]`(见下);库外构造用新增的构造函数:`AuthUser::new(..).in_tenant(..)` / `AuthUser::from_verified_token`、`VerifiedToken::new(..).in_tenant(..)`、`TokenClaims::new(&session, username, issued_at, ttl)`、`User::new`、`UserWithHash::new`、`UserListRow::new`、`Role::new`、`Session::new`、`Tenant::new`、`Membership::new`、`OutboxRecord::new`、`ListResult::new`;`match` 这些枚举要加通配分支 |
| `UnknownValue(pub String)` | 字段私有,用 `.value()` |
| `RegisterInput` / `LoginInput` / `ChangePasswordInput` 派生 `Debug`(**明文密码会进日志**) | 手写 `Debug`,密码打成 `<redacted>`(安全修正);`AuthOutcome` / `UserWithHash` / `NewUser` / `Hs256Tokens` 的 `Debug` 同样不输出令牌 / 密码 hash / 密钥 |

`#[non_exhaustive]` 的:`IdmError`、`CredentialFailure`、`UserSortBy`、`ListPage`、`LoginEntry`、`AuthUser`、`VerifiedToken`、
`TokenClaims`、`UserView`、`AuthOutcome`、`LoginCandidates`、`User`、`UserWithHash`、`UserListRow`、`Role`、`Session`、
`OutboxRecord`、`Tenant`、`Membership`、`ListResult`。没加的(指南条款例外):两态枚举 `TenantStatus` / `MemberStatus` /
`RoleScope` / `SortDirection`;靠 FRU(`..Default::default()`)构造的输入结构体 `RegisterInput` / `LoginInput` /
`UpdateMeInput` / `ChangePasswordInput` / `NewUser` / `NewRole` / `NewTenant` / `UserListFilter`;复合主键 `MemberKey` / `RoleGrant`。

新增(不破坏):每个端口(五个仓储 + `OutboxRepo`、`PasswordHasher`、`TokenSigner` / `TokenVerifier`、`Clock`)都有
`impl<T: Trait + ?Sized> Trait for Arc<T>` 和 `… for Box<T>` 转发实现(全部方法都转发);`AuthServiceBuilder` 类型上加了
`#[must_use]`(builder 各 setter 原先逐个标的 `#[must_use]` 随之去掉,效果不变);`From<VerifiedToken> for AuthUser`;`Membership::key()` / `is_effective()`;
`TenantStatus` / `MemberStatus` / `RoleScope` 实现 `Display`(= 库里的文本)。

**依赖 feature 收窄**(只影响靠 idm 顺带打开 feature 的下游):`tokio` 只开 `rt`(去掉 `rt-multi-thread` / `macros`)、
`uuid` 去掉 `v4`、`time` 由 `serde-well-known` 改为 `serde`、`argon2` 去掉 `std` —— 这些 idm 自己都用不到。
下游用到 `#[tokio::main]` / 多线程运行时、`Uuid::new_v4`、`time::serde::rfc3339` 等的,要在自己的 `Cargo.toml` 里显式开
(baserust 已经自己声明了)。

**行为变化**(都是 bug 修正,`00f4e4d` 起已生效,升级时核对消费方的错误映射):

- `change_password` / `delete_me` 密码确认错:`Unauthorized` → `InvalidCredentials(CredentialFailure::BadPassword)`(凭据错、会话仍有效;
  账号已不在仍是 `Unauthorized`)。消费方的 `From<IdmError>` 要把两者分成不同的机器码。
- refresh / `switch_tenant` 原子地用掉 refresh 会话:同一个 refresh token 并发使用只有一个成功,其余 `Unauthorized`
  (以前可能分出两个活会话);`logout` 被并发抢先撤掉时返回 `None`。
- `MemberRepo::add` 加已软删账号 → `NotFound`;成员列表和总数不含已软删账号。
- `UserRepo::list` 的 `roles` 列和 `roles_any` / `roles_none` 过滤只看**平台**角色(迁移 0004 复制进默认租户后
  `user_roles` 里残留的租户作用域行不再算)。
- 迁移 `0004_tenants.down.sql` 回滚前先按默认租户的有效成员关系对齐 `user_roles`(up 没变,已跑过 0004 的库不用重跑)。

### 0.6.0(多租户;相对 0.5.x **破坏性**)

升级要做的:把 `migrations/0004_tenants.*` 拷进应用的 `migrations/idm` 跑;`AuthService` 装配多传一个成员仓储;
自己实现了仓储端口的,按下表补方法 / 改签名。

| 变更 | 说明 |
|---|---|
| `AuthService::new(users, sessions, roles, members, hasher, …)` / `AuthService::builder(users, sessions, roles, members)` | 新增**必填**参数 `Arc<dyn MemberRepo>`(多租户恒开,没有关闭开关)。builder 新增 `.signup_tenant(Option<Uuid>)`(默认 `Some(DEFAULT_TENANT_ID)`)、`.signup_roles(Vec<String>)`(默认 `["user"]`,只认租户角色) |
| `AuthService::switch_tenant(refresh_token, user_id, tenant_id)` | 新方法。`user_id` = 当前已认证身份,refresh 会话不属于他 → `Unauthorized`;非有效成员 → `Forbidden` |
| `AuthService::login_with(input, choose)` | 新方法:验密同 `login`,进哪个租户由消费方的 `choose(LoginCandidates) -> Option<LoginEntry>` 决定 |
| `AuthService::my_tenants(user_id)` | 新方法:有效成员关系,最近用过的在前 |
| `AuthService::login` / `refresh` | 行为变化:登录进最近用过的有效租户(没有 → 平台上下文);refresh 沿用会话租户并重新校验,失效 → `Unauthorized` |
| `TokenClaims` | 新字段 `tenant_id: Option<Uuid>`、`tenant_roles: Vec<String>`、`tenant_slug` / `tenant_name: Option<String>`;`roles` 含义收窄为**平台角色**。自定义 `TokenSigner` 要写这些 claim |
| `VerifiedToken` / `AuthUser` | 新字段 `tenant_id: Option<Uuid>`、`tenant_roles: Vec<String>`(旧 token 没有这两个 claim 仍能验,读出来是平台上下文) |
| `RoleRepo::upsert(name, display_name, scope, by)` | 新增 `scope: RoleScope`(`Platform` / `Tenant`);`Role` 带 `scope` |
| `SessionRepo::create(user_id, tenant_id, token_hash, expires_at, by)` | 新增 `tenant_id: Option<Uuid>`;`Session` 带 `tenant_id`;新方法 `revoke_for_member` / `revoke_for_tenant` |
| `UserRepo::create_with_membership(…)` | 新方法:注册时一个事务建账号 + 加入租户 + 授租户角色 |
| `TenantRepo` / `MemberRepo` | 新端口(内存 `InMemoryTenantRepo` / `InMemoryMemberRepo`,PG `PgTenantRepo` / `PgMemberRepo`) |
| 新类型 | `Tenant`、`TenantStatus`、`Membership`、`MemberStatus`、`RoleScope`、`LoginCandidates`、`LoginEntry`、`ListResult`、常量 `DEFAULT_TENANT_ID`(`00000000-0000-0000-0000-000000000001`) |
| `IdmError::Forbidden` | 新变体:已认证但不是目标租户的有效成员。消费方的 `From<IdmError>` 要加一支(穷尽 match 会编译报错提醒) |
| 内存仓储 | 要看同一批数据时用 `InMemory{Role,Tenant,Member,Session,Outbox}Repo::sharing_with(&users)` |
| 事件 | outbox 新增 `tenant.created` / `tenant.updated` / `tenant.deleted` / `tenant.member_added` / `tenant.member_updated` / `tenant.member_roles_set` / `tenant.member_removed` |
| 迁移 `0004_tenants` | 建 `tenants` / `tenant_members` / `member_roles`,`roles.scope`、`sessions.tenant_id`;建默认租户,把存活账号加为它的成员、`user_roles` **复制**进默认租户的 `member_roles`;`superadmin` 标为平台角色并在默认租户兼任 `admin`(升级后老超管照样进后台);未吊销的旧会话(账号是默认租户 active 成员)回填 `tenant_id` = 默认租户(刷新后直接进默认租户) |

## 测试

```sh
just test       # 单元测试 + 内存仓储的一致性契约(不要数据库)
just test-pg    # + 内存↔Postgres 仓储对拍(要有在跑的 pg;默认连 baserust 本地 compose 的 pg,idm role)
just lint       # rustfmt 检查(稳定版 + nightly)+ clippy -D warnings(和 CI 一样)
```

`just lint` / `just fmt` 另外要 nightly 的 rustfmt(Google Rust 风格指南要求的三项格式化配置
`imports_granularity=Module`、`hex_literal_case=Lower`、`format_macro_matchers=true` 只有 nightly 支持):
`rustup toolchain install nightly --profile minimal --component rustfmt`。

工具、lint 配置和约定与 baserust 一致,见 `AGENTS.md`。

## 许可

MIT,见 [LICENSE](LICENSE)。
