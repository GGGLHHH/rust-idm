# idm

自包含的**认证 / 身份(IDM)领域与服务库(零 HTTP)**:`AuthService` + 可替换的仓储 / 密码哈希 / 令牌 / 时钟端口 + 自己的 `IdmError`。
作为库嵌进应用使用,HTTP 边界(路由、DTO、校验、cookie)归消费方。

> 从 **baserust** 脚手架里抽出来的,对应 `simple-idm-slim` ↔ 业务应用的关系(业务应用依赖一个可复用的认证库)。

## 里面有什么

- **领域**:`AuthService`(注册 / 登录 / 会话轮换 / 切换租户 / 改密码)+ 仓储端口 `UserRepo` / `SessionRepo` / `RoleRepo` /
  `TenantRepo` / `MemberRepo`
  (内存和 Postgres 两种实现)+ 发件箱 `OutboxRepo`(transactional outbox,写事务里顺带记事件)+ JWT
  (HS256 访问令牌 + 轮换的不透明刷新令牌)+ `PwHasher` 端口后面的 Argon2 密码哈希。
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
idm = { git = "https://github.com/GGGLHHH/rust-idm", tag = "v0.6.0" }
```

实现仓储端口(或直接用自带的 `InMemory*` / `Pg*`),建一个 `AuthService` 放进 `AppState`(`Clone` 很便宜),
在自己的 handler 里调用:

```rust
use std::sync::Arc;
use idm::{AuthService, InMemoryUserRepo, InMemorySessionRepo, InMemoryRoleRepo, InMemoryMemberRepo, Argon2Hasher};

let auth = AuthService::new(
    Arc::new(InMemoryUserRepo::new()),
    Arc::new(InMemorySessionRepo::new()),
    Arc::new(InMemoryRoleRepo::new()),
    Arc::new(InMemoryMemberRepo::new()),    // 成员仓储必填:多租户恒开
    Arc::new(Argon2Hasher),
    &jwt_secret, 900, 604_800,            // 访问 / 刷新令牌有效期(秒)
);
// 也可以用 builder 换掉单个端口(自定义 claims / RS256 / 测试时钟):
let auth = AuthService::builder(users, sessions, roles, members)
    .hs256_secret(&jwt_secret)
    .build();

let out = auth.register(register_input, Some(actor)).await?; // -> AuthOutcome { user: UserView, access_token, refresh_token, .. }
let who = auth.authenticate_token(&access_token)?;           // -> AuthUser { id, username, roles, tenant_id, tenant_roles }
```

## 服务方法

`AuthService`:`register` · `login` · `login_with` · `refresh` · `switch_tenant` · `my_tenants` · `logout` · `logout_all` · `me` ·
`update_me` · `delete_me` · `change_password` · `authenticate_token`。参数是领域的 `*Input` 结构(部分写方法另带 `by: Option<String>` 做审计),
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

成员仓储是 `AuthService::new` / `builder` 的**必填参数**(多租户恒开,没有"单租户 / 关闭租户"开关):

- **登录**:进有效成员关系(成员 active + 租户 active)里 `last_used_at` 最近的那个,并记一次 `last_used_at`;没有 → 平台上下文。
- **`login_with(input, choose)`**:验密同 `login`,但进哪里由消费方挑(本库不认识权限):`choose` 拿到
  `LoginCandidates { user_id, platform_roles, memberships }`(成员关系最近用过的在前),返回 `Some(LoginEntry::Tenant(id))`
  (进该租户并记 `last_used_at`)/ `Some(LoginEntry::Platform)`(平台上下文)/ `None`(→ `Forbidden`,**不建会话、不记 `last_used_at`**)。
  挑了不在候选里的租户或刚好被并发移出 → `Forbidden`(不退回平台上下文)。baserust 的后台登录用它挑「有后台权限的租户」。
- **refresh**:沿用会话上的租户,重新读成员关系和租户角色;成员被移出 / 停用、租户停用 / 删除 → `Unauthorized`
  (旧会话同时作废,绝不落到别的租户)。
- **`switch_tenant(refresh_token, user_id, tenant_id)`**:refresh 会话不属于 `user_id`(当前已认证身份)→ `Unauthorized`;非有效成员 → `Forbidden`(平台管理员也一样,原会话不动);成功则吊销旧会话、
  建带新租户的会话、记 `last_used_at`。
- **`my_tenants(user_id)`**:有效成员关系列表,最近用过的在前。
- **注册**:`UserRepo::create_with_membership` 一个事务建账号 + 加入 `signup_tenant`(默认 `Some(DEFAULT_TENANT_ID)`,
  该租户存活且 active 才加)+ 授 `signup_roles`(默认 `["user"]`;**只认存活的租户角色**,目录里没有或同名的是平台角色 → `IdmError::Internal`,
  什么都不建 —— 装配错误要响亮;不想授角色就配空 `Vec`)。
  `.signup_tenant(None)` = 注册只建账号。
- 内存实现要看同一批租户:`InMemory{Role,Tenant,Member,Session,Outbox}Repo::sharing_with(&users)`。

已发出的 access token 在过期前仍有效(成员被移出 / 租户停用的最长生效延迟 = access TTL);refresh 立即失败。

## 版本变更

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
just lint       # rustfmt 检查 + clippy -D warnings(和 CI 一样)
```

工具、lint 配置和约定与 baserust 一致,见 `AGENTS.md`。

## 许可

MIT,见 [LICENSE](LICENSE)。
