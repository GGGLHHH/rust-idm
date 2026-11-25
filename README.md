# idm

自包含的**认证 / 身份(IDM)领域与服务库(零 HTTP)**:`AuthService` + 可替换的仓储 / 密码哈希 / 令牌 / 时钟端口 + 自己的 `IdmError`。
作为库嵌进应用使用,HTTP 边界(路由、DTO、校验、cookie)归消费方。

> 从 **baserust** 脚手架里抽出来的,对应 `simple-idm-slim` ↔ 业务应用的关系(业务应用依赖一个可复用的认证库)。

## 里面有什么

- **领域**:`AuthService`(注册 / 登录 / 会话轮换 / 改密码)+ 仓储端口 `UserRepo` / `SessionRepo` / `RoleRepo`
  (内存和 Postgres 两种实现)+ 发件箱 `OutboxRepo`(transactional outbox,写事务里顺带记事件)+ JWT
  (HS256 访问令牌 + 轮换的不透明刷新令牌)+ `PwHasher` 端口后面的 Argon2 密码哈希。
- **令牌和时钟端口**:`TokenSigner` / `TokenVerifier`(默认 `Hs256Tokens`;拆开是为了独立的 idm 进程只签发、
  app 只验签)+ `Clock` / `SystemClock`(注入固定时钟,确定性地测过期和轮换)。
- **领域类型和错误**:`AuthOutcome` / `UserView` / `AuthUser`(纯数据),`IdmError` 五种:`NotFound` / `Unauthorized` /
  `InvalidCredentials`(带失败原因,只给审计用,对外仍统一 401)/ `Conflict` / `Internal`。
  HTTP 状态码、错误码和响应格式由消费方经 `From<IdmError> for AppError` 决定。
- **迁移**:在 `migrations/`,拷进应用的 `migrations/idm` 跑。

## 怎么用

```toml
[dependencies]
idm = { git = "https://github.com/GGGLHHH/rust-idm", tag = "v0.5.1" }
```

实现仓储端口(或直接用自带的 `InMemory*` / `Pg*`),建一个 `AuthService` 放进 `AppState`(`Clone` 很便宜),
在自己的 handler 里调用:

```rust
use std::sync::Arc;
use idm::{AuthService, InMemoryUserRepo, InMemorySessionRepo, InMemoryRoleRepo, Argon2Hasher};

let auth = AuthService::new(
    Arc::new(InMemoryUserRepo::new()),
    Arc::new(InMemorySessionRepo::new()),
    Arc::new(InMemoryRoleRepo::new()),
    Arc::new(Argon2Hasher),
    &jwt_secret, 900, 604_800,            // 访问 / 刷新令牌有效期(秒)
);
// 也可以用 builder 换掉单个端口(自定义 claims / RS256 / 测试时钟):
let auth = AuthService::builder(users, sessions, roles)
    .hs256_secret(&jwt_secret)
    .build();

let out = auth.register(register_input, Some(actor)).await?; // -> AuthOutcome { user: UserView, access_token, refresh_token, .. }
let who = auth.authenticate_token(&access_token)?;           // -> AuthUser { id, username, roles }
```

## 服务方法

`AuthService`:`register` · `login` · `refresh` · `logout` · `logout_all` · `me` · `update_me` · `delete_me` ·
`change_password` · `authenticate_token`。参数是领域的 `*Input` 结构(部分写方法另带 `by: Option<String>` 做审计),
返回领域数据(`AuthOutcome` / `UserView` / `AuthUser`);路由、httponly cookie、`{code, error}` 响应格式归消费方。

## 测试

```sh
just test       # 单元测试 + 内存仓储的一致性契约(不要数据库)
just test-pg    # + 内存↔Postgres 仓储对拍(要有在跑的 pg;默认连 baserust 本地 compose 的 pg,idm role)
just lint       # rustfmt 检查 + clippy -D warnings(和 CI 一样)
```

工具、lint 配置和约定与 baserust 一致,见 `AGENTS.md`。

## 许可

MIT,见 [LICENSE](LICENSE)。
