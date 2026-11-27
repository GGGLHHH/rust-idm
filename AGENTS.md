# AGENTS.md — rust-idm

`idm`:自包含的认证 / 身份**领域 / 服务库(零 HTTP)**,由 baserust 以 git 依赖引用:
发过版的按 tag 钉(`tag = "vX.Y.Z"`),没打 tag 的版本按提交钉(`rev = "<提交>"`,如 0.6.0 时 baserust 钉的 `rev = "00f4e4d"`)。
代码规范、工具、检查口径和 baserust 一致(同一套 `just` 目标、同一份 lint 配置、同一个 Rust 版本)。

- 人看的用法 / 端口 / 测试 / 版本变更 → `README.md`
- **怎么干活 → 本文**(`CLAUDE.md` 与 `AGENTS.md` 内容相同,改一个就同步另一个)

## 在这干活的铁律

1. **零 HTTP、零框架**:不许引入 axum / tower / utoipa / reqwest / 任何 web 框架;路由、DTO、校验、cookie、状态码、
   OpenAPI 全归消费方(baserust)。错误只用本 crate 的 `IdmError`,HTTP 映射由消费方 `From<IdmError> for AppError` 做。
2. **每个改动过 `just check && just test && just lint`**(clippy `-D warnings`,零警告;Rust 版本由 `rust-toolchain.toml` 固定)。
   动了 PG 仓储再跑 `just test-pg`。CI(`.github/workflows/ci.yml`)跑的是同一套。
3. **仓储改动 = 内存和 PG 两个实现一起改,契约一起加**:`tests/idm_repo_conformance.rs` 的 `*_contract` 函数和
   `idm_tenant_contract` 模块(`both_backends!` 生成两个入口)是唯一真相源,内存 / PG 各跑一遍。
   只断言顺序、相对关系、可见性、错误类型,**不断言绝对时间戳**(PG `now()` ≠ 内存时钟)。
   端口 trait 在 `src/repo/<端口>_repo.rs`,内存实现在 `src/repo/memory.rs`,PG 实现在 `src/repo/postgres.rs`(表 / 列名 `src/repo/schema.rs`)。
4. **每个 PG 仓储方法加 `#[tracing::instrument(name = "pg.<表>.<方法>", skip_all)]`**:baserust 后台「系统监控」的
   数据库耗时就是按这个 span 统计的,不加就看不到。`skip_all`:参数里有用户数据,别进日志字段。
   每秒一轮的轮询(如 outbox 的 `poll_unpublished`)不加,否则空轮询刷屏。
5. **事务**:一个原子单元 = 一个 trait 方法(方法内开事务);事务对象不进 trait 签名;内存实现先校验、后改状态。
6. **迁移在 `migrations/`**:消费方拷进自己的 `migrations/idm` 跑(落哪个 schema 由 role 的 search_path 决定)。
   SQL 不写 schema 前缀。**已发布的迁移(`*.up.sql` / 无后缀)不许改**,要变就加新迁移;改了迁移,baserust 那边要同步拷贝。
7. **发版**:改完升 `Cargo.toml` 的 `version`(`Cargo.lock` 跟着更新)、在 `README.md`「版本变更」写清不兼容项,
   打新 tag(`vX.Y.Z`,和 `version` 一致);baserust 改 `Cargo.toml` 的 tag(原先按 `rev` 钉的改回 `tag`)、更新 `Cargo.lock`,
   再在 baserust-stack 提交两边的新子模块指针(stack 的 CI 会核对子模块 = `Cargo.lock` 锁的提交)。
8. **注释、文档用中文**;代码标识符英文。代码风格见下文「代码风格」。
9. **提交需许可**:未经明确同意不要 commit / push / 打 tag。

## 多租户 / token 约定(0.6.0 起)

- token claim:`roles` = **平台角色**、`tenant_id`(平台上下文时缺省)= 当前租户、`tenant_roles` = 当前租户角色。
  新 claim 一律 `#[serde(default)]`,旧 token 必须还能验(有用例 `old_token_without_tenant_claims_still_verifies`)。
- 会话带 `tenant_id`;refresh **沿用**它并重新校验成员关系 + 租户状态,失效 → `Unauthorized`,绝不换到别的租户。
  切换租户(`switch_tenant(refresh_token, MemberKey { tenant_id, user_id })`)非有效成员 → `Forbidden`。
- refresh / 切换租户用 `SessionRepo::revoke` 的返回值做轮换闸:`false`(已被并发的另一次用掉)→ `Unauthorized`,
  绝不分出第二个活会话。自己实现 `SessionRepo` 必须是条件更新、只有一个调用方拿到 `true`。
- 成员仓储是 `AuthService::builder(users, sessions, roles, members)` 的必填参数:多租户恒开,**不许加关闭开关 / 悄悄降级**;
  注册 = `UserRepo::create_with_membership` 一个事务。
- 成员写操作(set_status / set_roles / touch_last_used / remove)对已软删租户一律 `NotFound`;内存会话仓储建会话时
  校验租户行存在(镜像 PG 外键)—— 内存仓储之间共享存储用 `InMemory*Repo::new_shared_with(&users)`。

## 代码风格

遵循 [Google Rust 风格指南](https://google.github.io/styleguide/rustguide.html)(本库是给别的团队用的库,API 条款全部适用;
`[chrome]` / `[Fuchsia]` 条目不适用)。

**工具守的**(过了 `just lint` 就算数):

- 格式:`rustfmt.toml`(`max_width = 100`)+ nightly rustfmt 的三项 `imports_granularity=Module,hex_literal_case=Lower,format_macro_matchers=true`
  (取值在 `justfile` 的 `google_fmt`,CI 里同一串;装法 `rustup toolchain install nightly --profile minimal --component rustfmt`);
- lint:`Cargo.toml` 的 `[lints]`(`unsafe_code = "forbid"`、`missing_docs`、`absolute_paths`、`must_use_candidate`、
  `missing_panics_doc`、`redundant_clone`、`exhaustive_enums` / `exhaustive_structs` 等)+ `clippy.toml` 的阈值(路径最多两段、测试里允许 unwrap / expect);
- `lib.rs` 的 `#![warn(clippy::unwrap_used)]`:产品代码不许 `unwrap`,必须 panic 的用 `expect("不变量")` 并写 `# Panics`。

**要人守的**(评审时看):

- 公开结构体 / 枚举加 `#[non_exhaustive]`,库外构造走构造函数(`Xxx::new`);落在条款例外里的用
  `#[allow(clippy::exhaustive_*, reason = "…")]` 写明依据;
- 写方法的审计主体参数一律 `by: Option<&str>`(「Prefer borrows over deep copies」「Accept flexible references」),
  不收 `Option<String>`;调用方从 `Option<String>` 传用 `.as_deref()`;
- 每个端口 trait 都配 `impl<T: Trait + ?Sized> Trait for Arc<T>` 和 `… for Box<T>` 转发实现(`AuthService<Arc<dyn UserRepo>, …>` /
  `Box<dyn …>` 靠它),**全部方法都转发**(含有默认实现的,否则下游覆盖的实现会被默认实现顶掉);builder 类型标 `#[must_use = "…"]`;
- 不用 glob 导入(测试模块的 `use super::*` 除外);一条 `use` 只从一个模块导入;类型 / trait 导入后不带路径用,
  跨模块的函数用「模块名::函数名」调用;只在一两处用到的 trait 在函数体里局部导入;
- 命名不缩写(`subquery` 不是 `sub`,`message` 不是 `msg`,`tenant` 不是 `t`),测试里的局部变量也一样;
- `.parse()` / `.into()` / `collect()` / `sqlx::query_as*` 的结果在变量声明上标类型,不用 turbofish;
- `for` 循环头里不放组合子链(先赋给有名字的变量);不用 `for_each`;
- 文件 / 叶子模块按主要条目命名(`AuthService` → `auth_service.rs`),一个文件一个主要条目;非叶子模块(`lib.rs`、`repo/mod.rs`)只放声明和重新导出;
- 锁中毒绝不读里面的数据:内存仓储的 `lock` 直接 panic(各 `InMemory*Repo` 的文档里写了 `# Panics`)。

**符合指南条款的例外情形**(每条都落在指南的明文例外 / 适用范围里,代码里也写了依据;别「顺手修掉」):

- **不加 `#[non_exhaustive]` 的公开类型**:
  - 两态枚举 `TenantStatus` / `MemberStatus` / `RoleScope` / `SortDirection` —— 「Apply `#[non_exhaustive]` to publicly-exposed enums」例外
    *"Enums with two states that could be Booleans"* / *"Enums describing an existing ontology"*;
  - 输入结构体 `RegisterInput` / `LoginInput` / `UpdateMeInput` / `ChangePasswordInput` / `NewUser` / `NewRole` / `NewTenant` / `UserListFilter` ——
    「Apply `#[non_exhaustive]` to public structs with public fields」例外 *"You want to enable your users to use functional record update (FRU)"*;
  - 复合主键 `MemberKey` / `RoleGrant` —— 同条款例外 *"The struct fields are unlikely to change, e.g., because they describe an existing ontology"*;
  - 单元结构体 `SystemClock` / `Argon2Hasher` / `FakeHasher` —— 没有公开字段,不在条款适用范围内。
- **`Arc`**:内存仓储之间共享 `Arc<Mutex<…>>` 存储(镜像 PG 同库多表)、`AuthService` 的哈希端口存 `Arc`(`spawn_blocking`
  的闭包要 `'static`)——「Avoid `Rc` and `Arc`」例外 *"the alternative ownership and borrowing structure would be unreasonably complex"*。
  `AuthService` 本身不 `Clone`、不内含共享,要共享由消费方包 `Arc`。
- **哈希 / 签发 / 验证 / 时钟端口内部存成 trait 对象**:builder 的 setter 收的是 `impl Trait + 'static`(「Generics versus `dyn Trait`」
  约束的是函数参数,已满足);存成 `Box<dyn …>` 是为了不让 `AuthService` 长出 8 个类型参数(同条款例外 *"Cases where code size matters"*)。
- **仓储方法返回 `Vec`、收 `&[Uuid]`**:「Iterators vs. owned collections in return types」例外 *"The function's implementation naturally
  constructs a vector"* / *"The function is returning a pre-existing vector"*;端口要 dyn 兼容(`Arc<dyn UserRepo>`),不能有泛型方法收 `impl IntoIterator`。
- **带模块名写的类型**:`anyhow::Error`、`sqlx::Error`、`fmt::Result` / `fmt::Formatter`、`sqlx::Result` ——「Type names should be imported and used
  unqualified」例外 *"In cases where there are ambiguities … `io::Error`"*;测试里 `both_backends!` 宏体内的 `sqlx::PgPool` 是 *"In macros and generated code"*。
- **直接导入的函数**:`tokio::time::sleep`(测试)——「Qualify calls to top-level functions with a module name」例外
  *"When the module name itself is prone to collisions"*(`time` 和 time crate 撞名)。
- **按用途命名的叶子模块**:`input.rs`(四个输入结构体)、`tenant.rs`(租户领域类型)、`token.rs`(claim + 签验端口)、
  `repo/memory.rs` / `repo/postgres.rs`(六个仓储实现)、`repo/schema.rs`(表 / 列标识)、`repo/event_payload.rs`(事件载荷函数)——
  「Name source files and leaf modules after the primary user-defined item」原文 *"Leaf modules that are not primarily about any particular
  abstraction can be named as desired."*
- **保留的缩写**(「Avoid abbreviations」例外 *"Common abbreviations found in Wikipedia"* / *"unlikely to be confusing to people outside of your project"*):
  IdM(`idm`)、JWT、HS256、PHC(`phc_string`)、PG / `Pg`(PostgreSQL)、SQL(`*_sql`)、UUID、TTL、FRU、`tx`(数据库事务)、`env`(测试环境);
  JWT 线上 claim 名 `sub` / `jti` / `iat` / `exp` 是 RFC 7519 规定的字段名;`fmt(&self, f: &mut Formatter)` 的 `f` 照标准库签名;
  一行内的短闭包参数(`|e|`、`|row|`)同指南自己的示例 `values.iter().any(|&v| v > threshold)`。

## 命令

`just check` · `just test` · `just test-pg` · `just lint` · `just fmt` · `just fix` · `just watch`
