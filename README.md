# idm

Self-contained **auth / IDM** crate for [axum](https://github.com/tokio-rs/axum): domain logic + HTTP + its own error type. Embed it in an app, or run it standalone.

> Extracted from the **baserust** scaffold; mirrors the `simple-idm-slim` ↔ app relationship (a reusable auth library a business app depends on).

## What's inside

- **Domain** — `AuthService` + repo ports (`UserRepo` / `SessionRepo` / `RoleRepo`, in-memory + Postgres impls) + JWT (HS256 access + rotating opaque refresh) + Argon2 password hashing behind a `PwHasher` port.
- **HTTP** — `router::<S>()` (generic over host state via `FromRef`) + `authenticate::<S: HasAuth>` middleware + `IdmState`.
- **Self-contained** — its own `IdmError` (renders the same `{code,error}` JSON contract as a host app), plus `AuditContext` / `CurrentUser` / `AuthUser`.
- **Migrations** — in `migrations/`; copy them into your app's migration dir to run.

## Use it

```toml
[dependencies]
idm = { git = "https://github.com/GGGLHHH/rust-idm", tag = "v0.1.0" }
```

**Embed in an app** (single binary) — host `AppState` impls `HasAuth` + `FromRef<AppState> for IdmState` (sharing one `AuthService`):

```rust
api_router = api_router.merge(idm::router::<AppState>());
// middleware stack: idm::authenticate::<AppState>
```

**Run standalone** — `idm::app(idm_state)` is a complete router (endpoints + authenticate) for a dedicated auth service / oneshot tests.

## Endpoints

`/api/v1/auth/*`: register · login · refresh · logout · logout-all · me (get / put / delete / password). httponly cookie auth + Bearer fallback. Errors render as `{code, error}`; raw detail only to logs.

## Testing

```sh
cargo test                                 # unit + oneshot HTTP contract (no DB)
cargo test --features pg-conformance        # + memory↔Postgres repo parity (needs a running pg)
```

## License

MIT — see [LICENSE](LICENSE).
