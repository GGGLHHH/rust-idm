# idm

Self-contained **auth / IDM** domain & service crate (**zero HTTP**): `AuthService` + pluggable repo / hasher / token / clock ports + its own `IdmError`. Embed it as a library — the consuming app owns the HTTP edge (routes, DTOs, validation, cookies).

> Extracted from the **baserust** scaffold; mirrors the `simple-idm-slim` ↔ app relationship (a reusable auth library a business app depends on).

## What's inside

- **Domain** — `AuthService` (register / login / session rotation / change-password) + repo ports (`UserRepo` / `SessionRepo` / `RoleRepo`, in-memory + Postgres impls) + JWT (HS256 access + rotating opaque refresh) + Argon2 password hashing behind a `PwHasher` port.
- **Token & clock ports** — `TokenSigner` / `TokenVerifier` (default `Hs256Tokens`; split so a dedicated idm process can sign-only and the app verify-only) + `Clock` / `SystemClock` (inject a fixed clock to test expiry / rotation deterministically).
- **Domain types & errors** — `AuthOutcome` / `UserView` / `AuthUser` (plain data) and a 4-variant `IdmError` (`NotFound` / `Unauthorized` / `Conflict` / `Internal`); HTTP status, machine code and wire shape are the app's job via `From<IdmError> for AppError`.
- **Migrations** — in `migrations/`; copy them into your app's `migrations/idm` dir to run.

## Use it

```toml
[dependencies]
idm = { git = "https://github.com/GGGLHHH/rust-idm", tag = "v0.2.0" }
```

Implement the repo ports (or use the bundled `InMemory*` / `Pg*` impls), build an `AuthService`, hold it in your `AppState` (cheap `Clone`), and call its methods from your own handlers:

```rust
use std::sync::Arc;
use idm::{AuthService, InMemoryUserRepo, InMemorySessionRepo, InMemoryRoleRepo, Argon2Hasher};

let auth = AuthService::new(
    Arc::new(InMemoryUserRepo::new()),
    Arc::new(InMemorySessionRepo::new()),
    Arc::new(InMemoryRoleRepo::new()),
    Arc::new(Argon2Hasher),
    &jwt_secret, 900, 604_800,            // access / refresh TTL (secs)
);
// or override individual ports (custom claims / RS256 / test clock) via the builder:
let auth = AuthService::builder(users, sessions, roles)
    .hs256_secret(&jwt_secret)
    .build();

let out = auth.register(register_input, Some(actor)).await?; // -> AuthOutcome { user: UserView, access_token, refresh_token, .. }
let who = auth.authenticate_token(&access_token)?;           // -> AuthUser { id, username, roles }
```

## Service methods

`AuthService`: `register` · `login` · `refresh` · `logout` · `logout_all` · `me` · `update_me` · `delete_me` · `change_password` · `authenticate_token`. Methods take domain `*Input` structs (some write methods also take `by: Option<String>` for audit) and return domain data (`AuthOutcome` / `UserView` / `AuthUser`); routing, httponly cookies and the `{code, error}` wire shape are the app's responsibility.

## Testing

```sh
cargo test                                 # unit tests (no DB)
cargo test --features pg-conformance        # + memory↔Postgres repo parity (needs a running pg)
```

## License

MIT — see [LICENSE](LICENSE).
