//! idm 仓储内存实现 —— 脚手架默认,无 DB 即可跑通注册/登录全链路 + 写单测。
//! 镜像 PG 的软删过滤、username 唯一、email(有则)唯一,保 parity。

use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{
    ListPage, Role, RoleRepo, Session, SessionRepo, SortDir, User, UserListFilter, UserListResult,
    UserListRow, UserRepo, UserSortBy, UserWithHash,
};
use crate::error::IdmError;

/// 内存内部行:比 `User` 多 password_hash + created_at + deleted_at(DTO 不暴露)。
#[derive(Clone)]
struct UserRow {
    id: Uuid,
    username: String,
    email: Option<String>,
    email_verified: bool,
    password_hash: String,
    created_at: OffsetDateTime,
    deleted_at: Option<OffsetDateTime>,
}

/// 角色 + 授予关系的**共享**存储:内存下 `UserRepo`(create_with_roles / list 读角色名)与
/// `RoleRepo`(upsert / grant / set_roles / roles_for_user)必须共用同一份 `roles` / `user_roles`,
/// 才能镜像 PG 两 repo 共表的语义。独立 `new()` 各自一份;`InMemoryRoleRepo::sharing_with` 共享。
#[derive(Default)]
struct RoleStore {
    roles: Mutex<Vec<RoleRec>>,       // 存活角色(内存无软删)
    grants: Mutex<Vec<(Uuid, Uuid)>>, // (user_id, role_id)
}

struct RoleRec {
    id: Uuid,
    name: String,
    display_name: String,
}

/// 排序方向套到一个原始 `Ordering` 上。
fn apply_dir(o: Ordering, dir: SortDir) -> Ordering {
    match dir {
        SortDir::Asc => o,
        SortDir::Desc => o.reverse(),
    }
}

/// `NULLS LAST` 比较:非空恒排在空之前(与 `dir` 无关),两非空按 `dir` 比。
fn opt_last_cmp(a: Option<&str>, b: Option<&str>, dir: SortDir) -> Ordering {
    match (a, b) {
        (Some(x), Some(y)) => apply_dir(x.cmp(y), dir),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

/// 单行比较:主键按 `sort_by`×`dir`(email `NULLS LAST`),再以 id 兜底(同 `dir`,镜像 PG)。
fn cmp_row(a: &UserListRow, b: &UserListRow, sort_by: UserSortBy, dir: SortDir) -> Ordering {
    let primary = match sort_by {
        UserSortBy::Username => apply_dir(a.username.cmp(&b.username), dir),
        UserSortBy::CreatedAt => apply_dir(a.created_at.cmp(&b.created_at), dir),
        UserSortBy::Email => opt_last_cmp(a.email.as_deref(), b.email.as_deref(), dir),
    };
    primary.then_with(|| apply_dir(a.id.cmp(&b.id), dir))
}

impl UserRow {
    fn to_user(&self) -> User {
        User {
            id: self.id,
            username: self.username.clone(),
            email: self.email.clone(),
            email_verified: self.email_verified,
            created_at: self.created_at,
        }
    }
}

pub struct InMemoryUserRepo {
    store: Mutex<HashMap<Uuid, UserRow>>,
    roles: Arc<RoleStore>,
}

impl InMemoryUserRepo {
    pub fn new() -> Self {
        Self {
            store: Mutex::new(HashMap::new()),
            roles: Arc::new(RoleStore::default()),
        }
    }
}

impl Default for InMemoryUserRepo {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl UserRepo for InMemoryUserRepo {
    async fn create(
        &self,
        username: &str,
        email: Option<&str>,
        password_hash: &str,
        _by: Option<String>,
    ) -> Result<User, IdmError> {
        let mut store = self.store.lock().expect("锁未中毒");
        // username 唯一 + email(有则)唯一,仅对存活行:镜像两个 partial unique 索引。
        let dup = store.values().any(|r| {
            r.deleted_at.is_none()
                && (r.username == username || (email.is_some() && r.email.as_deref() == email))
        });
        if dup {
            return Err(IdmError::Conflict(
                "Username or email already taken".to_owned(),
            ));
        }
        let row = UserRow {
            id: Uuid::now_v7(),
            username: username.to_owned(),
            email: email.map(str::to_owned),
            email_verified: false,
            password_hash: password_hash.to_owned(),
            created_at: OffsetDateTime::now_utc(),
            deleted_at: None,
        };
        let user = row.to_user();
        store.insert(row.id, row);
        Ok(user)
    }

    async fn find_by_identifier(&self, identifier: &str) -> Result<Option<UserWithHash>, IdmError> {
        Ok(self
            .store
            .lock()
            .expect("锁未中毒")
            .values()
            .find(|r| {
                r.deleted_at.is_none()
                    && (r.username == identifier || r.email.as_deref() == Some(identifier))
            })
            .map(|r| UserWithHash {
                user: r.to_user(),
                password_hash: r.password_hash.clone(),
            }))
    }

    async fn find_by_id(&self, id: Uuid) -> Result<User, IdmError> {
        self.store
            .lock()
            .expect("锁未中毒")
            .get(&id)
            .filter(|r| r.deleted_at.is_none())
            .map(UserRow::to_user)
            .ok_or(IdmError::NotFound)
    }

    async fn find_by_ids(&self, ids: &[Uuid]) -> Result<Vec<User>, IdmError> {
        let store = self.store.lock().expect("锁未中毒");
        // 镜像 PG:只返存活行,查不到的 id 直接缺席(不报错)。
        Ok(ids
            .iter()
            .filter_map(|id| store.get(id))
            .filter(|r| r.deleted_at.is_none())
            .map(UserRow::to_user)
            .collect())
    }

    async fn update(
        &self,
        id: Uuid,
        username: &str,
        email: Option<&str>,
        _by: Option<String>,
    ) -> Result<User, IdmError> {
        let mut store = self.store.lock().expect("锁未中毒");
        // 冲突检查(排除自己):username / email 撞别的存活用户
        let dup = store.values().any(|r| {
            r.id != id
                && r.deleted_at.is_none()
                && (r.username == username || (email.is_some() && r.email.as_deref() == email))
        });
        if dup {
            return Err(IdmError::Conflict(
                "Username or email already taken".to_owned(),
            ));
        }
        match store.get_mut(&id) {
            Some(r) if r.deleted_at.is_none() => {
                // PUT 全量替换:username 必填、email 总替换(含清空),替换 email 即重置验证。
                r.username = username.to_owned();
                r.email = email.map(str::to_owned);
                r.email_verified = false;
                Ok(r.to_user())
            }
            _ => Err(IdmError::NotFound),
        }
    }

    async fn soft_delete(&self, id: Uuid, _by: Option<String>) -> Result<(), IdmError> {
        let mut store = self.store.lock().expect("锁未中毒");
        match store.get_mut(&id) {
            Some(r) if r.deleted_at.is_none() => {
                r.deleted_at = Some(OffsetDateTime::now_utc());
                Ok(())
            }
            _ => Err(IdmError::NotFound),
        }
    }

    async fn update_password(&self, user_id: Uuid, password_hash: &str) -> Result<(), IdmError> {
        let mut store = self.store.lock().expect("锁未中毒");
        match store.get_mut(&user_id) {
            Some(r) if r.deleted_at.is_none() => {
                r.password_hash = password_hash.to_owned();
                Ok(())
            }
            _ => Err(IdmError::NotFound),
        }
    }

    async fn password_hash(&self, user_id: Uuid) -> Result<Option<String>, IdmError> {
        Ok(self
            .store
            .lock()
            .expect("锁未中毒")
            .get(&user_id)
            .filter(|r| r.deleted_at.is_none())
            .map(|r| r.password_hash.clone()))
    }

    async fn create_with_roles(
        &self,
        username: &str,
        email: Option<&str>,
        password_hash: &str,
        role_ids: &[Uuid],
        _by: Option<String>,
    ) -> Result<User, IdmError> {
        let mut store = self.store.lock().expect("锁未中毒");
        // 同 create:username / email(有则)唯一,仅对存活行。
        let dup = store.values().any(|r| {
            r.deleted_at.is_none()
                && (r.username == username || (email.is_some() && r.email.as_deref() == email))
        });
        if dup {
            return Err(IdmError::Conflict(
                "Username or email already taken".to_owned(),
            ));
        }
        let id = Uuid::now_v7();
        let row = UserRow {
            id,
            username: username.to_owned(),
            email: email.map(str::to_owned),
            email_verified: false,
            password_hash: password_hash.to_owned(),
            created_at: OffsetDateTime::now_utc(),
            deleted_at: None,
        };
        let user = row.to_user();
        store.insert(id, row);
        drop(store);
        // 授角色:写共享 user_roles(去重),parity with PG on_conflict do nothing。
        let mut grants = self.roles.grants.lock().expect("锁未中毒");
        for rid in role_ids {
            if !grants.contains(&(id, *rid)) {
                grants.push((id, *rid));
            }
        }
        Ok(user)
    }

    async fn list(
        &self,
        filter: &UserListFilter,
        sort_by: UserSortBy,
        dir: SortDir,
        page: &ListPage,
    ) -> Result<UserListResult, IdmError> {
        let store = self.store.lock().expect("锁未中毒");
        let grants = self.roles.grants.lock().expect("锁未中毒");
        let roles = self.roles.roles.lock().expect("锁未中毒");
        // 某用户的存活角色名(按名排序,parity with PG 子查询 ORDER BY r.name)。
        let role_names = |uid: Uuid| -> Vec<String> {
            let mut ns: Vec<String> = grants
                .iter()
                .filter(|(u, _)| *u == uid)
                .filter_map(|(_, rid)| roles.iter().find(|r| r.id == *rid).map(|r| r.name.clone()))
                .collect();
            ns.sort();
            ns
        };
        let uname = filter.username.as_ref().map(|s| s.to_lowercase());
        let mut rows: Vec<UserListRow> = store
            .values()
            .filter(|r| r.deleted_at.is_none())
            .filter(|r| match &uname {
                Some(q) => r.username.to_lowercase().contains(q),
                None => true,
            })
            .filter(|r| filter.created_from.is_none_or(|f| r.created_at >= f))
            .filter(|r| filter.created_to.is_none_or(|t| r.created_at <= t))
            .filter_map(|r| {
                let rn = role_names(r.id);
                if !filter.roles_any.is_empty() && !filter.roles_any.iter().any(|x| rn.contains(x))
                {
                    return None;
                }
                if filter.roles_none.iter().any(|x| rn.contains(x)) {
                    return None;
                }
                Some(UserListRow {
                    id: r.id,
                    username: r.username.clone(),
                    email: r.email.clone(),
                    email_verified: r.email_verified,
                    created_at: r.created_at,
                    roles: rn,
                })
            })
            .collect();
        rows.sort_by(|a, b| cmp_row(a, b, sort_by, dir));

        match *page {
            ListPage::Offset {
                offset,
                limit,
                with_total,
            } => {
                let total = with_total.then_some(rows.len() as u64);
                let page_rows = rows
                    .into_iter()
                    .skip(offset as usize)
                    .take(limit as usize)
                    .collect();
                Ok(UserListResult {
                    rows: page_rows,
                    total,
                    next_after: None,
                })
            }
            ListPage::Cursor { after, limit } => {
                // 镜像 PG:先 WHERE id keyset(相对 dir),再 ORDER BY,再取 limit+1 判下一页。
                let mut kept: Vec<UserListRow> = rows
                    .into_iter()
                    .filter(|r| match after {
                        Some(a) => match dir {
                            SortDir::Asc => r.id > a,
                            SortDir::Desc => r.id < a,
                        },
                        None => true,
                    })
                    .collect();
                let has_more = kept.len() as u64 > limit;
                kept.truncate(limit as usize);
                let next_after = if has_more {
                    kept.last().map(|r| r.id)
                } else {
                    None
                };
                Ok(UserListResult {
                    rows: kept,
                    total: None,
                    next_after,
                })
            }
        }
    }
}

/// 会话内存行。
#[derive(Clone)]
struct SessionRow {
    id: Uuid,
    user_id: Uuid,
    token_hash: String,
    expires_at: OffsetDateTime,
    revoked_at: Option<OffsetDateTime>,
}

pub struct InMemorySessionRepo {
    store: Mutex<Vec<SessionRow>>,
}

impl InMemorySessionRepo {
    pub fn new() -> Self {
        Self {
            store: Mutex::new(Vec::new()),
        }
    }
}

impl Default for InMemorySessionRepo {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SessionRepo for InMemorySessionRepo {
    async fn create(
        &self,
        user_id: Uuid,
        token_hash: &str,
        expires_at: OffsetDateTime,
        _by: Option<String>,
    ) -> Result<Session, IdmError> {
        let row = SessionRow {
            id: Uuid::now_v7(),
            user_id,
            token_hash: token_hash.to_owned(),
            expires_at,
            revoked_at: None,
        };
        let session = Session {
            id: row.id,
            user_id,
        };
        self.store.lock().expect("锁未中毒").push(row);
        Ok(session)
    }

    async fn find_active(
        &self,
        token_hash: &str,
        now: OffsetDateTime,
    ) -> Result<Option<Session>, IdmError> {
        Ok(self
            .store
            .lock()
            .expect("锁未中毒")
            .iter()
            .find(|r| r.token_hash == token_hash && r.revoked_at.is_none() && r.expires_at > now)
            .map(|r| Session {
                id: r.id,
                user_id: r.user_id,
            }))
    }

    async fn revoke(&self, session_id: Uuid) -> Result<(), IdmError> {
        let mut store = self.store.lock().expect("锁未中毒");
        if let Some(r) = store.iter_mut().find(|r| r.id == session_id) {
            r.revoked_at.get_or_insert(OffsetDateTime::now_utc());
        }
        Ok(())
    }

    async fn revoke_all(&self, user_id: Uuid, except: Option<Uuid>) -> Result<(), IdmError> {
        let now = OffsetDateTime::now_utc();
        let mut store = self.store.lock().expect("锁未中毒");
        for r in store.iter_mut() {
            if r.user_id == user_id && Some(r.id) != except && r.revoked_at.is_none() {
                r.revoked_at = Some(now);
            }
        }
        Ok(())
    }
}

/// 角色内存实现。与 `InMemoryUserRepo` 可共享 `RoleStore`(见 [`InMemoryRoleRepo::sharing_with`]),
/// 从而 `create_with_roles` / `set_roles` 写的授予对 `roles_for_user` / `list` 可见(镜像 PG 共表)。
pub struct InMemoryRoleRepo {
    inner: Arc<RoleStore>,
}

impl InMemoryRoleRepo {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RoleStore::default()),
        }
    }

    /// 与给定 `InMemoryUserRepo` **共享**角色/授予存储 —— 内存模式下让两 repo 语义等价于 PG 共表。
    pub fn sharing_with(users: &InMemoryUserRepo) -> Self {
        Self {
            inner: Arc::clone(&users.roles),
        }
    }
}

impl Default for InMemoryRoleRepo {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RoleRepo for InMemoryRoleRepo {
    async fn upsert(
        &self,
        name: &str,
        display_name: &str,
        _by: Option<String>,
    ) -> Result<Uuid, IdmError> {
        let mut roles = self.inner.roles.lock().expect("锁未中毒");
        if let Some(r) = roles.iter().find(|r| r.name == name) {
            return Ok(r.id);
        }
        let id = Uuid::now_v7();
        roles.push(RoleRec {
            id,
            name: name.to_owned(),
            display_name: display_name.to_owned(),
        });
        Ok(id)
    }

    async fn grant(
        &self,
        user_id: Uuid,
        role_id: Uuid,
        _by: Option<String>,
    ) -> Result<(), IdmError> {
        let mut grants = self.inner.grants.lock().expect("锁未中毒");
        if !grants.contains(&(user_id, role_id)) {
            grants.push((user_id, role_id));
        }
        Ok(())
    }

    async fn roles_for_user(&self, user_id: Uuid) -> Result<Vec<String>, IdmError> {
        let grants = self.inner.grants.lock().expect("锁未中毒");
        let roles = self.inner.roles.lock().expect("锁未中毒");
        Ok(grants
            .iter()
            .filter(|(u, _)| *u == user_id)
            .filter_map(|(_, rid)| roles.iter().find(|r| r.id == *rid).map(|r| r.name.clone()))
            .collect())
    }

    async fn list(&self) -> Result<Vec<Role>, IdmError> {
        let mut list: Vec<Role> = self
            .inner
            .roles
            .lock()
            .expect("锁未中毒")
            .iter()
            .map(|r| Role {
                id: r.id,
                name: r.name.clone(),
                display_name: r.display_name.clone(),
            })
            .collect();
        list.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(list)
    }

    async fn set_roles(
        &self,
        user_id: Uuid,
        role_ids: &[Uuid],
        _by: Option<String>,
    ) -> Result<(), IdmError> {
        // 全量替换:清该 user 的所有授予,再批量加新(去重)。幂等。
        let mut grants = self.inner.grants.lock().expect("锁未中毒");
        grants.retain(|(u, _)| *u != user_id);
        for rid in role_ids {
            if !grants.contains(&(user_id, *rid)) {
                grants.push((user_id, *rid));
            }
        }
        Ok(())
    }
}
