//! 发件箱仓储端口 [`OutboxRepo`](transactional outbox)。

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::idm_error::IdmError;

/// 发件箱记录(`OutboxRepo::poll_unpublished` 返回)。不含 `published_at`——返回的行按定义都未发布。
#[derive(Clone, Debug, PartialEq, sqlx::FromRow)]
#[non_exhaustive]
pub struct OutboxRecord {
    /// 自增 id(FIFO 顺序)。
    pub id: i64,
    /// 事件类型,如 `user.created`。
    pub event_type: String,
    /// 聚合根 id(用户事件 = 用户 id,租户 / 成员事件 = 租户 id)。
    pub aggregate_id: Uuid,
    /// 事件 payload。
    pub payload: Value,
    /// 写入时刻。
    pub created_at: OffsetDateTime,
}

impl OutboxRecord {
    /// 组装(给自己实现 [`OutboxRepo`] 的调用方、测试用)。
    #[must_use]
    pub fn new(
        id: i64,
        event_type: String,
        aggregate_id: Uuid,
        payload: Value,
        created_at: OffsetDateTime,
    ) -> Self {
        Self {
            id,
            event_type,
            aggregate_id,
            payload,
            created_at,
        }
    }
}

/// 发件箱仓储端口。只读轮询 + 标记已发布,**不参与写事务**——写事务里的那一行由各 repo 写方法内部的
/// emit 助手在自己的事务上插入。
#[async_trait]
pub trait OutboxRepo: Send + Sync {
    /// 取最早的未发布记录(按 id 升序,FIFO),最多 `limit` 条(负数当 0)。
    async fn poll_unpublished(&self, limit: i64) -> Result<Vec<OutboxRecord>, IdmError>;

    /// 标记已发布(盖 published_at)。幂等(重复标记 / 标记不存在的 id 都 Ok)。
    async fn mark_published(&self, ids: &[i64]) -> Result<(), IdmError>;

    /// **非事务** emit(auth 审计事件用):不挂任何领域写事务,单条 insert 到 outbox。
    /// 与仓储内部"领域写 + 事件同事务"的 emit 互补 —— 本方法给"无领域写的纯审计事件"(登录成功 / 失败 /
    /// 登出…),由消费方(app handler)在 HTTP 边界调用。
    async fn emit(
        &self,
        event_type: &str,
        aggregate_id: Uuid,
        payload: Value,
    ) -> Result<(), IdmError>;
}

/// 转发实现:`Arc<dyn OutboxRepo>` / `Arc<具体仓储>` 也是 `OutboxRepo`。
#[async_trait]
impl<T: OutboxRepo + ?Sized> OutboxRepo for Arc<T> {
    async fn poll_unpublished(&self, limit: i64) -> Result<Vec<OutboxRecord>, IdmError> {
        (**self).poll_unpublished(limit).await
    }

    async fn mark_published(&self, ids: &[i64]) -> Result<(), IdmError> {
        (**self).mark_published(ids).await
    }

    async fn emit(
        &self,
        event_type: &str,
        aggregate_id: Uuid,
        payload: Value,
    ) -> Result<(), IdmError> {
        (**self).emit(event_type, aggregate_id, payload).await
    }
}

/// 转发实现:同 `Arc<T>`,给独占所有权的 `Box<dyn OutboxRepo>` / `Box<具体实现>` 用。**每个方法都转发**。
#[async_trait]
impl<T: OutboxRepo + ?Sized> OutboxRepo for Box<T> {
    async fn poll_unpublished(&self, limit: i64) -> Result<Vec<OutboxRecord>, IdmError> {
        (**self).poll_unpublished(limit).await
    }

    async fn mark_published(&self, ids: &[i64]) -> Result<(), IdmError> {
        (**self).mark_published(ids).await
    }

    async fn emit(
        &self,
        event_type: &str,
        aggregate_id: Uuid,
        payload: Value,
    ) -> Result<(), IdmError> {
        (**self).emit(event_type, aggregate_id, payload).await
    }
}
