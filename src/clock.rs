//! 时间端口(可拔插)。生产用系统时钟;测试注入固定时钟可**确定性**验证 token / 会话过期、refresh
//! 轮换,无需 sleep 真实时间。解耦理由是**具体需求**(测试时间相关逻辑),不是"时间是外部的"。

use std::sync::Arc;

use time::OffsetDateTime;

/// 当前时刻来源。service 经它取 now(签发 iat / exp、判会话是否活跃),不直接调
/// `OffsetDateTime::now_utc()`。
pub trait Clock: Send + Sync {
    /// 当前时刻(UTC)。
    fn now(&self) -> OffsetDateTime;
}

/// 转发实现:让 `Arc<dyn Clock>` / `Arc<具体时钟>` 也能直接注入(调用方要和别处共享同一个时钟时用)。
impl<C: Clock + ?Sized> Clock for Arc<C> {
    fn now(&self) -> OffsetDateTime {
        (**self).now()
    }
}

/// 转发实现:同 `Arc<C>`,给独占所有权的 `Box<dyn Clock>` / `Box<具体实现>` 用。**每个方法都转发**。
impl<C: Clock + ?Sized> Clock for Box<C> {
    fn now(&self) -> OffsetDateTime {
        (**self).now()
    }
}

/// 生产实现:系统 UTC 时钟。
#[derive(Clone, Copy, Debug, Default)]
#[allow(
    clippy::exhaustive_structs,
    reason = "单元结构体没有公开字段,不在指南「Apply #[non_exhaustive] to public structs with public \
              fields」的范围内"
)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}
