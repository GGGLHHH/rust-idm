//! 时间端口(可拔插)。生产用系统时钟;测试注入固定时钟可**确定性**验证 token/会话过期、refresh
//! 轮换,无需 sleep 真实时间。解耦理由是**具体需求**(测试时间相关逻辑),不是"时间是外部的"。

use time::OffsetDateTime;

/// 当前时刻来源。service 经它取 now(签发 iat/exp、判会话是否活跃),不直接调 `OffsetDateTime::now_utc()`。
pub trait Clock: Send + Sync {
    fn now(&self) -> OffsetDateTime;
}

/// 生产实现:系统 UTC 时钟。
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}
