//! 列表分页:请求([`ListPage`])、结果([`ListResult`])、排序方向([`SortDirection`])。

use uuid::Uuid;

/// 排序方向。
#[derive(Clone, Copy, Debug, PartialEq)]
#[allow(
    clippy::exhaustive_enums,
    reason = "指南「Apply #[non_exhaustive] to publicly-exposed enums」例外:两态(升 / 降序),描述既有本体"
)]
pub enum SortDirection {
    /// 升序。
    Ascending,
    /// 降序。
    Descending,
}

/// 分页模式。`Offset` = 经典页 + 可选总数;`Cursor` = id keyset(v7 全序,默认 created desc 用)。
#[derive(Clone, Copy, Debug, PartialEq)]
#[non_exhaustive]
pub enum ListPage {
    /// 跳过 `offset` 行取 `limit` 行;`with_total` 时另查一次总数。
    Offset {
        /// 跳过的行数。
        offset: u64,
        /// 本页最多几行。
        limit: u64,
        /// 是否返回总数(多一次 COUNT 查询)。
        with_total: bool,
    },
    /// 从游标 `after`(上一页最后一行的 id,`None` = 第一页)往后取 `limit` 行。
    Cursor {
        /// 上一页最后一行的 id。
        after: Option<Uuid>,
        /// 本页最多几行。
        limit: u64,
    },
}

/// 分页结果。`total` 仅 `Offset { with_total: true }` 时 `Some`;`next_after` 仅 `Cursor` 且还有下一页时
/// `Some`(下一页游标)。
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct ListResult<T> {
    /// 本页的行。
    pub rows: Vec<T>,
    /// 总数(只在要了总数的 offset 分页时有)。
    pub total: Option<u64>,
    /// 下一页游标(只在还有下一页的 cursor 分页时有)。
    pub next_after: Option<Uuid>,
}

impl<T> ListResult<T> {
    /// 由各部分组装结果(给自己实现仓储端口的调用方用)。
    #[must_use]
    pub fn new(rows: Vec<T>, total: Option<u64>, next_after: Option<Uuid>) -> Self {
        Self {
            rows,
            total,
            next_after,
        }
    }

    /// cursor 分页收尾:`rows` 已按 key 升序(或调用方要的方向)排好,且多取了一条(limit + 1)判下一页。
    pub(crate) fn from_cursor_rows(mut rows: Vec<T>, limit: u64, key: impl Fn(&T) -> Uuid) -> Self {
        let has_more = rows.len() as u64 > limit;
        rows.truncate(limit as usize);
        let next_after = if has_more {
            rows.last().map(&key)
        } else {
            None
        };
        Self::new(rows, None, next_after)
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::ListResult;

    #[test]
    fn cursor_rows_trim_extra_row_and_report_next_cursor() {
        let ids: Vec<Uuid> = (1..=3).map(Uuid::from_u128).collect();
        let page = ListResult::from_cursor_rows(ids.clone(), 2, |id| *id);
        assert_eq!(page.rows, ids[..2].to_vec());
        assert_eq!(page.next_after, Some(ids[1]));
        assert_eq!(page.total, None);

        let last = ListResult::from_cursor_rows(ids[..2].to_vec(), 2, |id| *id);
        assert_eq!(last.next_after, None, "没多取到 → 没有下一页");
    }
}
