//! idm 服务的领域输入(纯数据:无 HTTP / 序列化 / 校验)。
//! HTTP 边界的反序列化 + 校验由消费方(app)做完,再 `.into()` 成这些结构传进 service。
//! 审计主体(created_by/updated_by)不在输入里 —— 由 service 方法的 `by: Option<String>` 参数单独传。

/// 注册输入。username 必填、唯一;email 可选;password 明文(service 负责 hash)。
#[derive(Debug)]
pub struct RegisterInput {
    pub username: String,
    pub email: Option<String>,
    pub password: String,
}

/// 登录输入。`identifier` = username 或 email,由 service 自动识别。
#[derive(Debug)]
pub struct LoginInput {
    pub identifier: String,
    pub password: String,
}

/// **全量更新**当前用户(PUT 语义)。username 必填;email 给值=设置、给 `None`=清空。
#[derive(Debug)]
pub struct UpdateMeInput {
    pub username: String,
    pub email: Option<String>,
}

/// 改密输入。
#[derive(Debug)]
pub struct ChangePasswordInput {
    pub current_password: String,
    pub new_password: String,
}
