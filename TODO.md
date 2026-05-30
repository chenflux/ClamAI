# ClamAI 500+ 用户 Token 中转站改造计划

## 目标
将 ClamAI 从单用户/小团队安全审计代理改造为面向 500+ 用户的 Token 中转站，保持 SQLite 默认存储但确保切换 PostgreSQL 简便。

## 改造原则
- 不引入 Redis 等外部依赖
- SQL 保持通用（SQLite/PostgreSQL 兼容）
- 改造分 P0（性能瓶颈）、P1（核心功能）、P2（运营功能）三级

---

## P0 — 性能瓶颈（不改扛不住 500 人）

### P0-1 流式转发改造
- **文件**: `handlers_proxy.go`
- **现状**: `io.ReadAll(LimitReader(resp.Body, 50MB))` 全量缓冲再转发，内存爆炸且客户端收不到 streaming
- **方案**: 检测 `stream: true` 时走 `io.Copy` 流式透传，从 SSE chunk 中提取 token usage；非流式才全量读取

### P0-2 异步日志写入
- **文件**: `db_stats.go`, `middleware.go`, `handlers_proxy.go`
- **现状**: 每个请求同步 `dbInsertLog`，阻塞响应返回
- **方案**: 新建 `logWriter` goroutine，通过 channel 接收日志条目，批量 INSERT（攒 100 条或 2 秒刷一次）

### P0-3 锁优化
- **文件**: `types.go`, `middleware.go`, `ratelimit.go`
- **现状**: `apiKeysMu` 写锁每请求抢（仅 `RequestCount++`）；`stats.mu` 全局互斥；`RateLimiterManager.mu` 是 Mutex
- **方案**: 计数器改 `atomic.Int64`；`stats` 改 channel 聚合；`RateLimiterManager.mu` 改 `sync.RWMutex`

### P0-4 请求体单次读取
- **文件**: `ratelimit.go`, `security.go`, `middleware.go`, `handlers_proxy.go`
- **现状**: body 被 4 个中间件各读一遍（rateLimit → security → tracking → proxy），CPU/内存 4x
- **方案**: 最早的中件件读一次 body，存入 `r.Context()`，后续中间件从 context 取

### P0-5 上游凭证注入
- **文件**: `handlers_proxy.go`, `middleware.go`
- **现状**: `APIKeyInfo.ProviderKeys` 字段存在但从未接入代理路径，所有请求用全局 provider key
- **方案**: `handleTransparentProxy` 中如果请求来自动态 API Key，查 `info.ProviderKeys[providerName]` 覆盖全局 key

### P0-6 SQLite 连接池 + 统计批量持久化
- **文件**: `gorm_init.go`, `db_stats.go`
- **现状**: `MaxOpenConns=10`；`dbSaveStats` 逐行 upsert 90+ 次/10s
- **方案**: 连接池提升 25-50；`dbSaveStats` 用事务批量写入；日志清理改 `WHERE timestamp < ?`

---

## P1 — 核心功能（中转站必备）

### P1-1 Token 配额系统
- **新表**: `user_quotas`（user_id, period, input_limit, output_limit, input_used, output_used, reset_at）
- **后端**: 配额检查中间件 + 异步扣减 + 管理员 CRUD API
- **前端**: 用户管理页增加配额配置；用户面板显示余额

### P1-2 成本定价模型
- **新表**: `model_pricing`（model_name, provider, input_price_per_1k, output_price_per_1k）
- **后端**: 定价 CRUD API + 请求日志关联成本字段
- **前端**: 管理员定价配置页

### P1-3 速率限制增强
- **文件**: `ratelimit.go`
- **新增**: `UserRPM`（按用户限速）、`UserTPM`（每分钟 token 数）
- **优化**: 防止单用户多 Key 绕限

### P1-4 日志保留改造
- **文件**: `db_stats.go`
- **现状**: 硬编码保留 50000 条，500 用户几小时轮换完
- **方案**: 按天数保留（默认 30 天），可配置；`DELETE WHERE timestamp < ?` 替代 `NOT IN (subquery)`

---

## P2 — 运营功能（上线后迭代）

### P2-1 用户自助面板
- **新页面**: `UserDashboard.tsx` — 个人用量、额度余额、账单摘要、API Key 管理
- **后端**: 面板数据聚合 API

### P2-2 管理员账单页面
- **新页面**: `Billing.tsx` — 全局成本/收入/利润、按用户统计、按模型统计
- **后端**: 账单聚合 API + 导出功能

---

## 数据库兼容性原则
- 所有 SQL 通过 GORM 执行，不写原生 SQL（除 PRAGMA）
- 新表字段类型使用 GORM 通用类型（`string`/`int`/`float64`/`time.Time`）
- 避免使用 SQLite 特有语法（如 `strftime` 用 GORM 抽象替代）
- 批量操作用事务包裹

---

## 改动量估算

| 模块 | 后端 | 前端 | 优先级 |
|------|------|------|--------|
| P0 流式转发 | ~200 行 | 0 | P0 |
| P0 异步日志 | ~150 行 | 0 | P0 |
| P0 锁优化 | ~100 行 | 0 | P0 |
| P0 请求体单次读取 | ~80 行 | 0 | P0 |
| P0 上游凭证注入 | ~30 行 | ~50 行 | P0 |
| P0 SQLite 优化 | ~60 行 | 0 | P0 |
| P1 Token 配额 | ~150 行 | ~100 行 | P1 |
| P1 成本定价 | ~120 行 | ~150 行 | P1 |
| P1 速率限制增强 | ~80 行 | ~30 行 | P1 |
| P1 日志保留 | ~40 行 | ~20 行 | P1 |
| P2 用户面板 | ~60 行 | ~200 行 | P2 |
| P2 账单页面 | ~80 行 | ~200 行 | P2 |
| **合计** | **~1150 行** | **~750 行** | |
