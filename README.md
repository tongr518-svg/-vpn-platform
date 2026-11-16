# VPN Platform 本地开发指南

本项目包含 PostgreSQL、Go 控制面 API、嵌入式 Web 管理后台和 Flutter 客户端源码。当前版本只管理账号、设备登记信息、套餐与订阅；**不建立 VPN 隧道、不接入节点或支付**。

API 和 PostgreSQL 端口只绑定到 `127.0.0.1`。这是本地开发配置，不要直接暴露到公网。

## 环境配置

需要 Docker Desktop（含 Docker Compose）。仓库提供 `.env.example`。如果还没有本地 `.env`，复制一份并替换为自己的随机值：

```powershell
cd D:\vpn-platform
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
```

`POSTGRES_PASSWORD` 建议使用 URL 安全字符；如果含有 URL 特殊字符，需要在数据库连接 URL 中编码。`JWT_SECRET` 至少 32 个字符。不要提交 `.env`。

## 启动和停止

```powershell
# 确认 Docker Desktop 已启动
docker version

# 启动本地 API 和数据库
docker compose up --build -d

# 查看容器状态
docker compose ps

# 查看最近 100 行 API 日志
docker compose logs --tail=100 api

# 健康检查
Invoke-RestMethod http://localhost:8080/healthz

# 停止服务，保留数据库数据
docker compose down

# 停止并删除本地数据库卷（会删除数据）
docker compose down -v
```

正常时，`docker compose ps` 中 `db` 和 `api` 应为 `healthy`，健康检查应返回：

```json
{"status":"ok"}
```

如果 `/healthz` 超时，先检查 `docker compose ps` 中 API 和数据库容器的状态，再查看 `docker compose logs --tail=100 api`。Docker Desktop 未启动、镜像仍在构建或 API 容器未启动时，本机 `localhost:8080` 没有服务响应属于预期；单次本机超时不能说明健康检查接口本身有问题。

API 启动时会按文件名顺序执行 `cmd/api/migrations/` 中尚未应用的迁移，并在 `schema_migrations` 中记录版本。`cmd/api/schema.sql` 保留为初始结构参考。管理后台地址：<http://localhost:8080/admin/>。

每个版本同时记录 SHA-256 校验和；已应用迁移文件若发生改变，启动会失败。已经应用的迁移文件不要修改；后续结构变更请新增零填充编号文件，例如 `0002_add_usage_index.sql`。对校验和功能启用前已经应用的迁移，首次启动会以当时的文件内容建立基线，无法识别此前已经发生过的修改。

## 首次管理员和常用流程

注册仍需邀请口令。口令来自本地 `.env` 中的 `INVITE_CODE`：

```powershell
$inviteCode = (Get-Content .env | Where-Object { $_ -match '^INVITE_CODE=' } | Select-Object -First 1) -replace '^INVITE_CODE=', ''
$registerBody = @{
  email = 'admin@example.test'
  password = 'replace-with-a-long-password'
  invite_code = $inviteCode
} | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri http://localhost:8080/v1/auth/register -ContentType 'application/json' -Body $registerBody
Remove-Variable inviteCode, registerBody
```

不要使用示例密码。注册管理员账号后，先确认 API 至少启动过一次并完成数据库迁移，然后在本机运行一次性初始化命令。它只在数据库还没有任何管理员时提升指定的 active 用户；角色变更、令牌版本递增和审计记录在同一事务中完成。已有管理员时命令会拒绝操作。

```powershell
cd D:\vpn-platform
$env:DATABASE_URL = "postgres://vpn:URL编码后的数据库密码@localhost:5432/vpn?sslmode=disable"
go run .\cmd\admin-bootstrap -email "admin@example.test"
Remove-Item Env:DATABASE_URL
```

这是本机运维命令，不会新增公开提权接口。不要把 `DATABASE_URL` 或数据库密码写入仓库、提交到 Git，或贴到日志中；密码含 URL 特殊字符时必须先编码。后续管理员在后台管理。打开管理后台并用该账号登录，可创建套餐、给有效用户开通订阅、查看并取消订阅、管理用户状态和设备，并在“操作审计记录”中查看已记录的管理员操作、用户改密和设备操作。设备审计只记录操作者、动作和设备 ID，不记录密钥。审计日志不会补齐该功能启用前的历史操作。普通客户端使用登录返回的 JWT 查看账号、订阅与自己的设备。

管理员也可在后台创建限次数、可选过期的邀请码。原码只在创建响应中显示一次，数据库仅存 SHA-256 哈希；请立即复制保存。旧 `INVITE_CODE` 仅在数据库尚无管理员时作为升级兼容口令，首位管理员创建正式邀请码后即不再有效。

## 手动验证清单

按此顺序验证关键路径：

1. `docker compose ps` 确认 API 和 PostgreSQL 均为 `healthy`；调用 `/healthz` 确认返回 `{"status":"ok"}`。
2. 使用 `.env` 中的邀请口令注册普通账号并登录。
3. 在管理后台创建一个设备上限为 1 的套餐，并为普通用户开通当前有效订阅。
4. 暂停该用户；确认其不能重新登录，已有 JWT 访问 `/v1/me` 和设备接口也会被拒绝。恢复账号后，旧 JWT 仍应无效，用户需重新登录。
5. 有有效订阅时注册一台设备应成功；再注册第二台应返回 `device_limit_reached`。撤销第一台后，设备列表会保留撤销状态，套餐名额可以重新使用。
6. 取消订阅后，`/v1/me/subscription` 不再返回有效订阅，设备注册应返回 `active_subscription_required`。

注册和登录接口分别为 `POST /v1/auth/register`、`POST /v1/auth/login`。受保护接口使用 `Authorization: Bearer <token>`。完整路由、权限、请求字段和常见错误码见 [`docs/API.md`](docs/API.md)；业务处理位于 `cmd/api/`。

## 集成测试

集成测试使用独立的 PostgreSQL **数据库** `vpn_test`，并在其中为每个测试创建、删除随机 schema。不要把开发数据库 `vpn` 配置为 `TEST_DATABASE_URL`。

先启动 PostgreSQL，再在容器中创建专用测试数据库（只需创建一次）：

```powershell
docker compose up -d db
docker compose exec db sh -c 'PGPASSWORD="$POSTGRES_PASSWORD" createdb -U vpn vpn_test'
```

安装 Go 后，在宿主机运行：

```powershell
cd D:\vpn-platform
$pgPassword = (Get-Content .env | Where-Object { $_ -match '^POSTGRES_PASSWORD=' } | Select-Object -First 1) -replace '^POSTGRES_PASSWORD=', ''
$env:TEST_DATABASE_URL = "postgres://vpn:${pgPassword}@localhost:5432/vpn_test?sslmode=disable"
go mod tidy
go test ./...
Remove-Item Env:TEST_DATABASE_URL
Remove-Variable pgPassword
```

未设置 `TEST_DATABASE_URL` 时，PostgreSQL 集成测试会跳过。Dockerfile 构建阶段生成的 `go.sum` 不会写回宿主机；安装 Go 后运行 `go mod tidy`，并将生成的 `go.sum` 纳入版本管理。

## 当前限制

- 本地开发配置没有 HTTPS、正式密钥管理、数据库备份或公网部署加固。
- 登录按 IP 初始允许 5 次、每分钟补充 5 次；注册初始允许 3 次、每分钟补充 3 次。限流器保存在单进程内存中，重启会重置，多实例部署不能依赖它作为生产级防护。
- 套餐的并发、流量和速度限制目前只记录，不实际执行。
- 设备撤销只更新数据库；节点同步和已连接隧道的断开尚未实现。
- Flutter 客户端尚未完成各平台构建、安全存储验证或 VPN 隧道接入。
- 支付尚未实现。
