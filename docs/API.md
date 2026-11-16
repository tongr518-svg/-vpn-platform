# API 契约

本地开发地址：`http://localhost:8080`

客户端只允许 `localhost`、`127.0.0.1`、`::1` 和 Android 模拟器地址 `10.0.2.2` 在开发时使用 HTTP；远程 API 必须使用 HTTPS。通过校验的 API 地址会保存在设备本地安全存储中，并在恢复 JWT 会话前重新校验。

受保护接口使用以下请求头：

```http
Authorization: Bearer <JWT>
```

JWT 有效期为 12 小时。账号暂停或 `token_version` 变化后，旧 JWT 失效。请求体使用 JSON，最大 1 MiB；每个请求体必须恰好包含一个 JSON 值，未知字段和尾随内容会被拒绝。密码长度按 UTF-8 字节计算。

## 通用接口

| 方法 | 路径 | 权限 | 用途 |
|---|---|---|---|
| `GET` | `/healthz` | 无 | 检查 API 和数据库状态 |
| `POST` | `/v1/auth/register` | 有效邀请码 | 注册并返回用户及 JWT；邀请码额度与用户创建在同一事务中扣减 |
| `POST` | `/v1/auth/login` | 无 | 登录并返回用户及 JWT |
| `GET` | `/v1/me` | 登录用户 | 获取当前账号 |
| `POST` | `/v1/me/password` | 登录用户 | 修改密码；成功后旧 JWT 失效 |
| `POST` | `/v1/me/sessions/revoke` | 登录用户 | 撤销所有 JWT 会话；当前 JWT 也失效 |
| `GET` | `/v1/me/subscription` | 登录用户 | 查询当前有效订阅 |
| `GET` | `/v1/me/subscriptions` | 登录用户 | 查询自己的最近 100 条订阅历史 |

注册请求示例：

```json
{
  "email": "user@example.com",
  "password": "至少 12 字节的密码",
  "invite_code": "团队邀请口令"
}
```

注册和改密密码长度要求为 12–72 字节。修改密码请求字段为 `current_password` 和 `new_password`。登录、注册和改密接口按客户端 IP 限流；超过限制时返回 `429` 和 `Retry-After` 响应头。

注册成功返回 `201`，登录、当前账号和订阅查询成功返回 `200`；修改密码和撤销所有会话成功返回 `204`。撤销会话会递增 `token_version` 并记录审计，因此包括当前令牌在内的所有旧 JWT 都会失效，客户端需重新登录。没有当前有效订阅时，`/v1/me/subscription` 返回 `404`。订阅历史接口始终返回 `200`，没有记录时返回空数组；状态根据取消状态和有效期计算，可能为 `active`、`scheduled`、`expired` 或 `cancelled`。

## 设备接口

| 方法 | 路径 | 权限 | 用途 |
|---|---|---|---|
| `GET` | `/v1/devices` | 登录用户 | 列出自己的设备，包含自己的公钥 |
| `POST` | `/v1/devices` | 登录用户及有效订阅 | 注册设备；检查账号状态和套餐设备上限 |
| `PATCH` | `/v1/devices/{id}` | 设备所有者 | 重命名未撤销设备 |
| `DELETE` | `/v1/devices/{id}` | 设备所有者 | 撤销设备 |

注册设备请求示例：

```json
{
  "name": "我的电脑",
  "platform": "windows",
  "public_key": "<Base64 编码的 32 字节公钥>"
}
```

重命名请求体为 `{"name":"新名称"}`。支持的平台为 `android`、`ios`、`windows`、`macos`。私钥不得发送给 API。设备撤销目前只更新数据库登记状态，尚未同步到 VPN 节点或断开已建立的连接。

设备列表查询返回 `200`，设备注册返回 `201`，重命名返回 `200`，撤销返回 `204`。

## 管理员接口

以下接口均要求数据库中的账号角色为 `admin`，且账号状态为 `active`。

| 方法 | 路径 | 用途 |
|---|---|---|
| `GET` | `/v1/admin/users` | 查询最近用户（最多 500 条） |
| `PATCH` | `/v1/admin/users/{id}/status` | 暂停或恢复用户 |
| `GET` | `/v1/admin/plans` | 查询套餐 |
| `POST` | `/v1/admin/plans` | 创建套餐 |
| `PATCH` | `/v1/admin/plans/{id}/status` | 启用或停用套餐 |
| `POST` | `/v1/admin/users/{id}/subscriptions` | 手动开通订阅 |
| `GET` | `/v1/admin/subscriptions` | 查询最近订阅记录（最多 500 条） |
| `POST` | `/v1/admin/subscriptions/{id}/cancel` | 取消尚未过期且状态为 `active` 的订阅 |
| `GET` | `/v1/admin/audit-logs` | 查询最近操作审计记录（最多 500 条） |
| `GET` | `/v1/admin/invites` | 查询邀请码状态、使用次数和期限，不返回原码或哈希 |
| `POST` | `/v1/admin/invites` | 创建限次数、可选过期的邀请码；原码仅在创建响应中返回一次 |
| `DELETE` | `/v1/admin/invites/{id}` | 撤销邀请码并写入审计 |
| `GET` | `/v1/admin/users/{id}/devices` | 查看用户设备，不返回公钥 |
| `DELETE` | `/v1/admin/users/{id}/devices/{deviceID}` | 管理员撤销用户设备 |
| `PUT` | `/v1/admin/devices/{id}/assignment` | 将设备分配到请求体指定的节点 |
| `DELETE` | `/v1/admin/devices/{id}/assignment` | 解除设备当前节点分配，不撤销设备登记 |
| `GET` | `/v1/admin/nodes` | 查询节点元数据、管理状态、健康状态、容量和最近心跳，不返回凭据 |
| `POST` | `/v1/admin/nodes` | 新增节点；需提供隧道 IPv4 CIDR，节点凭据仅在响应中显示一次 |
| `PATCH` | `/v1/admin/nodes/{id}` | 更新节点名称、区域、容量或隧道 IPv4 CIDR |
| `PATCH` | `/v1/admin/nodes/{id}/status` | 设置 `active`、`maintenance` 或 `disabled` |
| `POST` | `/v1/admin/nodes/{id}/credentials/rotate` | 轮换节点凭据，旧凭据立即失效，新凭据只返回一次 |
| `DELETE` | `/v1/admin/nodes/{id}/credentials` | 撤销节点凭据 |
| `POST` | `/v1/admin/nodes/{id}/config-approvals` | 批准指定的当前有效 dry-run 候选版本并签发短期签名审批 |
| `POST` | `/v1/node/heartbeat` | 节点使用专属 Bearer 凭据上报健康状态 |
| `GET` | `/v1/node/config` | 节点凭据拉取本节点当前期望快照及版本 |
| `POST` | `/v1/node/config/dry-run` | 节点凭据提交已确认快照，服务端只校验并返回候选 peer 差异，不应用配置 |
| `GET` | `/v1/node/config/signing-key` | 节点凭据获取 Ed25519 公钥；Agent 必须使用部署时固定的公钥验证签名 |
| `GET` | `/v1/node/config/approval` | 获取当前节点、版本和候选摘要匹配的未过期审批包 |
| `POST` | `/v1/node/config/approval/verify` | Agent 提交本地验证过的审批包；服务端核验签名并一次性消费 nonce |
| `POST` | `/v1/node/config/ack` | 节点确认已应用的快照版本，请求体为 `{"version": 1}` |

用户状态请求体为 `{"status":"active"}` 或 `{"status":"suspended"}`；套餐启停请求体为 `{"active":true}` 或 `{"active":false}`。创建套餐字段为 `name`、`device_limit`、`concurrent_limit`、`data_limit_bytes`、`speed_limit_mbps`；流量和速度限制设为 `0` 表示不限。订阅开通字段为 `plan_id`、`starts_at`、`ends_at`，时间使用 RFC 3339 格式。

列表和状态更新成功返回 `200`（列表）或 `204`（更新）；节点、套餐、订阅和设备节点分配创建成功返回 `201`；设备节点解除分配、取消订阅及管理员撤销设备成功返回 `204`。

订阅列表会把数据库状态为 `active`、但 `ends_at` 已过期的记录显示为 `expired`，不会自动改写数据库状态。取消接口仅匹配 `status = 'active'` 且 `ends_at > NOW()` 的记录；不符合条件时返回 `409 subscription_not_active`。套餐的流量和速度限制目前只保存和展示，尚未通过节点执行。

操作审计记录包括管理员后台操作、用户修改密码，以及用户设备注册、重命名、撤销、节点分配和解除分配。设备操作记录操作者、动作和设备 ID，不记录设备公钥、密码或 JWT。

节点凭据由安全随机数生成，数据库只保存 SHA-256 哈希；创建和轮换响应会一次性返回明文凭据，列表和后续读取都不会再次返回。`status` 是管理员设置的管理状态（`active`、`maintenance`、`disabled`）；`health_status` 是依据 `last_heartbeat_at` 单独计算的健康状态，最近 90 秒内有心跳为 `online`，否则为 `offline`。因此心跳过期不会覆盖管理状态。`maintenance` 节点仍可上报心跳，`disabled` 节点的心跳会被拒绝；撤销或轮换凭据会立即使旧凭据失效。

节点列表中的 `assigned_device_count` 只统计未撤销设备。容量必须为 1 至 1,000,000；降低容量后若小于已分配设备数，更新返回 `409 node_capacity_below_assigned_devices`。节点需配置有效 IPv4 CIDR（`/8` 至 `/30`），网络地址、网关（网段首个主机地址）和广播地址保留；设备地址从后续可用主机地址中分配。管理员分配设备时，服务端会校验账号 active、设备未撤销、存在有效订阅、节点管理状态为 active，并在事务中锁定设备和节点后检查设备容量和地址池；无有效订阅返回 `403`，节点不可分配、容量已满或地址池耗尽返回 `409`。数据库唯一索引和节点行锁共同避免重复分配。同一设备最多有一个节点分配。分配、解除分配和审计日志在同一事务中提交；解除分配只删除分配关系，不撤销设备。

管理员用户设备列表会显示分配节点及管理/健康状态，不返回设备公钥。分配、解除分配和撤销已分配设备会在同一事务内递增节点期望配置版本并写入 outbox。节点列表显示期望版本、最后确认版本、待同步状态、最后同步时间和地址池已占/可用数量。

节点 Agent 可用节点专属 Bearer 凭据调用 `GET /v1/node/config`。响应只包含该节点当前分配的设备 ID、公钥、平台、隧道地址、网段、网关、分配时间和快照版本；不包含私钥、用户密码或 JWT。相同数据库状态下重复拉取返回相同版本和快照。应用快照后，Agent 调用确认接口；服务端只接受该节点已存在且不超前的版本，较旧版本不能回退已确认版本，重复确认相同版本安全。撤销或轮换节点凭据后，旧凭据无法拉取或确认。

Agent 可用 `POST /v1/node/config/dry-run` 提交 `{"confirmed_snapshot": <此前已确认的完整快照>}`。服务端确认基线版本等于当前已确认版本，再以当前期望快照作为候选输入进行纯元数据规划；响应包含 `added`、`changed`、`removed` peer 列表及地址池变化。验证失败返回 `422 dry_run_validation_failed`，不返回候选计划。相同版本、相同快照得到稳定结果；候选版本低于基线、快照结构/地址无效、地址冲突、仍含已撤销设备或同版本内容不一致都会被拒绝。计划只含设备 ID、公钥和地址等公开 peer 元数据，没有 WireGuard 私钥或可直接应用的配置文本。

管理员节点列表仅显示最近一次 dry-run 的基线/候选版本、差异计数、校验状态和错误摘要。dry-run 保存由 `vpn-platform-node-config-snapshot-v1` 规范化字节协议计算的 SHA-256 摘要；摘要不包含私钥。协议固定字段顺序、对网段/网关和设备公钥文本使用无填充 Base64URL、按设备 ID 排序，并将时间编码为 UTC RFC3339Nano；具体跨语言测试向量见 `internal/nodeprotocol/testdata/v1_vector.json`。

管理员可提交 `{"candidate_version": 3}` 到节点审批接口。服务端仅接受与节点当前期望版本、最近一次有效 dry-run 和重新读取的候选快照摘要一致的审批；成功后使用服务端 Ed25519 私钥签发 10 分钟有效的一次性审批包，并在同一事务写入管理员审计记录。相同审批请求在仍有效时幂等返回原审批；候选版本或摘要变化后，旧审批无法再被 Agent 获取或验证。签名内容绑定节点 ID、候选版本、快照摘要、签发/过期时间和随机 nonce。

Agent 应使用部署时固定的 Ed25519 公钥，在本地验证签名、目标节点 ID、当前 dry-run 版本和到期时间；`GET /v1/node/config/signing-key` 只便于查询公钥，不能作为未验证链路上的信任根。随后 Agent 可将审批包提交至 verify 接口；服务端再次核对签名、当前候选并原子消费 nonce，重复提交返回 `409 approval_replayed`。签名无效、版本/节点不符、候选已变化或审批过期均被拒绝。此流程只验证并消费审批，不应用配置；响应明确为 `applied: false`，后台没有配置应用按钮。服务端不会调用 `wg` 或连接节点配置接口。

### 只读 Node Agent

独立 Agent 位于 `cmd/node-agent`，一次运行只会依次请求 `GET /v1/node/config`、`GET /v1/node/config/approval`，在本机完成快照校验、摘要计算和 Ed25519 审批验证，再调用 `POST /v1/node/config/approval/verify` 消费一次性 nonce。Agent 不会调用 dry-run 写入接口、确认配置接口或任何配置应用接口，也没有 WireGuard 配置生成、隧道或流量转发代码。成功响应要求 `applied: false`；已消费 nonce 会以文件标记保存在本地状态目录中，POSIX 系统使用 `0700` 目录和 `0600` 文件权限，其他系统应由运维设置等效的本机 ACL。服务器端仍是 nonce 一次性消费的最终防线。

Agent 通过环境变量配置：`API_BASE_URL`、`NODE_ID`、`NODE_CREDENTIAL`、`APPROVAL_PUBLIC_KEY`（标准 Base64 Ed25519 公钥）和 `AGENT_STATE_DIR`。远程地址必须为 HTTPS；仅 loopback HTTP 可用于本机开发。节点凭据只从环境读取，不作为命令行参数。公钥必须通过受信任的运维渠道固定到 Agent 配置，不能在 Agent 启动时从控制面不经验证地下载。示例：

```powershell
$env:API_BASE_URL = "https://control.example.test"
$env:NODE_ID = "42"
$env:NODE_CREDENTIAL = "<节点专属凭据>"
$env:APPROVAL_PUBLIC_KEY = "<已核对并固定的 Ed25519 公钥 Base64>"
$env:AGENT_STATE_DIR = "C:\ProgramData\vpn-platform-agent\state"
go run ./cmd/node-agent
```

日志只输出节点 ID、版本、摘要和错误类别，不输出 Bearer 凭据、审批签名或私钥。审批签名 v1 覆盖 domain、节点 ID、候选版本、摘要、签发/到期 Unix 秒和 32 字节 nonce；审批最长有效 10 分钟。当前固定单一公钥，密钥轮换时应通过带 `key_id` 的受控公钥集合与重叠轮换窗口单独升级协议；签名私钥只留在控制面并放入受控密钥存储，`.env` 仅用于本地开发且不得提交。

共享协议包和 Agent 的 golden/integration 单元测试在 CI 中运行，CI 另行构建 Agent。切换规范化摘要后，旧的 dry-run 摘要和审批不会再匹配；部署新版本后应重新生成 dry-run 并重新审批。

解除分配或撤销设备后，对应地址会保持 `releasing` 并计入占用，直到 Agent 确认包含移除的配置版本；确认时服务端在事务中释放地址，之后才可复用。节点离线、同步失败或轮换凭据不会释放地址。变更节点 CIDR 需要先清空分配，并等待所有释放版本确认。迁移前创建的旧分配没有隧道地址；需在使用快照前解除并重新分配这些设备。此控制面仍不生成 WireGuard 配置、不建立隧道或转发用户流量。

该同步内容只是控制面设备元数据和公钥快照，不包含可直接启用的 WireGuard 配置，不建立 VPN 隧道或转发用户流量。

邀请码原码由安全随机数生成，数据库只保存 SHA-256 哈希。管理员创建后需立即复制保存，之后列表只显示额度、状态和过期时间。注册会锁定邀请码并在同一事务中创建用户、增加使用次数；邮箱冲突或其他失败会回滚，不消耗额度。邀请码状态为 `active`、`exhausted`、`expired` 或 `revoked`。首位管理员创建正式邀请码后，旧 `INVITE_CODE` 不再接受；旧口令仅在数据库还没有任何管理员时兼容。

套餐 `active = false` 表示停止新开通，不撤销已开通订阅。用户已有状态为 `active` 且处于有效期内的订阅仍可注册设备至订阅到期，设备数量上限继续生效；管理员开通新订阅时仍只能选择 active 套餐。

## 常见错误

错误响应使用 JSON，例如：

```json
{"error":"device_limit_reached"}
```

| 状态码 | 常见含义 |
|---|---|
| `400` | JSON 格式、字段或参数无效 |
| `401` | 未登录、JWT 无效、账号不可用、登录凭证错误，或修改密码时当前密码错误 |
| `403` | 权限不足、邀请口令无效、账号非 active，或缺少有效订阅 |
| `404` | 资源不存在、属于其他用户或已撤销；当前没有有效订阅时也会返回此状态 |
| `409` | 资源冲突，例如邮箱或公钥已注册、设备达到套餐上限、订阅时段重叠，或订阅不可取消 |
| `422` | dry-run 基线或候选快照校验失败；不会返回候选计划 |
| `429` | 请求超过 IP 限流额度；响应包含 `Retry-After` |
| `500` | 服务内部错误 |
| `503` | 数据库健康检查失败或服务端未配置候选签名密钥 |

错误码会随接口校验阶段而异；请以实际 handler 的响应为准，接口实现变化时同步更新本文档。

签名配置密钥由 `CONFIG_SIGNING_SECRET` 派生，须与 JWT 密钥分开设置并通过密钥管理方式保存。签名审批包仅含节点 ID、版本、候选摘要、期限、nonce 和签名；审计记录只含管理员、动作及审批 ID，不保存密钥材料。

当前 API 仍不应用 WireGuard 配置、不建立 VPN 隧道、不转发用户流量，也不处理支付。
