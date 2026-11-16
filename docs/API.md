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
| `POST` | `/v1/admin/nodes` | 新增节点；节点凭据仅在响应中显示一次 |
| `PATCH` | `/v1/admin/nodes/{id}` | 更新节点名称、区域或容量 |
| `PATCH` | `/v1/admin/nodes/{id}/status` | 设置 `active`、`maintenance` 或 `disabled` |
| `POST` | `/v1/admin/nodes/{id}/credentials/rotate` | 轮换节点凭据，旧凭据立即失效，新凭据只返回一次 |
| `DELETE` | `/v1/admin/nodes/{id}/credentials` | 撤销节点凭据 |
| `POST` | `/v1/node/heartbeat` | 节点使用专属 Bearer 凭据上报健康状态 |

用户状态请求体为 `{"status":"active"}` 或 `{"status":"suspended"}`；套餐启停请求体为 `{"active":true}` 或 `{"active":false}`。创建套餐字段为 `name`、`device_limit`、`concurrent_limit`、`data_limit_bytes`、`speed_limit_mbps`；流量和速度限制设为 `0` 表示不限。订阅开通字段为 `plan_id`、`starts_at`、`ends_at`，时间使用 RFC 3339 格式。

列表和状态更新成功返回 `200`（列表）或 `204`（更新）；节点、套餐、订阅和设备节点分配创建成功返回 `201`；设备节点解除分配、取消订阅及管理员撤销设备成功返回 `204`。

订阅列表会把数据库状态为 `active`、但 `ends_at` 已过期的记录显示为 `expired`，不会自动改写数据库状态。取消接口仅匹配 `status = 'active'` 且 `ends_at > NOW()` 的记录；不符合条件时返回 `409 subscription_not_active`。套餐的流量和速度限制目前只保存和展示，尚未通过节点执行。

操作审计记录包括管理员后台操作、用户修改密码，以及用户设备注册、重命名、撤销、节点分配和解除分配。设备操作记录操作者、动作和设备 ID，不记录设备公钥、密码或 JWT。

节点凭据由安全随机数生成，数据库只保存 SHA-256 哈希；创建和轮换响应会一次性返回明文凭据，列表和后续读取都不会再次返回。`status` 是管理员设置的管理状态（`active`、`maintenance`、`disabled`）；`health_status` 是依据 `last_heartbeat_at` 单独计算的健康状态，最近 90 秒内有心跳为 `online`，否则为 `offline`。因此心跳过期不会覆盖管理状态。`maintenance` 节点仍可上报心跳，`disabled` 节点的心跳会被拒绝；撤销或轮换凭据会立即使旧凭据失效。

节点列表中的 `assigned_device_count` 只统计未撤销设备。容量必须为 1 至 1,000,000；降低容量后若小于已分配设备数，更新返回 `409 node_capacity_below_assigned_devices`。管理员分配设备时，服务端会校验账号 active、设备未撤销、存在有效订阅、节点管理状态为 active，并在事务中锁定设备和节点后检查容量；无有效订阅返回 `403`，节点不可分配或容量已满返回 `409`。同一设备最多有一个节点分配。分配、解除分配和审计日志在同一事务中提交；解除分配只删除分配关系，不撤销设备。

管理员用户设备列表会显示分配节点及管理/健康状态，不返回设备公钥。节点分配目前只记录控制面关系，不生成 VPN 配置、不建立隧道或转发用户流量。

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
| `429` | 请求超过 IP 限流额度；响应包含 `Retry-After` |
| `500` | 服务内部错误 |
| `503` | `/healthz` 检查时数据库不可用 |

错误码会随接口校验阶段而异；请以实际 handler 的响应为准，接口实现变化时同步更新本文档。

当前 API 只管理账号、设备登记信息、套餐和订阅，不建立 VPN 隧道，也不处理支付。
