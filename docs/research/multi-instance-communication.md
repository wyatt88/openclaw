# Multi-Instance OpenClaw Communication — Research Notes

## 研究目标
探索两个或多个 OpenClaw Gateway 实例之间的通信机制，实现：
1. Agent-to-Agent 跨实例对话
2. 共享 Session/Context
3. 任务分发与协调
4. 统一的消息路由

## 现有代码中的相关机制

### 1. Gateway WS Protocol（已有，可复用）
`src/gateway/client.ts` + `src/gateway/call.ts`

OpenClaw 已经有完整的 WS RPC 客户端：
- `GatewayClient`: 连接到任意 Gateway 实例
- `callGateway()`: 向 Gateway 发送 RPC 请求
- 支持 Token/Password/Device Identity 认证
- 支持 TLS + Tailscale 远程连接

**洞察**: 一个 OpenClaw 实例已经可以作为 client 连接到另一个实例的 Gateway。
现有的 `gateway.mode: "remote"` + `gateway.remote.url` 正是这个场景。

### 2. Sessions Send（已有，单实例内）
`src/agents/tools/sessions-send-tool.ts`

Agent 可以通过 `sessions_send` 工具向其他 Session 发消息。
当前限制：仅限同一 Gateway 内的 Session 间通信。

**扩展方向**: 将 sessionKey 扩展为 `gateway-id:session-key` 格式，
支持跨实例路由。

### 3. OpenAI-Compatible HTTP API（已有）
`src/gateway/openai-http.ts` + `src/gateway/openresponses-http.ts`

Gateway 暴露了标准 OpenAI API：
- `POST /v1/chat/completions`（ChatCompletions）
- `POST /v1/responses`（OpenResponses）

**洞察**: 一个 OpenClaw 实例可以把另一个实例当作 "LLM Provider" 来调用。

### 4. Webhook System（已有，单向）
`src/gateway/server/plugins-http.ts` + `src/plugin-sdk/webhook-path.ts`

各 Channel 插件可以注册 HTTP webhook 端点。

**扩展方向**: 添加 Gateway-to-Gateway webhook，用于事件推送。

### 5. Bonjour/mDNS Discovery（已有）
`src/gateway/server-discovery-runtime.ts` + `src/infra/bonjour.js`

Gateway 启动时自动通过 mDNS 广播自己的存在。

**洞察**: 局域网内的多个 OpenClaw 实例已经可以互相发现。

### 6. Node Registry（已有）
`src/gateway/node-registry.ts`

管理连接到 Gateway 的 Node 设备（macOS/iOS/Android）。

**扩展方向**: 其他 Gateway 实例也可以作为 "Node" 注册。

### 7. Tailscale Integration（已有）
`src/gateway/server-tailscale.ts`

通过 Tailscale Serve/Funnel 暴露 Gateway。

**洞察**: Tailscale MagicDNS 为跨网络的多实例通信提供了天然的安全通道。

---

## 方案设计

### 方案 A: Gateway Federation（联邦模式）

```
┌──────────────┐       federation       ┌──────────────┐
│  Gateway A   │◄─────────────────────►│  Gateway B   │
│  (Ark)       │    WS + Auth Token     │  (Nova)      │
│  Agent: main │                        │  Agent: main │
└──────┬───────┘                        └──────┬───────┘
       │                                       │
  Telegram                                  Discord
  飞书                                      Slack
```

核心组件：
1. **Federation Registry**: 配置已知的对等 Gateway
2. **Federation Client**: 复用现有 `GatewayClient`，长连接
3. **Cross-Instance Session Router**: sessionKey 包含 gateway ID
4. **Event Bridge**: 跨实例事件转发

配置示例：
```yaml
federation:
  enabled: true
  instanceId: "ark-primary"
  peers:
    - id: "nova-secondary"
      url: "wss://nova.tailnet:18789"
      token: "..."
      capabilities: [sessions, tools, events]
```

### 方案 B: Hub-Spoke（中心辐射模式）

```
┌──────────────┐
│  Gateway Hub │ ← 中心路由器
│  (Router)    │
└──┬────┬────┬─┘
   │    │    │
   ▼    ▼    ▼
  GW-A GW-B GW-C  ← 专用实例（按渠道/任务分）
```

适合场景：
- 一个实例专跑 Telegram
- 一个实例专跑 Discord
- Hub 做统一路由和 Session 管理

### 方案 C: OpenAI API Bridge（最轻量）

```
Gateway A                    Gateway B
    │                            │
    │  POST /v1/chat/completions │
    └───────────────────────────►│
                                 │ Agent 处理
                                 │
    ◄────────────────────────────┘
         SSE stream response
```

不需要新协议，直接复用现有 HTTP API。
缺点：单向、无状态、无事件订阅。

---

## 推荐路径

**Phase 1: OpenAI API Bridge（1-2天）**
- Gateway A 的 Agent 通过 `web_fetch` 或自定义 tool 调用 Gateway B 的 `/v1/chat/completions`
- 最少代码改动，验证跨实例通信可行性

**Phase 2: Gateway Federation Client（1周）**
- 新增 `src/federation/` 模块
- 复用 `GatewayClient` 建立对等连接
- 实现 `federation.send(peerId, method, params)` RPC
- 扩展 `sessions_send` 支持跨实例目标

**Phase 3: Event Bridge + Shared Context（2周）**
- 跨实例事件订阅（新消息、Agent 完成等）
- 共享 Session transcript（通过 federation 同步）
- 协同工具执行（A 的 Agent 调用 B 的 Browser/Canvas）

---

## 需要改动的文件

### Phase 1 (最小改动)
- 新增: `src/agents/tools/gateway-bridge-tool.ts` — 跨 Gateway 调用工具
- 修改: `src/agents/pi-tools.ts` — 注册新工具

### Phase 2 (联邦客户端)
- 新增: `src/federation/client.ts` — 联邦连接管理
- 新增: `src/federation/registry.ts` — 对等 Gateway 注册
- 新增: `src/federation/types.ts` — 类型定义
- 修改: `src/config/types.ts` — federation 配置类型
- 修改: `src/config/zod-schema.ts` — federation 配置校验
- 修改: `src/gateway/server.impl.ts` — 启动 federation
- 修改: `src/agents/tools/sessions-send-tool.ts` — 支持跨实例

### Phase 3 (事件桥接)
- 新增: `src/federation/event-bridge.ts` — 事件转发
- 新增: `src/federation/context-sync.ts` — Context 同步
- 修改: `src/gateway/server-methods/chat.ts` — 联邦消息路由
- 修改: `src/infra/agent-events.ts` — 跨实例事件
