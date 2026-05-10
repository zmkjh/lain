# Lain —— 设计文档

Lain 是一个零服务器、零配置的 P2P 网络基础设施，以 daemon 形式在终端设备上运行。

**理论基础**：见 `coverage-analysis.md` —— 在中国三大 ISP 异构 NAT 环境下，IPv6 + IPv4 STUN 打洞的组合覆盖率可达 97.8%。

---

## 1. 核心哲学

**节点是暂时的，连接是持续重建的。** Lain 面向没有固定公网 IP 的终端设备——手机、笔记本、台式机。IPv6 SLAAC 临时地址静默轮换、WiFi↔蜂窝切换、NAT 映射过期都是既定事实，设计上拥抱而非对抗。

- **PeerID 是永久的**：等于 `SHA256(Ed25519 公钥)`。只要密钥文件不丢，PeerID 在设备生命周期内不变。变化的只是网络地址。
- **网络是可重连资源的集合**：节点通过定期广播证明自己是活跃资源；长期不广播则自然淘汰。
- **Invite 码是初始寻址提示**：携带生成时刻的地址快照，接收方优先去 DHT 查找最新地址。
- **零配置启动**：daemon 不带任何参数就能运行，所有参数有内置默认值。

---

## 2. 技术选型

| 维度 | 选择 |
|------|------|
| 语言 | Rust (workspace) |
| 传输协议 | QUIC (UDP)，WebSocket over TCP 兜底 |
| 身份密钥 | Ed25519 |
| 握手 | Noise_IK (1-RTT)，高于 QUIC 层，端到端加密 |
| DHT | 基础 Kademlia，per-network 独立路由表 |
| NAT 穿透 | IPv6 直连 → STUN → Birthday Attack → TCP Simultaneous Open → WS → Relay |
| 网络准入 | Invite-only |

---

## 3. 架构全景

```
┌─────────────────────────────────────────────────────────────────┐
│                         lain daemon                             │
│                                                                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────────────┐  │
│  │ Identity │  │Discovery │  │   Node   │  │  Transport    │  │
│  │          │  │          │  │Lifecycle │  │               │  │
│  │ Ed25519  │  │ mDNS     │  │ LIVE     │  │ QUIC (直连)   │  │
│  │ Noise_IK │  │ Invite   │  │ STALE    │  │ Overlay relay │  │
│  │ PeerID   │  │ DHT      │  │ EXPIRED  │  │ WS fallback   │  │
│  └──────────┘  └──────────┘  └──────────┘  └───────────────┘  │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────┐    │
│  │ NAT Traversal│  │  Stream Mux  │  │     IPC API        │    │
│  │ STUN / IPv6  │  │ QUIC streams │  │ UDS (native 应用)  │    │
│  │ Birthday     │  │ QUIC datagram│  │ HTTP/WS (浏览器)   │    │
│  │ TSO / WS     │  │ Flow control │  │ 管控分离 + fd传递  │    │
│  └──────────────┘  └──────────────┘  └────────────────────┘    │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                    Kademlia DHT                           │   │
│  │  Heartbeat STORE (150s) + Emergency UPDATE + Lazy FIND   │   │
│  │  节点状态: LIVE → STALE → EXPIRED (基于相对 TTL)          │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3.5 并发模型

Daemon 采用 Tokio async runtime，以网络（network）为顶层调度单元。

### 任务层级

```
┌─ main task
│  ├─ IPC server task (UDS + HTTP)
│  ├─ per-network supervisor task
│  │   ├─ DHT task (UDP socket, RPC dispatch, bucket maintenance)
│  │   ├─ Discovery task (mDNS broadcast + listen, invite code gen/parse)
│  │   ├─ Heartbeat timer task
│  │   ├─ NAT probe task (on-demand)
│  │   └─ per-connection task (one per peer pair)
│  │       ├─ QUIC endpoint task
│  │       ├─ Noise handshake task (ephemeral)
│  │       ├─ Stream multiplex task (framed read/write)
│  │       └─ NAT traversal task (ephemeral, shared across connections)
│  ├─ WS fallback listener task (per-network, lazily spawned)
│  └─ Persistence flush timer
```

### 通信原语

| 组件间 | 机制 | 说明 |
|--------|------|------|
| IPC ↔ Supervisor | Tokio mpsc channel | 管理命令、连接请求 |
| Supervisor ↔ DHT | Tokio broadcast | 路由表变更、节点生命周期事件 |
| DHT ↔ QUIC endpoint | Arc + synchronization | 路由表为共享状态 |
| Connection tasks | Tokio oneshot / watch | 连接结果通知、状态同步 |
| Traversal ↔ Connection | Tokio mpsc | 穿透进度、端口列表更新 |

### 背压与流控

- 应用写入过快 → QUIC stream-level backpressure 逐跳传导到 IPC fd
- DHT RPC 过多 → 每 bucket 限速队列（max 10 pending RPCs per bucket）
- 连接建立并发 → 全局信号量（max_concurrent_connections = 32）

### 优雅关闭

1. SIGTERM / IPC shutdown 命令
2. 停止接受新连接
3. 向所有直连 peer 发送 CLOSE 帧
4. 序列化路由表 → `routes.bin`
5. 序列化 peers 列表 → `peers.json`
6. 关闭所有 QUIC connection（drain，超时 5s）
7. 退出进程

---

## 4. 身份与安全

### 4.1 PeerID

```
PeerID = SHA256(Ed25519_PublicKey)   // 256-bit，设备级永久身份
```

PeerID 同时作为 Kademlia DHT 的 node key。密钥对持久化在 `~/.lain/identity.json`，不丢则 ID 不变。

### 4.2 Noise_IK 握手

- **模式**: `Noise_IK_25519_ChaChaPoly_BLAKE2s`
- **角色**: Initiator 必须预先知道 Responder 的公钥（通过 invite code 获取）
- **RTT**: 1-RTT
- **位置**: 运行在 QUIC connection 之上。QUIC 提供传输加密（hop-by-hop），Noise 提供端到端身份认证（hop-to-hop）。Relay 节点无法解密 Noise 加密的 payload。

**设计权衡**：直连场景下 QUIC TLS 1.3 已提供传输加密，Noise_IK 叠加导致双重加密开销。保留此设计的原因：① Noise 层将 PeerID 与 Ed25519 密钥绑定，QUIC 层对应用层身份无感知，统一路径避免了直连/relay 分叉带来的代码复杂度；② 握手仅一次，后续对称加密（ChaChaPoly）开销可忽略。未来可在 QUIC 连接握手成功后协商关闭 Noise 层加密，仅保留身份帧。

**角色协调**：双方互换 invite 后都知道对方公钥，存在同时以 Initiator 身份发起 IK 的冲突。解法：**PeerID 小的一方为 Initiator，大的为 Responder**。PeerID 确定性可由双方独立计算，无需协商。

```
Initiator (PeerID 小)              Responder (PeerID 大)
  │  <- (s) 已知 Responder 公钥       │
  │  e, es, s, ss                    │
  │ ───────────────────────────────> │
  │  <- (encrypted) e, ee, se       │
  │ <─────────────────────────────── │
  │  (encrypted payload)             │
  │ ───────────────────────────────> │
```

### 4.3 Network 隔离

每个 overlay 网络有唯一的 `network_secret` (32 bytes)。`NetworkID = SHA256(network_secret)`。NetworkID 嵌入 Noise 握手和 DHT RPC，不同网络的流量、路由表、节点发现完全隔离。

---

## 5. 发现与邀请

### 5.1 发现路径

```
优先级:  mDNS (局域网) → Invite Code (广域网) → DHT lookup → Overlay relay
```

- **mDNS**: LAN 内广播 `_lain._udp.local`，TXT record 含 PeerID + 端口
- **Invite Code**: 用户通过 out-of-band 渠道交换（复制粘贴、QR、`lain://` 链接）
- **DHT lookup**: 解析 invite 后去 DHT `FIND_VALUE(peer_id)` 获取最新广播的地址（比 invite 中的快照更新鲜）

### 5.2 Invite 码结构

```
Invite = {
  version:      u8            // 协议版本 (当前 = 1)
  peer_id:      [u8; 32]     // SHA256(ed25519_pubkey)
  ed25519_pk:   [u8; 32]     // Ed25519 公钥
  network_id:   [u8; 32]     // SHA256(network_secret)

  capabilities: u8            // bitmask
    // bit 0: ipv6_available
    // bit 1: ipv6_inbound_open
    // bit 2-3: ipv4_nat_type (00=Cone, 01=S_ADF, 10=S_APDF)
    // bit 4: websocket_fallback
    // bit 5: relay_capable

  mappable_port_start: u16
  mappable_port_end:   u16
  port_delta_hint:     u8

  endpoints: [
    { addr, kind: IPv6|STUN|LAN|WS, priority, ttl_seconds }
  ]

  timestamp:   u64
  signature:   [u8; 64]     // Ed25519 over all above
}
```

编码：Compact Binary → Base62，约 300-400 字符。地址列表中的 TTL 由生成方根据 NAT 类型动态设定（Cone STUN ~120s，Symmetric ~30s，IPv6 ~300s）。

### 5.3 使用流程

1. A 生成 Invite 码（包含当前时刻的网络快照）
2. A 通过 out-of-band 渠道分享给 B
3. B 解析 → 获取 PeerID、公钥、能力声明、地址提示
4. B 用 invite 中的地址尝试直连 → 失败则 DHT `FIND_VALUE(peer_id)` 找新地址 → 还失败则节点可能离线
5. B 反向生成自己的 Invite 码发给 A
6. 双方完成 Noise_IK，建立对等连接

Invite 码是**初始寻址提示**，不是永久地址。成功连过一次之后，双方 daemon 记住了 PeerID，后续重连自动走 DHT，不需要再次交换 invite。

---

## 6. NAT 穿透

### 6.1 NAT 类型探测

启动时执行 RFC 5780 简化探测：

1. 向 STUN server A 发送两次 Binding Request：一次正常，一次带 CHANGE-REQUEST（要求服务器从不同 IP 回包）
2. 向 STUN server B 发送一次 Binding Request（交叉验证 CGNAT 多 IP 出口）
3. 对 A 的两次响应比较 mapped address：

| A 返回结果 | B 返回结果 | 判断 |
|-----------|-----------|------|
| 两次相同 IP+Port | 与 A 相同 IP+Port | EIM → Cone |
| 两次相同 IP+Port | 与 A 不同 IP | 多 IP CGNAT → 需进一步确认，默认按 Symmetric 处理 |
| 两次相同 IP，不同 Port | — | EDM → Symmetric → 进一步测 ADF vs APDF |

进一步区分 ADF vs APDF：从第二个 STUN server 的备用 IP 向本地 mapped address 发包，检测是否可达。可达为 ADF，不可达为 APDF。

结果缓存到 `~/.lain/cache/nat_type.json`，仅网络接口变更时重新探测。

### 6.2 穿透降级链

```
Step 1: IPv6 直连
  ─ 条件: 至少一方有 IPv6 inbound
  ─ 发起方主动向对方 IPv6 地址发起 QUIC connection

Step 2: UDP STUN 打洞 + Birthday Attack (并行)
  ─ 双方通过 STUN 获取映射地址
  ─ 基本打洞: 同时发送 UDP probe
  ─ 成功条件: 至少一方是 Cone NAT
  ─ 若基本打洞失败，并行执行 Birthday Attack

  Birthday Attack 子步骤:
  ─ 渐进式打开额外端口: 1 → 16 → 64 → 256
  ─ K×K 探测矩阵（K 为当前等级端口数）
  ─ 信令通道: 端口列表通过 invite 通道初次交换；后续等级放大所需的新端口列表通过 STUN server 间接通道传递（双方持续向 STUN 发送端口通告，STUN 作为临时信令中转），或通过已有的 relay 连接传递（若 Step 0 relay 已建立）
  ─ 所有探测包为裸 UDP 帧（不使用 QUIC），探测成功后端口对用于后续 QUIC 连接建立

Step 3: TCP Simultaneous Open
  ─ 双方同时向对方发起 TCP connect
  ─ 5 秒时间窗口（可用 relay 做精确时钟同步）
  ─ 利用 SO_REUSEADDR 和 SYN 碰撞

Step 4: WebSocket over TCP 443
  ─ 需一方可监听 TCP 入站 + 另一方出站 TCP 443
  ─ HTTP Upgrade → WebSocket → Noise_IK → Lain Frames
  ─ 适用场景: 企业防火墙封 UDP 只放 TCP 443

Step 5: Overlay Relay
  ─ 通过中继发现机制找到中间 relay 节点（见 §7）
  ─ 噪声端到端加密，relay 不可见明文

附加策略：Hairpin NAT 检测
  ─ 若双方 STUN mapped address 的 IP 相同，判定为同 NAT 后节点
  ─ 跳过公网地址直连尝试，优先使用 invite 中的 LAN endpoint 或 mDNS 发现的局域网地址直连
  ─ LAN 不可达时回退到 relay

穿透策略执行模型：不严格串行。Step 1-5 按优先级启动，上层步骤的尝试与下层步骤并行进行。首个成功的连接被采用，其余尝试取消。整个流程受 traversal_timeout (30s) 全局约束。
```

### 6.3 硬边界

| Peer A | Peer B | 直连 | 兜底 |
|--------|--------|------|------|
| S_APDF | S_APDF | ❌ | IPv6 或 relay |
| S_APDF | S_ADF | ❌ | IPv6 或 relay |

其他所有 NAT 组合均可直连（详见 `coverage-analysis.md` 第 4 章证明）。

### 6.4 WebSocket Fallback

#### 角色决策

通过 invite 阶段交换的能力声明决定谁监听、谁连接：

```
self_can_listen = (nat_type == Cone) || ipv6_inbound_open
peer_can_listen = (nat_type == Cone) || peer_ipv6_inbound_open

if peer_can_listen → 对方监听，我方连接
else if self_can_listen → 我方监听，对方连接
else → WS fallback 不可用，跳过
```

#### 握手流程

```
Listener                              Connector
───────────────────────────────────────────────────
bind TCP socket, random port
发送 ws_endpoint 给对方 (via invite)
                                      TCP connect → ws_endpoint
                                      HTTP Upgrade: GET /lain
                                        Lain-PeerID: xxx
                                        Lain-Network: xxx
验证 PeerID 和 Network 匹配
发送 101 Switching Protocols
────────── WebSocket 建立 ──────────
Noise_IK 握手 (与 QUIC 路径相同)
Lain Frames (与 QUIC 路径相同帧格式)
```

#### WS 路径与 QUIC 路径对比

| 特性 | QUIC | WebSocket |
|------|------|-----------|
| NAT 穿透力 | 强 (UDP 打洞) | 弱 (需一方监听) |
| Datagram | 支持 | 不支持 (退化为可靠) |
| 连接迁移 | 原生支持 | 不支持 |
| 0-RTT | 支持 | 不支持 |
| 场景 | UDP 可达 | UDP 被封 |

---

## 7. Relay

### 7.1 三角色模型

Relay 不只是数据面兜底通道，而是有三种角色，按需切换：

**角色一：信令助手** — A 和 B 无法直连但都能连到 R。R 充当 TSO 的精确时钟源，协调双方同时发 TCP SYN。TSO 成功则 R 退出。

**角色二：临时数据桥** — 初始通过 relay 建立连接保证即时可用，背后持续尝试 IPv6 → STUN → Birthday Attack 直连。一旦直连建立即切换。

**角色三：稳定 Relay** — 直连确认不可行后承担长期数据转发。

### 7.2 Relay 发现、选举与路由

#### Relay 能力条件

```
relay_capable = (nat_type == Cone) || ipv6_inbound_open
```

满足条件的节点在心跳 STORE 中设置 `capabilities.relay_capable = 1`，自然进入 DHT 存储。其他节点通过 DHT 查询发现 relay 候选。

#### 两阶段发现

**阶段一（被动收集）**：每个节点在 DHT 路由表中标记所有 `relay_capable` 节点。随着路由表自然填充，候选池逐步积累。

**阶段二（主动查询）**：候选池为空或全部不可达时，执行 `FIND_VALUE(RelayCapabilityMarker)` 查询。`RelayCapabilityMarker = SHA256(network_secret || "relay")` 是一个约定好的魔术 key，所有 relay 节点在心跳 STORE 中同时 STORE 自己的 `peer_id` 到这个 key。FIND_VALUE 返回的 value 是当前在线的 relay PeerID 列表。

#### Relay 选路：为 A↔B 找到合适的中继

当 A 需要经由 relay 连接 B 时：

1. A 取自己的候选池与 B 的候选池（通过 DHT 查询 B 的 STORE record 获取 B 的已知 relay 列表）
2. 求交集 → 优先选双方都能直连的 relay（一跳 relay）
3. 交集为空 → A 从自己候选池中选一个 R，要求 R 能连到 B（R 通过 DHT FIND_VALUE 验证 B 可达）
4. 上述均失败 → 全局 RELAY_NEEDED 广播

选路度量（同分时）：延迟优先（RTT 最小）→ 带宽估计优先 → PeerID 排序决定。

#### 拓扑连接

每个直连 relay 节点维持一个 QUIC connection。节点与节点之间通过 relay 通信时，A → relay → B 的数据路径为：

```
A ──[A↔R QUIC]──> R ──[R↔B QUIC]──> B
```

端到端 Noise_IK 加密确保 R 不可解密 payload。R 仅做 QUIC stream-level 的转发。

#### Relay 下线与迁移

1. 检测到该 relay 的 QUIC 连接断开
2. 从候选池中选出下一个可用 relay，优先级: 一跳 relay > 两跳 relay
3. 所有 relay-dependent stream 自动迁移到新 relay
4. 候选池为空 → 触发阶段二主动查询 → 仍为空则 DHT 广播 RELAY_NEEDED 查询

网络中有 ≥1 个 relay 候选存活，relay 路径就不中断。

---

## 8. 节点生命周期

### 8.1 远程节点状态机

被追踪的远程节点状态：

```
  UNKNOWN ──收到 invite/FIND_VALUE──→ LIVE
  LIVE ──TTL 到期未更新──→ STALE ──STALE窗口到期──→ EXPIRED
  任意状态 ──收到新的广播/STORE──→ LIVE
  EXPIRED ──收到新的广播──→ LIVE

LIVE:    expires_at 未到期（本地时钟判断），可直接尝试直连
STALE:   仍可尝试连接但标记不可靠，FIND_VALUE 获取新地址
EXPIRED: 从 k-bucket 移除，DHT republish 不再包含
```

**TTL 默认 300s，STALE 窗口 3×TTL = 900s。**

### 8.2 本地 Daemon 状态

Daemon 自身的运行状态：

```
INIT
  │ 加载 identity、读持久化路由表
  ▼
NAT_PROBING
  │ 执行 RFC 5780 探测
  ▼
RUNNING
  │
  ├─ 有活跃网络 ──→ 心跳广播、DHT 维护、接受连接
  │
  ├─ 全部网络 dormant ──→ IDLE (只维持 IPC 监听)
  │
  └─ 收到 SIGTERM ──→ DRAINING → 序列化 → EXIT
```

### 8.3 网络级别状态

```
BOOTSTRAPPING
  │ 从 seeds/peers.json 开始，PING → FIND_NODE → 填充 bucket
  │ 超时 120s 仍无任何节点 → DEGRADED
  ▼
JOINED
  │ STORE self → 接收心跳 → 接受 peer 连接
  │
  ├─ 所有远程节点 EXPIRED ──→ DORMANT (停止 DHT 维护)
  │   └─ 收到新 invite 或应用触发 ──→ BOOTSTRAPPING
  │
  └─ DHT bootstrap 失败 ──→ DEGRADED (仅已连接的直连 peer 可用)
```

### 8.4 防时钟漂移

TTL 使用相对值而非绝对时间戳。发布方 STORE 时写入 `ttl_seconds = 300`，接收方用**自己的本地时钟**计算 `expires_at = now() + ttl_seconds`。整个状态机完全基于接收方时钟，不受双方时钟偏差影响。Invite 码 timestamp 防重放窗口放宽至 30 分钟覆盖极端漂移。

### 8.5 心跳

```
广播间隔 = max(ttl / 2, 60s)  // 默认 150s

每次广播:
  1. 获取本机所有接口地址 (IPv6 GUA、STUN 映射、LAN)
  2. STORE(self_peer_id, endpoints + ttl_seconds) 到 k-closest 邻居
  3. UPDATE_ENDPOINTS 到所有直连 peer
```

**紧急广播**：检测到 SLAAC 轮换或网络接口变更时立即触发，不等定时器。

### 8.6 清理

每 300s 遍历路由表：STALE/EXPIRED 标记 → EXPIRED 移除 → 全部 EXPIRED 则网络标记为 dormant（保留 network_secret，释放连接资源）。

**Dormant 状态**：停止心跳 STORE 和 bucket 刷新，保留路由表序列化文件。收到该网络的 invite 或应用层触发时，从持久化路由表恢复并重新 bootstrap。此机制确保节点加入多个网络时，长期无活动的网络不消耗后台流量和 CPU。

### 8.7 网络切换

检测到接口变更 → 全量重建：重新 NAT 探测 → 重新 STUN → 紧急 UPDATE DHT → 重建所有直连 → 失败的回退 relay。

---

## 9. Kademlia DHT

### 9.1 路由表

- NodeID = PeerID (256-bit)
- 距离 = XOR(a, b)
- 256 个 k-bucket，bucket i 覆盖 `[2^i, 2^(i+1))`
- k = 20，α = 3（并发度）
- Bucket 内按最近通信时间排序 (LRU)

### 9.2 Bucket 插入

```
insert_node(new):
    bucket = buckets[distance(self.id, new.id).log2()]
    if new in bucket → move_to_tail, return
    if bucket not full → push_tail, return
    if bucket contains self.id → split_bucket, retry
    else → PING(bucket.head)
        if PING ok → old moves to tail, new dropped
        else → old replaced by new
```

### 9.3 RPC 消息格式

原始 UDP，简洁二进制：

```
请求:   version(1) | message_id(16) | msg_type(1) | sender_id(32) | network_id(32) | payload | Ed25519签名(64)
响应:   version(1) | message_id(16) | msg_type|0x80 | sender_id(32) | network_id(32) | payload | Ed25519签名(64)
```

版本不匹配时，接收方回复错误码 `UNSUPPORTED_VERSION`，附带自身支持的版本号。双方取 min 版本进行后续通信。

| RPC | Payload | 响应 |
|-----|---------|------|
| PING | 空 | k-closest (node_id, addr)... |
| STORE | key(32) + ttl(4) + value | ok/error |
| FIND_VALUE | key(32) | value 或 k-closest 节点列表 |

超时 5s，重试 2 次。

**签名策略**：请求端对所有 RPC 请求签名（防篡改 + 防重放，timestamp 隐含在 message_id 中）。响应端仅对包含可验证数据 payload 的响应签名（如 FIND_VALUE 返回的 value / STORE 返回的 key 确认）。空 payload 响应（如 PING 的 k-closest 列表仅含路由信息、STORE 的 ok）使用 HMAC(network_secret, message) 快速认证，降低 CPU 开销。

### 9.4 Bootstrap

```
1. 从 invite code 获取 endpoint
2. PING → 加入路由表
3. FIND_NODE(self.id) → 填充路由表
4. 递归 FIND_NODE 填满 256 个 bucket
5. STORE 自身信息到 k-closest 邻居
```

### 9.5 Lookup

迭代式 FIND_NODE，α=3 并行。每轮将搜索空间减半，O(log N) 轮收敛。

### 9.6 STORE 与维护

心跳向 k=20 个最近节点 STORE。接收方每 3600s republish。超过 TTL 未被更新的 record 自然过期。路由表每 3600s 刷新一次所有 bucket。

---

## 9.7 线格式规范

以下定义所有网络消息的精确二进制编码。多字节整数统一采用**大端序（Big-Endian）**。

### 9.7.1 基本类型编码

```
VarInt (可变长度整数):
  ─ 采用 QUIC/HTTP3 风格 varint，高 2 bit 编码长度
  ─ 00xxxxxx:         1 字节 (值 0-63)
  ─ 01xxxxxx xxxxxxxx: 2 字节 (值 0-16383)
  ─ 10xxxxxx ...:      4 字节 (值 0-1073741823)
  ─ 11xxxxxx ...:      8 字节 (值 0-4611686018427387903)

Address:
  ─ kind:       u8     // 0=IPv4, 1=IPv6
  ─ ip:         [u8; 4] | [u8; 16]
  ─ port:       u16
  ─ priority:   u8     // 0=lowest, 255=highest

Endpoint:
  ─ addr:       Address
  ─ kind:       u8     // 0=IPv6, 1=STUN, 2=LAN, 3=WS, 4=Relay
  ─ ttl_seconds: u32

PeerID:    [u8; 32]   // SHA256 hash
NetworkID: [u8; 32]   // SHA256 hash
```

### 9.7.2 DHT RPC 消息格式

所有 DHT RPC 通过单个 UDP socket 发送。消息头统一 83 字节，后跟可变长 payload：

```
┌──────────────────────────────────────────────────────┐
│ offset │ size │ field          │ description          │
├────────┼──────┼────────────────┼──────────────────────┤
│ 0      │ 1    │ version        │ 协议版本 (1)          │
│ 1      │ 16   │ message_id     │ 随机，请求/响应对应    │
│ 17     │ 1    │ msg_type       │ bit7=0请求 bit7=1响应  │
│ 18     │ 32   │ sender_id      │ 发送方 PeerID          │
│ 50     │ 32   │ network_id     │ NetworkID              │
│ 82     │ 1    │ payload_len_hi │ payload 长度高字节     │
│ 83     │ 2    │ payload_len_lo │ payload 长度低 2 字节  │
│ 85     │ var  │ payload        │ 见各 RPC 定义          │
│ 85+len │ 64   │ signature      │ Ed25519 覆盖 0..payload_end │
│        │      │ (或 HMAC)      │ HMAC 用于无数据响应     │
└──────────────────────────────────────────────────────┘
```

**msg_type 定义：**

| 值 | 名称 | 签名方式 |
|----|------|---------|
| 0x00 | PING | 请求: Ed25519, 响应: HMAC |
| 0x01 | STORE | 请求: Ed25519, 响应: HMAC |
| 0x02 | FIND_VALUE | 请求: Ed25519, 响应: Ed25519 |
| 0x03 | FIND_NODE | 请求: Ed25519, 响应: HMAC |
| 0x04 | RELAY_NEEDED | 请求: Ed25519, 响应: HMAC |
| 0x05 | ERROR | HMAC |

**各 RPC payload 格式：**

```
PING 请求:
  (空 payload)

PING 响应:
  node_count: u8
  nodes: [ { node_id: [u8; 32], addr: Address }, ... ]   // k-closest

STORE 请求:
  key: [u8; 32]
  ttl:  u32               // 秒
  value_len: u16
  value: [u8; value_len]  // 序列化的 endpoint 列表

STORE 响应:
  status: u8              // 0=ok, 1=error
  (if error) error_code: u8

FIND_VALUE 请求:
  key: [u8; 32]

FIND_VALUE 响应:
  has_value: u8           // 1=有值, 0=返回 k-closest
  (if has_value)
    ttl_remaining: u32
    value_len: u16
    value: [u8; value_len]
  (if !has_value)
    node_count: u8
    nodes: [ { node_id: [u8; 32], addr: Address }, ... ]

FIND_NODE 请求:
  target_id: [u8; 32]

FIND_NODE 响应:
  node_count: u8
  nodes: [ { node_id: [u8; 32], addr: Address }, ... ]

RELAY_NEEDED 请求:
  target_peer_id: [u8; 32]

RELAY_NEEDED 响应:
  relay_count: u8
  relays: [ { node_id: [u8; 32], addr: Address }, ... ]

ERROR 响应:
  error_code: u8
  // 错误码: 1=UNSUPPORTED_VERSION, 2=INVALID_SIGNATURE
  //         3=MESSAGE_TOO_LARGE, 4=INTERNAL_ERROR
```

### 9.7.3 Noise IK 握手帧

Noise_IK 握手通过 QUIC stream ID 0（首个 stream）或 WebSocket binary message 承载。握手帧格式：

```
┌──────────────────────────────────────────┐
│ offset │ size  │ field                   │
├────────┼───────┼─────────────────────────┤
│ 0      │ 3     │ magic: 0x4C 0x41 0x49 ("LAI") │
│ 3      │ 1     │ version: 0x01          │
│ 4      │ 1     │ handshake_step:         │
│        │       │   0 = IK message 1 (initiator → responder) │
│        │       │   1 = IK message 2 (responder → initiator) │
│        │       │   2 = payload (initiator → responder)      │
│ 5      │ 32    │ network_id             │
│ 37     │ 3     │ payload_len (u24 BE)   │
│ 40     │ var   │ Noise message payload  │
└──────────────────────────────────────────┘
```

握手完成后，后续 QUIC stream 上的 Lain 帧直接由 Noise 的 CipherState 加解密，不再包含握手头。

### 9.7.4 Lain 帧格式

Noise 握手完成后，所有数据通过以下帧格式传输。帧嵌入 QUIC stream 或 WebSocket binary message：

```
┌──────────────────────────────────────────┐
│ offset │ size  │ field                   │
├────────┼───────┼─────────────────────────┤
│ 0      │ 3     │ magic: 0x4C 0x41 0x49   │
│ 3      │ var   │ stream_id (VarInt)      │
│        │ var   │ frame_type (VarInt)     │
│        │ var   │ frame_length (VarInt)   │
│        │ var   │ payload                 │
└──────────────────────────────────────────┘
```

**Frame Types:**

| 值 | 名称 | Payload | 说明 |
|----|------|---------|------|
| 0x00 | HEADERS | key_count: u16, [(key_len: u8, key, val_len: u16, val), ...] | 应用层元数据，连接建立后首帧必为 HEADERS |
| 0x01 | DATA | raw bytes | 应用数据 |
| 0x02 | DATA_DGRAM | raw bytes (max 1200) | 不可靠数据报（仅 QUIC Datagram，WS 路径不支持） |
| 0x03 | CLOSE | error_code: u32 | 优雅关闭 stream |
| 0x04 | PING | (空) | 应用层心跳 |
| 0x05 | PONG | ping_payload (echo) | 应用层心跳响应 |
| 0x06 | PATH_CHANGE | endpoint_list (同 STORE value 格式) | 通知对方自己的地址变更 |

**Stream ID 分配：**
- Stream 0: 保留给 Noise IK 握手
- Stream 1: 控制通道（HEADERS, PATH_CHANGE, PING/PONG, CLOSE）
- Stream 2+: 应用数据流（由应用通过 IPC API 创建）

### 9.7.5 QUIC Datagram 帧

不可靠传输使用 QUIC Datagram 扩展（RFC 9221），payload 承载 DATA_DGRAM 帧。同一 magic + frame 格式，但不带 stream_id：

```
magic(3) | 0x02 (frame_type varint) | len (varint) | payload
```

### 9.7.6 WebSocket 帧映射

WS binary message = 一个完整的 Lain 帧（含 magic），与 QUIC stream 上的帧格式一致。WS 路径不支持 DATA_DGRAM——收到该帧类型时丢弃并向上层报告。

---

## 10. 数据传输

### 10.1 QUIC 连接

- UDP 单端口（默认随机），所有 QUIC connection 复用
- 持久长连接，idle timeout 30s，keep-alive PING 15s
- 每 peer pair 一条 QUIC connection
- QUIC 原生 stream multiplex（可靠） + Datagram 扩展（不可靠）

### 10.2 NAT Rebinding

QUIC 通过 Connection ID 标识连接（非四元组），支持透明路径迁移。NAT 映射变更时：
- QUIC 自动 PATH_CHALLENGE / PATH_RESPONSE 验证新路径
- Lain 并行执行：重新 STUN 获取新地址 → Emergency UPDATE DHT → 通知所有 peer
- Keep-alive 15s 使 rebinding 罕见（续活 NAT 映射）
- Migration 失败时：DHT FIND_VALUE 获取新地址 → 重建连接

### 10.3 帧格式

HTTP/3 风格：

```
Stream ID (varint) | Frame Type (varint) | Frame Length (varint) | Payload

Frame Types:
  0x00 = HEADERS  [key_count: u16] [(key_len, key, val_len, val)...]
  0x01 = DATA     [raw bytes]
  0x02 = CLOSE    [error_code: u32]
  0x03 = PING     [empty]
```

### 10.4 流控

- 可靠流：QUIC stream flow control（connection-level + stream-level 背压）
- 不可靠流：QUIC Datagram 扩展（无重传，适合音视频帧）
- WS 路径不支持 Datagram，退化为可靠

### 10.5 端到端加密

```
上层应用数据
  → Noise_IK Encrypted (端到端，relay 不解密)
    → QUIC TLS 1.3 (逐跳)
      → UDP
```

---

## 10.6 连接生命周期

### 完整时序

```
A (PeerID 小 = Initiator)                           B (PeerID 大 = Responder)
─────────────────────────────────────────────────────────────────────────

[Phase 0: 发现]
  A 获取 B 的 invite / DHT FIND_VALUE(B) ─────────→ 获得 B 的 PeerID、公钥、endpoints

[Phase 1: 穿透]
  A 按优先级尝试 endpoints:
    IPv6 ──→ 失败
    STUN ──→ 双方 STUN → A 发送 probe → B 回复 probe → 成功 ✓
  
[Phase 2: QUIC 连接]
  A ──QUIC Initial──→ B (在打洞成功的 UDP 路径上)
  A ←──QUIC Handshake──→ B (TLS 1.3 完成)

[Phase 3: Noise IK]
  A ──IK msg 1 (e, es, s, ss)──→ B (A 已知 B 公钥)
  A ←──IK msg 2 (e, ee, se)──── B
  A ──IK payload────────────────→ B (Noise 握手完成，端到端加密建立)

[Phase 4: 连接确认]
  A ──HEADERS { version, capabilities }──→ B  (stream 1)
  A ←──HEADERS { version, capabilities }── B

[Phase 5: 应用数据]
  A ──DATA (stream 2+)──→ B
  A ←──DATA (stream 2+)─── B

[Phase 6: 关闭]
  A ──CLOSE──→ B  (应用层关闭)
  A ←──QUIC CONNECTION_CLOSE── B  (传输层拆卸)
```

### 穿透阶段状态机

```
IDLE
  │ start_connection(target)
  ▼
DNS_RESOLVING          (解析 STUN domain / 直连地址)
  │ 
  ▼
NAT_PROBING             (若需要: 自身 NAT 类型未缓存)
  │
  ▼
TRAVERSING
  ├─ IPv6_ATTEMPT       (若有 IPv6 地址)
  ├─ STUN_HOLE_PUNCH    (并行)
  ├─ BIRTHDAY_ATTACK    (并行, 若 STUN 初步探测失败)
  ├─ TCP_SIM_OPEN       (若 UDP 全部失败)
  ├─ WS_FALLBACK        (若 TCP 入站可行)
  └─ RELAY_CONNECT      (若已预连 relay)
  │
  ├─ 任一路径成功 ──→ CONNECTED
  ├─ 全部路径失败 ──→ FAILED
  └─ 超时 (traversal_timeout=30s) ──→ FAILED

CONNECTED
  │ connection_lost
  ▼
RECONNECTING            (重连, 跳过邀请, 直接从 DHT 获取 endpoint)
  │ 退避: 1s, 3s, 9s, 27s, 60s...(max 5min)
  │ 恢复 ──→ CONNECTED
  └─ peer EXPIRED ──→ CLOSED
```

### 重连策略

断线后自动重连：
1. 检测断线（QUIC idle timeout / 显式 CLOSE）
2. 通过 DHT FIND_VALUE 获取 peer 最新 endpoint（peer 可能已经换了 IP）
3. 重新执行穿透（跳过已确定的不可行路径，如对 S_APDF 跳过 STUN 打洞）
4. 成功 → 恢复所有 stream（应用层需自行处理 stream 恢复逻辑）
5. 失败 → 指数退避重试，最大间隔 5 分钟。peer EXPIRED 则放弃。

### 并发连接限制

- 全局最大 QUIC connection 数: 256
- 单 peer pair 一条 QUIC connection（通过 QUIC stream multiplex 承载多路流，不是多 connection）
- 穿透并发: 最多同时进行 8 个穿透尝试
- Relay stream 上限: 32（保护 relay 资源）

---

## 11. IPC 与应用接口

### 11.1 双绑定

| 绑定 | 地址 | 用途 |
|------|------|------|
| Unix Domain Socket | `~/.lain/socket` | Native CLI、守护进程 |
| HTTP/WebSocket | `127.0.0.1:随机端口` | 浏览器、跨语言客户端 |
| Named Pipe (Windows) | `\\.\pipe\lain` | Windows 本地客户端（替代 UDS） |

### 11.2 CLI 命令 (JSON-RPC over UDS)

每行一条完整 JSON（换行符分隔），格式：

```
→ {"id":1,"method":"status","params":{}}
← {"id":1,"result":{"peer_id":"abc...","nat_type":"Cone","uptime_secs":3600}}
```

| method | params | result | 说明 |
|--------|--------|--------|------|
| `status` | {} | {peer_id, nat_type, networks, uptime_secs} | daemon 状态 |
| `identity` | {} | {peer_id, public_key_hex} | 查看身份 |
| `networks.list` | {} | [{network_id, name, peer_count, status}] | 列出网络 |
| `network.join` | {invite_code} | {network_id, status} | 加入网络 |
| `network.leave` | {network_id} | {status} | 离开网络 |
| `network.peers` | {network_id} | [{peer_id, status, latency_ms, path}] | 列出 peers |
| `peer.connect` | {network_id, peer_id} | {state, attempt_id} → +fd | 建立数据流 |
| `peer.disconnect` | {network_id, peer_id} | {status} | 断开 peer |
| `metrics` | {} | {connections, bytes_sent, ...} | 获取指标 |
| `shutdown` | {} | {status} | 优雅关闭 daemon |

### 11.3 管理面 HTTP API

```
GET   /identity                  → { peer_id, public_key }

POST  /network/join              ← { invite_code }
                                  → { network_id, status }
GET   /networks                  → [{ network_id, peer_count }]
POST  /network/{id}/leave        → { status }

GET   /networks/{id}/peers       → [{ peer_id, status: direct|relayed, latency_ms }]

POST  /networks/{id}/connect     ← { peer_id }
     → 202 Accepted { attempt_id }
     ... events ...
     → connection_established | connection_failed

GET   /metrics                   → Prometheus text

SUBSCRIBE /events                → SSE event stream
  events: peer_joined, peer_left, connection_changed, network_changed
```

### 11.4 数据面 — Native (UDS fd 传递)

连接流程：

```
Client                              Daemon
  │                                    │
  │  {"id":1,"method":"peer.connect",  │
  │   "params":{"network_id":"...",    │
  │   "peer_id":"..."}}                │
  │ ──────────────────────────────────→│
  │                                    │ 执行穿透/连接
  │  {"id":1,"result":{"state":        │
  │   "connecting","attempt_id":       │
  │   "a1b2"}}                         │
  │ ←────────────────────────────────  │
  │                                    │
  │  (穿透完成, 连接就绪)                 │
  │                                    │
  │  {"method":"connection_ready",     │
  │   "params":{"peer_id":"...",       │
  │   "path":"direct_quic"}}           │
  │ ←─ + SCM_RIGHTS (裸 fd) ────────  │
  │                                    │
  │  fd read/write                     │
  │  DataFrame                         │
  │ ←═══════════════════════════════→ │
```

fd 对应用透明：read 返回解密后的上层应用数据，write 自动封装为 DATA 帧 + Noise 加密 + QUIC 传输。

### 11.5 数据面 — WebSocket (浏览器)

通过 HTTP API 获得 ws_port后连接：`ws://127.0.0.1:{ws_port}/stream/{network_id}/{peer_id}` \\
WS binary message = 完整 Lain 帧（含 magic）。DATA_DGRAM 不适用。

| 特性 | UDS (native) | WebSocket (浏览器) |
|------|-------------|-------------------|
| 零拷贝 | 是 (fd 传递) | 否 |
| Datagram | 支持 | 不支持 |
| 流控粒度 | socket buffer | WS 帧级 |
| 跨平台 | Unix only | 全平台 |

### 11.6 应用层约定

不强制但推荐：
- **首帧 HEADERS**: `{"version":1,"app":"myapp/1.0","capabilities":["chat","file"]}`
- **背压**: QUIC 背压 → daemon 发送 JSON-RPC 通知 `backpressure` → 应用减速

### 11.7 `lain://` URI

```
lain://<base62_invite_code>
```

浏览器点击 → 系统 handler 转发给 lain daemon → 解析并加入网络。

### 11.8 错误响应

```json
{
  "error": {
    "code": "CONNECTION_FAILED",
    "message": "无法连接到 peer abc: 穿透策略已穷尽",
    "details": { "steps_tried": ["ipv6","stun","ws"], "last_error": "timeout" }
  }
}
```

**完整错误码：**

| 错误码 | HTTP | 含义 |
|--------|------|------|
| `INVALID_REQUEST` | 400 | 请求格式错误 |
| `INVALID_INVITE` | 400 | Invite 码无效/过期/签名失败 |
| `NETWORK_NOT_FOUND` | 404 | NetworkID 不存在 |
| `PEER_NOT_FOUND` | 404 | PeerID 不在网络中 |
| `PEER_UNREACHABLE` | 503 | 穿透穷尽，peer 不可达 |
| `CONNECTION_FAILED` | 502 | 连接建立后异常断开 |
| `CONNECTION_TIMEOUT` | 504 | 连接/穿透超时 |
| `STREAM_LIMIT_EXCEEDED` | 429 | stream 数达上限 |
| `STREAM_CLOSED` | 410 | stream 已被对方关闭 |
| `RELAY_UNAVAILABLE` | 503 | 无可用 relay |
| `VERSION_MISMATCH` | 400 | 协议版本不支持 |
| `INTERNAL_ERROR` | 500 | daemon 内部错误 |
| `NOT_READY` | 503 | daemon 未完成初始化 |

---

## 12. 运维

### 12.1 零配置启动

```
$ lain daemon
INFO  identity generated, peer_id=abc123...
INFO  QUIC listening on 0.0.0.0:52341 (random)
INFO  IPC on ~/.lain/socket + 127.0.0.1:9177
INFO  NAT probed: Cone, ipv6=available
```

可选的 `~/.lain/config.toml`（TOML 格式，所有字段可选，完整 schema）：

```toml
[network]
# quic_port = 0                # 0 = 随机, 指定则固定
# max_connections = 256
# max_streams_per_conn = 128

[ipc]
# uds_path = "~/.lain/socket"  # Unix Domain Socket 路径
# http_addr = "127.0.0.1:0"    # 0 端口 = 随机
# named_pipe = "\\\\.\\pipe\\lain"  # Windows only

[logging]
# level = "info"               # error|warn|info|debug|trace
# file_enabled = false         # 写日志文件
# file_path = "~/.lain/logs/lain.log"
# file_max_size_mb = 10        # 单文件最大，超限轮转

[dht]
# k = 20                       # bucket 容量
# alpha = 3                    # 查找并发度
# republish_interval_secs = 3600
# bootstrap_timeout_secs = 120

[timing]
# peer_ttl_secs = 300          # 节点记录 TTL
# heartbeat_interval_secs = 150
# stale_window_multiplier = 3  # STALE = TTL × multiplier

[connection]
# connect_timeout_secs = 10
# traversal_timeout_secs = 30
# idle_timeout_secs = 30
# keep_alive_interval_secs = 15

[traversal]
# birthday_levels = [1, 16, 64, 256]
# tso_window_secs = 5

[stun]
# servers = ["stun.miwifi.com", "stun.qq.com", "stun.cloudflare.com", "stun.l.google.com"]
# timeout_secs = 5

[security]
# noise_pattern = "IK"         # 可选: IK, KK (直连优化)
```

### 12.2 持久化

```
~/.lain/
├── config.toml          # 可选配置
├── identity.json        # Ed25519 密钥对 (0600)
├── logs/lain.log        # 可选日志文件
├── networks/<id>/
│   ├── network.json     # network_secret + 元数据
│   ├── peers.json       # 已知 peer 公钥 + 最后一次连接的地址
│   └── routes.bin       # Kademlia 路由表序列化
└── cache/nat_type.json  # NAT 探测缓存
```

#### routes.bin (DHT 路由表)

**写入时机**：
- graceful shutdown 时全量写入
- 每 600s 自动存盘（防止崩溃丢太多）
- bucket 发生结构性变化时（新节点插入触发 split / old node 被替换）标记脏，等待下一次定期存盘

**读取时机**：
- daemon 启动时读取。如果存在且未损坏 → 加载为初始路由表，跳过 bootstrap 的第一步（直接从已有邻居 PING 开始）。如果损坏或不存在 → 丢弃，从 invite/mDNS 重新 bootstrap。

**格式**：每个网络一条记录，序列化为 `[(node_id, address, last_seen), ...]`。lightweight 二进制格式（MessagePack），不存完整的 peer endpoint info（那些在 DHT STORE 中冗余存储）。

**损坏处理**：读取失败 → WARN 日志，丢弃文件，从零 bootstrap。不影响 daemon 启动。

#### peers.json

**写入时机**：首次成功 Noise 握手后写入（记录已验证的公钥 + 网络地址）。后续连接时更新 `last_connected` 时间戳。

**读取时机**：启动时加载，作为 DHT bootstrap 的 seed list——优先尝试连接这些已知 peer，成功后再填充路由表。

### 12.3 内置常量

```
STUN:  stun.miwifi.com, stun.qq.com, stun.cloudflare.com, stun.l.google.com (按序)
QUIC:  idle_timeout=30s, keep_alive=15s, max_udp_payload=1232 bytes
       (keep_alive 在移动网络下自动调整为 60s，连接建立后按路径 RTT 自适应)
DHT:   k=20, alpha=3, ttl=300s, heartbeat=150s, republish=3600s
       max_active_networks=32 (活跃网络数上限，超出部分自动标记 dormant)
连接:  connect_timeout=10s, traversal_timeout=30s, max_connections=256
       max_streams_per_conn=128, max_relay_streams=32
穿透:  birthday_levels=[1,16,64,256], tso_window=5s
```

### 12.4 端口分配

| 端口 | 用途 |
|------|------|
| UDP 随机 | QUIC 主端口（STUN + DHT RPC + 所有 QUIC 连接复用） |
| UDP :5353 | mDNS 公告/查询 |
| UDP 临时 | Birthday Attack 端口（动态开/关） |
| TCP 临时 | TSO / WS fallback listener |
| UDS 路径 | IPC native |
| TCP 127.0.0.1 随机 | IPC HTTP/WS |

### 12.5 日志

结构化 JSON 行 → stderr（systemd/容器友好）。可选文件轮转（保留 10MB）和 syslog。

关键事件：启动、NAT 探测、连接建立/断开、节点生命周期迁移、DHT 操作、网络切换、错误。

### 12.6 指标

通过 `GET /metrics` 暴露 Prometheus 格式：连接数（按路径类型）、延迟直方图、DHT 路由表大小、节点 LIVE/STALE 分布、字节流量、NAT 类型。

---

## 13. 错误处理

### 13.1 原则

永不 panic。逐层恢复。优雅降级。IPC 返回结构化错误。

### 13.2 优雅降级

```
Level 0 — 全功能: IPv6 + IPv4 NAT + DHT + 直连 + Relay
Level 1 — IPv4 降级: STUN server 全部不可达 → IPv6-only
Level 2 — IPv6 降级: 无 IPv6 → IPv4-only
Level 3 — 直连降级: 部分 peer 不可直连 → relay 补全
Level 4 — DHT 降级: bootstrap 不可达 → 仅现有直连 peer
Level 5 — 最小存活: 仅 relay 路径
```

### 13.3 重试策略

| 操作 | 最大重试 | 退避 |
|------|---------|------|
| STUN | 2 | 1s, 2s |
| 穿透单步 | 1 | 5s |
| DHT RPC | 2 | 2s, 4s |
| QUIC 连接 | 2 | 1s, 3s |
| Bootstrap | 3 | 10s, 30s, 60s |

所有退避附带随机抖动。

---

## 14. 安全威胁模型

### 14.1 信任假设

- **网络边界**：拥有 `network_secret` 即可加入网络。network_secret 通过 out-of-band 渠道分发（invite code），不经过 Lain 协议本身传递。
- **身份**：PeerID 与 Ed25519 公钥密码学绑定，无法伪造。
- **DHT 节点**：零信任。任何节点可能恶意、投毒、或不响应。
- **Relay 节点**：不可见明文（端到端 Noise 加密），但可观察元数据（谁和谁通信、流量大小、时间模式）。
- **STUN server**：不可信。仅用于获取公网映射地址，不传递密钥材料。

### 14.2 威胁与对策

| 威胁 | 严重度 | 对策 |
|------|--------|------|
| **DHT 投毒** (伪造 STORE) | 中 | STORE 签名绑定 PeerID。FIND_VALUE 返回的 record 必须通过签名验证。接收方额外验证 endpoint 可达性。 |
| **DHT Sybil 攻击** | 低 | PeerID = hash(公钥)，生成大量 ID 需大量计算。k-bucket 按 XOR 距离组织，Sybil 节点只能影响局部路由。 |
| **Eclipse 攻击** (隔离目标节点) | 中 | 多路径 bootstrap（invite seeds + peers.json + 持久化路由表）。定期从 seed 重新 FIND_NODE(self) 验证路由表一致性。 |
| **重放攻击** (Invite) | 低 | Invite 含 timestamp，接收方拒绝超过 30 分钟的 invite。一次性使用。 |
| **重放攻击** (DHT RPC) | 低 | message_id 为随机 16 字节，接收方 5 秒去重窗口。 |
| **中间人** (首次握手) | 低 | Noise IK 要求预先知道对方公钥（通过 invite 带外传递）。公钥不变则后续连接自动验证。 |
| **Relay 流量分析** | 低 | Relay 可见通信对、流量大小、时间模式。应对：padding 帧（可选），多 relay 分散流量。 |
| **QUIC 降级攻击** | 低 | QUIC TLS 1.3 自身防降级。Lain 固定使用 QUIC v1，不协商更低版本。 |
| **DoS (连接洪泛)** | 中 | 全局 max_connections=256。STUN server 请求限速。DHT RPC 每 bucket 队列上限。 |
| **密钥泄露** | 高 | Ed25519 密钥文件 0600 权限。泄露后 PeerID 永久不可信——需生成新身份重新加入所有网络。 |

### 14.3 数据分类与保护

| 数据 | 位置 | 保护方式 |
|------|------|---------|
| Ed25519 私钥 | `identity.json` (磁盘) | 文件权限 0600。不加密存储（依赖 OS 用户隔离）。未来可选 passphrase 加密。 |
| network_secret | `network.json` (磁盘) | 文件权限 0600。 |
| 应用层 payload | 网络传输 | Noise ChaChaPoly 加密 + QUIC TLS 1.3 双重加密。 |
| DHT 路由表 | 内存 + `routes.bin` | 仅含 node_id + address，不含密钥材料。 |
| Invite code 传输 | out-of-band (用户控制) | Ed25519 签名防篡改。传输通道安全性由用户保证。 |

### 14.4 隐私考虑

- **DHT 可见性**：任何拥有 network_secret 的节点可查询 DHT 获取所有节点的 PeerID 和 endpoint。PeerID 不直接关联真实身份（除非用户将 PeerID 公之于众）。
- **Relay 元数据**：Relay 可见通信双方 PeerID。在小型网络中可以推断社交图。缓解：大网络（node 多）自然模糊；多 relay 分散。
- **mDNS 广播**：局域网内任何人可见 PeerID。可在信任的局域网内使用。

---

## 15. 设计边界与已知限制

### 15.1 硬边界

- **S_APDF × S_APDF 且双方无 IPv6**：数学上无法直连，需 relay 或用户配置 IPv6
- **两端都在严格防火墙后（UDP 封 + TCP 入站封 + 无 IPv6）**：任何路径均不通

### 15.2 已知 tradeoff

- **Invite 是即时的**：发出后地址可能过期。成功连过一次后 daemon 记住 PeerID，后续无需 invite
- **STUN 依赖外部**：硬编码 4 个 STUN server（境内优先）。全部不可达时 IPv4 穿透罢工
- **小网络 DHT**：节点 <20 时 Kademlia 路由无优势，退化为全连接
- **移动端**：iOS/Android 后台限制可导致心跳停滞。需前台图标或 VPN 标记保活

### 15.3 已解决的边缘问题

- **时钟漂移**：相对 TTL，接收方本地时钟判断
- **IK 角色冲突**：PeerID 排序
- **Relay 单点**：多 relay 冗余 + 自动选举
- **NAT Rebinding**：QUIC Connection Migration + DHT 同步
- **STUN 被墙**：境内 STUN 优先

---

## 16. 协议版本与兼容性

### 16.1 版本号语义

版本号字段出现在 Invite code、DHT RPC 头、Noise 握手帧中。当前为 `1`。

版本号采用单个递增整数（非 semver）。向后不兼容的变更递增版本号。

### 16.2 协商机制

1. 高版本节点发现低版本对端后，降级到 min(本地版本, 对端版本) 通信。
2. 低版本节点收到高版本请求时，回复 `UNSUPPORTED_VERSION` 错误响应，附带自身支持的最高版本。请求方降级重试。
3. 所有新版本 MUST 兼容上一版本的消息格式至少一个版本周期（2 个 minor release），给用户升级窗口。

### 16.3 升级路径

- **identity.json**：从 v1 起格式固定（Ed25519 密钥对 JSON），不随协议版本变更。
- **network.json / peers.json**：JSON 格式，新增字段向后兼容（旧版本忽略未知字段）。
- **routes.bin**：MessagePack 格式，版本号嵌入文件头。不兼容时丢弃重建（从 DHT 自然恢复）。
- **config.toml**：新增 key 有默认值，删除 key 被忽略。

---

## 17. 测试策略

### 17.1 测试层级

| 层级 | 范围 | 工具 | 目标 |
|------|------|------|------|
| **单元测试** | 每个 crate 的函数/类型 | `#[cfg(test)]` + `cargo test` | >80% 行覆盖率 |
| **集成测试** | crate 间交互 | `tests/` 目录 | 核心路径全覆盖 |
| **模拟网络测试** | 虚拟 NAT 环境 | Docker 容器 + Linux netns | NAT 穿透矩阵全组合 |
| **性能基准** | QUIC 吞吐、DHT 查找延迟 | `criterion` | 回归检测 |
| **模糊测试** | 协议解析器 | `cargo-fuzz` | DHT RPC 解析、Invite 解析、帧解析 |
| **互操作测试** | 跨版本通信 | CI matrix | vN ↔ vN-1 兼容 |

### 17.2 关键测试场景

```
□ 双 Cone NAT — STUN 打洞成功
□ Cone × S_APDF — 非对称打洞成功
□ S_ADF × S_ADF — 双向打洞成功
□ S_APDF × S_APDF — 打洞失败 → 回退 relay/IPv6
□ S_APDF × S_ADF — 打洞失败 → 回退 relay/IPv6
□ 同 NAT hairpin — LAN 直连
□ IPv6 被封锁方发起 → IPv6 可达方响应 — 成功
□ 双方 IPv6 均不可达 + 全 Symmetric — relay 成功
□ WiFi ↔ 蜂窝切换 — QUIC migration + DHT update 成功
□ 路由表持久化 → 重启恢复 — bootstrap 时间缩短
□ Invite 解析 → DHT bootstrap → 直连 — 完整流程
□ NAT rebinding — QUIC PATH_CHALLENGE 响应成功
□ 100 节点 DHT — FIND_VALUE O(log N) 收敛
□ Relay 下线 → 自动切换候选 — 数据流不中断
□ SIGTERM 优雅关闭 — 路由表序列化、peer 通知
```

### 17.3 CI/CD

- `cargo fmt --check` + `cargo clippy` + `cargo test`
- NAT 穿透矩阵用 GitHub Actions + Docker（每个 PR 运行）
- 长时间 soak test (24h): 多节点加入/离开/重连（nightly）

---

## 18. Crate 结构

```
lain/
├── Cargo.toml               # workspace root
├── DESIGN.md
├── coverage-analysis.md     # NAT 覆盖率分析论文
├── crates/
│   ├── lain-core/           # 核心类型、trait、协议定义
│   ├── lain-identity/       # Ed25519 密钥、PeerID、NetworkID
│   ├── lain-noise/          # Noise IK 握手
│   ├── lain-nat/            # NAT 探测、STUN 客户端
│   ├── lain-discovery/      # mDNS、invite code 编解码
│   ├── lain-dht/            # Kademlia DHT
│   ├── lain-transport/      # QUIC + WS 连接管理、帧协议
│   ├── lain-daemon/         # daemon 主进程、IPC API
│   └── lain-cli/            # CLI 管理工具
└── tests/
```

---

## 19. 使用场景

Lain 的核心能力：**在两个设备之间建立加密字节流，不需要任何服务器。**

| 场景 | 用法 |
|------|------|
| 个人设备组网 | 手机、笔记本加入同一网络，剪贴板同步、文件共享 |
| 小团队内网 | 内部聊天、代码仓库、文档同步，零服务器 |
| 远程访问 | 从公司电脑访问家中 NAS（直连或 relay） |
| 局域网协作 | mDNS 自动发现，延迟 <1ms |
| 去中心化应用 | 开发者用 lain 做网络层，不需要买云服务器 |
| IoT / 边缘 | 树莓派、传感器组网，无需公网 IP |

上层应用通过 IPC 获取裸字节流 fd，协议完全自定义——lain 不参与应用层逻辑。
