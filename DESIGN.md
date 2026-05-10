# Lain —— 设计文档

Lain 是一个零服务器、零配置的 P2P 网络基础设施，以 daemon 形式在终端设备上运行。

**理论基础**：见 `coverage-analysis.md` —— 在中国三大 ISP 异构 NAT 环境下，IPv6 + IPv4 STUN 打洞的组合覆盖率可达 97.8%。

---

## 1. 核心哲学

**节点是暂时的，连接是持续重建的。** Lain 面向没有固定公网 IP 的终端设备——手机、笔记本、台式机。IPv6 SLAAC 临时地址静默轮换、WiFi↔蜂窝切换、NAT 映射过期都是既定事实，设计上拥抱而非对抗。

- **PeerID 是永久的**：等于 `SHA256(Ed25519 公钥)`。只要密钥文件不丢，PeerID 在设备生命周期内不变。变化的只是网络地址。
- **全联通，无分区**：一个全局 DHT，所有 Lain 节点共用一个地址空间。节点通过 DHT 宣告在线、发现彼此。没有"网络"概念——不需要创建、加入、切换。
- **Invite 码有两重角色**：① 新节点的 DHT 入场券——首次启动时路由表为空，必须通过已在 DHT 中的老节点的 invite 获取 bootstrap 地址，才能加入 DHT；② 之后的快捷方式——路由表填满后，知道 PeerID 就能从 DHT 查到公钥和地址，invite 退为可选的加速手段。
- **一对一连接，不是广播**：Lain 在两个设备之间建立加密字节流。如果要给多个 peer 发数据，就分别建立多条连接——每条都是独立的 Noise 端到端加密通道。
- **零配置启动**：daemon 不带任何参数就能运行，所有参数有内置默认值。
- **群组是应用层的事**：哪些 peer 之间通信、如何分组——Lain 不参与。基础设施只负责建通道。

---

## 2. 技术选型

| 维度 | 选择 |
|------|------|
| 语言 | Rust (workspace) |
| 传输协议 | QUIC (UDP)，WebSocket over TCP 兜底 |
| 身份密钥 | Ed25519 |
| 握手 | Noise_IK (1-RTT)，高于 QUIC 层，端到端加密 |
| DHT | 基础 Kademlia，全局单一路由表 |
| NAT 穿透 | IPv6 直连 → STUN 打洞 → P2P Relay（三层模型） |
| 发现 | DHT 全局目录 + Invite（bootstrap / 快捷拨号） |

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
│  │ IPv6 → STUN  │  │ QUIC streams │  │ UDS (native 应用)  │    │
│  │ → P2P Relay  │  │ QUIC datagram│  │ HTTP/WS (浏览器)   │    │
│  │ (三层模型)    │  │ Flow control │  │ fd 传递 + 管控分离  │    │
│  └──────────────┘  └──────────────┘  └────────────────────┘    │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                    Kademlia DHT (全局)                     │   │
│  │  STORE (PeerID + pubkey + endpoints) + FIND_VALUE(P2P目录) │   │
│  │  Heartbeat (150s) +  节点状态: LIVE → STALE → EXPIRED     │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3.5 并发模型

Daemon 采用 Tokio async runtime。单个 UDP socket 承载所有 DHT/QUIC/STUN 流量，按首字节分发。

### 任务层级

```
┌─ main task
│  ├─ IPC server task (UDS + HTTP)
│  ├─ DHT + connection supervisor task
│  │   ├─ DHT task (UDP socket, RPC dispatch, bucket maintenance)
│  │   ├─ Discovery task (mDNS broadcast + listen, invite code gen/parse)
│  │   ├─ Heartbeat timer task
│  │   ├─ NAT probe task (on-demand)
│  │   └─ per-connection task (one per peer pair)
│  │       ├─ QUIC endpoint task
│  │       ├─ Noise handshake task (ephemeral)
│  │       ├─ Stream multiplex task (framed read/write)
│  │       └─ NAT traversal task (ephemeral, shared across connections)
│  ├─ WS fallback listener task (lazily spawned)
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
- **角色**: Initiator 必须预先知道 Responder 的公钥（通过 DHT 查询或 invite code 获取）
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

### 4.3 全联通模型

所有 Lain 节点共享一个全局 DHT。没有 network_secret、没有 NetworkID、没有"网络"概念。

**DHT 是完整目录**：每个节点通过 STORE 宣告自己的 PeerID、Ed25519 公钥、当前 endpoints。任何人 `FIND_VALUE(peer_id)` 就能拿到连接所需的全部信息——公钥、IP、端口。公钥由 Ed25519 签名验证：PeerID = SHA256(公钥)，自然防伪造。

**连接已知 peer 不需要 invite**：知道 PeerID → DHT 查到公钥和地址 → 直接发起 QUIC + Noise IK。

**Invite 有两重角色**：① DHT 入场券——新节点路由表为空，invite 里的老节点地址是唯一 bootstrap 入口。② 地址快照——收到 invite 可以跳过 DHT 查找直接连，更快但不是必需。路由表填满后，invite 退为可选的加速手段。

**隐私考虑**：DHT 公开 PeerID、公钥、IP 和端口。PeerID 是公钥哈希，不直接关联真实身份。应用层自行管理"哪些 PeerID 属于我的联系人"。

---

## 5. 发现与邀请

### 5.1 发现路径

```
优先级:  mDNS (局域网) → Invite Code (广域网) → DHT lookup（持续）
```

- **mDNS**: LAN 内通过非特权端口（默认 53617，可配置）广播 `_lain._udp.local`，TXT record 含 PeerID + 实际 QUIC 端口。使用非标准 mDNS 端口避免与系统 mDNS 服务（avahi/Bonjour/mDNSResponder，占用 5353）冲突。
- **Invite Code**: 用户通过 out-of-band 渠道交换（复制粘贴、QR、`lain://` 链接）
- **DHT lookup**: 解析 invite 后去 DHT `FIND_VALUE(peer_id)` 获取最新广播的地址（比 invite 中的快照更新鲜）

### 5.2 Invite 码结构

```
Invite = {
  version:       u8
  peer_id:       [u8; 32]      // SHA256(ed25519_pubkey)
  ed25519_pk:    [u8; 32]      // Ed25519 公钥
  capabilities:  u8             // bitmask
  mappable_port_start: u16
  mappable_port_end:   u16
  port_delta_hint:     u8
  endpoints:     [ { addr, kind, priority, ttl_seconds } ]
  timestamp:     u64
  signature:     [u8; 64]      // Ed25519 over all above
}
```

编码：Compact Binary → Base62，约 300-400 字符。地址列表中的 TTL 由生成方根据 NAT 类型动态设定（Cone STUN ~120s，Symmetric ~30s，IPv6 ~300s）。

### 5.3 使用流程

invite 是最便捷的方式，但不是唯一方式。

**通过 invite（推荐）**：
1. A 生成 invite 码（含 PeerID、公钥、地址快照）
2. A 通过 out-of-band 渠道分享给 B
3. B 解析 → 获取 PeerID、公钥、地址
4. B 用 invite 中的地址直接尝试 QUIC + Noise IK
5. 失败则 DHT `FIND_VALUE(PeerID)` 获取新地址
6. 双方完成 Noise IK，连接建立

**通过 PeerID（无需 invite）**：
1. B 从任意渠道得知 A 的 PeerID（如复制粘贴、应用内分享）
2. B 执行 DHT `FIND_VALUE(PeerID)` → 获取 A 的公钥和最新地址
3. B 发起 QUIC + Noise IK → 连接建立

**重连**：成功连过一次之后，daemon 记住了 PeerID 和公钥。后续重连自动走 DHT，不需要 invite。

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

### 6.2 连接建立：三层模型

连接建立策略分为三层，按优先级执行。上层成功后不再尝试下层。

```
Layer 1: IPv6 直连
  ─ 条件: 至少一方有 IPv6 inbound reachable
  ─ 发起方通过 invite code 或 DHT lookup 获取 IPv6 地址，直接发起 QUIC connection
  ─ 覆盖: ~77% 的中国互联网用户（当前 IPv6 部署率），技术用户接近 100%
  ─ 延迟: 1-RTT（QUIC handshake）+ 1-RTT（Noise IK）= 2-RTT

Layer 2: IPv4 STUN 打洞
  ─ 条件: 双方均无 IPv6 inbound，且至少一方为 Cone NAT
  ─ 双方通过 STUN 获取 IPv4 映射地址，通过 DHT 或 invite 交换地址，同时发送 UDP probe
  ─ 覆盖: 在 Layer 1 未覆盖的 ~23% 中，再覆盖大部分（Cone NAT 在剩余中约占 70%）
  ─ 延迟: STUN 查询 (1-RTT) + 打洞 (1-RTT) + QUIC + Noise IK = 4-RTT

Layer 3: P2P Relay
  ─ 条件: 以上两层均失败
  ─ daemon 启动后即主动连接 relay 候选节点（临时数据桥），穿透阶段立即可用
  ─ 覆盖: 所有剩余不可直连对，包括 S_APDF × S_APDF/S_ADF 硬边界
  ─ 延迟: 己方↔relay (2-RTT) + relay↔对端 (2-RTT) = 4-RTT + relay 内部转发
  ─ 直连探测持续后台运行，一旦成功自动从 relay 切换为直连
```

Layer 3 依赖 P2P relay 节点（见 §7），不依赖任何中心化服务器。网络中任意一个 Cone NAT 或 IPv6-reachable 的节点即可充当 relay。

### 6.3 高级穿透技术（可选增强）

以下技术适用于 relay 暂时不可用的边界场景，不作为核心路径。实现优先级低于三层模型。

**Birthday Attack**：双方在 UDP 多端口上做 K×K 探测矩阵。需要 relay 提供实时信令通道来交换动态端口列表。无 relay 时仅可用 invite code 中的初始端口集合做单轮尝试。移动端降级为较低的端口数（max 128）。

**TCP Simultaneous Open**：利用 TCP SYN 碰撞建立连接。需要 relay 提供精确时钟同步（5s 窗口）。无 relay 时使用本机时钟 ±3s 窗口，成功率下降。依赖 SO_REUSEADDR。

**WebSocket over TCP 443**：当 UDP 被完全封锁（如部分企业防火墙）时，通过 HTTP Upgrade 建立 WebSocket 连接。需一方可监听 TCP 入站。WS 路径不支持 QUIC Datagram（不可靠传输），所有数据退化为可靠。

以上三项技术的信令都依赖 relay。在当前设计中，如果 relay 不可用，这些技术的实用性大幅下降。因此将它们定位为"有 relay 辅助的增强技术"而非"无 relay 时的替代方案"。

### 6.4 穿透执行细节

**Hairpin NAT 检测**：若双方 STUN mapped address 的 IP 相同，判定为同 NAT 后节点。跳过公网地址直连尝试，优先使用 invite 中的 LAN endpoint 或 mDNS 发现的局域网地址直连。LAN 不可达时回退到 relay。

**执行模型**：Layer 1-2 并行启动（IPv6 和 STUN 互不依赖），Layer 3 在启动时即预连 relay 候选。首个成功的 Layer 被采用，其余尝试取消。整个流程受 traversal_timeout (30s) 全局约束。

**穿透记忆**：连接成功后记录使用的路径类型（IPv6 / STUN / relay）和对方 NAT 类型。后续重连时跳过已知不可行路径。例如对 S_APDF 对端，直接走 IPv6 或 relay，不尝试 STUN 打洞。

### 6.5 硬边界

| Peer A | Peer B | 直连 | 兜底 |
|--------|--------|------|------|
| S_APDF | S_APDF | ❌ | IPv6 或 relay |
| S_APDF | S_ADF | ❌ | IPv6 或 relay |

其他所有 NAT 组合均可直连（详见 `coverage-analysis.md` 第 4 章证明）。

### 6.6 WebSocket Fallback 细节

WebSocket 路径用于 UDP 被完全封锁的场景。在 Layer 3 (relay) 可用时优先使用 relay（QUIC），WS 仅作为 relay 不可用时的最后兜底。

#### 角色决策

通过 invite 阶段交换的能力声明（或 DHT 中的 capabilities 字段）决定谁监听、谁连接：

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
发送 ws_endpoint 给对方 (via DHT 或 invite)
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

#### WS vs QUIC

| 特性 | QUIC | WebSocket |
|------|------|-----------|
| NAT 穿透力 | 强 (UDP 打洞) | 弱 (需一方监听) |
| Datagram | 支持 | 不支持 |
| 连接迁移 | 原生支持 | 不支持 |
| 场景 | UDP 可达 | UDP 被封 |

---

## 7. Relay

### 7.1 角色模型

Relay 是 P2P 网络内其他节点，不依赖任何中心化服务器。有两种角色：

**角色一：临时数据桥（主动）** — daemon 启动后即预连 relay 候选节点。穿透阶段，Layer 1 和 Layer 2 并行尝试的同时，relay 路径已就绪——连接立即可用。背后持续探测直连路径，一旦直连建立即切换。绝大多数连接在几秒内从 relay 切换到直连。

**角色二：稳定 Relay（被动）** — 直连确认不可行（如双方 S_APDF 且无 IPv6，或 UDP 被完全封锁）后承担长期数据转发。

注：TSO 时钟同步、Birthday Attack 端口列表传递等信令角色，仅在 relay 可用时作为增值功能可选启用（见 §6.3）。

### 7.2 Relay 发现、选举与路由

#### Relay 能力条件

```
relay_capable = (nat_type == Cone) || ipv6_inbound_open
```

满足条件的节点在心跳 STORE 中设置 `capabilities.relay_capable = 1`，自然进入 DHT 存储。其他节点通过 DHT 查询发现 relay 候选。

#### 两阶段发现

**阶段一（被动收集）**：每个节点在 DHT 路由表中标记所有 `relay_capable` 节点。随着路由表自然填充，候选池逐步积累。

**阶段二（主动查询）**：候选池为空或全部不可达时，执行 `FIND_VALUE(RelayCapabilityMarker)` 查询。`RelayCapabilityMarker = SHA256("lain-relay-v1")` 是一个全局静态魔术 key，所有 relay 节点在心跳 STORE 中同时 STORE 自己的 `peer_id` 到这个 key。FIND_VALUE 返回的 value 是当前在线的 relay PeerID 列表。

#### Relay 选路：为 A↔B 找到合适的中继

当 A 需要经由 relay 连接 B 时：

1. A 取自己的候选池与 B 的候选池（通过 DHT 查询 B 的 STORE record 获取 B 的已知 relay 列表）
2. 求交集 → 优先选双方都能直连的 relay（一跳 relay）
3. 交集为空 → A 从自己候选池中选一个 R，要求 R 能连到 B（R 通过 DHT FIND_VALUE 验证 B 可达）
4. 上述均失败 → 执行迭代式 `FIND_VALUE(RelayCapabilityMarker)`（α=3），扩大搜索范围。Kademlia FIND_VALUE 的自然行为会遍历 XOR 空间中最接近该 key 的节点，逐步收集 relay 候选。若仍为空，周期重试（退避 30s→60s→120s）。

选路度量（同分时）：延迟优先（RTT 最小）→ 带宽估计优先 → PeerID 排序决定。

注：RELAY_NEEDED (msg_type=0x04) 是一个显式的"请求 relay 列表"RPC，用于直连已知 relay 候选节点确认其 relay 意愿和当前负载。它不依赖广播——它发送给已知 relay 节点或通过 FIND_VALUE 新发现的候选。

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
4. 候选池为空 → 触发阶段二主动查询（迭代 FIND_VALUE(RelayCapabilityMarker)）→ 仍为空则周期重试（退避 30s→60s→120s）

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
  ├─ 有在线 peer ──→ 心跳广播、DHT 维护、接受连接
  │
  ├─ 全部远程节点 EXPIRED ──→ IDLE (停止 DHT 心跳，只维持 IPC 监听)
  │
  └─ 收到 SIGTERM ──→ DRAINING → 序列化 → EXIT
```

### 8.3 防时钟漂移

TTL 使用相对值而非绝对时间戳。发布方 STORE 时写入 `ttl_seconds = 300`，接收方用**自己的本地时钟**计算 `expires_at = now() + ttl_seconds`。整个状态机完全基于接收方时钟，不受双方时钟偏差影响。Invite 码 timestamp 防重放窗口放宽至 30 分钟覆盖极端漂移。

### 8.4 心跳

```
广播间隔 = max(ttl / 2, 60s)  // 默认 150s

每次广播:
  1. 获取本机所有接口地址 (IPv6 GUA、STUN 映射、LAN)
  2. STORE(self_peer_id, endpoints + ttl_seconds) 到 k-closest 邻居
  3. UPDATE_ENDPOINTS 到所有直连 peer
```

**紧急广播**：检测到 SLAAC 轮换或网络接口变更时立即触发，不等定时器。

### 8.5 清理

每 300s 遍历路由表：STALE/EXPIRED 标记 → EXPIRED 移除 → 全部 EXPIRED 则 DHT 标记为 dormant（保留 routes.bin 和 peers.json，释放连接资源，停止心跳）。收到新 peer 的 invite 或应用层触发时，从持久化路由表恢复并重新 bootstrap。

**Dormant 状态**：停止心跳 STORE 和 bucket 刷新，保留路由表序列化文件。收到新 peer 的 invite 或应用层触发连接时，从持久化路由表恢复并重新 bootstrap。此机制确保长期无活动时不消耗后台流量和 CPU。

### 8.6 接口切换

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
请求:   version(1) | message_id(16) | msg_type(1) | sender_id(32) | payload | Ed25519签名(64)
响应:   version(1) | message_id(16) | msg_type|0x80 | sender_id(32) | payload | Ed25519签名(64)
```

版本不匹配时，接收方回复错误码 `UNSUPPORTED_VERSION`，附带自身支持的版本号。双方取 min 版本进行后续通信。

| RPC | Payload | 响应 |
|-----|---------|------|
| PING | 空 | k-closest (node_id, addr)... |
| STORE | key(32) + ttl(4) + value | ok/error |
| FIND_VALUE | key(32) | value 或 k-closest 节点列表 |

超时 5s，重试 2 次。

**签名策略**：请求端对所有 RPC 请求 Ed25519 签名（防篡改 + 防重放）。响应端仅对包含可验证数据 payload 的响应签名（如 FIND_VALUE 返回的 value / STORE 返回的 key 确认）。空 payload 响应（如 PING 的 k-closest 列表、STORE 的 ok）无需签名——接收方通过 message_id 关联到原始请求即可验证响应合法性。

### 9.4 Bootstrap

新节点加入 DHT 的入口。Bootstrap 来源按优先级：

```
1. routes.bin + peers.json（重启恢复，最快）
2. invite code 中的 endpoint（新节点首次加入的唯一方式）
3. 硬编码的 DHT bootstrap 节点（公共 lain 网络的可选固定入口，非必需）

Bootstrap 步骤:
  1. 从上述来源获取至少一个已知 endpoint
  2. PING → 加入路由表
  3. FIND_NODE(self.id) → 填充路由表
  4. 递归 FIND_NODE 填满 256 个 bucket
  5. STORE 自身信息（PeerID + 公钥 + endpoints）到 k-closest 邻居
```

注：首次启动必须有 invite（来源 2）或公共 bootstrap 节点（来源 3）。重启则从来源 1 恢复。

### 9.5 Lookup

迭代式 FIND_NODE，α=3 并行。每轮将搜索空间减半，O(log N) 轮收敛。

### 9.6 STORE 与维护

心跳向 k=20 个最近节点 STORE。接收方每 3600s republish。超过 TTL 未被更新的 record 自然过期。路由表每 3600s 刷新一次所有 bucket。

---

## 9.7 线格式规范

以下定义所有协议消息的精确二进制编码。多字节整数统一采用**大端序（Big-Endian）**。

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
```

### 9.7.2 DHT RPC 消息格式

所有 DHT RPC 通过单个 UDP socket 发送。消息头统一 83 字节，后跟可变长 payload：

```
┌─────────────────────────────────────────────┐
│ offset │ size │ field         │ description  │
├────────┼──────┼───────────────┼──────────────┤
│ 0      │ 1    │ version       │ 协议版本 (1)  │
│ 1      │ 16   │ message_id    │ 随机ID        │
│ 17     │ 1    │ msg_type      │ bit7=0请求    │
│ 18     │ 32   │ sender_id     │ 发送方 PeerID │
│ 50     │ 1    │ payload_len_hi│               │
│ 51     │ 2    │ payload_len_lo│               │
│ 53     │ var  │ payload       │               │
│ 53+len │ 64   │ signature     │               │
└─────────────────────────────────────────────┘
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
  key: [u8; 32]           // = PeerID
  ttl:  u32
  pubkey: [u8; 32]        // Ed25519 公钥（与 PeerID 匹配，接收方可验证）
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
    pubkey: [u8; 32]      // Ed25519 公钥
    value_len: u16
    value: [u8; value_len]  // endpoint 列表
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
│ 5      │ 3     │ payload_len (u24 BE)   │
│ 8      │ var   │ Noise message payload  │
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
| 0x07 | STREAM_RESUME | [(stream_id: varint, last_seq: u64), ...] | 断线重连后恢复 stream 状态，发送方为发起重连的一方 |

**Stream ID 分配：**
- Stream 0: 保留给 Noise IK 握手 + 重连后 STREAM_RESUME
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

完整线格式见 §9.7.4。此处仅做概述：

```
magic(3) | Stream ID (varint) | Frame Type (varint) | Frame Length (varint) | Payload
```

帧类型速查：

| 值 | 名称 | 说明 |
|----|------|------|
| 0x00 | HEADERS | 首帧必发，应用层元数据 |
| 0x01 | DATA | 可靠应用数据 |
| 0x02 | DATA_DGRAM | 不可靠数据报（仅 QUIC） |
| 0x03 | CLOSE | 优雅关闭 stream |
| 0x04 | PING | 应用层心跳 |
| 0x05 | PONG | 心跳响应 |
| 0x06 | PATH_CHANGE | 地址变更通知 |
| 0x07 | STREAM_RESUME | 重连后 stream 恢复 |

Stream 0 保留给 Noise IK 握手 + 重连 STREAM_RESUME，Stream 1 为控制通道，Stream 2+ 为应用数据流。

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
  (握手超时: 15s，超时视为连接失败，关闭 QUIC connection)

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
  ├─ IPv6_ATTEMPT       (Layer 1, 若有 IPv6)
  ├─ STUN_HOLE_PUNCH    (Layer 2, 并行)
  └─ RELAY_CONNECT      (Layer 3, 预连 relay 候选，立即可用)
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
4. 成功 → 对端发送 STREAM_RESUME 帧（stream 0），格式为 `[(stream_id: varint, last_seq: u64), ...]`。接收方比对已收到的数据，缺失部分由发起方重传。应用层 fd 保持不变，恢复对应用透明。
5. 失败 → 指数退避重试，最大间隔 5 分钟。peer EXPIRED 则放弃，向上层应用发送 STREAM_LOST 通知。
6. 重启后重连：daemon 从 peers.json 恢复已知 peer 列表，从 routes.bin 恢复 DHT 路由表，优先连接这些 peer 以快速重建 DHT 邻居关系。

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
| `status` | {} | {peer_id, nat_type, peers_online, uptime_secs} | daemon 状态 |
| `identity` | {} | {peer_id, public_key_hex} | 查看身份 |
| `invite.generate` | {} | {invite_code} | 生成自己的 invite（快捷方式） |
| `invite.accept` | {invite_code} | {peer_id, status} | 通过 invite 添加 peer（可选，等价于 peer.connect 但跳过 DHT 查找） |
| `peer.list` | {} | [{peer_id, status, latency_ms, path}] | 已知 peer 列表 |
| `peer.connect` | {peer_id} | {state, attempt_id} → +fd | 建立一对一数据流（自动 DHT 查找公钥和地址） |
| `peer.disconnect` | {peer_id} | {status} | 断开 peer |
| `metrics` | {} | {connections, bytes_sent, ...} | 获取指标 |
| `shutdown` | {} | {status} | 优雅关闭 daemon |

### 11.3 管理面 HTTP API

```
GET   /identity                  → { peer_id, public_key }

POST  /invite/generate           → { invite_code }
POST  /invite/accept             ← { invite_code }
                                  → { peer_id, status }
GET   /peers                     → [{ peer_id, status, latency_ms, path }]

POST  /peer/connect              ← { peer_id }
       → 202 Accepted { attempt_id }
       ... events ...
       → connection_established | connection_failed

GET   /metrics                   → Prometheus text

GET   /events                    → SSE event stream
  events: peer_online, peer_offline, connection_changed
```

### 11.4 数据面 — Native (UDS fd 传递)

连接流程：

```
Client                              Daemon
  │                                    │
  │  {"id":1,"method":"peer.connect",  │
  │   "params":{"peer_id":"..."}}        │
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

通过 HTTP API 获得 ws_port后连接：`ws://127.0.0.1:{ws_port}/stream/{peer_id}` \\
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

浏览器点击 → 系统 handler 转发给 lain daemon → 解析 invite 并接受。

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
| `PEER_NOT_FOUND` | 404 | PeerID 未知或不在线 |
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

# 高级穿透技术（可选，默认关闭。仅在 relay 不可用时启用）
[traversal.advanced]
# birthday_enabled = false
# birthday_levels = [1, 16, 64, 256]
# tso_enabled = false
# tso_window_secs = 5
# ws_fallback_enabled = false

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
├── peers.json           # 已知 peer 公钥 + 最后连接地址
├── routes.bin           # Kademlia 路由表序列化
├── cache/nat_type.json  # NAT 探测缓存
└── logs/lain.log        # 可选日志文件
```

#### routes.bin (DHT 路由表)

**写入时机**：
- graceful shutdown 时全量写入
- 每 600s 自动存盘（防止崩溃丢太多）
- bucket 发生结构性变化时（新节点插入触发 split / old node 被替换）标记脏，等待下一次定期存盘

**读取时机**：
- daemon 启动时读取。如果存在且未损坏 → 加载为初始路由表，跳过 bootstrap 的第一步（直接从已有邻居 PING 开始）。如果损坏或不存在 → 丢弃，从 invite/mDNS 重新 bootstrap。

**格式**：序列化为 `[(node_id, address, last_seen), ...]`。lightweight 二进制格式（MessagePack），不存完整的 peer endpoint info（那些在 DHT STORE 中冗余存储）。

**损坏处理**：读取失败 → WARN 日志，丢弃文件，从零 bootstrap。不影响 daemon 启动。

#### peers.json

**写入时机**：首次成功 Noise 握手后写入（记录已验证的公钥 + 网络地址）。后续连接时更新 `last_connected` 时间戳。

**读取时机**：启动时加载，作为 DHT bootstrap 的 seed list——优先尝试连接这些已知 peer，成功后再填充路由表。

### 12.3 内置常量

```
STUN:  stun.miwifi.com, stun.qq.com, stun.cloudflare.com, stun.l.google.com (按序)
QUIC:  idle_timeout=30s, keep_alive=15s, max_udp_payload=1232 bytes
       (移动网络下 idle_timeout 自动调整为 120s, keep_alive 为 60s)
DHT:   k=20, alpha=3, ttl=300s, heartbeat=150s, republish=3600s
连接:  connect_timeout=10s, traversal_timeout=30s, max_connections=256
       max_streams_per_conn=128, max_relay_streams=32
穿透:  traversal_timeout=30s

# 高级穿透（可选，默认禁用，仅 relay 不可用时启用）
[traversal.advanced]
# birthday_enabled = false
# birthday_levels = [1, 16, 64, 256]
# tso_enabled = false
# tso_window_secs = 5
```

### 12.4 端口分配

| 端口 | 用途 |
|------|------|
| UDP 随机 | QUIC 主端口（STUN + DHT RPC + 所有 QUIC 连接复用，见 §12.4.1） |
| UDP :53617 或随机 | mDNS 公告/查询（避免与系统 mDNS 端口 5353 冲突，LAN 发现通过 mDNS TXT record 携带实际端口号） |
| UDP 临时 | Birthday Attack 端口（动态开/关） |

#### 12.4.1 UDP 端口解复用

单个 UDP socket 承载三种协议，按首字节分发：

| 首字节 | 协议 | 分发规则 |
|--------|------|---------|
| 0x00-0x03 | STUN | 首 2 bit = 00，紧接着 magic cookie `0x2112A442` 验证 |
| 0x01 | DHT RPC | version byte = 1，紧接着 message_id 随机性验证 |
| 0xC0-0xFF | QUIC long-header | 首 2 bit = 11（Initial/Handshake），或 0x40-0x7F（short-header，按 CID 匹配已注册 connection） |

QUIC short-header 包的首字节为 `01xxxxxx`（与 DHT version=1 冲突）。区分方式：收到 0x01 开头的包时，先尝试按已注册 QUIC Connection ID 匹配，无匹配则按 DHT RPC 解析。QUIC 握手完成后所有包均可按 CID 匹配，不存在歧义。

| 端口 | 用途 |
|------|------|
| TCP 临时 | TSO / WS fallback listener |
| UDS 路径 | IPC native |
| TCP 127.0.0.1 随机 | IPC HTTP/WS |

### 12.5 日志

结构化 JSON 行 → stderr（systemd/容器友好）。可选文件轮转（保留 10MB）和 syslog。

关键事件：启动、NAT 探测、连接建立/断开、节点生命周期迁移、DHT 操作、接口切换、错误。

### 12.6 指标

通过 `GET /metrics` 暴露 Prometheus 格式：连接数（按路径类型）、延迟直方图、DHT 路由表大小、节点 LIVE/STALE 分布、字节流量、NAT 类型。

### 12.7 移动端资源优化

移动设备（iOS/Android）的资源约束（电池、蜂窝数据、CPU、内存）与桌面端显著不同。以下策略使 daemon 在移动端可持续运行而不显著影响续航和数据套餐。

#### 12.7.1 电池优化

| 策略 | 桌面默认 | 移动默认 | 说明 |
|------|---------|---------|------|
| QUIC keep-alive | 15s | 60s | 减少无线电唤醒频率。idle_timeout 同步调整为 120s |
| DHT 心跳间隔 | 150s | 300s | 减少 STORE 发送。TTL 同步调整为 600s |
| bucket 刷新间隔 | 3600s | 7200s | 减少周期性 PING |
| republish 间隔 | 3600s | 7200s | 减少冗余 STORE |
| 批量 STORE | 关闭 | 开启 | 多个 key 的 STORE 合并到单个 UDP 包 |
| mDNS 广播 | 启用 | 关屏后关闭 | 屏幕关闭时暂停 LAN 发现，开屏恢复 |
| 连接建立限速 | 8 并发 | 3 并发 | 减少穿透阶段的并行无线电活动 |

**电源状态感知**：检测设备是否充电 → 充电时恢复桌面频率，拔电时采用移动频率。检测屏幕是否开启 → 关屏时降低所有定时器频率 50%。

#### 12.7.2 蜂窝数据优化

**流量预算**（移动模式，24 小时）：

| 组件 | 频率 | 单次流量 | 日流量 |
|------|------|---------|--------|
| DHT 心跳 STORE | 300s | ~5KB (20 nodes × 250B) | ~1.4 MB |
| bucket 刷新 PING | 7200s | ~2KB | ~7 KB |
| 路由表 republish | 7200s | ~5KB | ~17 KB |
| QUIC keep-alive | 60s/conn | ~50B | ~72 KB/conn |
| STUN refresh | 600s | ~200B | ~29 KB |
| **合计（5 连接，无 relay）** | — | — | **~1.8 MB/day** |
| **合计（5 连接，1 relay）** | — | — | **~3.5 MB/day** |

**流量优化措施**：
- DHT 消息合并：同一 heartbeat 周期内的多个 STORE 合并为一个 UDP datagram（路径 MTU 允许），减少包头开销
- 增量 STORE：仅当 endpoint 变更时发送完整 STORE，未变更时发送仅含 ttl 续期的轻量 PING 级消息
- Relay 流量计数：对 relay 路径做字节计数，通知用户月度 relay 流量消耗
- 蜂窝网络下默认禁用未请求的 relay 数据转发（仅为自己主动建立的连接使用 relay）

#### 12.7.3 CPU 优化

| 优化点 | 说明 |
|--------|------|
| DHT 签名批处理 | 同一 heartbeat 周期的多个 STORE 的签名在 tokio blocking pool 中并行，不阻塞 async runtime |
| 对称加密硬件加速 | ChaChaPoly 利用 ARM NEON / AES-NI 指令集（Rust `chacha20poly1305` crate 已支持） |
| 零拷贝转发 | Relay 节点：QUIC stream → QUIC stream 转发不经用户态 buffer 拷贝（使用 QUIC 的 `send_datagram` 或 stream pipe） |
| 路由表懒加载 | 仅访问的 k-bucket 做活跃维护，未使用的 bucket 保持序列化状态 |
| Birthday Attack 限流 | 移动端 birthday_levels 降为 [1,8,32,128]，减少 75% 探测包，且仅在 relay 信令可用时启动 |

#### 12.7.4 内存优化

| 组件 | 桌面上限 | 移动上限 | 说明 |
|------|---------|---------|------|
| max_connections | 256 | 64 | 减少 QUIC TLS 状态和 stream buffer |
| max_streams_per_conn | 128 | 32 | 减少 per-stream 缓冲区 |
| 接收 buffer 总量 | 8 MB | 2 MB | QUIC connection-level flow control 窗口 |
| DHT k-bucket 容量 | k=20 | k=8 | 减少路由表内存（~200KB → ~80KB per network） |
| relay candidate pool | 无上限 | 最多 16 个 | 减少 QUIC 连接数 |

#### 12.7.5 连接策略

**WiFi 优先**：蜂窝网络下仅维持已建立的关键连接和 DHT 基本维护，延迟非紧急的连接重建到 WiFi 可用时。

**连接暂停与恢复**：应用进入后台 → daemon 收到 OS 通知 → 降低所有定时器频率（×3）→ 保持 DHT STORE（证明存活）→ 暂停 mDNS → 进入前台 → 恢复全部定时器 → 紧急 UPDATE DHT → 重建断开的连接。

**后台保活**：Android 前台服务通知（必需）、iOS Background Task / VoIP push（如可用）。在 OS 强制杀死 daemon 后，下次启动从 routes.bin + peers.json 快速恢复。

---

## 13. 错误处理

### 13.1 原则

永不 panic。逐层恢复。优雅降级。IPC 返回结构化错误。

### 13.2 优雅降级

```
Level 0 — 全功能: IPv6 + IPv4 STUN + DHT + Relay（正常状态）
Level 1 — IPv4 降级: STUN server 全部不可达 → IPv6 + Relay
Level 2 — IPv6 降级: 无 IPv6 → STUN + Relay
Level 3 — DHT 降级: bootstrap 不可达 → 仅现有直连 peer + Relay
Level 4 — 最小存活: 仅 Relay 路径（所有直连不可用）
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

- **访问控制**：任何知道 PeerID 的节点可通过 DHT 获取公钥并发起 Noise IK 连接。Lain 不限制谁能连谁——接入控制是应用层的事。
- **身份**：PeerID 与 Ed25519 公钥密码学绑定，无法伪造。
- **DHT 节点**：零信任。任何节点可能恶意、投毒、或不响应。
- **Relay 节点**：不可见明文（端到端 Noise 加密），但可观察元数据（谁和谁通信、流量大小、时间模式）。
- **STUN server**：不可信。仅用于获取公网映射地址，不传递密钥材料。

### 14.2 威胁与对策

| 威胁 | 严重度 | 对策 |
|------|--------|------|
| **DHT 投毒** (伪造 STORE) | 中 | STORE 必须 Ed25519 签名，FIND_VALUE 响应验证签名。 |
| **DHT Sybil / Eclipse** | 中 | ① Liveness 门槛——攻击者必须持续运营在线节点（心跳、响应 PING），LIVE→STALE→EXPIRED 自动淘汰停止维护的 Sybil 节点。② peers.json 持久化真实 peer，不参与 bucket LRU 替换，Eclipse 不掉已连接过的 peer。③ 多源 bootstrap：routes.bin + peers.json + invite，不依赖单一入口。攻击者需要长期维护大量在线节点才能有效 Eclipse，成本远高于批量生成 PeerID。 |
| **Eclipse 攻击** (隔离目标节点) | 中 | 多路径 bootstrap（invite seeds + peers.json + 持久化路由表）。定期从 seed 重新 FIND_NODE(self) 验证路由表一致性。 |
| **重放攻击** (Invite) | 低 | Invite 含 timestamp，接收方拒绝超过 30 分钟的 invite。一次性使用。 |
| **重放攻击** (DHT RPC) | 低 | message_id 为随机 16 字节，接收方 5 秒去重窗口。 |
| **中间人** (首次握手) | 低 | Noise IK 要求预先知道对方公钥（通过 DHT 或 invite 获取）。公钥不变则后续连接自动验证。 |
| **Relay 流量分析** | 低 | Relay 可见通信对、流量大小、时间模式。应对：padding 帧（可选），多 relay 分散流量。 |
| **QUIC 降级攻击** | 低 | QUIC TLS 1.3 自身防降级。Lain 固定使用 QUIC v1，不协商更低版本。 |
| **DoS (连接洪泛)** | 中 | 全局 max_connections=256。STUN server 请求限速。DHT RPC 每 bucket 队列上限。 |
| **密钥泄露** | 高 | Ed25519 密钥文件 0600 权限。泄露后 PeerID 永久不可信——需生成新身份，重新分享 PeerID 给所有 peer。 |

### 14.3 数据分类与保护

| 数据 | 位置 | 保护方式 |
|------|------|---------|
| Ed25519 私钥 | `identity.json` (磁盘) | 文件权限 0600。不加密存储（依赖 OS 用户隔离）。未来可选 passphrase 加密。 |
| 应用层 payload | 网络传输 | Noise ChaChaPoly 加密 + QUIC TLS 1.3 双重加密。 |
| DHT 路由表 | 内存 + `routes.bin` | 仅含 node_id + address，不含密钥材料。 |
| Invite code 传输 | out-of-band (用户控制) | Ed25519 签名防篡改。传输通道安全性由用户保证。 |

### 14.4 隐私考虑

- **DHT 可见性**：任何 lain 节点可查询 DHT 获取任意 PeerID 的 endpoint 记录。PeerID 是公钥哈希，不直接关联真实身份。暴露的信息与 STUN server 相当（IP + 端口 + 在线状态）。
- **Relay 元数据**：Relay 可见通信双方 PeerID。在小型网络中可以推断社交图。缓解：大网络（node 多）自然模糊；多 relay 分散。
- **mDNS 广播**：局域网内任何人可见 PeerID。可在信任的局域网内使用。

---

## 15. 设计边界与已知限制

### 15.1 硬边界

- **S_APDF × S_APDF 且双方无 IPv6**：数学上无法直连，需 relay 或用户配置 IPv6
- **S_APDF × S_ADF 且双方无 IPv6**：同上（APDF 过滤端不可达），IPv6 或 relay 兜底
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
- **peers.json**：JSON 格式，新增字段向后兼容（旧版本忽略未知字段）。
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
│   ├── lain-identity/       # Ed25519 密钥、PeerID
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

## 19. 典型用法

Lain 的核心能力：**在两个设备之间建立加密字节流，不需要任何服务器。**

上层应用通过 IPC 获取裸字节流 fd，协议完全自定义——lain 不参与应用层逻辑。

---

### 19.1 用户视角：全联通

**invite 是最快的方式，但不是唯一方式。**

```
笔记本$ lain daemon
  INFO  identity=b3f1..., IPv6 inbound open, NAT Cone

笔记本$ lain invite generate
  invite: lain://3KqWx7...          ← 发到家庭群

手机$ lain invite accept lain://3KqWx7...
  INFO  peer d7e4... connected      ← 一键直连（invite 有地址快照）

NAS$ lain peer connect a1c2...      ← 没有 invite，直接通过 PeerID 连
  INFO  DHT lookup... connected     ← DHT 查到公钥和地址，自动连接

笔记本$ lain peer list
  d7e4...  (手机)  direct_quic,  12ms
  a1c2...  (NAS)   relayed,      28ms
```

连接方式：有 invite 就 `invite accept`（跳 DHT 查找），只有 PeerID 就 `peer connect`（自动 DHT 查）。效果一样，只是速度不同。

---

### 19.2 开发者视角：IPC 写入应用

**Lain 是纯 P2P（一对一）。** 每个 `peer.connect` 建立的是两个特定设备之间的加密 QUIC 流——不是广播、不是群发、不是消息总线。如果要给多个 peer 发数据，就分别 connect 每个。

**场景**：写一个简单的剪贴板同步工具。

```python
import socket, json, os

# 1. 连接 daemon
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect(os.path.expanduser("~/.lain/socket"))

def rpc(method, params={}):
    msg = json.dumps({"id": 1, "method": method, "params": params}) + "\n"
    sock.sendall(msg.encode())
    return json.loads(sock.recv(4096).decode())

rpc("invite.accept", {"invite_code": "3KqWx7..."})

# 2. 获取已知 peer 列表
peers = rpc("peer.list")
# → [{"peer_id":"d7e4...","status":"direct"}, {"peer_id":"a1c2...","status":"relayed"}]

# 3. 逐一到每个 peer 建立连接，获取独立的字节流 fd
connections = {}
for p in peers["result"]:
    result = rpc("peer.connect", {"peer_id": p["peer_id"]})
    fd = received_fd  # daemon 通过 SCM_RIGHTS 传回
    connections[p["peer_id"]] = fd

# 4. 每个 fd 是独立的一对一加密通道
for peer_id, fd in connections.items():
    fd.sendall(b"clipboard: hello from b3f1...")
    data = fd.recv(4096)
    print(f"{peer_id}: {data}")
```

`sendall(b"clipboard: hello")` 走的是 `笔记本 ──QUIC/Noise──→ 手机` 这条加密通道，NAS 收不到。发给 NAS 的是另一条独立的加密通道。lain 不提供广播——如果你需要群发，在应用层自己遍历所有连接即可。

**Rust 版本**（使用 `lain-core` crate）：

```rust
use lain_core::ipc::Client;

let mut client = Client::connect_default().await?;
client.accept_invite("3KqWx7...").await?;

// 获取所有 peer，逐一建立一对一连接
let peers = client.list_peers().await?;
for peer in peers {
    let mut stream = client.connect(&peer.peer_id).await?;
    stream.write_all(b"clipboard: hello").await?;
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf).await?;
    println!("{}: {}", peer.peer_id, String::from_utf8_lossy(&buf[..n]));
}
// stream 被 drop 时自动发送 CLOSE 帧，fd 关闭
```

---

### 19.3 浏览器视角

浏览器通过 HTTP/WebSocket 与 daemon 通信：

```javascript
// 加入（添加 peer）
const resp = await fetch('http://127.0.0.1:9177/invite/accept', {
  method: 'POST',
  body: JSON.stringify({ invite_code: '3KqWx7...' })
});
const { peer_id } = await resp.json();

// 连接 peer（数据面）
const { ws_port } = await fetch(
  'http://127.0.0.1:9177/peer/connect',
  { method: 'POST', body: JSON.stringify({ peer_id: 'd7e4...' }) }
).then(r => r.json());

// WebSocket 直连 daemon 数据面
const ws = new WebSocket(`ws://127.0.0.1:${ws_port}/stream/d7e4...`);
ws.binaryType = 'arraybuffer';
ws.onopen  = () => ws.send(new TextEncoder().encode('clipboard: hello'));
ws.onmessage = (e) => console.log('收到:', new TextDecoder().decode(e.data));
```

---

### 19.4 完整时序（两个开发者互连）

```
A 的机器                                              B 的机器
─────────────────────────────────────────────────────────────

$ lain daemon                                        $ lain daemon
  → 生成 identity, 启动 QUIC, 开启 IPC                   → 同上

$ lain invite generate
  → 输出 invite: lain://3KqWx7...
  → A 把 invite 发到微信群 / AirDrop 给 B
  → （invite 包含 PeerID + 公钥 + 地址快照）

                                                     $ lain invite accept lain://3KqWx7...
                                                       → 解析 invite，获取 A 的 IPv6 地址
                                                       → 跳过 DHT 查找（invite 已有地址）
                                                       → QUIC → Noise IK → 连接建立 ✓

# 之后 B 只需要知道 A 的 PeerID 就能重连
$ lain peer connect b3f1...                           $ lain peer connect d7e4...
  → DHT 查到公钥 + 地址                                   → DHT 查到公钥 + 地址
  → QUIC → Noise IK → 连接建立 ✓                          → 连接建立 ✓

# 两个 app（各自用 IPC 连接 daemon）开始通信
A的app ──IPC fd──→ lain daemon ──IPv6 QUIC──→ B的daemon ──IPC fd──→ B的app
  │                                                                       │
  └──────────── 端到端 Noise_IK 加密，零服务器 ────────────────────────────┘
```

---

### 19.5 典型连接路径分布

在实际使用中，按概率降序：

| 路径 | 典型场景 | 占比 |
|------|---------|------|
| **IPv6 直连** | 双方至少一方有 IPv6 inbound（当前 ~84%，逐年上升）| 绝大多数 |
| **STUN 打洞** | 双方均无 IPv6，但至少一方 Cone NAT | 少数 |
| **P2P Relay** | 硬边界 NAT 对，或 UDP 被封锁 | 极少数 |
| **LAN 直连 (mDNS)** | 同一 WiFi / 局域网内 | 局域网场景自动优先 |

用户和开发者不需要关心最终走的是哪条路径——daemon 透明选择。
