# Lain

**零服务器 P2P 网络基础设施。** 无需 bootstrap 节点、无需 DNS、无需 TLS 证书。PeerID 即身份，Invite 即入口，DHT 即拓扑。

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-125-brightgreen.svg)](https://github.com/zmkjh/lain/actions)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)

## 核心创新

传统 P2P 网络依赖硬编码的 bootstrap 节点作为网络入口——这些节点成为单点故障和审查目标。Lain 用社交关系替代基础设施：

- **Invite 替代 Bootstrap**：每份邀请码是一条网络入口。A 邀请 B，B 的连接动作自动播种 DHT。B 再邀请 C，网络随人际关系自然生长，无需任何公共服务器。
- **DHT 自组织**：QUIC 连接成功后双方交换真实 DHT 地址并立即执行 `store_self`，路由表从零开始病毒式扩张。
- **IPv6 优先**：自动检测全局单播地址（2000::/3），有则直连——零 NAT、零 relay。无全局 IPv6 时自动降级至 IPv4 + STUN + relay。
- **TSO 穿透 CGNAT**：TCP Simultaneous Open + Birthday Attack 作为最后一层穿透。双方从同端口范围 bind+connect，出站 SYN 创建 NAT hole，对端 SYN 交叉握手。N×M 端口对并发（Birthday Attack），NAT 探测（端口保持性 delta + RTT）驱动自适应参数：端口保持型 4 端口、随机型 8 端口，超时和间隔也根据 RTT 动态调整。专为中国移动 CGNAT 设计。

详细设计及协议规范见 [DESIGN.md](DESIGN.md) 和 [PROTOCOL.md](PROTOCOL.md)。

## 快速开始

```bash
git clone https://github.com/zmkjh/lain
cd lain
cargo build --release
```

**启动 daemon**

```bash
$ lain daemon
Starting daemon (NAT probe + DHT bootstrap may take a few seconds)...
Lain daemon started
PeerID: f8df8b59c08df278
Logs: ~/.lain/daemon.log
```

**生成邀请码**

```bash
$ lain invite
lain://5KncdUB060WGkVZU...
```

**对端连接**

```bash
$ lain connect lain://5KncdUB060WGkVZU...
connecting...
connected to f8df8b59c08df278
```

**DHT 发现（无需 invite）**

```bash
$ lain find f8df8b59c08df278
searching DHT...
connected to f8df8b59c08df278
```

**断开连接**

```bash
$ lain disconnect f8df8b59c08df278
```

**查看状态**

```bash
$ lain status
PeerID:    f8df8b59c08df278
NAT:       APDFSymmetric
IPv6:      2001:db8::1
Port:      port-preserving (delta=1)
STUN RTT:  45ms
DHT nodes: 3
Known:     5
Connected: 2
```

**监控事件**

```bash
$ lain monitor
monitoring...
[connected] ffe4d9a8
[disconnected] ffe4d9a8
```

## 场景指南

以下场景覆盖从零开始的完整连接流程。**每一方都需要先启动 `lain daemon`**。

### 场景 1：两人直连（Invite）

这是最基础的连接方式——一人发邀请，另一人连接。

```bash
# ====== A 的终端 ======
$ lain invite
lain://5KncdUB060WGkVZU...          ← 复制这行，通过任意方式发给 B

# ====== B 的终端 ======
$ lain connect lain://5KncdUB060WGkVZU...
connecting...
connected to f8df8b59c08df278        ← 连上了
```

如果双方都在同一个局域网，mDNS 会自动发现——连上后 `lain status` 里 DHT nodes ≥ 1。

### 场景 2：不能直连（校园网 / CGNAT）

中国移动宽带、校园网等对称 NAT 环境下，UDP 打洞失败。用 TSO：

```bash
# A 和 B 都需要对方的 invite，然后同时运行
# ====== A 的终端 ======
$ lain invite
lain://AAAAAA...

$ lain tso lain://BBBBBB...          ← 用 B 的 invite

# ====== B 的终端（102 秒内） ======
$ lain invite
lain://BBBBBB...

$ lain tso lain://AAAAAA...          ← 用 A 的 invite
```

双方都应在 102 秒内看到 `connected to ... via TSO`。

### 场景 3：局域网组网（mDNS 自动）

同一局域网内无须 invite。启动 daemon 后 mDNS 自动发现——`lain status` 查看 DHT 节点数是否增长。但**第一个上线的人**没有网络可加入（路由表为空），需要等人连接后才会扩张。

### 场景 4：小网络起步（第一个上线的人）

```bash
$ lain daemon
$ lain status
PeerID:    0425cd35d5fa46d0
NAT:       APDFSymmetric
DHT nodes: 0                          ← 正常，你是第一个
Known:     0
Connected: 0

# 现在生成 invite 发给第二个人。他连接后：
$ lain status
DHT nodes: 1                          ← 网络开始生长
Known:     1

# 第三个人连第二个人 → DHT nodes: 2 → 网络已建成
```

### 常见问题

| 现象 | 原因 | 解决 |
|---|---|---|
| `DHT nodes: 0` 且连不上 | 你是第一个人，或网络完全隔离 | 找人通过 invite 连接你 |
| `lain connect` 超时 | NAT 太严，UDP/relay 都失败 | 双方用 `lain tso` |
| 连上但 `DHT nodes` 不增长 | 对方 daemon 未启动或已断 | 确认对方 `lain status` 正常 |
| 重启后 `Known` 还在但连不上 | IP 变了，存储的地址过时 | `lain connect` 重新用 invite |

## 命令参考

| 命令 | 说明 |
|------|------|
| `lain` | 查看网络状态 |
| `lain daemon` | 启动 daemon（后台，日志写文件） |
| `lain daemon -f` | 前台模式（日志输出至终端） |
| `lain whoami` | 显示 PeerID |
| `lain invite` | 生成邀请码 |
| `lain connect <code>` | 连接指定 peer |
| `lain find <peer_id>` | DHT 查找并自动连接 |
| `lain tso <code>` | TCP 同时打开（Symmetric NAT fallback） |
| `lain disconnect <peer_id>` | 断开指定 peer |
| `lain monitor` | 订阅事件流 |
| `lain status` | 查看网络状态 |
| `lain shutdown` | 停止 daemon |

## 连接路径

daemon 自动选择最优路径连接 peer：

```
lain connect / lain find
  │
  ├─ ① UDP 直连（STUN / IPv6）
  │    优先尝试 IPv6 直连 → STUN 地址 → LAN
  │
  ├─ ② relay 中继
  │    DHT 查找 relay 节点 → 连接 relay → 管道转发
  │
  ├─ ③ TSO（TCP Simultaneous Open + Birthday Attack）
  │    自适应端口数（4/8），并发 bind+connect，RTT 驱动超时，jitter 避免限速
  │
  └─ ④ 失败（所有路径不通）
```

TSO 是 Lain 专门针对 CGNAT（中国移动/校园网对称 NAT）的最后一层穿透手段。

**原理**：TCP Simultaneous Open — 双方各用 `TcpSocket.bind(5000X).connect(对端 5000X)` 从同一端口发起连接。出站 SYN 在各自 NAT 上创建映射，对端 SYN 交叉抵达，完成握手。无需 TcpListener，纯 bind+connect。

**自适应参数**：
| NAT 类型 | 内部端口数 | 超时 | 间隔 |
|---|---|---|---|
| 端口保持型（探测 delta=1） | 4 | 依 RTT | 200ms |
| 随机端口型（未知） | 8 | 依 RTT | 300ms |
| RTT < 100ms | — | 200ms | — |
| RTT < 300ms | — | 400ms | — |
| RTT > 300ms | — | 600ms | — |

**使用条件**：双方必须在 102s 内同时运行 `lain tso <对端 invite>`。8×8=64 对组合并发，±50ms jitter 避免 CGNAT 限速。

**端口范围**：50000-50007（IANA ephemeral 49K-65K 内，CGNAT 可识别）。

## IPC 事件

应用程序通过 IPC 订阅以下事件：

| 事件 | 触发 |
|------|------|
| `peer_connected` | 连接建立，含 `via` 路径（direct/relay/tso/dht） |
| `peer_disconnected` | 手动断开或连接丢失 |
| `peer_error` | 连接失败，含 error 详情 |
| `data` | 收到数据，`data.bytes` 为 base64 编码 |

## 应用开发

Lain 是基础设施，数据收发通过 IPC 通信。CLI 仅管理 daemon 生命周期。

**Unix (Domain Socket)：**

```python
import socket, json
s = socket.socket(socket.AF_UNIX)
s.connect("/home/user/.lain/socket")
s.send(b'{"cmd":"Subscribe"}\n')
while True:
    ev = json.loads(s.recv(4096))
    if ev.get("event") == "data":
        print(f"received from {ev['peer_id']}")
```

**Windows (Named Pipe)：**

```python
import json, win32file
h = win32file.CreateFile(r"\\.\pipe\lain",
    win32file.GENERIC_READ | win32file.GENERIC_WRITE,
    0, None, win32file.OPEN_EXISTING, 0, None)
win32file.WriteFile(h, b'{"cmd":"Whoami"}\n')
_, data = win32file.ReadFile(h, 4096)
print(json.loads(data))
```

IPC 协议完整规范见 [PROTOCOL.md §8](PROTOCOL.md#8-ipc-api)。

## 跨平台

| 平台 | IPC | 状态 |
|------|-----|------|
| Linux | Unix Domain Socket | 完整 |
| macOS | Unix Domain Socket | 完整 |
| Windows | Named Pipe | 完整（已真机验证） |

## 构建与测试

```bash
cargo build --release    # 生产构建
cargo test               # 125 自动化测试 (0 warning)

125 个测试覆盖全部协议层：identity、noise、nat、dht、discovery、transport（PeekConnection + Mock Transport）、daemon（编排函数 + 签名验证 + ConnectionGuard）+ 11 个端到端集成测试（连接握手、多消息、双向通信、并发连接、大消息、生存时间、连接关闭）。

## 许可证

MIT © 2026 zmkjh

## 最近更新 (2026-05)

### 架构重构
- **Trait 隔离**：`CryptoProvider`、`Transport`、`Connection`、`DhtBackend` 全部定义为 trait，daemon 通过 `Arc<dyn Transport>` 引用实现，transport 不再直接依赖 lain-noise
- **统一 Connection 接口**：QUIC、TSO、Relay 三种路径统一为 `Connection` trait（`send`/`recv`/`close`/`peer_id`），daemon 只有一个 `spawn_reader`
- **PeerID 在握手中确定**：Noise IK 握手 payload 携带 PeerID，不需要额外的 DHT_ADDR 协议
- **自动重连**：指数退避（1s→3s→9s→27s→60s），`ConnectionGuard` 通过 watch channel 优雅取消
- **NAT 探测重写**：多服务器 Binding Request 比较，不再依赖 CHANGE-REQUEST
- **Relay 回退**：`find_relays()` 返回 `RelayInfo`（含 noise_pubkey），daemon 层 `recv→send` pipe
- **1423 行新增 / 3480 行删除**，crate 间死依赖全部清理
