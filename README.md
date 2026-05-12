# Lain

**零服务器 P2P 网络基础设施。** 无需 bootstrap 节点、无需 DNS、无需 TLS 证书。PeerID 即身份，Invite 即入口，DHT 即拓扑。

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-152-brightgreen.svg)](https://github.com/zmkjh/lain/actions)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)

## 核心创新

传统 P2P 网络依赖硬编码的 bootstrap 节点作为网络入口——这些节点成为单点故障和审查目标。Lain 用社交关系替代基础设施：

- **Invite 替代 Bootstrap**：每份邀请码是一条网络入口。A 邀请 B，B 的连接动作自动播种 DHT。B 再邀请 C，网络随人际关系自然生长，无需任何公共服务器。
- **DHT 自组织**：QUIC 连接成功后双方交换真实 DHT 地址并立即执行 `store_self`，路由表从零开始病毒式扩张。
- **IPv6 优先**：自动检测全局单播地址（2000::/3），有则直连——零 NAT、零 relay。无全局 IPv6 时自动降级至 IPv4 + STUN + relay。
- **TSO 穿透 CGNAT**：TCP Simultaneous Open（同时打开）作为最后一层穿透手段。双方从同端口范围（50000-50007）并发 bind+connect，出站 SYN 创建 NAT hole，对端 SYN 交叉握手。自适应参数：根据 NAT 端口保持性（delta 探测）和 RTT 动态调整端口数、超时和间隔。专为中国移动 CGNAT/校园网对称 NAT 设计。

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
IPv6:      yes
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
  ├─ ③ TSO（TCP Simultaneous Open）
  │    8 端口 (50000-50007) 并发 Birthday Attack，400ms 超时 + jitter，102s 窗口
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
cargo test               # 152 自动化测试 (0 warning)
```

152 个测试覆盖全部协议层：identity、noise、nat（含全部 NAT 类型分类）、dht（全部消息类型）、discovery、transport（QUIC/TSO/relay/并发）、daemon + 13 个端到端集成测试。

## 许可证

MIT © 2026 zmkjh

## 最近更新 (2026-05)

### Bug 修复
- **IPC 事件通知**：修复 Subscribe 命令从不转发事件到客户端的问题（cli `lain monitor` / `lain connect` 现在可正常收到 `peer_connected` 等通知）
- **Invite 签名验证**：ConnectPeer 和 TsoPeer 现在验证 Ed25519 签名（之前只检查 PeerId 但不验证签名，MITM 可替换 noise_pk 和 endpoints）
- **TSO 噪声密钥**：ts_connect 现在从 `noise_secret` 正确派生 X25519 公钥
- **DHT 签名验证**：peers.json 现在验证 Ed25519 签名后再加载
- **DHT 随机性**：`random_id_in_bucket` 真正随机化后缀位
- **DHT 查询丢失**：`spawn_cleanup` 不再清空 `pending_queries`（之前每 10 分钟丢弃所有进行中的 find_peer 请求）
- **STUN CHANGE-REQUEST**：修复 message length 字段始终为 0 的问题
- **IPC listener 健壮性**：Unix/Windows/HTTP listener 现在在瞬态 accept 错误时 continue 而不是 exit

### 测试增强
- NAT 类型检测：mock STUN 服务器覆盖 Cone / APDFSymmetric / ADFSymmetric 全部分类
- TSO 端到端：TCP 同时打开 + Noise IK 握手 + 交叉会话加密验证
- accept_connection：响应端 Noise IK 完整测试
- DHT：AddrReflect / RelayNeeded 消息收发
- DHT：`spawn_bucket_refresh` 后台维护任务
