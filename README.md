# Lain

**零服务器 P2P 网络基础设施。** 无需 bootstrap 节点、无需 DNS、无需 TLS 证书。PeerID 即身份，Invite 即入口，DHT 即拓扑。

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-135-brightgreen.svg)](https://github.com/zmkjh/lain/actions)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)

## 核心创新

传统 P2P 网络依赖硬编码的 bootstrap 节点作为网络入口——这些节点成为单点故障和审查目标。Lain 用社交关系替代基础设施：

- **Invite 替代 Bootstrap**：每份邀请码是一条网络入口。A 邀请 B，B 的连接动作自动播种 DHT。B 再邀请 C，网络随人际关系自然生长，无需任何公共服务器。
- **DHT 自组织**：QUIC 连接成功后双方交换真实 DHT 地址并立即执行 `store_self`，路由表从零开始病毒式扩张。
- **IPv6 优先**：自动检测全局单播地址（2000::/3），有则直连——零 NAT、零 relay。无全局 IPv6 时自动降级至 IPv4 + STUN + relay。

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
  │    16 端口 Birthday Attack 并发，102s 窗口
  │
  └─ ④ 失败（所有路径不通）
```

TSO 专为 APDF Symmetric NAT（中国移动宽带）设计——双方各开 16 个 TCP 端口同时互连，K×K 并发提升穿透概率。

## IPC 事件

应用程序通过 IPC 订阅以下事件：

| 事件 | 触发 |
|------|------|
| `peer_connected` | 连接建立，含 `via` 路径（direct/relay/tso/dht） |
| `peer_disconnected` | 手动断开或连接丢失 |
| `peer_error` | 连接失败，含 error 详情 |
| `data` | 收到数据，`data.bytes` 为 base64 编码 |
| `incoming_connection` | 入站连接请求，含 `connection_id` |

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
cargo test               # 135 自动化测试 (0 warning)
```

135 个测试覆盖全部协议层：identity、noise、nat、dht、discovery、transport、daemon + 12 个端到端集成测试（含 relay、TSO、并发）。

## 许可证

MIT © 2026 zmkjh
