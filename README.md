# Lain

零服务器、零配置的 P2P 网络。**不需要公共 bootstrap 节点，不需要 DNS，不需要 TLS 证书。** 你认识谁就跟谁组网，社交关系就是网络拓扑。

## 与传统 P2P 的区别

传统 DHT 网络需要一个硬编码的 bootstrap 节点作为入口（`router.bittorrent.com:6881`），这些节点是单点故障和审查目标。

**Lain 用 invite 替代 bootstrap。** 每个 invite 就是一个网络入口——A 生成 invite 发给 B，B 连接的同时把自己的 DHT 路由表种入 A 的网络。B 再接 C，C 接 D，网络随人际关系自然扩张。

IPv6 下更纯粹：每台设备有全球唯一地址，零 NAT，零 relay，纯直连。IPv4 下自动走 STUN 穿透 + relay 转发。

## 安装

```bash
git clone https://github.com/zmkjh/lain
cd lain
cargo build --release
# Unix
sudo cp target/release/lain-cli /usr/local/bin/lain
# Windows
copy target\release\lain-cli.exe C:\Windows\System32\lain.exe
```

## 快速开始

**启动 daemon**

```bash
$ lain
Lain daemon started
PeerID: f8df8b59c08df278
Logs: ~/.lain/daemon.log
```

**分享 invite 给对端**

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

**看状态**

```bash
$ lain status
PeerID:    f8df8b59c08df278
NAT:       APDFSymmetric
IPv6:      yes
DHT nodes: 0
Known:     1
Connected: 1
```

**停 daemon**

```bash
$ lain shutdown
daemon shutting down
```

## 所有命令

| 命令 | 功能 |
|------|------|
| `lain` | 启动 daemon（后台模式，日志写文件） |
| `lain daemon -f` | 前台运行（日志输出到终端） |
| `lain whoami` | 查看自己的 PeerID |
| `lain invite` | 生成邀请码 |
| `lain connect <code>` | 连接到 peer |
| `lain monitor` | 监控事件流（连接、数据通知） |
| `lain status` | 查看网络状态 |
| `lain shutdown` | 停止 daemon |

数据收发通过 IPC API 由应用程序实现，详见下文"应用开发"。

## 原理

```
IPv6 路径（纯直连，零 NAT）：
  A ←── QUIC + Noise IK ──→ B

IPv4 路径（STUN 穿透，relay 兜底）：
  A → STUN → 公网地址 → STUN → B
  A ←── relay ←── B（symmetric NAT 时）
```

每个 peer 启动时：
1. **身份** — Ed25519 密钥 → SHA256 → PeerID
2. **NAT 探测** — STUN 获取公网地址，IPv4 NAT 分类（Cone / Symmetric）
3. **IPv6 检测** — 自动发现全局 unicast 地址，有则优先直连
4. **DHT 注册** — 256 桶 Kademlia，Ed25519 签名防伪造
5. **mDNS 注册** — 局域网自动发现

## IPv6：这才是 P2P 该有的样子

**如果双方都有 IPv6 全局地址，不需要 STUN，不需要 relay，不需要 NAT 穿透。** 你的 IPv6 地址就是你的公网身份，QUIC + Noise IK 直接加密连接。

Lain 会自动检测本机 IPv6 全局地址（2000::/3），加入 invite。对端连接时优先走 IPv6 直连。如果没有全局 IPv6（ISP 未分配、路由器未开启），自动降级到 IPv4 + STUN + relay。

## 应用开发

Lain 是基础设施，数据收发通过 IPC API 实现。CLI 只管理 daemon 生命周期。

**Unix（Unix Domain Socket）：**

```python
import socket, json
s = socket.socket(socket.AF_UNIX)
s.connect("/home/user/.lain/socket")
s.send(b'{"cmd":"Whoami"}\n')
print(json.loads(s.recv(4096)))
```

**Windows（Named Pipe）：**

```python
import json, win32file
handle = win32file.CreateFile(
    r"\\.\pipe\lain",
    win32file.GENERIC_READ | win32file.GENERIC_WRITE,
    0, None, win32file.OPEN_EXISTING, 0, None)
win32file.WriteFile(handle, b'{"cmd":"Whoami"}\n')
_, data = win32file.ReadFile(handle, 4096)
print(json.loads(data))
```

IPC 协议详情见 DESIGN.md 附录 A.5。

## 跨平台

| 平台 | 状态 |
|------|------|
| Linux | daemon + CLI |
| macOS | daemon + CLI |
| Windows | daemon + CLI（Named Pipe IPC，已验证） |

## 文件位置

| 文件 | 说明 |
|------|------|
| `~/.lain/identity.json` | Ed25519 密钥对（丢失则 PeerID 改变） |
| `~/.lain/socket`（Unix）或 `\\.\pipe\lain`（Windows） | IPC 通信 |
| `~/.lain/daemon.log` | 运行日志 |
| `~/.lain/peers.json` | 已知 peer 列表（Ed25519 签名防篡改） |
| `~/.lain/routes.json` | DHT 路由表（启动恢复，心跳更新） |

## 从源码构建

```bash
cargo build --release    # daemon + CLI
cargo test               # 135+ 自动化测试，零 warning
```

## 许可

MIT
