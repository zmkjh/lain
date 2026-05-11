# Lain

零服务器、零配置的 P2P 网络基础设施。每台设备都是一个服务器。

**PeerID 就是你的域名，DHT 就是 DNS，三层穿透就是端口映射。** 任何人知道你的 PeerID，就能在任何网络环境下找到你、连接你。

## 安装

```bash
git clone https://github.com/lain-p2p/lain
cd lain
cargo build --release
sudo cp target/release/lain /usr/local/bin/
```

## 快速开始

**启动 daemon**

```bash
$ lain
Lain daemon started
PeerID: a1b2c3d4e5f6a7b8
Logs: ~/.lain/daemon.log
```

**分享 invite 给对端**

```bash
$ lain invite
Invite: lain://0a1b2c3d4e5f...
```

**对端连接**

```bash
$ lain connect 0a1b2c3d4e5f...
connecting...
connected to a1b2c3d4e5f6a7b8
```

**发文件**

```bash
$ lain send a1b2c3d4 ./hello.txt
sent 13 bytes to a1b2c3d4
```

**看状态**

```bash
$ lain status
PeerID:    a1b2c3d4
NAT:       Cone
IPv6:      yes
DHT nodes: 47
Connected: 1
Peers:
  ffe4d9a8
```

**停 daemon**

```bash
$ lain shutdown
```

## 所有命令

| 命令 | 功能 |
|------|------|
| `lain` 或 `lain daemon` | 启动守护进程 |
| `lain daemon -f` | 前台运行（日志输出到终端） |
| `lain whoami` | 查看自己的 PeerID |
| `lain invite` | 生成邀请码 |
| `lain connect <code>` | 连接到 peer |
| `lain send <peer> <file>` | 发送文件 |
| `lain monitor` | 监控事件流（连接、收数据） |
| `lain status` | 查看网络状态 |
| `lain shutdown` | 停止 daemon |

## 原理

Lain 是一个运行在终端设备上的 daemon，让没有固定公网 IP 的设备也能像服务器一样被访问。

```
A 生成身份 → NAT 探测 → DHT 注册
B 拿到 A 的 invite → 解析 PeerID+公钥+地址
A ←── DHT 查找 ──→ B 互相发现
A ←── QUIC + Noise IK ──→ B 加密连接建立
A ←── 数据流 ──→ B 端到端加密通信
```

用户不需要配置 IP、端口、NAT 类型、TLS 证书。底层自动完成穿透、握手、加密、路由查找。

## 跨平台

| 平台 | 状态 |
|------|------|
| Linux | 完整支持 |
| macOS | 完整支持 |
| Windows | daemon 完整，CLI 通过 Named Pipe 连接 |

## 文件位置

| 文件 | 说明 |
|------|------|
| `~/.lain/identity.json` | Ed25519 密钥对（丢失则 PeerID 改变） |
| `~/.lain/daemon.log` | 运行日志 |
| `~/.lain/socket` | IPC 通信 socket（Unix） |
| `\\.\pipe\lain` | IPC 通信 pipe（Windows） |
| `~/.lain/peers.json` | 已知 peer 列表 |
| `~/.lain/routes.bin` | DHT 路由表 |

## 从源码构建

```bash
cargo build --release    # 构建 daemon + CLI
cargo test               # 运行全部测试（50+ 单元 + 9 集成）
```

## 许可

MIT
