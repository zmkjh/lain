# Lain Protocol Specification v1

**版本：** 0.1  
**日期：** 2026-05  
**仓库：** https://github.com/zmkjh/lain

---

## 1. 概述

Lain 是一个零服务器 P2P 网络协议。本规范定义两个接口层：

1. **Peer Protocol（§2-§7）**——节点间通信的线格式、握手过程、DHT 操作、NAT 穿透。
2. **IPC API（§8-§9）**——应用程序与本地 Lain daemon 通信的 JSON 行协议。

实现者可以仅实现 Peer Protocol 来构建兼容节点，或仅实现 IPC API 来构建 Lain 应用程序。

**配套文档：**
- `README.md`——快速开始和命令参考
- `DESIGN.md`——架构设计和实现细节
- `coverage-analysis.md`——NAT/IPv6 覆盖率分析
- `compute_coverage.py`——覆盖率计算引擎（可复现）

---

## 2. 身份与加密

### 2.1 密钥体系

每个节点拥有两对密钥，均从同一个 32-byte Ed25519 seed 派生：

| 密钥 | 算法 | 用途 |
|------|------|------|
| 签名密钥 | Ed25519 | PeerID 生成、DHT RPC 签名、InviteCode 签名 |
| 交换密钥 | X25519 | Noise IK 端到端加密握手 |

**PeerID = SHA-256(Ed25519 公钥)**，编码为大写十六进制字符串（64 字符）。

### 2.2 Ed25519 → X25519 派生

X25519 私钥通过 SHA-256 领域分离 KDF 从 Ed25519 seed 派生：

```
ed_seed = Ed25519 SigningKey::to_bytes()            # 32 bytes
x25519_seed = SHA-256("lain-noise-x25519-v1" || ed_seed)
x25519_secret = x25519_dalek::StaticSecret::from(x25519_seed)
x25519_public = x25519_dalek::PublicKey::from(&x25519_secret)
```

领域分离标签 `"lain-noise-x25519-v1"` 确保 Ed25519 签名密钥和 X25519 交换密钥在密码学上独立，防止同一 seed 被跨协议不当复用。

**注意：** Ed25519 和 X25519 从同一个 seed 产生不同的标量值（Ed25519 预过 SHA-512）。因此 DHT 同时存储两种公钥，应用不可用 Ed25519 公钥替代 X25519 公钥。

### 2.3 Noise IK 握手

传输加密使用 Noise IK 模式：`Noise_IK_25519_ChaChaPoly_BLAKE2s`。

- **发起方** — 持有自身 X25519 私钥和对端 X25519 公钥，发送 IK message 1。Payload 携带发起方 PeerID。
- **响应方** — 仅需自身 X25519 私钥，读取 IK message 1，回复 IK message 2。Payload 携带响应方 PeerID。

握手完成后双方已知对方 PeerID，无需额外的身份交换协议。

握手完成后的 Noise Transport 状态用于端到端对称加密。在 QUIC 路径上，加密由 QUIC TLS 1.3 提供，Noise 仅用于身份认证；在 TSO/TCP 路径上，Noise 提供完整传输加密。

---

## 3. 传输层 (QUIC)

所有节点间数据交换基于 QUIC（RFC 9000）传输。

### 3.1 QUIC 连接

- TLS 1.3 自签名证书（ServerName: "lain"）
- 客户端跳过证书验证（NoVerify）——安全性由 Noise IK 层保证
- 默认最大并发连接数 256
- idle timeout 默认 30s，保活间隔 15s

### 3.2 Lain 帧协议

QUIC 流上承载 Lain 帧。帧格式：

```
[0..2]   MAGIC: 0x4C 0x41 0x49 ("LAI")
[3..]    stream_id: VarInt
         frame_type: VarInt
         payload_len: VarInt
         payload: [u8; payload_len]
```

`payload_len` 上限为 **4 MiB**（`MAX_PAYLOAD_SIZE = 4 * 1024 * 1024`）。超过此值的帧头将被拒绝，防止恶意超大分配。

**帧类型：**

| 值 | 类型 | 说明 |
|----|------|------|
| 0x00 | Headers | 能力协商（JSON） |
| 0x01 | Data | 应用数据流 |
| 0x02 | DataDgram | 数据报模式 |
| 0x03 | Close | 关闭流 |
| 0x04 | Ping | 保活探测 |
| 0x05 | Pong | 保活应答 |
| 0x06 | PathChange | 路径迁移通知 |
| 0x07 | StreamResume | 断线续传 |
| 0x08 | RelayConnect | 中继请求（§7） |
| 0x09 | RelayData | 中继数据 |

### 3.3 VarInt 编码

无符号整数变长编码：

| 值范围 | 编码 |
|--------|------|
| 0–63 | 单字节，高 2 bit = 00 |
| 64–16383 | 双字节，首字节高 2 bit = 01 |
| 16384–1073741823 | 四字节，首字节高 2 bit = 10 |
| 1073741824–2^62-1 | 八字节，首字节高 2 bit = 11 |

### 3.4 DHT 路由表同步

QUIC 连接建立后，节点根据 Noise IK 握手确定的 PeerID，将对方加入 DHT 路由表。路由表同步通过 DHT RPC（§4）完成，不依赖独立线协议。

---

## 4. DHT 协议 (Kademlia)

### 4.1 概述

- 256-bucket Kademlia 路由表
- k=20 每桶
- α=3 并发查找
- SHA-256 距离度量（XOR）
- Ed25519 签名防伪造
- 6 种 RPC 消息

### 4.2 消息格式

```
[0]       版本号 (0x01)
[1..16]   消息 ID (随机 16 bytes)
[17]      类型字节 (低 7 bit = msg_type, bit 7 = is_response)
[18..49]  发送者 PeerID (32 bytes)
[50..52]  payload 长度 (3 bytes, 大端)
[53..]    payload
[payload_end..]  Ed25519 签名 (64 bytes, 可选)
```

**消息类型：**

| 值 | 类型 | 说明 |
|----|------|------|
| 0x00 | PING | 保活 + 路由表同步 |
| 0x01 | STORE | 存储 PeerRecord |
| 0x02 | FIND_VALUE | 查找 peer 记录 |
| 0x03 | FIND_NODE | 查找最近节点 |
| 0x04 | RELAY_NEEDED | 请求中继候选 |
| 0x05 | ERROR | 错误响应 |
| 0x06 | ADDR_REFLECT | 地址反射 |

响应消息：类型字节 bit 7 置 1。

### 4.3 PeerRecord (STORE 负载)

```
[0..31]    key = PeerID (SHA-256 of Ed25519 pubkey)
[32..35]   TTL (u32, 大端, 单位秒. 0 或 >3600 则 clamp 至 300)
[36..67]   Ed25519 公钥 (32 bytes)
[68..99]   X25519 noise 公钥 (32 bytes)
[100..101] endpoints 数据长度 (u16, 大端)
[102..]    endpoints 数据 (§4.4)
```

接收端验证：`SHA-256(Ed25519公钥) == key`，否则拒绝。

### 4.4 Endpoint 编码

```
[0]       addr_kind: 0=IPv4, 1=IPv6
[1..]     address: IPv4(4 bytes IP + 2 bytes port) 或 IPv6(16 bytes IP + 2 bytes port)
[kind]    endpoint_kind: 0=IPv6, 1=STUN, 2=LAN, 3=WebSocket, 4=Relay, 5=TSO (1 byte)
[ttl]     ttl_seconds: u32 大端 (4 bytes)
```

注意：DHT STORE 消息中的 endpoint 编码**不含 priority 字节**（与 invite 编码不同），总长 = addr_len + 1 + 4。

### 4.5 DHT RPC 语义

**PING**：请求无 payload。响应含 k-closest 节点列表（count: u8, 后跟 [PeerID: 32 bytes, addr: 7/19 bytes] 重复）。

**STORE**：payload = PeerRecord（§4.3）。响应为 ACK（1 byte status = 0）。

**FIND_VALUE**：payload = PeerID (32 bytes)。若本地有未过期 record，响应 `[0x01] + record_payload`（flag 1 开头）。否则响应 `[0x00] + node_count: u8 + k-closest nodes`（flag 0 开头）。

**FIND_NODE**：payload = target PeerID (32 bytes)。响应含 k-closest 节点列表。

### 4.6 签名验证

非响应消息必须携带 Ed25519 签名（消息末尾 64 bytes）。验证逻辑：

1. 签名全零 → 跳过验证（未签名的消息）。例外：FIND_VALUE 响应若签名全零且 `message_id` 不匹配任何本地待处理查询（`pending_queries`），直接丢弃以防御签名绕过攻击。
2. 本地 peer_records 中有 sender_id → 用其 Ed25519 pubkey verify_strict(body, sig)
3. 本地没有 sender_id → 接受（deferred verification，后续 STORE 记录会提供 pubkey）

**签名覆盖范围**：消息头 + payload（不含末尾 64 bytes 签名）。

---

## 5. NAT 穿透

### 5.1 STUN 探测

启动时向 STUN 服务器发送 Binding Request + CHANGE-REQUEST：

1. 基础 Binding Request → 获取 MAPPED-ADDRESS / XOR-MAPPED-ADDRESS
2. CHANGE-REQUEST（设置 Change Port flag）→ 比较两次端口
3. 同端口 → Cone NAT；不同 → Symmetric NAT
4. 跨服务器验证：若第二个 STUN 服务器返回的端口与第一次不同 → APDF Symmetric

**默认 STUN 服务器：** `stun.miwifi.com:3478`, `stun.qq.com:3478`, `stun.l.google.com:19302`

### 5.2 连接建立优先级

1. IPv6 全局地址直连（任一方有全局 unicast 即可，非对称发起）
2. STUN 发现地址直连
3. P2P 中继转发（通过任意 Cone NAT 或 IPv6 可达节点的 pipe_connections）

---

## 6. InviteCode

### 6.1 格式

```
encode_payload 布局：
[0]       version (1 byte, 当前 0x01)
[1..32]   peer_id (32 bytes)
[33..64]  ed25519_pk (32 bytes)
[65..96]  noise_pk (32 bytes, X25519)
[97]      capabilities (1 byte, bitmask)
[98..99]  mappable_port_start (u16, 大端)
[100..101] mappable_port_end (u16, 大端)
[102]     port_delta_hint (u8)
[103]     ep_count (u8, 最多 255)
[104..]   endpoints (§6.2)
[...]     timestamp (u64, 大端, Unix 秒)
[...]     Ed25519 signature (64 bytes)
```

编码为 Base62 字符串（字符集：`0-9A-Za-z`），前缀 `lain://` 构成完整 URI。

### 6.2 Invite Endpoint 编码（与 DHT STORE 不同）

```
[0]       addr_kind: 0=IPv4, 1=IPv6
[1..]     address: IPv4(4+2) 或 IPv6(16+2)
[kind]    endpoint_kind: 0=IPv6, 1=STUN, 2=LAN, 3=WebSocket, 4=Relay, 5=TSO (u8)
[priority] priority: u8    // v0.1.2+: 写固定值 128（保留字段，运行时不再用于排序）
[ttl]     ttl_seconds: u32 大端

**注意：** invite 中的 endpoint 编码**含 priority 字节**，与 DHT STORE 中的 endpoint 编码不同。

### 6.3 验证

接收端必须验证：`SHA-256(ed25519_pk) == peer_id` 且 `noise_pk` 非全零。

### 6.4 有效期

生成后 30 分钟内有效（`is_expired()` 检查 `now - timestamp > 1800`）。

---

## 7. Relay 中继

### 7.1 中继请求

节点 A 无法直接连接节点 C 时，向已知中继节点 B 发送 RelayConnect 帧：

```
RelayConnect payload: [requester_peer_id: 32 bytes] [target_peer_id: 32 bytes]
```

### 7.2 中继流程

1. A → B: QUIC 连接 + RelayConnect(target=C) 帧
2. B 在 DHT 中查找 C (find_peer)
3. B → C: QUIC 连接 (connect_internal)
4. B 调用 pipe_connections(A_conn, C_conn) 建立双向管道
5. 管道每方向 30s accept_bi 超时，断开时自动查找新 relay 迁移

---

## 8. IPC API

应用通过本地 IPC 与 daemon 通信。

**Unix：** Unix Domain Socket `~/.lain/socket`  
**Windows：** Named Pipe `\\.\pipe\lain`

### 8.1 协议

每行一条 JSON（`\n` 分隔），tagged union（基于 `cmd`/`type` 字段区分方向）。

### 8.2 应用 → Daemon 请求

#### Connect — 连接 peer

```json
→ {"cmd":"Connect","invite":"lain://..."}
← {"type":"Ok","message":"connecting: lain://..."}
← {"type":"Event","event":"peer_connected","peer_id":"..."}
← {"type":"Event","event":"connection_failed","error":"..."}
```

#### Whoami — 查看自己的 PeerID

```json
→ {"cmd":"Whoami"}
← {"type":"Ok","message":"a1b2c3d4e5f6a7b8"}
```

#### GetInvite — 获取邀请码

```json
→ {"cmd":"GetInvite"}
← {"type":"Ok","message":"lain://5KncdUB060WGkVZU..."}
```

#### ListPeers — 查看网络状态

```json
→ {"cmd":"ListPeers"}
← {"type":"Ok","data":{"peer_id":"...","nat_type":"APDFSymmetric","ipv6":true,"ipv6_addr":"2001:db8::1","port_delta":1,"stun_rtt_ms":45,"dht_nodes":3,"known_peers":5,"connected_peers":2,"peers":["..."]}}
```

#### Send — 发送数据到已连接 peer

`data` 字段为 Base64 编码的字节。`peer_id` 必须为 64 位十六进制 PeerID。
Send 是同步操作——daemon 确认数据已提交后返回响应。

```json
→ {"cmd":"Send","peer_id":"a1b2c3d4","data":"aGVsbG8="}
← {"type":"Ok","message":"sent"}

→ {"cmd":"Send","peer_id":"a1b2c3d4","data":"aGVsbG8="}
← {"type":"Error","code":"NOT_CONNECTED","message":"no active connection to a1b2c3d4"}

→ {"cmd":"Send","peer_id":"a1b2c3d4","data":"aGVsbG8="}
← {"type":"Error","code":"SEND_FAILED","message":"open: ..."}

→ {"cmd":"Send","peer_id":"invalid","data":"aGVsbG8="}
← {"type":"Error","code":"INVALID_ID","message":"invalid PeerID: invalid"}

→ {"cmd":"Send","peer_id":"a1b2c3d4","data":"!!base64??"}
← {"type":"Error","code":"INVALID_DATA","message":"base64 decode: ..."}
```

#### Subscribe — 订阅事件流

```json
→ {"cmd":"Subscribe"}
← {"type":"Ok","message":"subscribed"}
← {"type":"Event","event":"peer_connected","peer_id":"..."}
← {"type":"Event","event":"data","peer_id":"...","data":{"bytes":"aGVsbG8="}}
← {"type":"Event","event":"peer_disconnected","peer_id":"..."}
```

#### Disconnect — 断开连接

```json
→ {"cmd":"Disconnect","peer_id":"a1b2c3d4"}
← {"type":"Ok","message":"disconnected"}

→ {"cmd":"Disconnect","peer_id":"invalid"}
← {"type":"Error","code":"INVALID_ID","message":"invalid PeerID: invalid"}
```

#### Shutdown — 停止 daemon

```json
→ {"cmd":"Shutdown"}
← {"type":"Ok","message":"shutting down"}
```

### 8.3 Daemon → 应用事件

```json
← {"type":"Event","event":"peer_connected","peer_id":"a1b2c3d4"}
← {"type":"Event","event":"data","peer_id":"a1b2c3d4","data":{"bytes":"aGVsbG8="}}
← {"type":"Event","event":"peer_disconnected","peer_id":"a1b2c3d4"}
← {"type":"Error","code":"ERR","message":"reason"}
← {"type":"Ok","message":"optional message","data":{...}}
```

### 8.4 应用示例

**Python (Unix)：**

```python
import socket, json
s = socket.socket(socket.AF_UNIX)
s.connect("/home/user/.lain/socket")

# 先订阅事件（避免错过 peer_connected 通知）
s.send(b'{"cmd":"Subscribe"}\n')

# 连接 peer
s.send(b'{"cmd":"Connect","invite":"lain://..."}\n')

# 发送数据
s.send(b'{"cmd":"Send","peer_id":"a1b2c3d4","data":"aGVsbG8="}\n')
s.send(b'{"cmd":"Disconnect","peer_id":"a1b2c3d4"}\n')

# 监听事件
while True:
    ev = json.loads(s.recv(4096))
    if ev.get("event") == "data":
        import base64
        raw = base64.b64decode(ev["data"]["bytes"])
        print(f"收到 {len(raw)} bytes 来自 {ev['peer_id']}")
```

**Python (Windows)：**

```python
import json, base64, win32file
handle = win32file.CreateFile(
    r"\\.\pipe\lain",
    win32file.GENERIC_READ | win32file.GENERIC_WRITE,
    0, None, win32file.OPEN_EXISTING, 0, None)

win32file.WriteFile(handle, b'{"cmd":"Whoami"}\n')
_, data = win32file.ReadFile(handle, 4096)
print(json.loads(data))
```

---

## 9. 发现路径

节点上线时可从以下来源构建初始 DHT 路由表：

1. **invite**（§6）—— 解析对端 invide 后 QUIC 连接 + DHT 地址交换
2. **mDNS** —— 局域网 `_lain._udp.local` 服务发现，收到事件后发 PING
3. **routes.json** —— 上次运行保存的路由表（启动时 load，心跳时 save）
4. **peers.json** —— 已知 peer 地址列表（Ed25519 签名防篡改）

**不需要公共 bootstrap 节点。** 社交关系 = 网络入口。

---

## 10. 实现注意事项

### 10.1 安全性

- Ed25519 公钥永不通过网络传输其对应的私钥 seed
- DHT STORE 消息验证 `SHA-256(pubkey) == key` 防止伪造
- Noise IK 握手提供前向安全和身份隐藏
- peer_records 中的 pubkey 由签名消息验证，不可伪造
- InviteCode 签名防止篡改端点列表

### 10.2 兼容性

- 协议版本号嵌入 DHT 消息首字节和 InviteCode
- 不兼容的版本将收到 ERROR 响应
- routes.json / peers.json 使用 JSON 格式（含版本字段），损坏时丢弃重建

### 10.3 端口

- QUIC Transport 绑定随机端口（`0.0.0.0:0` 或 `[::]:0`）
- DHT UDP socket 绑定独立随机端口
- STUN 探测使用临时 UDP socket
- IPv6 可用时优先双栈绑定 `[::]:0`
