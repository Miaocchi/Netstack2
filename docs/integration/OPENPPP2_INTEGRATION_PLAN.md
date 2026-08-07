# OpenPPP2 集成规划

> **状态**: read-only audit + 集成规划 (对应 NETSTACK2-002 并行工作)。
> 本文档主体是只读审计和规划; 未接 submodule、未改 OpenPPP2 构建、未替换 lwIP。
> API freeze 前只允许 compile-only adapter spike 验证公共契约; 真实 OpenPPP2
> 构建依赖和运行时接线仍在 `NETSTACK2-API-FREEZE-001` 之后 (P4)。
> 架构基线见 `docs/architecture/NETSTACK2_ARCHITECTURE.md`; 任务进度见 `docs/roadmap.md`。
> 审计基于本地 `/home/openppp2` (当前工作区, 不含 `.tmp-v215-src` 备份)。

## 1. 审计范围与方法

对照范围 (只读):

* `ppp/ethernet/VNetstack.cpp/.h` — lwIP/原生 NAT 核心;
* `ppp/ethernet/VEthernet.cpp/.h` — 包分发与 SSMT 分片;
* `linux/ppp/tap/TapLinux.cpp/.h` — Linux TUN (Ssmt/SsmtMQ);
* `ppp/ethernet/VNetstack.h` 中的 `TapTcpLink`/`TapTcpClient`;
* `ppp/app/client/VEthernetNetworkTcpipStack/Connection`;
* `ppp/app/ApplicationConfig.cpp` — 配置解析;
* `ios/OpenPPP2PacketTunnelBridge.cpp` + `ios/App/OpenPPP2PacketTunnel/*.swift`;
* `android/libopenppp2.cpp` + `OpenPPP2VpnProtectBridge/TelemetryBridge`;
* `windows/ppp/tap/WintunAdapter.cpp/.h` + `TapWindows.cpp`;
* 根 / Linux / Android / iOS / Windows CMake;
* `common/libtcpip/netstack.h` — lwIP 胶水接口;
* `VNetstack.cpp` 中 `vnetstack.*` telemetry 计数。

结论综述: OpenPPP2 当前是 **单线程同步收包 + 每连接线程/strand + 内核 socket
转发** 的模型。TCP 热路径上 lwIP 只在一处被实际接线 (`VEthernet.cpp:616`),
Android 已硬编码 `lwip=false`, iOS/Windows 的 lwIP 开关由配置/host 决定。
Netstack2 的插入点集中在 `VEthernet` 的包分发点 (唯一 true 分叉点)。

## 2. 现有链路与调用图

### 2.1 通用 TUN→TCP→转发 主路径

```
OS tunnel (NEPacketTunnelFlow / tun_fd / Wintun ring)
        ↓
ITap 实现 (TapIos / TapLinux / TapWindows)
        ↓ 读入 ITap::_packet[MTU+4] 可复用 buffer, 同步 OnInput
TAP_PACKET_INPUT_EVENT                  VEthernet.cpp:450-501
        ↓
VEthernet::PacketInput 分发              VEthernet.cpp:594-653
        ├─ lwip_==true  → lwip::netstack::input(iphdr, len)   :616-618
        └─ 否则          → netstack->Input(iphdr, tcphdr, tcp_len)
                                  ↓
        VNetstack::Input  (NAT + 简化状态机)                  VNetstack.cpp:453-719
                                  ↓
        BeginAcceptClient (客户端)                            VNetstack.cpp:566
                                  ↓
        VEthernetNetworkTcpipStack::BeginAcceptClient         ...Stack.cpp:33-143
                                  ↓
        VEthernetNetworkTcpipConnection::ConnectToPeer        ...Connection.cpp:174-322
                                  ↓
        出站内核 socket: Rinetd 直连 / VMUX / VPN transmission
```

### 2.2 双重 TCP 终结路径 (lwIP 模式, 要删除)

```
TAP 客户端包
   ↓
lwip::netstack::input → lwIP pbuf → 内部 PCB 终结 TCP
   ↓ accept 回调 → LwIpBeginAccept            VNetstack.cpp:1406-1573
   ↓ 合成 SYN-ACK (netstack_wrap_ipv4_tcp_syn_packet)
   ↓ 入 loopback 内核 socket (127.0.0.1:NAT_port)
   ↓ SocketAcceptor accept → TapTcpClient     VNetstack.cpp:1013-1118
   ↓ 内核再次终结 loopback TCP
   ↓ 转发层 (Rinetd/VMUX/VPN) → 远端
```

即: **lwIP 终结一次 TCP + loopback 内核再终结一次 TCP** 的双重终结。
Netstack2 目标是: `IPacketQueue → StackShard → TcpFlow → ITransportSession`,
在引擎内一次终结, 删除 loopback accept 腿。

### 2.3 原生 SSMT 路径 (native, 参考架构)

```
lwip_==false + ssmt_>0 + mta_
   ↓ TapLinux::Ssmt: 每 worker 一个 TUN fd           TapLinux.cpp:1794-1851
   ↓ 每 fd 独立 async_read_some 循环                 TapLinux.cpp:1853-1881
   ↓ ssmt_tls_.tun_fd_ 线程本地 fd → OnInput
   ↓ PacketSsmtInput 4-tuple 哈希 → worker io_context   VEthernet.cpp:275-327
   ↓ netstack->Input (NAT + 简化状态机)
   ↓ Output → ::write(线程本地 fd) 无锁回写           TapLinux.cpp:1768-1792
```

这是 Netstack2 的 **参考实现**: 每 queue 固定 owner 线程、无锁回写、
流按 4-tuple 哈希分片。Netstack2 用 `IPacketQueue` + `StackShard` 重新表达
同一不变量, 并补全完整 TCP 状态机 (OpenPPP2 的 `VNetstack::Input` 只是
NAT helper, 无 seq/ack 校验、无 RTO、无重组、无窗口)。

## 3. Netstack2 Adapter 插入点

### 3.1 唯一 true 分叉点: `VEthernet::PacketInput`

所有平台、所有 ITap 实现最后都汇入 `VEthernet.cpp:594-653` 的分发。
这里现在是:

```cpp
if (tcp 且 lwip_)  → lwip::netstack::input(...)      // 或 pbuf 变体
else               → netstack->Input(iphdr, tcphdr, tcp_len)
```

Netstack2 需要一个新的三分支:

```cpp
if (stack == netstack2)  → netstack2_engine.input(IP 包)
else if (lwip_)          → lwip::netstack::input(...)   // 回退保留
else                     → netstack->Input(...)         // native 保留
```

`--stack=lwip|netstack2|native` 在启动阶段解析, 同一实例只启用一个 engine,
不做热切换。

### 3.2 出站点: `VEthernet::Output` → `tap->Output`

`VEthernet.cpp:997-1016`。Netstack2 `TcpFlow` 出站包必须经过同一出口
(TUN 回写 / Wintun SendPacket / iOS flow.writePackets)。这意味着 Netstack2
需要一个 `IPacketIo` 适配器, 其 `SendBatch` 落到现有 `ITap::Output`, 或
`IPacketQueue` 直接包装 OS tunnel fd (Linux)。

### 3.3 传输层: `ITransportSession` ↔ OpenPPP2 转发层

现有出站由 `TapTcpClient` (内核 socket) + `VEthernetNetworkTcpipConnection::ConnectToPeer`
完成。Netstack2 的 `KernelSocketSession` 对应这条腿; 替换关系:

| OpenPPP2 现有 | Netstack2 对应 |
|---|---|
| `TapTcpClient` (asio tcp::socket) | `KernelSocketSession` |
| `SocketAcceptor` + loopback accept | 删除 (不再 loopback) |
| `BeginAcceptClient` 虚接口 | `KernelSocketSession` 连接建立 |
| `VEthernetNetworkTcpipConnection::ConnectToPeer` | 保留为转发层, session 直连远端 |
| Onload socket | `OnloadSocketSession` |
| DPDK 出站 | `DpdkSession` (UserspaceSession) |

## 4. 可直接复用的逻辑

### 4.1 SYN-ACK 重试引擎 (P3B 优先迁移)

`VNetstack.cpp:1895-2245`:

* 固定退避 200/400/800/1200/1600 ms (`:2222-2233`);
* CAS `sync_ack_state_` `SYN_SENT→SYN_RECVD` 防重入 (`AckAccept`);
* 原子包缓存 `sync_ack_byte_array_` (由 `VNetstack::Output` 填充);
* 收到 ACK 取消 (`:651-665`)、`EndAccept` 取消。

这是协议无关的, 可直接平移到 Netstack2 的 `TcpFlow` retransmission。

### 4.2 原子流 link 设计

`TapTcpLink` (`VNetstack.h:42-130`): `state/accepting/closed/lastTime` 全
atomic, CAS-accept 防重复 SYN (`VNetstack.cpp:552-561`)。Netstack2 的
flow table 沿用该模式, 但改成单 shard 线程内非原子 + owner 断言。

### 4.3 多队列 TUN 模式 (NETSTACK2-003 对齐)

`TapLinux::Ssmt`: 每 worker 一个 fd + 线程本地 fd 无锁回写
(`TapLinux.cpp:1768-1881`)。这正是 NETSTACK2-003 `TapPacketIo` 每 queue
一个 `IPacketQueue` + owner shard 固定的模型。注意:
`TapLinux::OpenDriver` (`:752-816`) 的 `/dev/tun`→`/dev/net/tun` 回退和
`IFF_MULTI_QUEUE`→单队列回退 (`:783-799`) 必须复刻。

### 4.4 zero-copy 工程

* `ITap::_packet[MTU+4]` 单 buffer 复用 (`ITap.h:249`);
* `BufferswapAllocator` 池化 buffer;
* `TapLinux::Output` 同步 `::write` 零分配零拷贝 (`:1790`)。

Netstack2 的 `PktBufferPool`/`BufferLease` 吸收这些工程经验, 并加上严格
所有权 (cross-thread 归还走 owner return queue)。

### 4.5 VMUX FakeClock / DeliveryOracle 确定性测试

OpenPPP2 已有确定性测试经验 (FakeClock 等), 直接用于 Netstack2 的
TimerWheel / TcpFlow 测试。

## 5. 必须删除或旁路的 lwIP/loopback 路径

1. **`VEthernet.cpp:612-618`** 的 `lwip::netstack::input` 调用点:
   `--stack=netstack2` 时旁路, `--stack=lwip` 时保留为回退。
2. **`VNetstack::LwIpBeginAccept` / `LwIpAcceptLink` / `lwipKey` PCB 匹配**
   (`VNetstack.cpp:1406-1573`, `VNetstack.h:337`): netstack2 模式全部旁路。
3. **loopback accept 腿**: `VNetstack::Open` 的 `SocketAcceptor` +
   `ProcessAcceptSocket` (`VNetstack.cpp:334-392, 1013-1118`):
   netstack2 模式删除, 改为 session 直连远端。
4. **`lwip::netstack_pbuf_*` 系列** (`common/libtcpip/netstack.h`):
   netstack2 模式不分配 pbuf。
5. **mta/SSMT lwIP pbuf 分支** (`VEthernet.cpp:460-495`): 仅 lwIP 模式需要。

lwIP 代码与 loopback 腿在迁移期保留 (回退), 由启动期 engine 选择旁路,
不做运行中热切换、不做源码级删除。

## 6. 配置项设计

`ApplicationConfig.cpp` (651 行) 需要新增 (架构文档 §17 已定):

```text
--stack=lwip|netstack2|native
--linux-datapath=auto|tc-hairpin|afxdp|netmap|dpdk|tun
--netstack-shards=N
--netstack-rx-queues=N
--netstack-pool-capacity=N
--netstack-cpu-affinity=...
```

配置解析位置: `ppp/app/ApplicationConfig.cpp` (新增解析 + 存储), 通过
`ApplicationConfiguration` 流到 `VEthernetNetworkSwitcher` 构造参数, 再传入
`VEthernet::Open` / `TapLinux` / `VNetstack`。**启动阶段完成**, 不进热路径。

注意 `ApplicationConfig.cpp` 现有结构与 options 命名须先审计再接线 (见 §8 已知风险)。

## 7. 平台差异

### 7.1 iOS (唯一潜在 lwIP 平台)

* 桥: `ios/OpenPPP2PacketTunnelBridge.cpp` (1394 行), Swift adapter:
  `ios/App/OpenPPP2PacketTunnel/OpenPPP2PacketTunnelAdapter.swift`.
* `mta=false` 硬编码 (`Bridge.cpp:804`) → SSMT 分片从未启用, 单 runtime 线程
  内联处理。架构文档 §20 要求修正该限制, 允许 shard 1~2。
* 收包: NEPacketTunnelFlow → Swift 拷入 Data → `openppp2_ios_tap_input` →
  `TapIos::Input` 拷入 `ITap::_packet` → 同步 OnInput。无异步包所有权。
* 出包背压: `PacketFlowOutputQueue.swift` + `readBackpressureDelay = 5ms`。
* 生命周期: `openppp2_ios_tap_create/start/stop` + `start_runtime` 5 MiB 栈
  单 pthread; iPhone 线程数 `min(max_concurrent, 2)` (`:745-748`)。
* Netstack2: `TapIos`→`TapIosIo` (IPacketIo), shard 1~2, `KernelSocketSession`
  复用现有转发层。

### 7.2 Android (已 lwip=false)

* 主桥: `android/libopenppp2.cpp` (~2080 行 JNI)。`lwip=false` 硬编码
  (`:1635`), 一直走 VNetstack 原生路径。
* TUN: `PppVpnService.kt` `builder.establish()` → `detachFd()` →
  `set_network_interface(tunFd,...)` (`:578-604`); `run(0)` 在 32 MiB 栈线程。
* `TapLinux::From(context, dev, tun_fd, ...)` (`libopenppp2.cpp:1556-1579`),
  `VEthernetNetworkSwitcher(..., lwip=false, mta=(max_concurrent>1), ...)`
  (`:1640`)。
* socket protect: `OpenPPP2VpnProtectBridge.cpp` JNI `protect(fd)`。
* Netstack2: `TapLinux` 已是 `IPacketIo` 候选 (Linux 回退路径), 默认
  shard 1~2, 电量/温控策略留 P6。

### 7.3 Windows

* `windows/ppp/tap/WintunAdapter.cpp/.h` + `TapWindows.cpp`。
* Wintun: `WintunStartSession(adapter, MAX_RING_BUFFER_SIZE=1<<20)`
  (`:32`), 独立 "wintun" 接收线程 (`:354-423`)。
* 收包指针仅在 `WintunReleaseReceivePacket` 前有效 → `OnInput` 必须同步消费
  (`TapWindows.cpp:470-488`)。若 Netstack2 引入异步收包, 此约束会破坏,
  必须让 `TapWindowsIo` 同步把 Wintun 包拷入 pool buffer。
* 出包: `TapWindows::Output` → `WintunAllocateSendPacket` + memcpy +
  `WintunSendPacket` (`WintunAdapter.cpp:285-327`)。
* lwIP 开关由 host 决定 (需进一步确认 host 传入值)。
* Netstack2: `WintunIo` (IPacketIo), 多 queue 能力探测, `KernelSocketSession`。

### 7.4 通用约束

* 所有平台收包目前是**同步单包** (async_read_some 单 shot / 同步 handler)。
  Netstack2 `RecvBatch` 批量语义需要桥接层聚合; Linux TUN batch read 在
  NETSTACK2-003 ✅, iOS/Android/Windows 聚合留 P6。
* 所有平台 `ITap::_packet` 是**栈/成员内复用 buffer**, 非池化。Netstack2
  要求 `RecvBatch` 产出 `BufferLease`, 桥接层必须改为从
  `PktBufferPool` 分配后再交给 handler。

## 8. 文件级改动矩阵 (P4)

| 文件 | 改动 | 阶段 |
|---|---|---|
| `ppp/ethernet/VEthernet.cpp/.h` | PacketInput 三分支 (netstack2/lwip/native); mta/SSMT 适配 | P4 |
| `ppp/ethernet/VNetstack.cpp/.h` | 保留 native; netstack2 模式旁路 lwIP/loopback; session 接线 | P4 |
| `ppp/app/ApplicationConfig.cpp/.h` | `--stack`/`--linux-datapath`/`--netstack-*` 解析 | P4 |
| `linux/ppp/tap/TapLinux.cpp/.h` | `TapPacketIo` 对齐 (NETSTACK2-003 ✅); Ssmt/SsmtMQ 复刻 | P4 + 003 ✅ |
| `ios/OpenPPP2PacketTunnelBridge.cpp` | `mta=false` 修正; `TapIosIo` 接线 | P4/P6 |
| `ios/App/.../OpenPPP2PacketTunnelAdapter.swift` | 收包改 pool buffer; batch | P6 |
| `android/libopenppp2.cpp` | `lwip=false` → 读配置; `TapLinuxIo` 接线 | P4/P6 |
| `android/OpenPPP2VpnProtectBridge.cpp` | 不变 (socket protect 与 engine 无关) | — |
| `windows/ppp/tap/WintunAdapter.cpp/.h` | `WintunIo` 接线; 收包拷入 pool | P4/P6 |
| `windows/ppp/tap/TapWindows.cpp` | 同上 | P6 |
| 根 CMakeLists.txt | 接 submodule `common/libtcpip2` | P4 |
| Android/iOS/Windows CMake | 引入 libtcpip2 链接 | P4 |
| `common/libtcpip/netstack.h` | 保留 (lwIP 回退), 不动 | — |

## 9. P4 前置条件

1. ~~`NETSTACK2-002H/003/004` 完成~~ ✅, compile-only adapter spike 验证通过,
   `NETSTACK2-API-FREEZE-001` 通过
   (public header 精确签名冻结);
2. GitHub SSH 恢复 + `git submodule add git@github.com:Miaocchi/netstack2.git
   common/libtcpip2` (禁止本地绝对路径写 `.gitmodules`);
3. `--stack`/`--linux-datapath` 配置解析落地并验证启动期单引擎选择;
4. 至少一个平台 (建议 Linux) 完成 `TapPacketIo` 端到端冒烟;
5. lwIP 回退路径验证仍可用 (差分测试基线)。

## 10. 不在 002–004 阶段接线的部分

* submodule 添加与 OpenPPP2 构建改动 (等 API-FREEZE);
* `VEthernet::PacketInput` 三分支代码 (等 stack 可用);
* TC/eBPF + kernel hairpin NAT (OPENPPP2-LINUX-DP-001/002, 属于 Linux
  adapter, 不在 Netstack2 核心);
* AF_XDP / netmap / DPDK 后端接线 (P5);
* Android/iOS/Windows 平台适配 (P6);
* Onload / EF_VI session (P5/P7)。

允许的唯一例外是 compile-only adapter spike: 它只验证 public header 是否足以
表达 Packet I/O、Session 创建、路由元数据和 shutdown, 不合入默认数据路径,
不添加 submodule, 不替换 lwIP。

## 11. 已知风险与未决点

* **`common/libtcpip` 命名冲突**: 现目录是 lwIP 胶水 (`netstack.h`),
  未来 submodule 名 `common/libtcpip2` 不冲突, 但 CMake target 需确认
  不与现 lwIP target 重名。
* **Windows host lwIP 开关**: 未确认 host (MFC/WPF/console) 是否传
  `lwip=true`; 影响 Windows 侧回退基线。
* **Android/iOS TUN fd 线程**: 现模型是单线程同步; Netstack2 shard 线程
  需改为池化 buffer + 批量 Recv, 桥接层改动量中等。
* **iOS `mta=false` 修正**: 涉及 PacketTunnelProvider 生命周期与后台限制,
  需单独评估。
* **`TapTcpClient` 线程模型**: 现用 per-connection strand; Netstack2 改为
  单 owner shard, `KernelSocketSession` 回调必须回投 owner shard (§4.4)。
* **NAT helper vs 完整 TCP**: OpenPPP2 `VNetstack::Input` 只是 NAT/状态机
  helper, 不能直接复用为 TCP 栈; 只有 SYN-ACK retry 与原子 link 模式可迁移。
* **差分测试基线**: P4 前需建立 lwIP vs Netstack2 vs Linux 三路差分。

## 12. 结论

OpenPPP2 → Netstack2 的插入点高度集中:

```text
OS tunnel
  → ITap (同步收包)
  → VEthernet::PacketInput (唯一分叉点)
      ├─ netstack2 → IPacketQueue → StackShard → TcpFlow
      ├─ lwip (回退, 保留)
      └─ native (VNetstack, 保留)
  → VEthernet::Output → ITap (出站不变)
```

净效果: 删除 lwIP 终结 + loopback 内核终结的双重路径; 保留
`KernelSocketSession` 复用现有 Rinetd/VMUX/VPN 转发层; lwIP 全程回退可用。
NETSTACK2-002H/003/004 已完成, 期间不触碰 OpenPPP2 默认构建与运行时接线; 仅允许
compile-only adapter spike 验证公共 API。
