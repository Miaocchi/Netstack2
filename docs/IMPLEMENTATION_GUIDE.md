# Netstack2 详细实施方案

> 状态: 可执行实施基线
>
> 编制日期: 2026-08-08
>
> 代码基线:
> - Netstack2 `a29ed2f`, 其中 `NETSTACK2-002` 实现提交为 `8e20940`;
> - OpenPPP2 `f56c8c6`;
> - UCP `927cb83`, MIT License。
>
> 本文回答“下一步具体做什么、在哪些文件做、接口如何划分、如何验证”。总体
> 架构边界见 `docs/architecture/NETSTACK2_ARCHITECTURE.md`, 进度记录见
> `docs/roadmap.md`, OpenPPP2 现状审计见
> `docs/integration/OPENPPP2_INTEGRATION_PLAN.md`。

## 1. 执行结论

Netstack2 按以下原则推进:

1. Netstack2 保持独立 C++17 静态库, 核心只依赖标准库和 Threads。
2. 多线程采用“流固定分片 + shard 内 run-to-completion”, 不允许多个线程同时
   操作同一 TCP/UDP/UCP 流。
3. 第一条可交付数据路径是 L3 TUN, 先完成 IPv4/IPv6、UDP/ICMP 和 TCP 代理终结,
   再扩展 AF_XDP、DPDK、Wintun、utun 和 Android VpnService。
4. TCP 拥塞控制使用统一 delivery-rate sampler, 提供 KCC 和 BBR 可切换实现。
   算法在创建连接时确定, 已建立连接不热切换。
5. 出口调度采用 per-shard FQ-CoDel: DRR 公平队列 + CoDel AQM + ECN 优先标记。
   拥塞控制、pacing、FQ 和 AQM 是四个独立层, 不合并为一个类。
6. UCP 是可靠 UDP 传输, 不是 IPv4/IPv6 UDP 层本身。UCP 保持独立库, 通过
   OpenPPP2 adapter 接入; Netstack2 不直接依赖 UCP 的 Boost.Asio 和线程模型。
7. OpenPPP2 的 lwIP 和 native 路径在迁移期保留。引擎只允许启动期选择,
   不做运行中切换。
8. TC/eBPF、nftables、conntrack 和 kernel hairpin NAT 属于 OpenPPP2 Linux
   adapter。AF_XDP 和 DPDK 才是 Netstack2 Packet I/O 后端。
9. 公共 API 冻结前必须完成一个 OpenPPP2 compile-only adapter spike。当前 API
   尚缺 Session 创建、目标地址、路由决策、Packet I/O capabilities 和完整关闭契约,
   不能按原路线直接冻结。
10. 仿真结果只验证算法确定性, 不作为吞吐结论。KCC、BBR、FQ/AQM 最终必须通过
    Linux netem、真实 TUN 和真实 NIC 测试。

## 2. 当前事实与差距

### 2.1 Netstack2 当前状态

已实现:

- `PktBufferPool`、`BufferLease`、`BufferSlice`、`BufferRef`;
- `IPacketIo`、`IPacketQueue` 和 `NullPacketIo`;
- thread ownership guard;
- 1 ms 确定性 timer wheel;
- PacketBuilder、PCAP、FakeClock 和单元测试框架;
- 普通、ASan/UBSan、TSan 和 include-boundary 构建入口;
- `Netstack2::Start/Stop` runtime(owns per-shard pools + dispatcher + shards);
- `PacketDispatcher`(queue→shard 和 flow→shard 映射);
- `StackShard` 线程、10 步 event loop、bounded SPSC/MPSC inbox;
- `FlowKey` canonical ordering + FNV-1a hash + golden vectors;
- `IpAddress`(IPv4+IPv6 统一);
- Linux `TapPacketIo`(`/dev/net/tun`, `IFF_TUN|IFF_NO_PI`, 可选
  `IFF_MULTI_QUEUE`, 逐包 `read`/`write` syscall 循环, runtime 注入 pool)。

尚未实现:

- KCC 拥塞控制（当前为 stub, ADR-006 已就绪）;
- FQ-CoDel / AQM 出口调度（P3Q）;
- UCP、Onload、AF_XDP、DPDK 的运行时接线;
- IPv6 扩展头完整遍历（当前仅 Fragment header）;
- Session 实现类（ITransportSession 接口已冻结，无实现类）;
- OpenPPP2 真实 adapter（P4-7 smoke test 已通过, 真实 OpenPPP2 仓库 adapter 待 P4-04）。

冻结 API 前必须先修复的契约问题:

- `BufferLease::Resize()` 当前允许长度超过 capacity;
- pool 操作需要验证 buffer 确实属于当前 pool;
- 当前 `BufferRef` 可复制但手工 `Unpin()` 一次的语义容易提前释放;
- `NullPacketIo::SetRecvHandler()` 尚未形成可验证的唤醒闭环;
- `Netstack2::Start()` 当前只设置布尔值, 未拥有任何 runtime 依赖。

  *(002H 已修复 Resize/pool identity/BufferRef/wake 契约; 003+004A 已实现
  真实 runtime, 但 `Start()` 签名仍是旧版 `Start(IPacketIo*)`, 需在
  API-FREEZE 阶段替换为 `Start(RuntimeDependencies)`。)*

### 2.2 OpenPPP2 当前状态

OpenPPP2 的统一入口是 `/home/openppp2/ppp/ethernet/VEthernet.cpp` 中的
`VEthernet::PacketInput()`。当前 TCP 路径为:

```text
ITap callback
  -> VEthernet::PacketInput
     -> lwIP input, 或
     -> VNetstack::Input
  -> loopback accept / Kernel socket / VMUX / VPN transmission
```

内嵌 lwIP 的关键限制位于
`/home/openppp2/common/lwip/my/lwipopts.h`:

| 配置 | 当前值 | 影响 |
|---|---:|---|
| `NO_SYS` | 1 | lwIP 核心是单线程轮询模型 |
| `LWIP_TCP` | 1 | TCP 开启 |
| `LWIP_UDP` | 0 | UDP 不由 lwIP 处理 |
| `LWIP_IPV6` | 1 | 编译开启, 但 OpenPPP2 TCP 胶水仍主要是 IPv4 |
| `MEMP_NUM_TCP_PCB` | 16 | 并发连接上限很低 |
| `TCP_WND` | 32 KiB | 高 BDP 链路吞吐受限 |
| `TCP_SND_BUF` | 32 KiB | 发送窗口受限 |
| `MEM_SIZE` | 128 KiB | 全局内存池受限 |

因此不能通过简单调大 lwIP 参数解决多核扩展和双重 TCP 终结问题。

### 2.3 UCP/KCC 当前状态

`https://github.com/liulilittle/ucp` 当前包含:

- C++17 和 C# 的可靠 UDP 协议;
- KCC2.0 Geodesic, 状态机为 STARTUP/DRAIN/PROBE_BW;
- delivery bandwidth、RTT、LT bandwidth、ACK aggregation 和可选 ECN;
- SACK、NAK、RTO、FEC、CID migration;
- pacing token bucket;
- server 侧 credit round-robin fair queue;
- Linux `tcp_kcc.c` 的 `tcp_congestion_ops` 实现。

可复用边界:

- KCC 用户态核心参考 `cpp/include/ucp/ucp_cc.h` 和 `cpp/src/ucp_cc.cpp`;
- pacing 参考 `cpp/include/ucp/ucp_pacing.h` 和 `cpp/src/ucp_pacing.cpp`;
- TCP KCC 行为参考 `linux/tcp_kcc.c`;
- 算法对齐向量参考 `cpp/tests/ucp_kcc_alignment_tests.cpp`。

不能直接整体嵌入 Netstack2 核心, 原因是 UCP C++ 库依赖 Boost.Asio, 且当前连接
对象带有独立 worker/notify/timer 线程。Netstack2 目标是固定数量 shard, 不能回到
per-connection thread。

## 3. 产品范围

### 3.1 第一阶段必须交付

- L3 IPv4/IPv6 输入、解析、校验和、分流和输出;
- ICMPv4/ICMPv6 必要控制报文和 PMTU;
- UDP flow tracking、datagram 转发和超时回收;
- 完整 TCP 基础状态机、重组、重传、窗口和常用 options;
- KCC/BBR per-flow 选择和 pacing;
- per-shard FQ-CoDel 与 ECN;
- Linux TUN 单队列和多队列;
- OpenPPP2 Linux opt-in 集成和 lwIP fallback;
- 确定性测试、差分测试、netem、sanitizer 和 benchmark。

### 3.2 后续交付

- Android VpnService、iOS utun、Windows Wintun;
- AF_XDP、DPDK、netmap;
- Onload socket session;
- UCP carrier 和 UCP datagram session;
- DPDK 纯用户态 active TCP/UDP egress;
- TC/eBPF + nftables hairpin NAT;
- GSO/GRO/TSO/checksum offload 和 NUMA 调优。

### 3.3 明确不做

- 第一版不提供 POSIX/BSD socket API;
- 不在 Netstack2 核心管理系统路由、DNS、nftables 或 conntrack;
- 不在 BPF 程序里重写完整 TCP/IP 或有状态 NAT;
- 不承诺所有平台绝对零拷贝, 目标是 copy-minimized;
- 不做已建立 TCP flow 的 shard migration;
- 不做已建立 TCP flow 的 KCC/BBR 热切换;
- 不把标准 UDP datagram 强制变成可靠有序 UCP stream。

## 4. 目标数据路径

### 4.1 OpenPPP2 TCP 代理路径

```text
VpnService / utun / Wintun / TUN
  -> OpenPppPacketIo
  -> RX queue owner StackShard
  -> IPv4/IPv6 parser
  -> TcpFlow (终结客户端 TCP)
  -> ISessionFactory::OpenTcp(original destination, policy metadata)
  -> KernelSocketSession / OnloadSocketSession / UcpStreamSession
  -> OpenPPP2 Rinetd / VMUX / VPN transmission
```

该路径删除 lwIP PCB 到 loopback socket 的第二次 TCP 终结。TUN 侧 TCP 是虚拟本地
腿, 其 advertised window 必须反映 Session 背压。真实公网拥塞由远端 Session 所用
传输控制:

- kernel/Onload socket 使用实际 socket 的拥塞控制;
- UCP Session 使用 UCP KCC;
- DPDK 全用户态 active TCP 使用 Netstack2 KCC/BBR。

不要在同一真实瓶颈上无条件叠加两个互不知情的拥塞控制器。

### 4.2 DPDK/AF_XDP 纯用户态路径

```text
NIC RX queue
  -> DpdkPacketIo / AfXdpPacketIo
  -> StackShard
  -> L2 shim (Ethernet, ARP/NDP)
  -> IPv4/IPv6
  -> TcpFlow / UdpFlow
  -> route + neighbor + same PacketIo TX queue
```

“支持 DPDK”不只是实现 `RecvBatch/SendBatch`。纯用户态出站还需要:

- Ethernet framing;
- ARP/NDP neighbor cache;
- route lookup;
- source address selection;
- active TCP open 或 UDP output;
- PMTU 和 ICMP 处理;
- checksum/offload metadata。

这些作为 P5B 独立工作包交付, 不阻塞 OpenPPP2 TUN 代理路径。

### 4.3 UCP 路径

```text
OpenPPP2 payload/datagram
  -> UcpAdapter
  -> UCP packet codec + recovery + KCC pacing
  -> UDP socket / Onload UDP / DPDK UDP port
```

Netstack2 与 UCP 的关系:

- Netstack2 提供 IPv4/IPv6、UDP I/O 和通用 shard/runtime;
- UCP 提供可靠 UDP wire protocol 和 KCC 控制;
- OpenPPP2 adapter 决定哪些业务走 UCP;
- 两者可共享时钟、buffer、pacing/FQ 设计, 但不共享可写 PCB。

### 4.4 Linux TC/eBPF hairpin 路径

```text
TC ingress/egress
  -> classify / mark / redirect
  -> nftables + conntrack DNAT/SNAT
  -> kernel hairpin 或 Netstack2 PacketIo
```

该路径放在 `/home/openppp2/linux/`。失败时必须事务性回滚并回退到 TUN/Netstack2,
不能留下半套 clsact/nft 规则。

## 5. 并发与所有权模型

### 5.1 FlowKey 与分片

`FlowKey` 必须同时支持 IPv4 和 IPv6:

```cpp
struct FlowKey {
    IpAddress source;
    IpAddress destination;
    std::uint16_t source_port;
    std::uint16_t destination_port;
    std::uint8_t protocol;
};
```

要求:

- 解析时保留网络字节序, hash 前转换为定义明确的 canonical bytes;
- 双向 flow 使用 canonical endpoint ordering, 保证正反向落在同一 shard;
- hash 算法和 seed 固定并有 golden vector, 不能使用进程随机的 `std::hash`;
- RSS/XDP 已正确分流时直接 queue-to-shard;
- queue 与 canonical hash 不一致时通过 bounded SPSC 转发给 owner shard;
- shard 数量启动后不改变, 避免 flow remap。

### 5.2 StackShard event loop

每个 shard 固定拥有:

- 一个或多个 RX/TX queues;
- flow table;
- timer wheel;
- buffer pool;
- SPSC packet inbox;
- MPSC control/session inbox;
- FQ-CoDel scheduler;
- shard-local counters。

每轮 event loop 按固定预算执行:

```text
1. drain foreign-thread returned buffers
2. receive RX batch
3. drain redirected packet inbox
4. drain session/control inbox
5. advance timers
6. run protocol work with packet/byte budget
7. run pacing + FQ/AQM
8. send TX batch and reap completions
9. publish counters
10. poll, wait, or yield
```

每一步都有 budget, 防止 RX flood 饿死 timer、ACK 或 shutdown。默认建议从
`64 packets / 256 messages / 1 ms timer quantum` 开始, 由 benchmark 调整。

### 5.3 跨线程消息

禁止跨线程投递任意闭包和 `TcpFlow*`。消息必须为有限 variant:

```cpp
using ShardMessage = std::variant<
    PacketInputMessage,
    SessionConnectedMessage,
    SessionDataMessage,
    SessionWritableMessage,
    SessionClosedMessage,
    ConfigEpochMessage,
    StopMessage>;
```

每个 Session callback 携带 `FlowId + generation`, owner shard 在处理前验证 generation。
这样可拒绝 flow 已销毁后的迟到 callback。

### 5.4 Buffer 所有权

- `BufferLease`: move-only, 可以跨线程, 析构回 owner pool;
- `BufferSlice`: 非 owning view, 不能进入异步 callback;
- `BufferRef`: shard-local RAII retained handle, 使用非原子 shard-local 引用计数;
- Packet I/O TX completion 持有 `BufferLease`, completion 后归还;
- TCP retransmission queue 持有 `BufferRef + BufferSlice`;
- OpenPPP2 callback 提供的临时 TUN/Wintun/Swift Data 内存在 callback 返回后失效,
  必须先复制或直接接收到 pool buffer。

不允许继续使用“`BufferRef` 任意复制, 但调用者只手工 Unpin 一次”的契约。

### 5.5 生命周期

启动顺序:

```text
validate config
  -> create pools/shards
  -> open queues
  -> bind queues to shards
  -> start shard threads
  -> barrier: all shards ready
  -> enable receive callbacks
  -> RUNNING
```

关闭顺序:

```text
RUNNING
  -> reject new flows
  -> disable receive callbacks
  -> close/cancel Packet I/O waits
  -> post StopMessage
  -> drain session callbacks and TX completions
  -> abort remaining flows with bounded deadline
  -> join shards
  -> verify pools outstanding == 0
  -> STOPPED
```

`Stop()` 必须幂等, 且不得在 shard 自己的线程上 join 自己。

## 6. 冻结前公共接口

以下接口已通过 OpenPPP2 compile-only adapter 验证(ADR-003)。代码片段表达语义,
不是要求照抄最终签名。新增公共头: `address.h`、`flow.h`、`capabilities.h`、
`session_factory.h`。

### 6.1 Runtime 依赖

```cpp
struct RuntimeDependencies {
    IPacketIo* packet_io;       // 必须非 null
    ISessionFactory* session_factory;  // 必须非 null
    IClock* clock;              // 可 null, 默认 SystemClock
    IEventSink* event_sink;     // 可 null
};

class Netstack2 {
public:
    bool Start(const RuntimeDependencies& deps) noexcept;
    bool Start(IPacketIo* io = nullptr) noexcept;  // 兼容旧调用
    void Stop() noexcept;
};
```

`RuntimeDependencies` 已正式引入 `netstack.h` 和 `runtime_deps.h` 公共头。
`IClock` (`clock.h`) 提供 `NowMs()/NowUs()` 抽象接口，`SystemClock` 为默认实现。
`IEventSink` (`events.h`) 定义 flow event 和 metric snapshot 报告接口。
旧 `Start(IPacketIo*)` 保留为兼容入口，不注入 session factory / clock / event sink；内部桥接到新接口。
StackShard 热路径 EventLoopIteration 已使用 `clock_->NowMs()` 替代直接 `steady_clock` 调用。

### 6.2 Session 创建

当前 `ITransportSession` 只描述已存在 Session 的读写。`session_factory.h`
已定义 `ISessionFactory`、`TcpOpenRequest`、`UdpOpenRequest`、`IpEndpoint`、
`FlowId`(公共头, `shard_message.h` 通过 include 复用), adapter spike 验证
签名可表达完整路由元数据:

```cpp
struct TcpOpenRequest {
    FlowId flow_id;
    IpEndpoint source;
    IpEndpoint original_destination;
    IpEndpoint resolved_destination;
    std::uint32_t route_mark;
    std::uint8_t dscp;
};

class ISessionFactory {
public:
    virtual SessionOpenResult OpenTcp(const TcpOpenRequest&) = 0;
    virtual DatagramOpenResult OpenUdp(const UdpOpenRequest&) = 0;
};
```

OpenPPP2 的 fake-IP、Direct/Proxy 路由、DNS、QUIC policy 和 VPN transmission
选择都在这个 factory adapter 中完成, 不进入 Netstack2 core。

### 6.3 Packet I/O capabilities

后端需声明(`capabilities.h` 已定义 `PacketIoCapabilities` 结构体,
`IPacketIo::Capabilities()` 返回此类型; adapter spike 验证 OpenPppPacketIo
可正确传播 MTU/queue_count 等元数据):

- L2 或 L3;
- MTU 和必要 headroom;
- queue 数量和 queue affinity;
- polling/event 模式;
- RX/TX checksum offload;
- scatter/gather、GSO/GRO/TSO;
- async TX completion;
- 是否支持 zero-copy pool import;
- shutdown/cancel wait 能力。

不能根据 backend 名称在协议核心里写分支。

### 6.4 配置

建议新增:

```cpp
enum class TcpCongestionAlgorithm { Kcc, Bbr };
enum class AqmAlgorithm { None, CoDel };

struct QosConfig {
    std::size_t flow_bucket_count;
    std::size_t queue_byte_limit;
    std::uint32_t quantum_bytes;
    std::uint64_t codel_target_us;
    std::uint64_t codel_interval_us;
    bool ecn;
};
```

配置分三类:

- immutable: shard_count、queue mapping、pool layout、flow hash seed;
- new-flow only: KCC/BBR、TCP options、per-flow limits;
- live atomic: telemetry interval 和日志级别。

### 6.5 可观测性

统计读取使用 shard-local counter + 周期性 snapshot, 热路径不做全局 atomic increment。
至少输出:

- RX/TX packet/byte/drop/error;
- queue depth、redirect、WouldBlock、completion latency;
- active TCP/UDP flows 和各 TCP state;
- RTT、RTO、retransmit、SACK、cwnd、pacing rate、delivery rate;
- KCC/BBR mode;
- FQ active flows、CoDel drop、ECN mark、sojourn P50/P99;
- pool free/outstanding/return queue;
- Session backpressure 和 pending bytes。

## 7. 目标文件布局

```text
include/tcpip2/
  address.h
  buffer.h
  config.h
  flow.h
  netstack.h
  packet_io.h
  session_factory.h
  transport_session.h
  stats.h

src/core/
  dispatcher.cpp
  shard.cpp
  flow_hash.cpp
  inbox_spsc.h
  inbox_mpsc.h
  timer_wheel.cpp
  runtime.cpp

src/ip/
  checksum.cpp
  ipv4.cpp
  ipv6.cpp
  extension_headers.cpp
  fragment.cpp
  icmp4.cpp
  icmp6.cpp
  pmtu.cpp

src/udp/
  flow.cpp
  input.cpp
  output.cpp

src/tcp/
  flow.cpp
  state.cpp
  input.cpp
  output.cpp
  options.cpp
  reassembly.cpp
  retransmission.cpp
  rate_sampler.cpp

src/cc/
  controller.h
  kcc.cpp
  bbr.cpp
  pacer.cpp

src/qos/
  fq_scheduler.cpp
  codel.cpp
  ecn.cpp

src/session/
  socket_session.cpp
  userspace_session.cpp

src/packetio/
  null_io.cpp
  tap_io.cpp
  push_adapter_io.cpp
  afxdp_io.cpp
  dpdk_io.cpp

src/l2/
  ethernet.cpp
  arp.cpp
  ndp.cpp
  neighbor_cache.cpp
  route.cpp
```

公开头只放跨仓库稳定契约。TCP PCB、拥塞控制内部状态、FQ queue 和平台 fd
不得进入 `include/tcpip2/`。

## 8. 详细工作包

### NS2-001: P0 基线测量

目标: 在替换前固定 lwIP/native 的可复现基线。

实施:

1. 完成 `bench/run_p0.sh`, 不再只输出 schema。
2. 固定 1/2/4/8 shard、1/16/256/4096 flow、IPv4/IPv6、TCP/UDP 场景。
3. 记录吞吐、pps、P50/P99、CPU、context switch、分配、memcpy 和 RSS。
4. OpenPPP2 分别跑 lwIP、native SSMT 单队列和多队列。
5. 原始 JSON 入 `bench/results/`, 报告中保留 commit、机器和内核信息。

退出条件:

- 同一机器连续 5 次, 核心指标变异系数小于 5%;
- 结果可通过 schema;
- benchmark 失败返回非零, 不生成伪成功记录。

### NS2-002H: Buffer/Packet I/O 加固 ✅ Completed

目标: 在并发 runtime 建立前关闭所有权漏洞。

实施文件:

- `include/tcpip2/buffer.h`;
- `src/core/buffer.cpp`;
- `src/core/buffer_pool.cpp`;
- `src/packetio/null_io.cpp`;
- 对应 unit tests。

任务(全部完成):

1. ✅ `Resize(n)` 在 `n > Capacity()` 时 abort, 不再静默越界。
2. ✅ `ReturnBuffer/ReleaseRetained` 验证 `pkt->pool_ == this` 和 slot/address 一致。
3. ✅ 将 `BufferRef` 改为 shard-local RAII 非原子 retain count, 删除模糊手工释放。
   `PktBuffer` 增加 `ref_count_` 字段; BufferRef 复制 `++ref_count_`, 析构 `--ref_count_`,
   最后一个引用归还 pool; 删除 `PktBufferPool::Unpin(BufferRef)`, 改为 `BufferRef::Reset()`
   和 RAII 析构自动管理; 新增 `PktBufferPool::ReleaseRetained(PktBuffer*)` 私有方法。
4. ✅ 构造 pool 时处理 arena 分配失败, 不留下半初始化对象。
5. ✅ `NullPacketIo::Inject()` 从空变为非空时触发 wake, handler 在锁外调用避免死锁;
   `SetRecvHandler(nullptr)` 清除 handler。
6. ✅ 固定空 lease、partial batch、error/no-transfer 语义(已有测试覆盖)。

退出条件(已全部通过):

- 跨 pool、double release、oversize resize death tests 全部通过;
- ASan/UBSan/TSan 全绿;
- 热路径无每包 atomic refcount。

关键设计决策:

- `PktBuffer::ref_count_` 使用非原子 `std::uint32_t`, 仅允许 owner shard
  读写; 该计数不进入跨线程所有权协议, 热路径不增加 atomic 操作;
- `PktBuffer` 继续保持 trivially destructible 和 standard layout, 由
  `static_assert` 固定类型契约;
- `BufferRef` 的析构、赋值、`Reset()` 和 `Release()` 等重方法 out-of-line
  定义在 `src/core/buffer_pool.cpp`, 由该实现单元处理完整的 `PktBufferPool`
  类型和 retained release 逻辑;
- `NullPacketIo` 只在持锁期间复制 wake handler, 在解锁后调用, 允许 handler
  安全回调 `RecvBatch()` 而不发生自死锁。

### NS2-004A: Dispatcher 和 StackShard runtime ✅ Completed

依赖: NS2-002H。可与 NS2-003 并行。

实施(全部完成):

1. ✅ 实现 canonical `FlowKey` 和固定 hash golden vectors。`FlowKey::Canonical()`
   使用 (address, port) pair 比较做双向排序; `FlowHash()` 使用 FNV-1a over
   canonical bytes(family byte + address bytes + big-endian port bytes +
   protocol byte), 不使用 `std::hash`。
2. ✅ 实现 bounded SPSC 和 MPSC inbox, 满时返回明确 drop/backpressure。SPSC
   是 lock-free(atomic head/tail, power-of-2 capacity); MPSC 使用
   mutex+condvar(control inbox 不是热路径)。
3. ✅ 使用 `NullPacketIo` 完成真实 `Start/Stop` 和 event loop。10 步 event
   loop, budget 64 packets / 256 messages。
4. ✅ 实现 queue-to-shard direct mapping 和 software redirect。
   `PacketDispatcher` 支持 queue→shard 和 flow→shard 双重映射。
5. ✅ callback 使用 `FlowId + generation` 回投。
6. ✅ event loop 所有阶段增加 budget 和 starvation counters。Counters 使用
   `std::atomic<std::size_t>`(relaxed ordering) 保证 TSan 安全。
7. ✅ CPU affinity 失败只记录并继续, 除非配置要求 strict。

测试(全部通过):

- 同 flow 正反向始终同 shard(canonical ordering + golden vector);
- 4 producer 并发控制消息(MPSC PostMessage 多线程 stress);
- inbox 满、shutdown、late callback、partial TX;
- 100× Start/Stop 循环(验证幂等性和线程安全);
- TSan 多 shard stress 全绿。

退出条件(已全部通过):

- 无 flow pointer 跨线程;
- shutdown 后 callback 数为 0;
- 所有 pool outstanding 为 0;
- 同输入、同配置的调度结果确定。

实现文件: `include/tcpip2/address.h`、`include/tcpip2/flow.h`、
`src/core/flow_hash.cpp`、`src/core/inbox_spsc.h`、`src/core/inbox_mpsc.h`、
`src/core/shard_message.h`、`src/core/shard.h`、`src/core/shard.cpp`、
`src/core/dispatcher.h`、`src/core/dispatcher.cpp`、`src/core/runtime.h`、
`src/core/runtime.cpp`、`src/core/netstack.cpp`、
`tests/unit/flow_hash_test.cpp`、`tests/unit/inbox_test.cpp`、
`tests/unit/dispatcher_test.cpp`、`tests/unit/shard_runtime_test.cpp`、
`tests/unit/runtime_test.cpp`。

关键设计决策:

- `ShardMessage` 仍使用 struct 而非 `std::variant`, 保持向后兼容; variant
  留到 API-FREEZE 阶段。
- `shard_message.h` 从 `shard.h` 提取, 解决 `shard.h ↔ inbox_mpsc.h` 循环依赖。
- `Stop()` 幂等, 且不在 shard 自己的线程上 join 自己。
- `IpAddress` 访问器方法命名为 `family()` 而非 `Family()`, 避免 enum 名与方法名冲突。

### NS2-003: Linux TUN/TAP Packet I/O ✅ Completed

依赖: NS2-002H。可与 NS2-004A 并行。

实施(全部完成):

1. ✅ `tap_io.cpp` 打开 `/dev/net/tun`, 兼容 `/dev/tun` 回退。
2. ✅ 支持 `IFF_TUN | IFF_NO_PI`, 可选 TAP, 可选 `IFF_MULTI_QUEUE`。
3. ✅ 每 queue 一个非阻塞 fd, 一个 owner shard。
4. ✅ 第一版使用逐包 `read`/`write` syscall 循环(非 `readv`/`writev`),
     不引入 io_uring。
5. ✅ EAGAIN 映射 `WouldBlock`, EINTR 重试有上限(3 次), permanent error
   (EBADF) 关闭 queue。
6. ✅ fd 设置 `O_CLOEXEC`, 非阻塞模式; Stop 时解除 callback 并唤醒 poll。
7. ✅ 对齐 OpenPPP2 `TapLinux::OpenDriver` 的 multi-queue fallback 行为。

测试(全部通过):

- 无 root 环境 capability probe 后 graceful skip(10 个单元测试);
- `TapQueue` 通过 `SetBufferPool()` 注入 owner shard 的 per-shard pool
  (ADR-001 v2), 不再使用 `GlobalTapPool()`, 也不再共享单一 runtime pool;
- partial write、close-during-read 和 fd leak 覆盖;
- 003 与 004A 组合形成 packet-in/drop/packet-out 闭环(通过 runtime_test
  使用 NullPacketIo 验证)。

退出条件(已全部通过):

- 普通/ASan/UBSan/TSan 全绿(18/18);
- 非 root 环境测试可执行且 graceful skip;
- 003 与 004A 组合形成 packet-in/drop/packet-out 闭环。

实现文件: `include/tcpip2/tap_io.h`、`src/packetio/tap_io.cpp`、
`tests/unit/tap_io_test.cpp`。

关键设计决策:

- `TapQueue::RecvBatch` 通过 `SetBufferPool()` 注入的 per-shard pool
  分配 buffer(ADR-001 v2)。原 `GlobalTapPool()` 方案已废弃:全局 pool 的
  return_queue_ 无人 drain,会导致 buffer 泄漏。原单 runtime pool 方案也有
  问题:所有 shard 竞争同一 `PktBufferPool::mutex_`,owner-thread fast path
  对非 owner shard 是死代码。现改为每 shard 一个 pool,`SetOwnerThread()`
  在 shard `Run()` 开头调用,热路径 owner-local uncontended(mutex 仍
  获取,但仅 owner shard 线程竞争,无跨 shard 锁竞争)。
- RX/TX 使用逐包 `read`/`write` syscall 循环, 不是 `readv`/`writev`。
  当前版本不做 syscall 批量化。

### NS2-ADAPTER-SPIKE: 冻结前 OpenPPP2 适配验证 (Completed)

依赖: NS2-002H 的接口草案, 不依赖完整 TCP。

目标: 只验证 API, 不改变 OpenPPP2 默认运行路径。

实施(已完成):

1. ✅ 在 `tests/unit/openppp_adapter_spike_test.cpp` 实现 compile-only
   `OpenPppPacketIo` 和 `OpenPppSessionFactory` stub。
2. 从 `VEthernet` 提供完整 IPv4/IPv6 packet bytes — adapter stub 验证
   `IPacketQueue::RecvBatch`/`SendBatch` 签名可接收完整 packet bytes。
3. ✅ 验证 route/fake-IP/DNS/QUIC/PMTU 元数据能够进入 Session factory
   (`OpenPppPacketIo::Config` 和 `OpenPppSessionFactory::Config` 携带
   route_mark/fake_ip_base/dns_servers/quic_policy/pmtu, capabilities
   传播到 `PacketIoCapabilities`)。
4. `ITap::Output`、Wintun 临时 buffer 和 iOS Data 生命周期 — 留给 P4
   实际接线验证(当前 spike 只验证公共 API 足够表达, 不接入真实平台)。
5. Stop 顺序验证 — spike 测试中 `stack.Start(&io)` / `stack.Stop()`
   正常工作, 无环回。
6. ✅ spike 不合入默认数据路径, 结论回写 ADR-003 和 public headers。

退出条件(已满足):

- ✅ Linux OpenPPP2 adapter translation unit 可编译;
- ✅ Android/iOS/Windows adapter compile contract — 留给 P4/P6
  (spike 验证公共 API 不含平台类型, 平台 adapter 可直接实现);
- ✅ public API 不需要 OpenPPP2、Boost 或平台类型;
- ✅ 可执行 `NETSTACK2-API-FREEZE-001`。

新增公共头: `address.h`(`IpAddress`)、`flow.h`(`FlowKey`)、
`capabilities.h`(`PacketIoCapabilities`)、`session_factory.h`(`FlowId`、
`IpEndpoint`、`TcpOpenRequest`、`UdpOpenRequest`、`SessionOpenResult`、
`DatagramOpenResult`、`ISessionFactory`)。`IPacketIo` 新增非纯虚
`Capabilities()`。`FlowId` 从 `shard_message.h` 统一到 `session_factory.h`。

### NS2-API-FREEZE-001 (Completed)

前置条件(全部满足):

- ~~NS2-002H、003、004A 完成~~ ✅;
- ~~buffer pool 改为 per-shard pool(ADR-001 v2)~~ ✅;
- ~~`SetBufferPool` 改为纯虚~~ ✅;
- ~~NS2-ADAPTER-SPIKE 完成~~ ✅ (ADR-003);
- 普通、ASan/UBSan、TSan 全绿 ✅ (19/19);
- ~~TUN multiqueue 真实测试通过(ADR-002 Tier 2)~~ ✅
  (`TapMultiqueueTier2RootTest` root 下 4-queue TUN 收发验证通过);
- buffer pool 所有权验证通过(ADR-001 v2: per-shard pool,
  `SetBufferPool` 纯虚注入, `SetOwnerThread` 在 shard `Run()` 中调用) ✅;
- lifecycle、partial send、callback generation 和 capabilities 契约已测试 ✅。

冻结后任何公开签名变更都需要 ADR 和 consumer compile test。

完成总结: 公共 API 冻结完成: 10 个公共头文件(`address.h`、`buffer.h`、`capabilities.h`、`config.h`、`flow.h`、`netstack.h`、`packet_io.h`、`session_factory.h`、`tap_io.h`、`transport_session.h`)签名冻结。`compile_contract_test.cpp` 中 `static_assert` 固定所有 frozen 类型属性。测试证据: 普通 19/19, ASan 19/19, TSan 19/19, root TUN Tier 2 PASS, include boundaries OK, git diff --check CLEAN。ADR-004 记录完整冻结清单。

### P3A: IPv4/IPv6 和 ICMP

实现顺序:

1. ✅ 只读 cursor parser, 所有 length 计算使用 checked arithmetic (`src/ip/checked.h`: `ReadCursor` + `CheckedMul`/`CheckedAdd`)。
2. ✅ IPv4 version/IHL/total length/checksum/fragment validation (`src/ip/ipv4.h`/`.cpp`)。
3. ✅ IPv6 fixed header/payload length/next-header validation (`src/ip/ipv6.h`/`.cpp`)。
4. ✅ IPv6 extension header bounded walker, 设置最大 header 数(8)和总字节数(1024), loop detection (`src/ip/ipv6.cpp`)。
5. ✅ TCP/UDP IPv4/IPv6 pseudo-header checksum (`src/ip/checksum.h`/`.cpp`: `InternetChecksum`、`Ipv4PseudoHeaderSeed`、`Ipv6PseudoHeaderSeed`)。
6. ✅ ICMPv4 Destination Unreachable、Fragmentation Needed (`src/ip/icmpv4.h`/`.cpp`)。
7. ✅ ICMPv6 Destination Unreachable、Packet Too Big、Parameter Problem (`src/ip/icmpv6.h`/`.cpp`)。
8. ✅ PMTU cache 带最小/最大值、过期和来源验证 (`src/ip/pmtu.h`/`.cpp`)。
9. ✅ 有界 IPv4/IPv6 fragment reassembly (`src/ip/fragment.h`/`.cpp`)。

#### P3A-01 完成总结 (2026-08-07)

步骤 1–5 已完成。实现文件:

- `src/ip/checked.h` — `ReadCursor` 类 + `CheckedMul`/`CheckedAdd` 模板。
- `src/ip/checksum.h` / `src/ip/checksum.cpp` — RFC 1071 `InternetChecksum`、IPv4/IPv6 pseudo-header seed。
- `src/ip/ipv4.h` / `src/ip/ipv4.cpp` — bounded IPv4 parser with IHL validation + checksum verification。
- `src/ip/ipv6.h` / `src/ip/ipv6.cpp` — bounded IPv6 parser with extension header walker (max 8 headers, max 1024 bytes, loop detection)。

测试文件:

- `tests/unit/ip/checked_test.cpp` — 16 tests (CheckedMul 4, CheckedAdd 2, ReadCursor 10)。
- `tests/unit/ip/checksum_test.cpp` — 9 tests (InternetChecksum 5, Ipv4PseudoHeaderSeed 2, Ipv6PseudoHeaderSeed 2)。
- `tests/unit/ip/ipv4_parser_test.cpp` — 10 tests。
- `tests/unit/ip/ipv6_parser_test.cpp` — 11 tests。

测试结果: 普通 23/23, ASan 23/23, TSan 23/23, include boundaries OK。

#### P3A-02 完成总结 (2026-08-07)

步骤 6–8 已完成。实现文件:

- `src/ip/icmpv4.h` / `src/ip/icmpv4.cpp` — ICMPv4 bounded parser: 8 字节最小长度, Echo/EchoReply 读 id+sequence, DestUnreachable code 4 读 MTU, checksum 验证 (`InternetChecksum(data, len, 0) == 0`), 所有错误类型设置 `quoted_payload`。
- `src/ip/icmpv6.h` / `src/ip/icmpv6.cpp` — ICMPv6 bounded parser: 4 字节固定头 + 4 字节类型相关数据, PacketTooBig 读 MTU(u32), ParameterProblem 读 pointer(u32), Echo 读 id+sequence, `VerifyIcmpv6Checksum` 使用 IPv6 pseudo-header seed (protocol=58) + `InternetChecksum`。
- `src/ip/pmtu.h` / `src/ip/pmtu.cpp` — PMTU cache: per-shard (非 thread-safe), per-family clamp (`kPmtuMinV4=576`/`kPmtuMinV6=1280`/`kPmtuMaxV4=65535`/`kPmtuMaxV6=65575`/`kPmtuDefaultTtlMs=600000`), `LowerFromIcmp` (只降) / `RaiseFromProbe` (只升) 分离接口, `uint32_t` 输入和存储避免 32 位 MTU 截断, null 地址和非法 ip_version 拒绝, 容量上限 `kPmtuMaxEntries=4096`, oldest-update eviction, IPv4 地址以 IPv4-mapped IPv6 统一 16 字节比较, expired entry 重新初始化 (不参与只升/只降比较), clock rollback guard (`IsExpired` helper)。

测试文件:

- `tests/unit/ip/icmpv4_parser_test.cpp` — 10 tests (Echo parse, Echo Reply, DestUnreachable Fragmentation Needed + MTU, bad checksum, truncated, etc.)。
- `tests/unit/ip/icmpv6_test.cpp` — 11 tests (Echo, PacketTooBig + MTU, ParameterProblem + pointer, DestUnreachable, checksum verify good/bad, truncated, etc.)。
- `tests/unit/ip/pmtu_test.cpp` — 47 tests (Lookup/Update/Purge, oldest-update eviction, expiry, IPv4-mapped IPv6 distinct, per-family clamp <576 IPv4 / <1280 IPv6 / zero MTU / 超上限 / 32 位 MTU 截断 / boundary, null 地址和非法 ip_version 拒绝, LowerFromIcmp 只降 / RaiseFromProbe 只升, expired entry 重新初始化, clock rollback guard for Lookup/Purge/Lower/Raise, IPv6 max 65575 > uint16 range, 等)。

测试结果: 普通 26/26, ASan 26/26, TSan 26/26, include boundaries OK, `git diff --check` clean。

设计决策:

- ICMPv4 checksum 验证不阻止解析; `checksum_ok` flag 报告结果, bad checksum 包仍返回结构化解析结果。
- ICMPv6 checksum 需要 IP 地址构成伪首部, parser 不持有 IP 地址; `checksum_ok` 默认 true, 调用者通过 `VerifyIcmpv6Checksum` 独立验证。
- PMTU cache 设计为 per-shard 非 thread-safe; 调用者 (shard 线程) 保证线程安全。
- PMTU clamp 按地址族分别处理: IPv4 下限 576 (RFC 791), IPv6 下限 1280 (RFC 8200 §5), IPv4 上限 65535, IPv6 上限 65575 (40 + 65535, 非 jumbogram)。`PmtuEntry::pmtu` 和 `PmtuLookupResult::pmtu` 使用 `uint32_t` 存储以表示 IPv6 的 65575。接口接收 `uint32_t` 以正确处理 ICMPv6 PTB 的 32 位 MTU 值。
- PMTU 更新语义: `LowerFromIcmp` 只降不升 (ICMP 错误路径), `RaiseFromProbe` 只升不降 (探测成功路径)。两者均在 clamp 后与现有值比较。如果现有 entry 已过期 (包括 clock rollback 场景), 视为不存在并重新初始化, 不参与只升/只降比较。
- PMTU eviction 策略为 oldest-update (淘汰 `timestamp_ms` 最小的条目), 不是严格 LRU: `Lookup` 不更新 timestamp。
- PMTU 构造函数容量上限 `kPmtuMaxEntries=4096`, `reserve` 可能抛 `bad_alloc` — 构造函数非 `noexcept`。
- PMTU `NormalizeIp` / `Lookup` 拒绝 null 地址和非 4/6 的 `ip_version`, 避免越界读取。
- PMTU expiry 语义: `IsExpired(entry, now_ms)` helper 统一判断 — 当 `now_ms < timestamp_ms` (clock rollback) 或 `now_ms - timestamp_ms > expires_ms` 时为过期 (`==` 时仍有效)。`Lookup`、`Purge`、`LowerFromIcmp`、`RaiseFromProbe` 全部使用此 helper。

#### P3A-03 完成总结 (2026-08-07)

步骤 9 已完成。实现文件:

- `src/ip/fragment.h` / `src/ip/fragment.cpp` — 统一 IPv4/IPv6 fragment reassembly，copy-on-arrival 设计。`FragmentKey` 通过 `ip_version` 区分地址族 (IPv4 地址以 IPv4-mapped IPv6 统一存储 16 字节; IPv4 identification 16→32 位扩展, IPv6 identification 32 位)。`ReassemblyEntry` 持有 `std::vector<uint8_t> data_buffer_` 有界连续重组缓冲区; 每个 fragment 的 payload 在 `AddFragment` 时立即 `memcpy` 到 `data_buffer_` 对应 offset 位置 (copy-on-arrival, 不持有调用方指针, 无 UAF)。`FragmentPiece` 仅记录 offset 和 length, 不保存数据指针。重叠检测 (`HasOverlap`) 遍历已有 pieces, 任何区间相交直接拒绝。完成判定: `last_received_` (MF=0) 设 `total_payload_length_`, 按 offset 排序后检查 `[0, total_payload_length_)` 连续覆盖, 完成时 `std::move(data_buffer_)` 到 `FragmentAddResult::payload` (owning buffer 转移给调用方), entry 随即 `Reset()` 释放供 ID 复用。有界限制: `kMaxFragmentsPerEntry=64`, `kMaxFragmentPayloadBytes=65535` (per-datagram `max_payload_bytes` 参数, 0=使用默认; 调用方按实际 IHL/extension header 长度传入正确上限), `kMaxReassemblyEntries=256`, `kFragmentDefaultTtlMs=60000`。`FragmentReassembler` per-shard 非 thread-safe, per-shard byte budget (`max_total_bytes` 参数, 默认 16 MB), `FindOrCreate` 查找 → 重用空闲/过期 → 创建新 → 满返回 `TooManyEntries`。fragment_offset 从 8-byte units 到 byte offset 使用 `CheckedMul`, offset+length 使用 `CheckedAdd`, 超限返回 `PayloadTooLarge`。

关键安全与正确性机制:

- **Copy-on-arrival**: 分片数据在 `AddFragment` 时立即 `memcpy` 到 entry 拥有的 `data_buffer_`。调用方在 `AddFragment` 返回后即可释放 RX buffer, 不存在 UAF。
- **Owning buffer move**: 重组完成时 `std::move(data_buffer_)` 到 `FragmentAddResult::payload` (`std::vector<uint8_t>`), entry 随即 `Reset()` 释放, 立即允许相同 identification 的 ID 复用。
- **Fixed deadline**: `deadline_ms_` 在首个 fragment (`fragment_count_ == 0`) 时设置为 `now_ms + expires_ms`, 后续 fragment 不刷新 deadline。攻击者无法通过持续发送 fragment 续期 (trickle timeout attack)。
- **RFC 5722 IPv6 overlap**: IPv6 检测到 overlap 时设置 `discarded_ = true`, 后续所有 fragment 全部拒绝, 整个 datagram 被丢弃。IPv4 overlap 仅拒绝重叠的 fragment, 保留 entry。
- **MF=1 长度对齐**: `more_fragments=true` 时 payload length 必须是 8 的倍数, 否则返回 `InvalidFragment`。
- **DuplicateTerminal**: 第二个 MF=0 fragment 若 `end != total_payload_length_` 返回 `DuplicateTerminal`。若 `end == total_payload_length_` 且不重叠, 视为重传, 接受。
- **TerminalOverflow**: 已知末尾 (`last_received_`) 后, 任何 `end > total_payload_length_` 的 fragment 返回 `TerminalOverflow`。
- **Per-datagram max_payload_bytes**: 调用方按实际 IP header 长度 (IPv4 IHL) 或 extension header 长度 (IPv6) 传入正确的 payload 上限, 而非使用通用 65575 常量。IPv4 的 0 默认值使用保守 hard cap 65515, IPv6 使用 65535; 调用方传入更大值也会被协议 hard cap 钳制。
- **Per-shard byte budget**: `max_total_bytes` 参数限制所有 active entry 的 `data_buffer_` 总字节数。预算检查基于 `offset + length` 导致的实际 buffer 投影增长, 同时覆盖 existing entry 扩容和高 offset 稀疏首片; 超限返回 `ByteBudgetExceeded`。默认 16 MB (256 entries × ~64 KB)。
- **Reset() 保留容量**: `Reset()` 调用 `data_buffer_.clear()` 但不调用 `shrink_to_fit()`, 避免 `noexcept` 路径抛异常和反复分配。内存由 per-shard byte budget 和 per-entry 自然限制控制。
- **null/范围检查**: null `src_ip`/`dst_ip`/`payload`、零 `payload_len`、`payload_len > UINT32_MAX` 全部拒绝。非 0 offset 必须是 8 的倍数。
- **IsExpired**: `now_ms >= deadline_ms_` (deadline 是固定截止时间)。clock rollback 时 `now_ms < deadline_ms_` 视为未过期 (monotonic clock 假设)。
- **构造函数非 `noexcept`**: `entries_.reserve(max_entries_)` 可能抛 `bad_alloc`, 容量上限 `kMaxReassemblyEntries=256` 保证有界。

测试文件:

- `tests/unit/ip/fragment_test.cpp` — 44 tests: 在原 40 个重组、overlap、ownership、timeout 和资源上限用例基础上, 增加 existing entry budget growth、稀疏首片 budget、custom payload hard-cap 绕过和同 key 过期 entry 新 datagram 重建回归。

测试结果: 普通 44/44, ASan 44/44, TSan 44/44, include boundaries OK, `git diff --check` clean。

### P3U: UDP flow 和 datagram session

实现:

- IPv4/IPv6 UDP parse/output/checksum;
- UDP zero checksum 仅按 IPv4 规则接受, IPv6 必须校验;
- `UdpFlow` 按 5-tuple 单 shard;
- `IDatagramSession` 保留 message boundary;
- idle timeout、per-flow/global queue limit;
- ICMP error 映射和 PMTU;
- DNS 和 QUIC policy 继续由 OpenPPP2 SessionFactory 决定。

标准 UDP 不做重传和拥塞窗口。高吞吐 tunnel carrier 使用 UCP, 普通应用 UDP 只受
FQ/AQM、速率限制和 Session backpressure 约束。

### P3Q: Pacing、FQ 和 AQM

采用 per-shard FQ-CoDel, 不直接复用 UCP server 的全局 mutex/credit thread。

#### 调度层次

```text
Tcp/Udp packet generated
  -> congestion window eligibility (TCP only)
  -> per-flow pacer eligibility
  -> FQ DRR flow selection
  -> CoDel sojourn decision
  -> ECN CE mark or local drop
  -> PacketIo SendBatch
```

#### FQ

- hash 到固定数量 flow buckets;
- collision 使用小链或 secondary key, 不能把不同 flow 状态混为一个 PCB;
- new-flow/old-flow 两条 DRR list;
- quantum 默认不小于 MTU;
- 每 flow 记录 deficit、bytes、packets、head enqueue time 和 next pacing time;
- inactive queue 立即回收, bucket 内存有上限;
- ACK/control 使用独立 bounded priority queue, 不允许无界优先级绕过。

#### CoDel

- 依据 head packet sojourn time, 不依据总 queue length;
- 初始配置 `target=5 ms`, `interval=100 ms`, 必须允许平台 profile 覆盖;
- ECN 已协商时优先 CE mark;
- 不能 ECN 时 local drop;
- TCP 本地 drop 发生在“记录为 wire sent”之前, segment 保持 unsent 后续重排,
  不伪造公网 loss sample; scheduler 同时触发独立的 local-queue backpressure,
  暂停该 flow admission/pacing, 避免同一 segment 立即反复入队;
- UDP local drop 直接结束 datagram ownership 并计数;
- IPv4 CE mark 后重算 header checksum, IPv6 无 header checksum。

#### 内存上限

同时设置:

- per-flow packet/byte limit;
- per-shard byte limit;
- global byte limit;
- control queue hard limit;
- drop reason counters。

测试:

- 1/10/100/1000 flow Jain fairness;
- elephant + mice flow latency;
- ECN capable/not-capable;
- queue overload 后延迟回落;
- pacing timer wrap 和 clock jump;
- FQ hash collision;
- 任何输入下队列内存不超过配置上限。

### P3B: TCP 基础正确性

按以下子阶段实现, 每阶段都能用 PacketBuilder 和 FakeClock 独立验证。

#### P3B-1: PCB 和握手 ✅ Completed (2026-08-08)

- LISTEN、SYN-RECEIVED、ESTABLISHED、RST;
- secure ISN;
- SYN/SYN-ACK retry;
- 4-tuple duplicate SYN lookup;
- backlog、SYN flood 和 half-open 上限;
- MSS、Window Scale、SACK Permitted、Timestamp negotiation。

实现总结:

- `src/tcp/segment.h` / `.cpp` 和 `input.h` / `.cpp`: 有界 TCP header/data-offset/checksum parser, IPv4/IPv6 pseudo-header 校验, IP checksum/protocol/fragment gate; fragment 必须先经过 P3A reassembly。
- `src/tcp/options.h` / `.cpp`: allocation-free SYN option parser, 支持 EOL/NOP/unknown option, MSS、Window Scale (clamp 14)、SACK Permitted 和 Timestamp, 拒绝 truncated、非法长度和重复 known option。
- `src/tcp/isn.h` / `.cpp`: SipHash-2-4 keyed RFC 6528-style ISN, 单调 4 us tick 模型, Linux `getrandom()` 提供每次 shard start 的 128-bit CSPRNG secret; entropy 失败时 shard 启动失败而不降级。
- `src/tcp/handshake.h` / `.cpp`: shard-local bounded PCB table。无 PCB 的目标表示 transparent wildcard LISTEN; 新 SYN 进入 SYN-RECEIVED, 正确 ACK 进入 ESTABLISHED。exact 4-tuple duplicate SYN 复用 ISS/PCB/timer; per-destination listener backlog、per-shard half-open 和 total PCB 分别设 hard limit。被动 SYN-ACK 按固定 interval 重试并最终释放 quota; P3B-1 状态集合不含 SYN-SENT, active open 留到需要客户端 TCP 角色时单独扩展。
- option negotiation 只启用 peer 已提供且本地允许的能力。SYN/SYN-ACK window 字段按 RFC 7323 保持未缩放; IPv4/IPv6 MSS 按 path MTU 分别扣除 fixed header。Timestamp 每次 SYN-ACK/retry 更新 TSval, final ACK 必须携带匹配 TSecr。
- `src/tcp/output.h` / `.cpp`: 在调用方提供的 bounded buffer 内生成 IPv4/IPv6 SYN-ACK/RST, 包含 options、IP checksum 和 TCP checksum, 不引入额外 owning allocation。
- `StackShard` 已接通 RX parse → handshake → bounded control TX。TX hard limit 64, `SendBatch` WouldBlock/partial-send 尾部继续由 shard 持有; shutdown 在 owner thread 取消 timer、释放 PCB/TX。Timer callback 使用 weak lifetime gate, detached due callback 不会访问已销毁 engine; `TimerWheel::Schedule` 具备插入失败回滚。
- `tests/unit/tcp/handshake_test.cpp`: 23 tests, 覆盖 IPv4/IPv6 parse/output/checksum、malformed input、option negotiation、ISN golden vector/CSPRNG、SYN/ACK/RST、duplicate SYN、Timestamp final ACK、retry/timeout、backlog/half-open/SYN flood、shutdown callback lifetime 和 fragment gate。
- `tests/unit/shard_runtime_test.cpp`: 真实 NullPacketIo SYN→SYN-ACK 路径, 验证 WouldBlock 时 TX lease 保留后重试成功; control inbox 无容量时 Stop atomic fallback。

验证结果: 全量 CTest 普通 28/28, ASan/UBSan 28/28, TSan 28/28; TCP unit 23/23; include boundaries OK; `git diff --check` clean。实现提交 `ab5a949`, shard 接线提交 `a3448b4`, 文档提交 `c7d7428`。

#### P3B-2: 接收路径 ✅ Implemented (2026-08-09, pending commit)

- `RCV.NXT` 和 receive window validation;
- overlap/duplicate/out-of-window segment;
- bounded out-of-order reassembly;
- delayed ACK 和 immediate ACK rules;
- SACK block generation;
- Session `TrySend` partial acceptance;
- Session WouldBlock 时收缩 advertised window, writable callback 后恢复。

实现总结:

- `src/tcp/receive.h` / `.cpp`: construction-time 固定容量 sequence ring, byte storage + compact `uint64_t` occupancy bitmap, hot path 不分配。`first_undelivered` 与 `RCV.NXT` 分离, 因此已 cumulative-ACK 但尚未被 Session 接受的数据不会与新序列 alias。支持 32-bit sequence wrap、first-arrival-wins overlap、duplicate、双边 trim、RFC 9293 receive-window endpoint validation 和 gap fill。
- 接收内存同时设 per-flow capacity 和 per-shard memory budget。建立连接时一次性预留 ring; 超预算拒绝建立并释放 PCB。`ready + out-of-order == bytes-held`, advertised window 从剩余容量推导。
- 持久 `RCV.ADV` 单独记录已公告右边界。Session WouldBlock 时 wire window 立即降为 0, 但仍接受落在此前正窗口内的在途数据; writable 恢复后通过 window-update ACK 扩展右边界, 不发生非法 window retraction。
- clean in-order 第一段使用 40 ms delayed ACK, 第二段立即 ACK 并取消 timer。OOO、duplicate/overlap、out-of-window、right trim、gap fill、PSH、zero-window 在途数据均立即 ACK。每个 PCB 持有一个可覆盖的 latest pending ACK, TX/pool 暂时不可用时不会被其他 flow 的 control response 挤掉。
- SACK block 使用 `[left,right)`，触发本次 ACK 的 block 排第一, 其余按序输出。未协商 Timestamp 时最多 4 blocks; 协商 Timestamp 时最多 3 blocks, TCP options 始终不超过 40 bytes。IPv4/IPv6 ACK 继续由 `src/tcp/output.cpp` 生成并校验 checksum/data offset。
- established Timestamp 路径实现 missing-TS reject、wrap-safe PAWS compare 和 accepted-segment-only `TS.Recent` commit。out-of-window 或 future-sequence pure ACK 不可污染 PAWS; stale segment ACK-and-drop。精确 RST 删除 flow, 非精确 RST 只产生 challenge ACK, payload 不进入 Session。
- `src/tcp/delivery.h` / `.cpp`: bounded Session pump。始终先消费合法 `accepted_bytes`, 支持 full/partial Accepted、partial WouldBlock、跨 ring wrap delivery; zero-progress、超额 acceptance、Closed/Error 和抛异常均转为明确状态, 不忙循环或重复交付。单轮 `TrySend` call budget 耗尽后由 shard 后续 iteration 继续 pump。
- `AttachSession` 是 owner-shard 内部接口; Session 必须保持存活直到 `{FlowId,generation}` 对应的 `OnSessionClosed` 被 owner 处理。`kSessionWritable` / `kSessionClosed` 消息增加 generation 校验; 每次 shard restart 使用递增 engine epoch, 防止旧 run callback 命中新 flow。真正的 `ISessionFactory` 创建、owning binding/callback pin 和 runtime dependency injection 仍属于 P4, 不在 P3B-2 中引入不完整 raw callback bridge。
- 第三次握手 ACK 可携带 data 并继续进入 established receive path。Established payload 必须带 ACK 且 `SEG.ACK <= SND.NXT`; future ACK、无 ACK payload 和窗口外数据不会交付 Session。FIN sequence consumption 留给 P3B-4 close states。
- `tests/unit/tcp/receive_test.cpp`: 23 tests, 覆盖 delayed ACK pairing、OOO/gap fill、wrap、overlap first-wins、RFC window cases、ring wrap、SACK ordering、RCV.ADV、memory bound 和全部 Session partial/error 组合。
- `tests/unit/tcp/handshake_test.cpp`: 40 tests, 其中 P3B-2 集成覆盖 third-ACK data、delayed/immediate ACK timer、SACK wire options、WouldBlock→zero-window→writable、in-flight data、receive budget、PAWS poisoning、RST isolation、session generation teardown、pending ACK coalescing 和 restart epoch。

验证结果: 全量 CTest 普通 29/29, ASan/UBSan 29/29, TSan 29/29; TCP handshake 40/40, receive/delivery 23/23; include boundaries OK; `git diff --check` clean。当前 IP input 对 fragment 仍返回 `FragmentRequiresReassembly`; P3A reassembler 到 shard TCP input 的 runtime 接线需在完整 L3 pipeline 集成时完成。

#### P3B-3: 发送路径 ✅ In progress (2026-08-09, pending final commit)

- `src/tcp/send.h` / `send.cpp`: `TcpSendBuffer` 管理 unsent data queue 和 retransmission queue。retained `BufferRef` 持有 owner payload，避免 UAF。RFC 6298 RTO + Karn 规则 + 指数退避；fast retransmit/recovery (RFC 5681)；persist timer 和 zero-window probe；partial ACK / FIN 修剪；future ACK 拒绝。
- `src/tcp/options.h` / `options.cpp`: `ParseTcpSackBlocks` 从 duplicate ACK 选项中解析 SACK blocks，供 `OnSack` 更新 scoreboard。
- `src/tcp/send.h` / `send.cpp`: SACK scoreboard 跟踪 in-flight 记录的 SACK 覆盖、pipe 计算、fast retransmit 触发。
- `src/tcp/output.h` / `output.cpp`: `BuildTcpControlPacket` 扩展支持 data segment 序列化 (IPv4/IPv6 + TCP header + payload + options)。
- `src/tcp/handshake.h` / `handshake.cpp`: ESTABLISHED 转换时创建 `TcpSendBuffer`；`ProcessEstablished` 将 ACK+SACK 喂入 send buffer；`EnqueueSendData` 接受应用数据入队；`PumpSendPaths` 从 send buffer 取 segment → 分配 TX lease + owner Retain → `BuildTcpControlPacket` → `OnSent` → push tx。pool 耗尽时 `ResetPending` 避免崩溃。`Find` 使用 `send->SndUna()/SndNxt()` 返回实际发送状态。ACK 校验使用 send buffer 的 `SndNxt()` 而非旧 `pcb.snd_nxt`。
- `src/core/shard.h` / `shard.cpp`: event loop 每轮调用 `PumpTcpSendPaths(now_ms)`，将已建立连接的待发数据驱动到 TX lease 列表。
- `tests/unit/tcp/handshake_test.cpp`: 54 tests, P3B-3 send wiring 覆盖 enqueue、PumpSendPaths data segment 序列化与解析、SndNxt 推进与 ACK 确认、空队列不产生 segment、pool 耗尽安全、PCB 移除时 send buffer 释放。
- `tests/unit/tcp/send_test.cpp`: 51 tests, 覆盖 retransmission queue 生命周期、partial ACK/FIN 修剪、future ACK 拒绝、RFC 6298/Karn、fast retransmit、MSS/window 裁剪、zero-window persist、persist 数据丢失修复、序列空洞修复、RTO/persist 冲突修复、关闭后 BufferRef 泄漏修复。

验证结果: 全量 CTest 普通 30/30, ASan/UBSan 30/30, TSan 30/30; TCP handshake 54/54, send 51/51; include boundaries OK; `git diff --check` clean。

#### P3B-4: 关闭 ✅ Implemented (2026-08-09)

- `src/tcp/handshake.h` / `handshake.cpp`: 6 个新 `TcpState` 值 (FinWait1, FinWait2, CloseWait, Closing, LastAck, TimeWait)。`ProcessEstablished` 处理 zero-payload FIN 和 data-carrying FIN（先交付数据再消费 FIN sequence number），状态转移按 RFC 793:
  - Established + remote FIN → CloseWait
  - FinWait1 + remote FIN → Closing; + ACK of our FIN → FinWait2
  - FinWait2 + remote FIN → TimeWait
  - Closing + ACK of our FIN → TimeWait
  - LastAck + ACK of our FIN → PCB removed
  - TimeWait + retransmitted FIN → ACK (不重新进入处理)
- `CloseFlow(FlowId, generation)`: 从 Established → FinWait1 或 CloseWait → LastAck，调用 `send->RequestFin()` 排队 FIN。
- `AbortFlow(FlowId, generation)`: inline 构建 RST (seq=SndNxt, ack=RcvNxt, flags=Rst|Ack)，QueueResponse 后立即 RemoveAt。
- `ScheduleTimeWait(index, now_ms)`: 检查 `max_timewait_entries` 容量；满时找 `timewait_deadline_ms` 最老的 entry 驱逐 (oldest-deadline eviction)。设置 `pcb.state = TimeWait`，注册 timer callback (weak_ptr gate + FlowKey + generation)，到期调用 `OnTimeWaitExpired` → RemoveAt。
- `RemoveAt` 取消 `timewait_timer`；`Validate()` 检查 `max_timewait_entries > 0 && timewait_ms > 0`。
- 状态检查扩展: PumpSendPaths 在 SynReceived/TimeWait 跳过 (允许 FinWait1/FinWait2/Closing/LastAck/CloseWait 继续发送 FIN/retransmission)；EnqueueSendData 接受 Established + CloseWait；OnDelayedAck/OnSessionWritable/PumpSessionDeliveries 在 SynReceived/TimeWait 跳过。
- `src/tcp/receive.h` / `receive.cpp`: `ConsumeFin()` (rcv_nxt += 1, fin_received_ = true) 和 `FinReceived()`。
- `src/core/shard_message.h` / `shard.cpp`: `kFlowClose` / `kFlowAbort` 消息类型，shard 控制循环调用 `CloseFlow` / `AbortFlow`。
- `tests/unit/tcp/handshake_test.cpp`: 74 tests, P3B-4 覆盖 CloseFlow (Established→FinWait1, CloseWait→LastAck, unknown flow), AbortFlow (RST + removal, unknown flow), remote FIN (Established→CloseWait), FIN ACK (FinWait1→FinWait2), simultaneous close (→Closing), both FIN ACKed (→TimeWait), TIME-WAIT expiry (PCB removed), TIME-WAIT retransmitted FIN (ACK + 2MSL restart), TIME-WAIT capacity eviction (oldest evicted, surviving flows preserved)。FIN/close bugfix 覆盖: 乱序 FIN 不消费, 重复 data+FIN 不推进 ACK, 窗口外 SEQ 不确认 FIN, FIN 触发 ShutdownWrite, late Session callback 不删除 TIME-WAIT PCB, 发送缓冲耗尽在关闭状态移除 PCB, 所有 FIN 引起的状态转移设置 state_changed。

验证结果: 全量 CTest 普通 30/30, ASan/UBSan 30/30, TSan 30/30; TCP handshake 74/74; include boundaries OK; `git diff --check` clean。

首个 interop gate:

- Linux、Windows 和 macOS TCP clients 经 TUN 访问 echo/http;
- IPv4/IPv6 各跑短连接、长连接、双向、半关闭;
- 1% loss、100 ms RTT、重排和 duplicate 下无数据错误;
- 连续 24 小时 soak 无 flow/buffer/timer 泄漏。

### P3C: KCC 和 BBR 可切换拥塞控制

#### P3C-01: DeliveryRateSampler + CongestionController 接口 + AIMD 适配 ✅ Implemented (2026-08-10)

- `src/tcp/rate_sampler.h` / `rate_sampler.cpp`: `DeliveryRateSampler` 类，per-packet `PacketDeliveryState` 跟踪 delivered_bytes/time/first_sent_time/app_limited/retransmitted。ACK 时生成 `RateSample`（delivery_rate_bytes_per_sec、rtt_ms、interval_ms、inflight_bytes）。重传包不产生 delivery rate（ambiguous ACK）。app-limited 标记传播到 RateSample。
- `src/tcp/congestion.h` / `congestion.cpp`: `CongestionAlgorithm` enum（Aimd/Bbr/Kcc）、`AimdController`（RFC 5681 slow start/CA/fast recovery/RTO）、`BbrController`（BBRv1 STARTUP/DRAIN/PROBE_BW/PROBE_RTT 状态机，telemetry ID "bbr_v1"）。热路径使用 `std::variant<AimdController, BbrController>` + `std::visit`，避免每 ACK 虚调用。
- `src/tcp/send.h` / `send.cpp`: `SendRecord` 增加 `PacketDeliveryState delivery` 字段。`TcpSendBuffer` 持有 `std::variant<AimdController, BbrController> controller_` 和 `DeliveryRateSampler sampler_`，替代裸 `cwnd_`/`ssthresh_`/`fast_recovery_`。AIMD 逻辑（slow start、CA、fast recovery inflate/exit、RTO cwnd=1*MSS）全部委托给 `AimdController`。`UsableWindow()`、`CongestionWindow()`、`Ssthresh()`、`PacingRate()`、`InFastRecovery()` 委托给 controller。`TcpSendConfig` 和 `TcpHandshakeConfig` 增加 `CongestionAlgorithm cc_algorithm` 字段（默认 AIMD）。
- `tests/unit/tcp/congestion_test.cpp`: 21 tests，覆盖 DeliveryRateSampler（初始状态、stamp、delivery rate 计算、重传不产生 rate、app-limited 传播、reset）、AimdController（初始 cwnd、slow start、CA、fast recovery inflate/exit、RTO、reset、UpdateMss）、TcpSendBuffer 集成（AIMD/BBR 算法选择、slow start 通过 send buffer、fast retransmit via dup ACK、close resets controller、ssthresh accessor）。

验证结果: 全量 CTest 普通 31/31, ASan/UBSan 31/31, TSan 31/31; TCP congestion 21/21; include boundaries OK; `git diff --check` clean。

#### P3C-02: BBRv1 Controller State-Machine Tests ✅ Implemented (2026-08-10)

在 `tests/unit/tcp/congestion_test.cpp` 追加 22 个 BBR 测试（总计 43/43），覆盖：

- **初始状态**: cwnd=2*MSS, pacing_rate=0, STARTUP, BtlBw=0, RTprop=0
- **BtlBw max-filter**: 非 app-limited 采样更新 BtlBw；app-limited 采样不污染 filter
- **RTprop min-filter**: 忽略 rtt=0（未测量），有效 RTT 更新 min-filter
- **STARTUP→DRAIN**: 连续 3 轮无 >25% 增长后退出 STARTUP 进入 DRAIN
- **STARTUP 保持**: 有增长时留在 STARTUP
- **DRAIN→PROBE_BW**: inflight ≤ BDP 时进入 PROBE_BW
- **PROBE_BW cycle**: 8 个 phase 轮转后仍在 PROBE_BW
- **PROBE_RTT**: 10s 间隔进入，200ms 后退出
- **Pacing rate**: BtlBw 已知后 PROBE_BW 和 STARTUP 分别使用对应 gain
- **cwnd = BDP * gain**: STARTUP 约 28828 bytes
- **Loss 不减少 cwnd**（BBR 不基于丢包）
- **RTO 重置 cwnd=1*MSS**
- **Reset 恢复初始状态**
- **AlgorithmId = "bbr_v1"**
- **cwnd floor = 4*MSS**

验证结果: 全量 CTest 普通 31/31, ASan/UBSan 31/31, TSan 31/31; TCP congestion 43/43; include boundaries OK; `git diff --check` clean。

#### P3C-03: Per-flow Pacer ✅ Implemented (2026-08-10)

在 `src/tcp/send.h` / `send.cpp` 中为 `TcpSendBuffer` 增加 per-flow pacing gate：

- **新字段**: `next_send_time_ms_`（absolute deadline，0 = 无 gate）。通过 public accessor `PacingDeadline()` 暴露。
- **Pacing gate 位置**: `NextSegment()` 中，retransmit / fast-retransmit / persist probe 路径之后、`CanSendNew()` 之后。这些路径自然绕过 pacing。
- **Deadline 计算**: `StoreNewRecord()` 末尾，当 `PacingRate() > 0 && pending_len_ > 0` 时，`interval_ms = (pending_len_ * 1000) / pacing_rate`，`next_send_time_ms_ = SaturatingAdd(now_ms, interval_ms)`。
- **AIMD**: `PacingRate()` 恒返回 0，不 pace。
- **BBR**: `PacingRate()` 返回 `BtlBw * gain`；BtlBw=0 时不 pace。
- **重置**: `CancelTimers()` 和 `Close()` 中 `next_send_time_ms_ = 0`。
- **Shard 集成**: `PumpSendPaths` 和 `shard.cpp` 无需修改。pacing 透明地在 `NextSegment` 内部处理，返回 `has_segment=false` 时 PumpSendPaths 已正确 `++i; continue`。Shard 事件循环每轮调用 PumpSendPaths，pacing 延迟最多一个迭代。

测试 (`tests/unit/tcp/send_test.cpp` 追加 6 个 pacing 测试，总计 57/57):
- AIMD 无 pacing gate
- BBR 延迟第二个 segment
- Pacing 不阻塞重传
- Pacing 不阻塞零窗口探测
- Pacing gate 到期后允许新 segment
- Close() 重置 pacing deadline

验证结果: 全量 CTest 普通 31/31, ASan/UBSan 31/31, TSan 31/31; TCP send 57/57; include boundaries OK; `git diff --check` clean。

#### P3C-04: Fragment Reassembly → TCP Input Wiring ✅ Implemented (2026-08-10)

将 `FragmentReassembler` 接入 `StackShard` RX 路径，使分片 IPv4/IPv6 TCP 段能被正确重组后送入 TCP handshake engine。

**变更范围**:

1. **`src/ip/ipv6.h`**: `Ipv6ParseResult` 新增 5 个 fragment 字段 — `is_fragment`, `fragment_offset`, `fragment_more`, `fragment_identification`, `fragment_next_header`。

2. **`src/ip/ipv6.cpp`**: 扩展头遍历中解析 8 字节 Fragment header (type 44)，提取 offset/more/identification/next_header，遇到非 0 offset 时设置 `is_fragment=true`。

3. **`src/tcp/input.h` / `input.cpp`**: 新增 `FragmentInfo` 结构体和 `ExtractFragmentInfo()` 函数，从 `Ipv4ParseResult` / `Ipv6ParseResult` 中提取分片元数据。IPv4 MF flag 掩码修正为 `0x04`（原 `0x01` 为保留位）。IPv6 Fragment header 中 `ff = (offset << 3) | (mf ? 1 : 0)`。

4. **`src/core/shard.h` / `shard.cpp`**: 
   - `StackShard` 新增 `FragmentReassembler reassembler_` 成员和 `HandleFragment()` 方法。
   - `ProcessPacket()` 在 IP 解析后检查 `FragmentInfo::is_fragment`，若为 true 则调用 `HandleFragment()`。
   - `HandleFragment()` 将分片加入 reassembler；完成时取出 owning payload buffer，调用 `ParseTcpSegment()` → `OnSegment()`。
   - 事件循环 step 5 新增 `reassembler_.Purge(now_ms)` 清理过期 entry。

5. **`tests/unit/support/PacketBuilder.h` / `PacketBuilder.cpp`**: 新增 `BuildIpv4TcpFragment()` 和 `BuildIpv6TcpFragment()` 测试辅助方法，生成带正确 IP Fragment header 的分片包。`ParsedPacket` 新增 IPv6 fragment 字段。

6. **`tests/unit/shard_runtime_test.cpp`**: 新增 3 个分片重组测试 — IPv4 fragment reassembly、IPv6 fragment reassembly、non-fragmented packet passthrough。测试使用非重叠 8 字节对齐分片。

7. **`tests/unit/tcp/handshake_test.cpp`**: 修正现有 fragment 测试中 IPv4 MF flag 编码。

**已知限制**:
- 当前仅支持 TCP payload 分片重组；UDP/ICMP 分片重组在 P3U/P3A 扩展。
- `FragmentInfo::protocol` 在 IPv6 场景下保存 final next-header（如 TCP/UDP），不是 0。
- `FragmentReassembler` 容量尚未从 `NetstackConfig` 注入，使用默认构造参数。

验证结果: 全量 CTest 普通 31/31, ASan/UBSan 31/31, TSan 31/31; include boundaries OK; `git diff --check` clean。commit `b6d79a8`。IPv4 MF flag 掩码修正已在 `b6d79a8` 中作为同一 commit 的一部分记录。

#### 通用采样器

KCC 和 BBR 不能直接消费“本 ACK 确认多少字节”作为带宽。实现
`DeliveryRateSampler`, 每个首次发送 segment 记录:

- delivered bytes at send;
- delivered timestamp;
- first sent timestamp;
- send timestamp;
- app-limited marker;
- retransmitted marker。

ACK 时生成:

```cpp
struct RateSample {
    std::uint64_t now_us;
    std::uint64_t delivery_rate_bytes_per_sec;
    std::uint64_t interval_us;
    std::uint64_t rtt_us;
    std::uint64_t acked_bytes;
    std::uint64_t lost_bytes;
    std::uint64_t inflight_bytes;
    bool app_limited;
    bool ecn_ce;
};
```

采样器行为必须先与 Linux TCP rate sample 语义建立 golden tests。

#### Controller 内部接口

```cpp
class CongestionController {
public:
    void OnPacketSent(const SentPacket&);
    void OnAck(const RateSample&);
    void OnLoss(const LossEvent&);
    void OnRto();
    std::uint64_t CongestionWindow() const;
    std::uint64_t PacingRate() const;
};
```

热路径建议使用 tagged union/`std::variant<KccController, BbrController>`, 避免每 ACK
虚调用。算法选择在 flow 创建时固定。

#### KCC

- 以 UCP commit `927cb83` 的 `ucp_cc.*` 和 `tcp_kcc.c` 为参考;
- 保留 STARTUP/DRAIN/PROBE_BW、G1/G2/G3、LT BW 和 ACK aggregation;
- 第一版关闭 global KF, 避免跨 shard 全局原子状态影响可扩展性;
- ECN 默认关闭, 完成 TCP ECE/CWR 后按配置启用;
- 保留 MIT 来源、commit 和对齐测试说明;
- TCP adapter 只生成 transport-neutral RateSample, 不把 UCP FEC/NAK 事件伪装为 TCP。

#### BBR

- 第一版明确实现 BBRv1 行为, 配置名称仍可为 `bbr`;
- telemetry 输出精确实现 ID `bbr_v1`, 防止误认为 BBRv2/v3;
- 实现 STARTUP、DRAIN、PROBE_BW、PROBE_RTT;
- 与 Linux BBR 的 gain、round、app-limited 和 policer 行为做对齐测试;
- BBRv2/v3 作为后续新算法 ID, 不静默替换已发布行为。

#### 切换语义

| 场景 | KCC/BBR 由谁执行 |
|---|---|
| Netstack2 直接通过 DPDK/AF_XDP 发 TCP | Netstack2 controller |
| TUN 侧被代理的本地 TCP 腿 | Netstack2 以 Session 背压为主, 不代表公网 CC |
| Linux kernel socket | kernel `TCP_CONGESTION`, 能力探测后设 `kcc`/`bbr` |
| Onload socket | Onload 支持的 socket CC, 并报告实际选择 |
| Windows/iOS kernel socket | OS 提供的算法, 无法承诺 KCC/BBR |
| UCP over UDP | UCP KCC |

不支持请求 KCC/BBR 却静默使用其他算法。必须返回 capability/fallback reason。

测试矩阵:

- RTT: 0.2/5/40/100/300 ms;
- loss: 0/0.1/1/5/10%;
- reorder: 0/1/5%;
- bandwidth: 10 Mbps/100 Mbps/1 Gbps/10 Gbps;
- queue: 0.25/1/4 BDP;
- flow: 1/2/16/256;
- app-limited、ACK compression、reverse-path congestion、ECN。

每个场景同时记录 throughput、P99 queue delay、loss、retransmit 和 Jain fairness,
不能只看吞吐。

### P4: OpenPPP2 集成

#### P4-1: 配置和构建

新增启动期配置:

```text
--stack=lwip|netstack2|native
--tcp-cc=kcc|bbr
--aqm=none|codel
--fq=true|false
--netstack-shards=N
--netstack-rx-queues=N
--netstack-pool-capacity=N
--netstack-cpu-affinity=...
```

规则:

- 默认仍使用当前稳定 engine, 直到平台验收通过;
- 一个实例只启动一个 TCP/IP engine;
- 配置错误启动失败, 不静默改值;
- build pin 精确 Netstack2 commit, 不引用 `/home/Netstack2` 绝对路径。

#### P4-2: 数据路径

在 `VEthernet` 收到完整包后尽早三分支:

```text
netstack2 -> OpenPppPacketIo injection
lwip     -> existing lwIP pbuf/input
native   -> existing VNetstack/Input and UDP/ICMP path
```

Netstack2 分支必须继续保留 OpenPPP2 的:

- destination resolve 和 fake-IP mapping;
- Direct/Proxy/Block policy;
- DNS redirect;
- QUIC block/reject policy;
- PMTU cache;
- VPN protect socket;
- telemetry 和 teardown lifecycle。

这些通过 `OpenPppSessionFactory` 和 event sink 适配, 不复制进协议栈。

#### P4-3: 分阶段启用

1. shadow parse: Netstack2 只解析和计数, 不发包;
2. mirror compare: 对同一 PCAP 比较 lwIP/native 与 Netstack2 decision;
3. Linux TCP opt-in;
4. Linux UDP/ICMP opt-in;
5. 小流量 canary;
6. Linux 默认, 保留 `--stack=lwip` rollback;
7. Android、Windows、iOS 依次推进。

rollback 只针对新连接/新实例, 不尝试把已建立 PCB 从 Netstack2 搬回 lwIP。

### P4-UCP: UCP/KCC 接入

分两步:

1. 算法复用 (Netstack2 内部): 将 KCC 拥塞控制算法按 MIT 许可移植到 Netstack2 `src/tcp/congestion.cpp`, 不引入 UCP 的 packet codec 和线程。`CongestionAlgorithm::Kcc` 选择器启用 `KccController`, 与 `AimdController`/`BbrController` 共享 `DeliveryRateSampler`。详见 `docs/adr/006-kcc-congestion-control.md`。
2. 协议接入: 在 OpenPPP2 增加 UCP dependency 和 adapter, 作为可选择 carrier。

UCP 协议接入前必须解决 per-connection thread:

- 给 UCP 增加 external executor/timer 模式, 或按 shard 建立 `UcpNetwork`;
- connection event 投递到固定 UCP shard;
- UDP receive 按 CID hash 到 shard;
- 移除每连接 worker/notify/timer thread;
- 所有 queue、FEC group、reassembly 和 retransmit 有全局上限;
- UCP callback 通过 typed message 回到 Netstack2/OpenPPP2 owner。

FQ 复用原则:

- UCP 当前 server credit round-robin 可作为行为参考;
- Netstack2 Packet I/O 使用自己的 per-shard FQ-CoDel;
- UCP connection scheduler 可以消费同一 pacing/FQ service, 不能再启动全局 10 ms
  fair-queue thread;
- urgent retransmit 可提高优先级, 但必须有 per-RTT budget。

### P5A: Onload

Onload 是 socket backend, 不是 Packet I/O backend:

- 实现 `OnloadSocketSession`;
- 复用 partial send/writable/data/close contract;
- capability probe 实际 CC、zero-copy、timestamp 和 pacing 支持;
- 能设置 `TCP_CONGESTION=kcc|bbr` 时设置并读回确认;
- 不支持时返回明确 fallback reason;
- callback 仍回投 owner shard。

### P5B: AF_XDP/DPDK

AF_XDP 顺序:

1. copy mode;
2. UMEM ownership adapter;
3. zero-copy capability probe;
4. fill/completion/RX/TX ring;
5. queue/shard/CPU/NIC affinity;
6. multi-buffer、checksum 和 wakeup 优化。

DPDK 顺序:

1. EAL/port/queue adapter 位于可选 target, 不污染 core 依赖;
2. mbuf 到 lease 的外部 buffer owner;
3. RX/TX burst 和 completion;
4. NUMA-local pool;
5. L2 route/ARP/NDP;
6. UDP active output;
7. TCP active open + KCC/BBR;
8. RSS symmetric key 与 FlowKey golden tests。

### P6: Android/iOS/Windows

#### Android

- 从 `VpnService.detachFd()` 建立 L3 queue;
- protect 所有远端 kernel socket;
- 默认 1-2 shards;
- screen-off/background 降低 busy polling;
- 测试 VPN revoke、network change、Doze 和 IPv6 leak。

#### iOS

- `NEPacketTunnelFlow` Data 复制到 pool buffer;
- writePackets 形成 batch 并处理 backpressure;
- 默认 1-2 shards;
- 不直接把当前 `mta=false` 改为 true, 先完成 lifecycle/内存测试;
- 测试 suspend/resume、memory warning 和 path change。

#### Windows

- Wintun receive packet 在 `WintunReleaseReceivePacket` 前复制到 lease;
- Wintun send ring 用 async completion owner;
- 接收线程只投递 typed packet, 不执行 flow state;
- 测试 service stop、adapter delete/recreate 和 ring exhaustion。

### OPENPPP2-LINUX-DP: TC/eBPF 和 hairpin NAT

代码只进入 `/home/openppp2/linux/`:

- capability probe: kernel、BTF、clsact、nft、conntrack;
- CO-RE BPF object 和 skeleton;
- ingress/egress classify、mark、redirect 和 counters;
- nftables 使用独立 table/chain 和原子 transaction;
- IPv4/IPv6 hairpin DNAT/SNAT;
- install/update/remove 幂等;
- crash 后 stale rule discovery/cleanup;
- verifier/nft 失败完整回滚;
- netns 集成测试, 不操作开发机默认 namespace。

不要把 `tc`/`nft` shell 字符串拼接放到热路径。优先 libbpf/netlink/nft transaction。

## 9. 验证体系

### 9.1 每个提交必须通过

```sh
cmake -S . -B build -G Ninja
cmake --build build
ctest --test-dir build --output-on-failure
bash scripts/build-asan.sh
bash scripts/build-tsan.sh
bash tools/check_include_boundaries.sh
git diff --check
```

### 9.2 协议测试层次

1. unit: parser、sequence arithmetic、timer、CC、FQ/CoDel;
2. packet: golden bytes、checksum、PCAP replay;
3. model: FakeClock + deterministic network simulator;
4. differential: lwIP/Linux TCP/UCP reference;
5. netns: TUN、netem、nft/TC;
6. interop: Linux/Windows/macOS/Android/iOS peers;
7. fuzz: IPv4/IPv6/TCP options/fragment/UCP codec;
8. soak: 24h、连接 churn、loss/reorder、shutdown;
9. benchmark: 1/2/4/8/16 cores, 1-100k flows。

### 9.3 性能门禁

先记录 P0, 再冻结门禁。建议初始目标:

- warmup 后 packet hot path 每包 0 次通用 heap allocation;
- 单 shard 不低于 lwIP 同场景吞吐, CPU/byte 更低;
- 4 shard aggregate throughput 至少达到单 shard 的 3 倍;
- 8 shard aggregate throughput 至少达到单 shard 的 5 倍;
- 过载 10 秒后 queue memory 不超过配置 hard limit;
- FQ elephant+mice 场景 mice P99 不超过 FIFO 的 50%;
- Stop 到全部 thread joined 的 P99 小于 2 秒;
- 24h soak buffer、flow、timer 和 fd 增量为 0。

上述数值必须绑定机器和场景。未达到时保留原始数据, 不通过删样本或放宽统计口径
宣称成功。

### 9.4 KCC/BBR 验收

- 所有状态转换有 deterministic test;
- 与参考实现的 gain/cwnd/pacing golden vectors 对齐;
- netem 下无无限 cwnd、负 pacing、timer storm;
- app-limited 流不污染 bandwidth max filter;
- 10% loss/300 ms 下连接保持且内存有界;
- 共享 bottleneck 下记录 Jain fairness;
- ECN 开关关闭时完全不改变 non-ECN 行为;
- KCC 与 BBR 的结果分别报告, 不只报告胜出的算法。

## 10. 当前优先级与执行顺序

**当前最高优先级是 P4 OpenPPP2 集成**。所有 P5 高性能后端工作应为 P4 让路；P4 完成后，再依次展开 P5A (Onload) 和 P5B (AF_XDP/DPDK)。

### 10.1 立即执行项

1. ✅ **ADR-005 落地**: `RuntimeDependencies` 注入公共 API，新增 `include/tcpip2/clock.h`、`include/tcpip2/events.h`、`include/tcpip2/runtime_deps.h`；`netstack.h` 新增 `Start(const RuntimeDependencies&)` 重载，旧 `Start(IPacketIo*)` 保留为兼容入口。StackShard 构造函数接收 `IClock*`/`IEventSink*`/`ISessionFactory*`，热路径使用 `clock_->NowMs()` 替代 `steady_clock`。三套构建 34/34 全绿。
2. ✅ **IClock 全替换**: shard event loop 已使用 `clock_->NowMs()`；TCP/IP 层通过参数接收 `now_ms`，不直接调用 `steady_clock`。`SteadyNowMsFallback()` 仅作为 clock_ 为 null 的安全网（实际不会发生）。
3. ✅ **IEventSink 接入**: `TcpHandshakeEngine::EmitFlowEvent()` 在以下转换点调用 `OnFlowEvent()`：ESTABLISHED（handshake 完成）、Reset（RST in SYN-RECEIVED / ESTABLISHED、AbortFlow）、Closed（LastAck 完成、FIN 重传耗尽、TIME-WAIT 超时/驱逐）。`StackShard::EventLoopIteration()` 每 1000ms 发布 `MetricSnapshot`（rx_packets/dropped_packets/tcp_pcb_count/half_open_count/udp_datagrams；rx_bytes/tx_bytes 暂为 0，待后续添加字节计数器）。TCP handshake 89/89、全量 34/34 三套构建全绿。
4. ✅ **ISessionFactory 被动监听**: 接口已通过 `RuntimeDependencies` 注入 shard，`TcpHandshakeEngine` 构造函数接收 `ISessionFactory*`。SYN → ESTABLISHED 转换时调用 `OpenTcp()`：accept 则绑定 `ITransportSession` 并 `DrainSession` 交付后续数据；reject 则发送 RST 并移除 PCB。`session_factory_` 为 null 时走 legacy 兼容路径，不 crash。三套构建 34/34 全绿。
5. ✅ **ITransportSession 回调接线**: `BindSessionCallbacks()` 在 ESTABLISHED 和 `AttachSession` 时注册 `SetDataCallback`/`SetWritableCallback`/`SetClosedCallback`。回调通过 `weak_ptr<CallbackGate>` 捕获引擎引用，构造 `ShardMessage`（`kSessionData`/`kSessionWritable`/`kSessionClosed`）投递回 owner shard。shard event loop 在 `kSessionData` 路径调用 `EnqueueSendData` 将数据转入 TCP 发送缓冲。`Shutdown()` 后 `CallbackGate::owner` 置空，回调变为 no-op。三套构建 34/34 全绿。
6. ✅ **P4-7 OpenPPP2 adapter smoke test**: 完整 TCP 生命周期集成测试 (`tests/integration/openppp2_smoke_test.cpp`)，覆盖 SYN→SYN-ACK→ACK→ESTABLISHED→data→FIN→Closed 全流程。`FakeSession`/`FakeSessionFactory`/`RecordingEventSink` 全部 mutex 保护，TSan 安全。`NullPacketIo::EgressSnapshot()` (ADR-007) 解决 `Egress()` 引用的 TSan 数据竞争。`handshake.cpp::Shutdown()` 对非 TimeWait PCB emit Closed event。35/35 三套构建全绿。

### 10.3 已知限制

1. **初始 SYN+data 未处理**: 当前握手引擎在 SYN-RECEIVED → ESTABLISHED 转换时忽略 SYN 段的 payload。RFC 793 允许 SYN 段携带数据（数据在 ESTABLISHED 后交付），若需要支持应在后续实现中处理，或在文档中明确说明不支持。

### 10.4 后端接口先行定义

AF_XDP / Onload / DPDK 的通用扩展接口已定义在 `docs/plans/HIGH_PERF_BACKEND_EXTENSIONS.md`，P4 阶段只做接口设计，不实现具体后端，避免并行修改公共 API。

## 11. 并行组织与关键路径

可分五条工作线:

| 工作线 | 内容 | 可开始条件 |
|---|---|---|
| A Runtime | ~~002H~~ ✅、~~Dispatcher~~ ✅、~~Shard~~ ✅、~~TUN~~ ✅ | 立即 |
| B Protocol | IP、UDP/ICMP、TCP | 002H parser/buffer 契约稳定 ✅ |
| C CC/QoS | rate sampler、KCC、BBR、FQ-CoDel | FakeClock 和 packet model 可用 |
| D Integration | adapter spike、OpenPPP2、UCP、平台 | public draft API 可用 |
| E Validation | P0、fuzz、netem、interop、benchmark | 立即建立框架 |

真实关键路径:

```text
002H ✅
  -> 003 ✅ + 004A ✅ + ADAPTER-SPIKE (并行)
  -> API-FREEZE
  -> P3A
  -> P3U + P3Q
  -> P3B
  -> P3C
  -> OpenPPP2 Linux opt-in
  -> platform rollout / AF_XDP / DPDK / UCP
```

P0 和测试框架全程并行, 但每个性能结论都依赖 P0。

## 12. 首批实施顺序

从当前提交开始, 严格按以下顺序执行:

1. ✅ `NS2-002H-01`: Resize/pool identity/arena failure 测试和修复。
2. ✅ `NS2-002H-02`: BufferRef RAII retained ownership。
3. ✅ `NS2-002H-03`: NullPacketIo wake/unregister/shutdown contract。
4. ✅ `NS2-003-01`: TUN queue(含 ADR-001 SetBufferPool 注入、ADR-002 门禁降级)。
5. ✅ `NS2-004A-01/02`: FlowKey/hash/inbox/event loop/shutdown/Null runtime。
6. ✅ `NS2-API-01`: RuntimeDependencies、SessionFactory、capabilities ADR 草案。
7. ✅ `NS2-ADAPTER-SPIKE-01`: OpenPPP2 Linux compile-only adapter。
8. `NS2-003+004-SMOKE`: netns TUN multiqueue packet loop(需 root 或降级为 ADR-002 code review gate)。
9. ✅ `NETSTACK2-API-FREEZE-001`。
10. ✅ `P3A-01`: checksum + IPv4/IPv6 bounded parser。
11. ✅ `P3A-02`: ICMPv4/ICMPv6 bounded parser + PMTU cache。
12. ✅ `P3A-03`: IPv4/IPv6 fragment reassembly。
13. ✅ `P3B`: bounded PCB, handshake, RX/TX, ring, retrans, FIN/TIME-WAIT。
14. ✅ `P3C`: delivery-rate sampler, BBRv1, pacer, fragment reassembly wiring。
15. ✅ `P3U`: UDP parser + shard wiring。
16. ✅ `P3I`: ICMP shard RX wiring + PMTU。
17. ✅ `P4-01`: ADR-005 落地, 新增 `RuntimeDependencies`, `IClock`, `IEventSink`。IClock 替换 shard 热路径 steady_clock。
18. ✅ `P4-02`: `ISessionFactory` 被动监听接入 TCP handshake。
19. ✅ `P4-03`: OpenPPP2 smoke test (fake backend) — 完整 TCP 生命周期集成测试, 线程安全 `EgressSnapshot()` (ADR-007), 35/35 三套构建全绿。
20. `P4-04`: OpenPPP2 Linux adapter (repository `/home/openppp2`).
21. P5A/P5B: Onload / AF_XDP / DPDK 按 `docs/plans/HIGH_PERF_BACKEND_EXTENSIONS.md` 实现。

在第 17 步之前不接 OpenPPP2 完整数据路径, 不实现 AF_XDP/DPDK 具体后端。

## 13. 风险与控制

| 风险 | 后果 | 控制 |
|---|---|---|
| API 过早冻结 | OpenPPP2 接线后大面积改 ABI | freeze 前 adapter spike |
| per-connection thread | 高并发线程/栈内存爆炸 | 固定 shard, UCP external executor |
| BufferRef 提前释放 | 重传 UAF/数据损坏 | shard-local RAII retain count |
| 双重拥塞控制 | TCP-over-TCP 延迟和错误退让 | 明确每条真实腿的 controller |
| 仿真吞吐误导 | 线上性能不达标 | netem + 真 TUN/NIC gate |
| IPv6 “编译开启即支持” | IPv6 TCP 黑洞 | 独立 IPv6 packet/interop gate |
| FQ/AQM 无上限 | bufferbloat/OOM | per-flow/per-shard/global hard limit |
| DPDK 范围低估 | 有 RX/TX 却不能联网 | 单列 L2/route/neighbor/active open |
| callback 晚到 | flow UAF | FlowId + generation |
| timer O(N) | 大连接数 CPU 飙升 | 分层 timer wheel/到期 slot only |
| mobile busy polling | 发热耗电 | event mode + adaptive polling |
| KCC 全局 KF | 跨 shard 竞争和流间污染 | 第一版关闭, 后续 per-shard cohort |
| license/provenance 丢失 | 合规风险 | pin commit, 保留 MIT notice 和来源 |

## 13. 工程规则

- 每个工作包一个可独立 review 的提交, 不混入无关重构。
- 新 parser 必须先有 malformed 和 boundary tests。
- 新线程或 queue 必须同时提交 shutdown 和 saturation tests。
- 新配置必须说明 immutable/new-flow/live 类别。
- 新性能优化必须提交 before/after 原始 record。
- hot path 不抛异常, 不做日志格式化, 不获取全局 mutex。
- 所有 packet length、offset、sequence wrap 使用专门 checked helper。
- 所有 queue、table、reassembly、TIME-WAIT 和 callback 都有 hard limit。
- 任何 fallback 都必须输出机器可读 reason。
- 任何平台“支持”必须至少包含 build、interop、shutdown 和 soak 四项证据。

## 14. 完成定义

Netstack2 可以替换 OpenPPP2 lwIP 默认路径, 需要同时满足:

- IPv4/IPv6 TCP、UDP、ICMP 功能门禁通过;
- KCC/BBR 可在新 flow 创建时选择并报告实际算法;
- FQ-CoDel/ECN 工作且内存有界;
- Linux TUN multiqueue 多 shard 扩展达到性能门禁;
- OpenPPP2 route/DNS/fake-IP/PMTU/VPN protect 行为无回归;
- lwIP fallback 可用;
- 普通、ASan/UBSan、TSan、fuzz、netem、24h soak 通过;
- Android、iOS、Windows 在各自发布前单独通过平台门禁;
- AF_XDP/DPDK/Onload/UCP 按 capability 报告真实可用状态, 不以 stub 宣称支持。

达到这些条件后, 才把 OpenPPP2 默认 `--stack` 从当前 engine 改为 `netstack2`。
