# Netstack2 架构基线

> **状态**: baseline (NETSTACK2-000 已提交, tag `v0.1.0`)。
> 本文件是合并全部已确认决策后的完整工程方案, 作为 Netstack2 的架构基线、
> 开仓计划和后续实施路线图。公共签名冻结由 `NETSTACK2-API-FREEZE-001` 控制,
> 冻结前签名变更不要求 ADR。

## 1. 项目目标

Netstack2 是一个独立开发、可嵌入 OpenPPP2 的多线程用户态 IPv4/IPv6 TCP/IP 引擎。

项目目标:

1. 替换 OpenPPP2 当前基于 lwIP 的 TCP/IP 热路径。
2. 删除"用户态协议栈终结 TCP → loopback → 内核再次终结 TCP"的双重 TCP 终结路径。
3. 通过连接级固定分片实现多核扩展, 避免全局锁竞争。
4. 支持 Android VpnService、iOS utun、Windows Wintun 和 Linux 多种包 I/O 后端。
5. 支持 Linux AF_XDP、netmap、DPDK 等高性能用户态包路径。
6. 为 DPDK、EF_VI 等纯用户态环境提供全用户态出站能力。
7. lwIP 在迁移期间继续保留为回退路径。
8. 核心库保持零外部依赖, 可脱离 OpenPPP2 独立编译、测试和压测。

Netstack2 不负责实现完整 Linux 系统网络管理。TC/eBPF、nftables、conntrack
和内核 hairpin NAT 属于 OpenPPP2 Linux 适配层。

## 2. 总体架构

```text
┌──────────────────────────────────────────────────────────────┐
│                         OpenPPP2                             │
│                                                              │
│  VEthernet / VpnService / utun / Wintun / Linux datapath    │
│                          │                                   │
│                 Netstack2 Adapter                            │
└──────────────────────────┼───────────────────────────────────┘
                           │
┌──────────────────────────▼───────────────────────────────────┐
│                       Netstack2 Core                         │
│                                                              │
│  PacketDispatcher                                           │
│    ├─ IPv4/IPv6 FlowKey                                     │
│    ├─ RX queue → shard 映射                                  │
│    └─ 4 元组稳定哈希                                        │
│                                                              │
│  StackShard × N                                             │
│    ├─ 单线程事件循环                                         │
│    ├─ Flow table                                             │
│    ├─ Timer wheel                                            │
│    ├─ Buffer pool                                            │
│    ├─ Control inbox                                          │
│    └─ TcpFlow                                                │
│         ├─ SYN/SYN-ACK/ESTABLISHED                           │
│         ├─ seq/ack/window                                    │
│         ├─ RTO/快速重传/乱序重组                              │
│         ├─ FIN/RST/TIME-WAIT                                 │
│         └─ ITransportSession                                 │
│              ├─ SocketSession                               │
│              │    ├─ KernelSocketSession                    │
│              │    └─ OnloadSocketSession                    │
│              └─ UserspaceSession                            │
│                   ├─ DpdkSession                            │
│                   └─ EfViSession                            │
└──────────────────────────┬───────────────────────────────────┘
                           │ IPacketIo / IPacketQueue
┌──────────────────────────▼───────────────────────────────────┐
│                        Packet I/O                            │
│                                                              │
│  TapPacketIo / VpnServiceIo / UtunIo / WintunIo             │
│  AfXdpIo / NetmapIo / DpdkIo / NullPacketIo                 │
└──────────────────────────────────────────────────────────────┘
```

## 3. 平台数据路径

### 3.1 Android、iOS、Windows

这些平台主要依赖 Netstack2 完成用户态 TCP/IP 终结。

```text
VpnService / utun / Wintun
        ↓
IPacketQueue
        ↓
StackShard
        ↓
TcpFlow
        ↓
KernelSocketSession
        ↓
OpenPPP2 transmission / 远端网络
```

目标是删除 lwIP 和本机 loopback accept 路径。

移动端默认:

```text
shard_count = 1 或 2
```

允许根据设备核心数、电量策略和吞吐目标配置。

### 3.2 Linux 路径一: TC/eBPF + 内核 hairpin NAT

Linux 首先探测是否能够启用 TC/eBPF 和内核 hairpin NAT。

```text
Linux ingress/egress
        ↓
TC/eBPF 分类、打标、重定向
        ↓
nftables + conntrack
        ↓
内核 DNAT/SNAT/hairpin
        ↓
目标内核 socket 或 OpenPPP2 传输路径
```

职责划分:

#### TC/eBPF

负责:

* 流量分类;
* mark 设置;
* ingress/egress hook;
* redirect;
* 决定流进入 hairpin 路径还是 Netstack2 路径;
* 统计和快速拒绝。

#### nftables + conntrack

负责:

* DNAT;
* SNAT;
* hairpin NAT;
* 正反向连接映射;
* NAT 生命周期;
* IPv4/IPv6 规则管理。

第一阶段不在 BPF 程序中自行实现完整有状态 NAT。

TC/eBPF hairpin 不是 Netstack2 的 `IPacketIo` 后端, 其代码必须位于
OpenPPP2 Linux adapter。

### 3.3 Linux 路径二: AF_XDP

```text
NIC RX queue
    ↓
XDP program
    ↓
XDP_REDIRECT / XSKMAP
    ↓
AF_XDP socket
    ↓
AfXdpPacketQueue
    ↓
StackShard
```

AF_XDP 是真正的 Netstack2 `IPacketIo` 后端。

每个 AF_XDP queue 由一个固定 shard 独占。

### 3.4 Linux 路径三: DPDK/netmap

```text
NIC queue
    ↓
DPDK PMD / netmap ring
    ↓
DpdkPacketQueue / NetmapPacketQueue
    ↓
StackShard
    ↓
TcpFlow
    ↓
UserspaceSession 或 SocketSession
```

DPDK 纯用户态部署可以使用 `DpdkSession` 实现用户态出站。

Onload 仍然使用 socket API, 应建模为 `OnloadSocketSession`, 而不是 DPDK
风格的 UserspaceSession。

### 3.5 Linux 回退路径: 多队列 TUN/TAP

```text
MQ TUN/TAP
    ↓
TapPacketIo
    ↓
每 queue 固定 owner shard
    ↓
Netstack2
```

TC/eBPF、AF_XDP、DPDK 和 netmap 均不可用时, 回退到该路径。

## 4. 核心并发模型

### 4.1 连接单归属

每个连接根据稳定 FlowKey 固定归属一个 StackShard。

FlowKey 至少包含:

```text
IP version
source address
destination address
source port
destination port
protocol
```

核心不变量:

> 一个 TcpFlow 从创建到销毁, 只能由一个 StackShard 线程读写。

禁止:

* 多个 shard 同时修改同一 TcpFlow;
* Session 回调线程直接修改 TcpFlow;
* 控制线程持有并操作 TcpFlow 指针;
* 任意闭包捕获 TcpFlow 后跨线程执行。

### 4.2 RX queue 与 shard 绑定

优先采用:

```text
RX queue 0 → StackShard 0
RX queue 1 → StackShard 1
RX queue 2 → StackShard 2
...
```

尽量利用 RSS、XDP redirect、DPDK queue 或 TUN multiqueue 在进入引擎前完成
流量分配。

不能直接映射时, 再由 PacketDispatcher 使用 FlowKey 哈希分发。

### 4.3 跨线程通信

使用两类队列:

* 每来源一条 SPSC, 用于已知单生产者路径;
* MPSC control inbox, 用于管理、Session 回调和多个控制来源。

跨线程消息必须是类型化消息:

```cpp
struct ShardMessage {
    ShardMessageType type;
    FlowId flow_id;
    BufferLease data;
    SessionError error;
};
```

`postToShard()` 是内部接口, 不允许公开任意函数闭包。

### 4.4 Session 回调

`KernelSocketSession`、`OnloadSocketSession` 或其他 Session 的异步回调必须
先投递回 owner shard。

```text
Socket completion thread
        ↓
ShardMessage
        ↓
owner StackShard
        ↓
TcpFlow 状态变更
```

## 5. Buffer 与所有权模型

### 5.1 PktBuffer

`PktBuffer` 是 buffer pool 内部对象:

* 不公开引用计数接口;
* 不包含每包原子引用计数;
* 固定布局;
* 保存容量、数据长度、headroom 和 owner pool 信息;
* 用户不能直接 delete。

### 5.2 BufferLease

`BufferLease` 表示唯一所有权:

* move-only;
* 不可复制;
* 析构时归还 owner pool;
* 可跨线程移动;
* 跨线程释放时通过 owner return queue 回到所属 shard;
* noexcept move。

### 5.3 BufferSlice

`BufferSlice` 是非 owning 只读视图:

```text
PktBuffer*
offset
length
```

要求:

* trivially copyable;
* 不拥有数据;
* 不允许超出原始 buffer 范围;
* 生命周期不得超过对应 `BufferLease` 或 `BufferRef`。

### 5.4 BufferRef

`BufferRef` 是 shard-local retained handle, 用于:

* TCP 重传;
* 乱序重组;
* 分段发送;
* 一个 payload 被多个 TxSegment 引用。

它不应成为跨 shard 通用共享指针。

### 5.5 TxSegment

```cpp
struct TxSegment {
    std::uint32_t seq;
    std::uint32_t len;
    BufferRef owner;
    BufferSlice data;
};
```

`BufferRef` 保证 `BufferSlice` 在重传队列生命周期内有效。

### 5.6 零拷贝目标

正式目标定义为 copy-minimized, 而不是承诺所有路径绝对零拷贝。

要求:

* TUN/AF_XDP/DPDK 收包直接进入池化 buffer;
* header parser 使用 view;
* TCP payload 不做整包复制;
* 重传引用原始 payload;
* 仅在重组、加密、平台 API 限制或聚合时复制;
* AF_XDP/DPDK 在条件允许时实现 DMA buffer 复用。

## 6. Packet I/O 契约

```cpp
enum class IoError {
    None,
    WouldBlock,
    NoBuffer,
    Invalid,
    Closed,
    Internal
};
```

### 6.1 IPacketQueue

```cpp
class IPacketQueue {
public:
    virtual ~IPacketQueue() = default;

    virtual std::size_t RecvBatch(
        BufferLease out[],
        std::size_t capacity,
        IoError& error) noexcept = 0;

    virtual std::size_t SendBatch(
        BufferLease packets[],
        std::size_t count,
        IoError& error) noexcept = 0;

    virtual std::size_t QueueId() const noexcept = 0;

    virtual void SetRecvHandler(
        std::function<void()> wake) = 0;
};
```

### 6.2 IPacketIo

```cpp
class IPacketIo {
public:
    virtual ~IPacketIo() = default;

    virtual std::size_t QueueCount() const noexcept = 0;

    virtual std::unique_ptr<IPacketQueue> OpenQueue(
        std::size_t queue_id) = 0;
};
```

### 6.3 所有权规则

`RecvBatch()`:

* 返回值为 `n`;
* `out[0..n-1]` 的 lease 所有权转移给调用方;
* 返回 0 且无错误时设置 `IoError::None`;
* 暂无数据时可以返回 0 和 `IoError::WouldBlock`。

`SendBatch()`:

* 返回值为 `n`;
* `packets[0..n-1]` 所有权转移给后端;
* 剩余 lease 仍归调用方;
* 异步后端在 TX completion 后归还 owner pool;
* `count == 0` 必须返回 0 和 `IoError::None`。

每个 `IPacketQueue` 在打开后由一个固定线程或 shard 独占。

## 7. Transport Session 契约

### 7.1 SendResult

```cpp
enum class SendStatus {
    Accepted,
    WouldBlock,
    Closed,
    Error
};

struct SendResult {
    std::size_t accepted_bytes = 0;
    SendStatus status = SendStatus::Accepted;
};
```

### 7.2 ITransportSession

```cpp
using WritableCallback = std::function<void()>;
using DataCallback = std::function<void(BufferLease)>;
using ClosedCallback = std::function<void(SessionError)>;

class ITransportSession {
public:
    virtual ~ITransportSession() = default;

    virtual SendResult TrySend(BufferView data) = 0;

    virtual void ShutdownWrite() = 0;

    virtual void Abort(SessionError error) = 0;

    virtual void SetWritableCallback(
        WritableCallback callback) = 0;

    virtual void SetDataCallback(
        DataCallback callback) = 0;

    virtual void SetClosedCallback(
        ClosedCallback callback) = 0;
};
```

冻结语义:

* `TrySend()` 支持部分接收;
* 返回后 Session 不得继续引用传入的 `BufferView`;
* `WouldBlock` 必须通过 WritableCallback 恢复发送;
* DataCallback 传递 owning `BufferLease`;
* 所有 callback 必须投递回 owner shard 后才能修改 TcpFlow;
* Session 背压必须反馈到 TCP advertised window 和内部缓存上限。

## 8. TCP/IP 实现范围

### 8.1 P3A: IPv4/IPv6 与 L3

实现:

* IPv4 header 解析;
* IPv6 header 解析;
* IPv4 header checksum;
* TCP/UDP pseudo-header checksum;
* IPv4/IPv6 protocol demux;
* MTU/MSS;
* ICMPv4 Destination Unreachable;
* ICMPv6 Packet Too Big;
* PMTU;
* 有界 IPv4 fragment reassembly;
* IPv6 extension header 支持或明确拒绝;
* malformed packet 拒绝;
* 长度和越界检查。

对于 L3 虚拟网卡:

* TUN;
* utun;
* Wintun;
* VpnService;

不需要 ARP/NDP。

TAP 或 L2 后端通过单独 Ethernet/ARP/NDP shim 支持。

### 8.2 P3B: TCP 基础状态机

实现:

* LISTEN;
* SYN-RECEIVED;
* ESTABLISHED;
* FIN-WAIT;
* CLOSE-WAIT;
* LAST-ACK;
* TIME-WAIT;
* RST;
* seq/ack;
* receive window;
* send window;
* receive reassembly;
* retransmission queue;
* RTT 估算;
* RTO;
* delayed ACK;
* persist timer;
* partial send;
* Session 背压;
* 主动和被动关闭;
* SYN-ACK retry。

优先复用和迁移 OpenPPP2 已验证逻辑:

* TapTcpLink SYN-ACK 重试模式;
* TapTcpClient 出站状态;
* 已有 zero-copy buffer 工程;
* VMUX FakeClock、DeliveryOracle 和确定性测试经验。

不直接复制 lwIP 核心代码, 但可以参考其成熟协议处理逻辑。

### 8.3 P3C: 互操作与性能

实现:

* MSS option;
* Window Scale;
* SACK Permitted;
* SACK blocks;
* TCP Timestamp;
* duplicate ACK;
* fast retransmit;
* RTO exponential backoff;
* keepalive;
* challenge ACK;
* SYN flood 保护;
* TIME-WAIT 资源上限;
* 黑洞 PMTU 处理;
* Linux/Windows/macOS/Android TCP 互操作测试。

Window Scale 不推迟到最终调优阶段, 应在正式吞吐测试前完成。

## 9. 仓库结构

```text
Netstack2/
├── CMakeLists.txt
├── LICENSE
├── README.md
├── .clang-format
├── .gitignore
├── cmake/
│   └── compiler_flags.cmake
├── include/
│   └── tcpip2/
│       ├── buffer.h
│       ├── packet_io.h
│       ├── transport_session.h
│       ├── config.h
│       ├── netstack.h
│       └── shard.h
├── src/
│   ├── CMakeLists.txt
│   ├── core/
│   │   ├── buffer.cpp
│   │   ├── buffer_pool.cpp
│   │   ├── dispatcher.cpp
│   │   ├── shard.cpp
│   │   └── timer_wheel.cpp
│   ├── ip/
│   │   ├── ipv4.cpp
│   │   ├── ipv6.cpp
│   │   ├── icmp.cpp
│   │   └── checksum.cpp
│   ├── tcp/
│   │   ├── flow.cpp
│   │   ├── input.cpp
│   │   ├── output.cpp
│   │   ├── recovery.cpp
│   │   ├── reassembly.cpp
│   │   └── options.cpp
│   ├── session/
│   │   ├── socket_session.cpp
│   │   └── userspace_session.cpp
│   └── packetio/
│       ├── null_io.cpp
│       ├── tap_io.cpp
│       ├── afxdp_io.cpp
│       ├── netmap_io.cpp
│       └── dpdk_io.cpp
├── platform/
│   ├── linux/
│   ├── android/
│   ├── ios/
│   └── windows/
├── tests/
│   ├── unit/
│   │   └── support/
│   ├── packet/
│   ├── integration/
│   ├── differential/
│   └── fuzz/
├── bench/
│   ├── README.md
│   ├── scenarios.md
│   ├── record.json.schema
│   ├── run_p0.sh
│   └── results/
├── examples/
├── scripts/
│   ├── build.sh
│   ├── build-asan.sh
│   └── build-tsan.sh
└── tools/
    └── check_include_boundaries.sh
```

源码在 CMake 中显式列举, 不使用 glob。

## 10. 构建规范

固定决策:

| 项目            | 值                           |
| ------------- | --------------------------- |
| 仓库            | `/home/Netstack2`           |
| 默认分支          | `main`                      |
| CMake project | `Netstack2`                 |
| Target        | `tcpip2`                    |
| Alias         | `tcpip2::tcpip2`            |
| 产物            | `libtcpip2.a`               |
| Namespace     | `tcpip2`                    |
| 公开头           | `include/tcpip2/`           |
| C++ 标准        | C++17                       |
| 许可证           | GPL-3.0                     |
| 核心依赖          | stdlib + Threads            |
| 禁止依赖          | OpenPPP2、Boost、Asio、OpenSSL |
| 格式化           | 复用 OpenPPP2 `.clang-format` |

顶层选项:

```cmake
option(ENABLE_COVERAGE "Enable coverage" OFF)
option(ENABLE_SANITIZERS "Enable ASan and UBSan" OFF)
option(ENABLE_TSAN "Enable ThreadSanitizer" OFF)
```

`ENABLE_SANITIZERS` 与 `ENABLE_TSAN` 同时开启时必须 `FATAL_ERROR`。

## 11. NETSTACK2-000: 开仓和测试底座

### 11.1 A1: 仓库与构建骨架

内容:

* `git init -b main`;
* `.gitignore`;
* GPL-3.0 LICENSE;
* `.clang-format`;
* 顶层 CMake;
* `tcpip2` 静态库;
* `tcpip2::tcpip2` alias;
* CTest;
* sanitizer 脚本;
* include boundary 检查;
* consumer TU 编译检查;
* README 标记 API experimental。

### 11.2 A2: 测试基础设施

建立:

* FakeClock;
* TimerWheelHarness;
* PacketBuilder;
* PacketParser;
* checksum known vectors;
* Pcap reader/writer;
* NullPacketIo;
* LeakTracker;
* InvariantAssert;
* death-test 子进程框架。

double-release 等致命断言必须在子进程中测试。

### 11.3 A3: Experimental API 契约

NETSTACK2-000 只冻结:

* 模块边界;
* 单 shard 归属;
* 所有权原则;
* per-queue owner;
* batch I/O 语义;
* partial send;
* 背压;
* 核心类型名;
* 核心零外部依赖。

精确 ABI/API 在 002、003、004 实现验证后冻结。

### 11.4 A4: 测试清单

#### Buffer

* 分配和归还;
* pool 耗尽;
* 泄漏检测;
* double-release death test;
* 跨线程归还;
* BufferSlice 越界;
* 长度 0;
* view 不复制;
* BufferRef 保活;
* TxSegment 重传引用。

#### Timer

* 确定性到期;
* 取消;
* 重复触发保护;
* slot wrap;
* 多粒度;
* shutdown 后不再回调。

#### Packet

* IPv4 round-trip;
* IPv6 round-trip;
* TCP round-trip;
* UDP round-trip;
* checksum known vectors;
* malformed packet;
* PCAP round-trip。

#### Packet I/O

* RecvBatch;
* SendBatch;
* WouldBlock;
* count==0;
* multi-queue;
* ownership prefix transfer;
* 异步 completion 模拟。

#### Shard

* owner thread 断言;
* 跨线程 direct access 拒绝;
* typed message 路由;
* control inbox;
* drain;
* shutdown;
* 无泄漏。

#### Compile contract

```cpp
static_assert(std::is_move_constructible_v<BufferLease>);
static_assert(!std::is_copy_constructible_v<BufferLease>);
static_assert(std::is_nothrow_move_constructible_v<BufferLease>);
static_assert(std::is_trivially_copyable_v<BufferSlice>);
```

`PktBuffer` 无原子引用计数通过类型定义审查、layout 测试和源码检查保证。

### 11.5 A5: 提交和标签

提交:

```text
NETSTACK2-000: repo skeleton + experimental API contracts + test base
```

创建 annotated tag:

```text
v0.1.0
```

v0.1.0 明确标记:

```text
Experimental API — signatures may change before
NETSTACK2-API-FREEZE-001.
```

### 11.6 NETSTACK2-000 退出条件

必须全部通过:

```text
普通 CTest 全绿
ASan/UBSan 全绿
TSan 全绿
include-boundary 检查通过
consumer TU 编译通过
cmake --build build --target tcpip2 通过
git diff --check 通过
工作区干净
NETSTACK2-000 已提交
annotated tag v0.1.0 已创建
```

## 12. NETSTACK2-001: P0 测量框架

P0 不阻塞 002–004, 但协议和数据格式必须尽早固定。

测试模式:

```text
lwIP 模式
native --lwip=no --tun-ssmt=1
native --lwip=no --tun-ssmt=N
后续加入 netstack2-tun
后续加入 netstack2-afxdp
```

固定环境信息:

* CPU;
* NUMA;
* NIC;
* 驱动;
* Linux kernel;
* 编译器;
* Build type;
* 睿频状态;
* CPU governor;
* CPU isolation;
* IRQ affinity;
* queue 数量;
* MTU;
* offload 设置。

指标:

* 单流吞吐;
* 多流总吞吐;
* pps;
* P50/P95/P99 延迟;
* CPU 总量;
* 单核 CPU;
* context switch;
* 每包分配次数;
* 每包 memcpy 字节;
* buffer pool miss;
* queue drop;
* RTT × 丢包率矩阵;
* 1/2/4/8/16 核扩展;
* 每瓦吞吐, 移动端后补。

结果统一写入 `bench/record.json.schema`。

## 13. NETSTACK2-002: Buffer 和 Packet I/O

实现:

* PktBuffer;
* PktBufferPool;
* BufferLease;
* BufferSlice;
* BufferRef;
* TxSegment;
* owner return queue;
* NullPacketIo;
* IPacketIo;
* IPacketQueue;
* SendBatch/RecvBatch 所有权语义;
* TX completion 模拟;
* buffer 上限和统计。

门禁:

* 所有 buffer 测试从占位变为真实实现;
* ASan/UBSan;
* TSan;
* 泄漏为 0;
* double-release 可检测;
* 热路径无每包 atomic refcount。

## 14. NETSTACK2-003: Linux TapPacketIo

实现:

* `/dev/net/tun`;
* TUN;
* 可选 TAP;
* `IFF_MULTI_QUEUE`;
* 每 queue 一个 IPacketQueue;
* 单队列;
* multiqueue;
* batch read/write;
* owner shard 固定;
* shutdown;
* fd 错误处理;
* 与 `TapLinux::Ssmt/SsmtMQ` 行为对齐。

优先使用稳定系统调用完成第一版, 不在 003 强制引入 io_uring。

测试:

* 无 root 环境自动 skip TUN 集成测试;
* NullPacketIo 单元测试始终执行;
* root 环境执行 TUN loopback 冒烟;
* 多队列路由;
* shutdown/drain;
* fd 泄漏检查。

## 15. NETSTACK2-004: Dispatcher 和 StackShard

实现:

* IPv4 FlowKey;
* IPv6 FlowKey;
* 稳定 hash;
* PacketDispatcher;
* queue→shard 映射;
* StackShard 线程;
* event loop;
* flow table;
* timer wheel;
* SPSC data queue;
* MPSC control inbox;
* typed message;
* shutdown/drain;
* CPU affinity;
* load statistics;
* owner assertion;
* session callback 回投;
* bounded queue。

门禁:

* 多 producer 控制消息压测;
* 多 queue 输入;
* 无 flow 跨 shard 修改;
* shutdown 后无悬挂回调;
* drain 无泄漏;
* TSan 全绿;
* 线程数量变化时行为确定;
* 同一 FlowKey 永远映射相同 shard。

## 16. NETSTACK2-API-FREEZE-001

触发条件:

```text
NETSTACK2-002 完成
NETSTACK2-003 完成
NETSTACK2-004 完成
普通测试全绿
ASan/UBSan 全绿
TSan 全绿
至少一个真实 Linux TUN multiqueue 测试通过
```

冻结内容:

* public header 精确签名;
* Buffer 所有权;
* Packet I/O ownership transfer;
* Session partial-send;
* callback 生命周期;
* shard message;
* config schema;
* error enums;
* shutdown 语义。

从 P3A 开始, 公开签名变更必须:

* 提交 ADR;
* 说明兼容性;
* 提供迁移;
* 更新 consumer contract test。

## 17. P4: OpenPPP2 集成

新增配置建议:

```text
--stack=lwip
--stack=netstack2
--stack=native
```

Linux 数据路径建议:

```text
--linux-datapath=auto
--linux-datapath=tc-hairpin
--linux-datapath=afxdp
--linux-datapath=netmap
--linux-datapath=dpdk
--linux-datapath=tun
```

Netstack2 配置:

```text
--netstack-shards=N
--netstack-rx-queues=N
--netstack-pool-capacity=N
--netstack-cpu-affinity=...
```

OpenPPP2 改动位置:

* `ppp/ethernet/VEthernet.cpp/.h`;
* `VNetstack.cpp/.h`;
* `ppp/app/ApplicationConfig.cpp`;
* `linux/ppp/tap/TapLinux.*`;
* `ios/OpenPPP2PacketTunnelBridge.cpp`;
* Android bridge;
* Windows Wintun adapter;
* 根、Android、iOS CMake。

集成原则:

* OpenPPP2 依赖 Netstack2;
* Netstack2 不依赖 OpenPPP2;
* Netstack2 通过 adapter 接入 transmission;
* lwIP 保留回退;
* 同一运行实例只启用一个 TCP/IP engine;
* engine 切换在启动阶段完成, 不做运行中热切换。

## 18. Linux TC/eBPF 和 Hairpin NAT 工作包

### OPENPPP2-LINUX-DP-001: TC/eBPF

实现:

* capability probe;
* BPF object 加载;
* verifier 错误处理;
* clsact;
* ingress/egress attach;
* mark/classify;
* redirect;
* detach;
* 原子升级;
* 异常回滚;
* 运行时统计;
* 系统重启和进程崩溃后的清理。

代码位于 OpenPPP2 Linux adapter, 不进入 Netstack2 核心。

### OPENPPP2-LINUX-DP-002: Hairpin NAT

实现:

* nftables table/chain;
* IPv4 DNAT/SNAT;
* IPv6 NAT;
* conntrack;
* mark 或 zone 隔离;
* 规则幂等;
* 与现有防火墙共存;
* 安装、更新、删除;
* crash recovery;
* stale rule cleanup;
* fallback 到 Netstack2。

探测失败时必须明确记录原因并回退, 不能让数据路径处于半配置状态。

## 19. P5: 高性能 Packet I/O

### NETSTACK2-005: AF_XDP

实现:

* XDP capability probe;
* XSKMAP;
* UMEM;
* fill/completion rings;
* RX/TX rings;
* copy mode;
* zero-copy mode;
* per-queue IPacketQueue;
* poll/busy poll;
* completion 回收;
* fallback 原因。

### NETSTACK2-006: netmap/DPDK

实现:

* NetmapPacketIo;
* DpdkPacketIo;
* per-core queue;
* rte_ring 或原生 queue;
* hugepage/NUMA 配置;
* checksum offload;
* TX completion;
* UserspaceSession;
* queue 与 shard 亲和。

## 20. P6: 平台铺开

### Android

* VpnService Packet I/O;
* 默认 shard 1~2;
* 电量和温控策略;
* 前后台切换;
* VPN 生命周期;
* IPv4/IPv6;
* 与 Java/Kotlin bridge 隔离。

### iOS

* utun Packet I/O;
* 修正当前 bridge 中固定 `mta=false` 的限制;
* PacketTunnelProvider 生命周期;
* shard 1~2;
* 内存警告处理;
* IPv6;
* 后台执行限制。

### Windows

* Wintun;
* IOCP 或平台 adapter;
* KernelSocketSession;
* 多 queue 能力探测;
* service lifecycle;
* IPv4/IPv6。

## 21. P7: 性能调优

内容:

* TCP Window Scale;
* 更大 receive/send window;
* SACK 优化;
* batch input/output;
* GRO/GSO;
* checksum offload;
* TSO;
* CPU affinity;
* NUMA;
* timer batching;
* ACK 合并;
* cache-line 对齐;
* false sharing 检查;
* buffer pool 分层;
* adaptive polling;
* mobile idle sleep;
* DPDK UserspaceSession;
* EF_VI;
* Onload socket tuning。

任何性能优化不得破坏:

* 单 flow 单 shard;
* ownership;
* bounded memory;
* deterministic shutdown;
* fallback 可用性。

## 22. 可观测性

### Backend

* backend 类型;
* capability probe 结果;
* fallback reason;
* RX/TX packets;
* RX/TX bytes;
* drops;
* WouldBlock;
* completion latency;
* queue depth。

### Shard

* flow count;
* queue depth;
* messages processed;
* timer count;
* loop latency;
* CPU utilization;
* buffer pool usage;
* cross-thread return count。

### TCP

* SYN;
* SYN retry;
* established;
* reset;
* retransmission;
* fast retransmission;
* RTO;
* RTT/SRTT;
* duplicate ACK;
* out-of-order;
* receive window;
* send window;
* session WouldBlock;
* TIME-WAIT count。

### Linux 快速路径

* TC attach 状态;
* BPF verifier 错误;
* hairpin flow 数;
* nftables rule 状态;
* conntrack drop;
* fallback 到 AF_XDP/TUN 的原因。

## 23. 资源和安全边界

所有资源必须有明确上限:

* 每 shard 最大 flow;
* 全局最大 flow;
* 每 flow send buffer;
* 每 flow receive reassembly;
* retransmission bytes;
* fragment reassembly;
* TIME-WAIT 数量;
* control queue;
* packet queue;
* buffer pool;
* pending Session connect;
* SYN backlog。

错误策略:

* 内存不足: 拒绝新 flow 或缩小窗口;
* Session 堵塞: 反馈 TCP 背压;
* queue 满: 计数并有界丢弃;
* backend 故障: 停止接收并进入明确 fallback;
* BPF/NAT 安装失败: 完整回滚;
* shutdown: 停止新输入、drain、关闭 Session、释放 buffer。

## 24. 差分、模糊和互操作测试

### 差分测试

同一 PCAP 输入:

```text
Netstack2 输出
对比 Linux TCP 行为
对比 lwIP 参考行为
```

不要求字节级所有时序相同, 但必须验证:

* ACK 合法;
* seq 单调;
* window 合法;
* checksum 正确;
* 状态转换合法;
* 不发送越界数据。

### 模糊测试

目标:

* IPv4 parser;
* IPv6 parser;
* extension headers;
* TCP options;
* fragment reassembly;
* checksum;
* state transition;
* malformed ACK/RST/SYN。

### 互操作

至少覆盖:

* Linux;
* Windows;
* Android;
* iOS/macOS;
* NAT;
* 高 RTT;
* 丢包;
* reorder;
* duplicate;
* MTU 变化;
* IPv6-only;
* dual-stack。

## 25. GitHub 和 Submodule

远端:

```text
git@github.com:Miaocchi/netstack2.git
```

禁止将本地绝对路径写入 `.gitmodules`。

当前 GitHub SSH 通道顺延, 不阻塞 NETSTACK2-000 和 NETSTACK2-001。

恢复 SSH 前:

1. 获取 GitHub host key;
2. 与 GitHub 官方公布的 fingerprint 核验;
3. 再写入 `known_hosts`;
4. 测试 `ssh -T git@github.com`;
5. 测试 `git ls-remote`;
6. 创建并推送仓库。

OpenPPP2:

```bash
git submodule add \
  git@github.com:Miaocchi/netstack2.git \
  common/libtcpip2
```

Submodule 钉的是 commit; `v0.1.0` 仅用于标识里程碑。

000–004 期间暂不接 OpenPPP2 主构建。

## 26. 完整执行顺序

```text
A1 仓库与 CMake
 ↓
A2 测试基建
 ↓
A3 Experimental API
 ↓
A4 单元测试和 sanitizer
 ↓
A5 NETSTACK2-000 commit + v0.1.0
 ├─ NETSTACK2-001 P0 测量框架
 ├─ GitHub 通道恢复后执行 OpenPPP2 submodule
 └─ NETSTACK2-002 Buffer/Packet I/O
       ↓
    NETSTACK2-003 Linux TapPacketIo
       ↓
    NETSTACK2-004 Dispatcher/StackShard
       ↓
    NETSTACK2-API-FREEZE-001
       ↓
    P3A IPv4/IPv6/L3
       ↓
    P3B TCP 基础
       ↓
    P3C TCP 互操作与性能
       ↓
    P4 OpenPPP2 集成
       ↓
    P5 TC/eBPF、hairpin、AF_XDP、DPDK/netmap
       ↓
    P6 Android/iOS/Windows
       ↓
    P7 性能和功耗调优
```

## 27. 最终架构结论

Netstack2 是一个以连接单 shard 归属为核心、面向 IPv4/IPv6 的多线程用户态
TCP/IP 引擎。

跨平台主路径:

```text
虚拟网卡
→ IPacketQueue
→ StackShard
→ TcpFlow
→ ITransportSession
```

Linux 同时支持:

```text
TC/eBPF + kernel hairpin NAT
AF_XDP → Netstack2
DPDK/netmap → Netstack2
MQ TUN/TAP → Netstack2
```

其中:

* TC/eBPF 与 hairpin NAT 属于 OpenPPP2 Linux adapter;
* AF_XDP、DPDK、netmap 和 TUN/TAP 属于 Netstack2 Packet I/O;
* Android、iOS、Windows 主要依赖 Netstack2 替换 lwIP;
* Linux 根据能力自动选择最佳数据路径;
* lwIP 在迁移期间保留为回退;
* Netstack2 核心始终保持零外部依赖和平台无关。
