# Netstack2 Roadmap

> 本文记录里程碑状态、工作包范围、前置依赖、验收门禁、当前 commit/tag 和已知阻塞项。
> 架构设计与边界见 `docs/architecture/NETSTACK2_ARCHITECTURE.md`; 详细实施顺序、
> 文件级任务和验收方法见 `docs/IMPLEMENTATION_GUIDE.md`; 本文只记录任务进度,
> 不混入架构决策。OpenPPP2 集成细节见 `docs/integration/OPENPPP2_INTEGRATION_PLAN.md`。

## 1. 里程碑状态

| 里程碑 | 状态 | 说明 |
|------|------|------|
| NETSTACK2-000 | **Completed** | 开仓 + 测试底座, commit `628eb60`, tag `v0.1.0` |
| NETSTACK2-001 | Planned | P0 测量框架, 不阻塞 002–004 |
| NETSTACK2-002 | **Completed** | Buffer 与 Packet I/O 契约, commit `8e20940` |
| NETSTACK2-002H | **Completed** | Buffer/Packet I/O 所有权加固: Resize 边界、pool identity、BufferRef RAII、arena 失败、NullPacketIo wake |
| NETSTACK2-003 | **Completed** | Linux TapPacketIo, 与 004 并行完成 |
| NETSTACK2-004 | **Completed** | Dispatcher 与 StackShard, 与 003 并行完成 |
| NETSTACK2-ADAPTER-SPIKE | **Completed** | compile-only `OpenPppPacketIo` + `OpenPppSessionFactory` 编译通过; 新增 `session_factory.h`、`capabilities.h`、`address.h`、`flow.h` 公共头; `IPacketIo::Capabilities()` 虚方法加入; FlowId 统一到公共头 |
| NETSTACK2-API-FREEZE-001 | **Completed** | 公共 API 冻结(10 头文件), ADR-004, tag `v0.2.0` |
| P3A-01 | **Completed** | checked arithmetic、IPv4/IPv6 bounded parser、checksum，23/23 三套构建全绿 |
| P3A-02 | **Completed** | ICMPv4/ICMPv6 bounded parser + PMTU cache，26/26 三套构建全绿 |
| P3A-03 | **Completed** | IPv4/IPv6 fragment reassembly，44/44 三套构建全绿（含 byte-budget hardening） |
| P3B-1 | **Completed** | bounded PCB + passive handshake + IPv4/IPv6 wire RX/TX，TCP 23/23、全量 28/28 三套构建全绿 |
| P3B-2 | **Completed** | bounded receive ring、delayed ACK/SACK、Session partial/WouldBlock，TCP 40+23、全量 29/29 三套构建全绿 |
| P3B-3 | **Completed** | retransmission queue + RTO、SACK scoreboard、data segment serialization、send buffer 接入 handshake engine 和 shard event loop，TCP 54+51、全量 30/30 三套构建全绿 |
| P3B-4 | **Completed** | FIN/close/TIME-WAIT 状态机、CloseFlow/AbortFlow API、TIME-WAIT 容量驱逐，FIN 处理/half-close/TIME-WAIT 驱逐 bugfix，TCP handshake 74/74、全量 30/30 三套构建全绿。SACK scoreboard wire 接线仍属 P3C |
| P3C | **In progress** | P3C-01 DeliveryRateSampler + CongestionController 接口 + AIMD 适配完成，TCP congestion 21/21、全量 31/31 三套构建全绿。BBRv1 状态机已编译，测试待 P3C-02 完善。Pacing 和 fragment 接线待 P3C-03/04 |
| P4 | Planned | OpenPPP2 集成(在 API-FREEZE 之后接线) |
| P5–P7 | Planned | 高性能 Packet I/O、平台铺开、调优 |

## 2. 提交与标签

| 里程碑 | commit | tag |
|------|--------|-----|
| NETSTACK2-000 | `628eb60` | `v0.1.0`(annotated) |
| NETSTACK2-002 | `8e20940` | 无(tag 留给 v0.2.0) |
| NETSTACK2-API-FREEZE-001 | `3d82bb0` | `v0.2.0`(annotated) |
| P3A-01 | `707b14a` | 无 |
| P3A-02 | `86d8adc` | 无 |
| P3A-03 | `c889289` + hardening `2b5607e` | 无 |
| P3B-1 | `ab5a949` + shard wiring `a3448b4` | 无 |
| P3B-2 | `15c55f8` + integration `6a166d8` + shard `4ce7a35` | 无 |
| P3B-3 (send core) | `6fb047b` | 无 |
| P3B-3 (SACK scoreboard) | `5583c8d` | 无 |
| P3B-3 (data segment output) | `8bdf43e` | 无 |
| P3B-4 (FIN/close/TIME-WAIT) | `83b7a04` + bugfix `f2c49dc` | 无 |
| P3C-01 (rate sampler + CC interface) | `pending` | 无 |

规则:

* `v0.1.0` 固定指向 `628eb60`, 不移动、不重打。
* 架构文档和 roadmap 单独提交, 不混入 NETSTACK2-002 实现。
* NETSTACK2-002 完成时只提交 commit, 不打 tag。
* `v0.2.0` 将打在 `NETSTACK2-API-FREEZE-001` 的 freeze commit 上(annotated),
  002–004 已完成且通过 API 冻结门禁。

## 3. 工作包范围、前置依赖与门禁

### NETSTACK2-000: 开仓和测试底座 (Completed)

范围: 仓库骨架、GPL-3.0、`.clang-format`、顶层 CMake、`tcpip2` 静态库、
`tcpip2::tcpip2` alias、CTest、sanitizer 脚本、include boundary 检查、
consumer TU 编译检查、测试基建(FakeClock / PacketBuilder / PacketParser /
Pcap / NullPacketIo / LeakTracker / death-test 子进程框架)。

前置: 无。

门禁(已全部通过): 普通 CTest 全绿; ASan/UBSan 全绿; TSan 全绿;
include-boundary 通过; consumer TU 编译通过; `--target tcpip2` 通过;
`git diff --check` 通过; 工作区干净; 已提交; tag `v0.1.0` 已创建。

### NETSTACK2-001: P0 测量框架 (Planned)

范围: `bench/record.json.schema` 数据格式、环境信息固定、指标定义
(单流/多流吞吐、pps、P50/P95/P99、CPU、ctx switch、每包分配/拷贝、
pool miss、queue drop、RTT×丢包矩阵、1/2/4/8/16 核扩展)。

前置: 无(不阻塞 002–004)。

门禁: 协议与数据格式固定; run 脚本可复现。

### NETSTACK2-002: Buffer 和 Packet I/O (Completed)

范围: PktBuffer; PktBufferPool; BufferLease(move-only, noexcept, 析构归还
owner pool, 跨线程归还走 owner return queue); BufferSlice(trivially
copyable 只读视图); BufferRef(shard-local retained handle); TxSegment;
owner return queue; NullPacketIo; IPacketIo/IPacketQueue;
SendBatch/RecvBatch 所有权语义(prefix transfer); TX completion 模拟;
buffer 上限和统计。

前置: NETSTACK2-000。

门禁(已全部通过): 所有 buffer 测试从占位变为真实实现; 普通/ASan/UBSan/
TSan 全绿; 泄漏为 0; double-release 可检测(death test, 含 queued 状态);
热路径无每包 atomic refcount; include-boundary 与 consumer TU 通过;
`git diff --check` 通过。

实现文件(commit `8e20940`, 未打 tag): `include/tcpip2/buffer.h`、
`include/tcpip2/packet_io.h`、`src/core/buffer_pool.cpp`、
`src/packetio/null_io.cpp`、`tests/unit/buffer_pool_test.cpp`、
`tests/unit/packet_io_contract_test.cpp`、`tests/unit/shard_ownership_test.cpp`、
`tests/unit/compile_contract_test.cpp`。

### NETSTACK2-002H: Buffer 和 Packet I/O 加固 (Completed)

范围: `Resize` capacity 边界; pool identity 校验; `BufferRef` shard-local
RAII retained ownership; arena 分配失败; NullPacketIo wake/unregister/shutdown。

前置: NETSTACK2-002。

门禁(已全部通过): 跨 pool return death test; double release death test;
oversize resize death test; BufferRef RAII 析构释放; arena 失败降级为 0 可用 slot;
NullPacketIo Inject 空→非空触发 wake、handler 可解除注册、handler 在锁外调用
避免死锁。普通/ASan/UBSan/TSan 全绿; 热路径无每包 atomic refcount。

实现文件: `include/tcpip2/buffer.h`、`src/core/buffer_pool.cpp`、
`src/core/buffer.cpp`、`src/packetio/null_io.cpp`、
`tests/unit/buffer_ref_test.cpp`、`tests/unit/buffer_pool_test.cpp`、
`tests/unit/packet_io_contract_test.cpp`、`tests/unit/compile_contract_test.cpp`、
`tests/unit/static_assert_test.cpp`。

变更摘要:

- `PktBuffer::Resize(n)` 在 `n > capacity_` 时 abort, 不再静默越界。
- `ReturnBuffer` 和 `ReleaseRetained` 校验 `pkt->pool_ == this` 和 slot 地址一致。
- `BufferRef` 改为 shard-local RAII 非原子 retain count: `PktBuffer` 增加
  `ref_count_` 字段; BufferRef 复制时 `++ref_count_`, 析构时 `--ref_count_`,
  最后一个引用归还 pool; 删除手动 `Unpin(BufferRef)`, 改为 `BufferRef::Reset()`
  和 RAII 析构自动管理。
- Pool 构造时 arena 分配失败显式降级为 0 可用 slot, 不留半初始化对象。
- `NullPacketIo::Inject()` 在 backlog 从空变为非空时触发 `recv_handler`,
  handler 在锁外调用; `SetRecvHandler(nullptr)` 清除 handler。

### NETSTACK2-003: Linux TapPacketIo (Completed)

范围: `/dev/net/tun`; TUN; 可选 TAP; `IFF_MULTI_QUEUE`; 每 queue 一个
IPacketQueue; 单/多队列; batch read/write; owner shard 固定; shutdown;
fd 错误处理; 与 `TapLinux::Ssmt/SsmtMQ` 行为对齐。第一版用稳定系统调用,
不强制 io_uring。

前置: NETSTACK2-002H。与 NETSTACK2-004 并行, 两者在 API freeze 前汇合。

门禁(已全部通过): 无 root 环境自动 skip TUN 测试(10 个单元测试, 非 root
环境 graceful skip); `IFF_TUN | IFF_NO_PI`、可选 `IFF_MULTI_QUEUE`;
逐包 `read`/`write` syscall 循环(非 `readv`/`writev`);
EAGAIN→WouldBlock, EINTR 重试(上限 3), EBADF→Closed;
`O_CLOEXEC` + 非阻塞 fd; `SetBufferPool()` 注入 owner shard 的 per-shard
pool(ADR-001 v2, 原 `GlobalTapPool()` 已废弃); 003 与 004A 组合形成
packet-in/drop/packet-out 闭环(通过 runtime_test 验证)。
普通/ASan/UBSan/TSan 全绿(18/18)。

实现文件: `include/tcpip2/tap_io.h`、`src/packetio/tap_io.cpp`、
`tests/unit/tap_io_test.cpp`。

### NETSTACK2-004: Dispatcher 和 StackShard (Completed)

范围: IPv4/IPv6 FlowKey; 稳定 hash; PacketDispatcher; queue→shard 映射;
StackShard 线程; event loop; flow table; timer wheel; SPSC data queue;
MPSC control inbox; typed message; shutdown/drain; CPU affinity;
load statistics; owner assertion; session callback 回投; bounded queue。

前置: NETSTACK2-002H。与 NETSTACK2-003 并行, 先使用 NullPacketIo 验证 runtime。

门禁(已全部通过): 多 producer 控制消息压测(4 线程并发 MPSC PostMessage);
多 queue 输入; 无 flow 跨 shard 修改; shutdown 后无悬挂回调(100× Start/Stop
循环验证幂等); drain 无泄漏(pool outstanding==0); TSan 全绿; 线程数量变化时
行为确定; 同一 FlowKey 永远映射相同 shard(canonical ordering + FNV-1a hash
golden vector 测试)。普通/ASan/UBSan/TSan 全绿(18/18)。

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
- SPSC packet inbox 是 lock-free(atomic head/tail, power-of-2 capacity);
  MPSC control inbox 使用 mutex+condvar(control inbox 不是热路径,
  256 messages/iteration)。
- Shard counters 使用 `std::atomic<std::size_t>`(relaxed ordering), 因为
  shard 线程写、测试线程读, 避免 TSan 误报。
- FlowHash 使用 FNV-1a over canonical bytes(family byte + address bytes +
  big-endian port bytes + protocol byte), 不使用 `std::hash`。
- Canonical ordering: 比较 (address, port) pair, 小的放 source, 大的放
  destination, 保证正反向 flow 落在同一 shard。
- `shard_message.h` 从 `shard.h` 提取, 解决 `shard.h ↔ inbox_mpsc.h` 循环依赖。
- `Stop()` 幂等, 且不在 shard 自己的线程上 join 自己。

### NETSTACK2-ADAPTER-SPIKE: OpenPPP2 编译适配验证 (Completed)

范围: 使用 public API 草案实现 compile-only `OpenPppPacketIo` 和
`OpenPppSessionFactory`; 验证 IPv4/IPv6 packet、路由策略、目标地址、输出和
shutdown 契约。不接入默认数据路径, 不替换 lwIP。

前置: NETSTACK2-002H public API 草案。

门禁(已全部通过):
- ✅ Linux adapter translation unit (`openppp_adapter_spike_test.cpp`) 可编译;
- ✅ adapter 使用纯 public header, 不依赖 OpenPPP2/Boost/平台类型;
- ✅ capabilities 传播(route_mark/fake_ip/DNS/QUIC/PMTU → PacketIoCapabilities);
- ✅ ISessionFactory OpenTcp/OpenUdp 签名可表达完整路由元数据;
- ✅ 19/19 测试三套构建(default/ASan/TSan)全绿;
- ✅ ADR-003 记录结论与公共 API 变更。

新增公共头: `address.h`、`flow.h`、`capabilities.h`、`session_factory.h`。
`IPacketIo` 新增非纯虚 `Capabilities()`。`FlowId` 统一到 `session_factory.h`,
`shard_message.h` 通过 include 复用(不再重复定义)。

### NETSTACK2-API-FREEZE-001 (Completed)

门禁(已全部通过): 003/004 已完成 ✅; OpenPPP2 compile-only adapter spike 完成 ✅;
普通/ASan/UBSan/TSan 全绿 ✅; TUN multiqueue 真实测试通过(ADR-002 Tier 2 ✅,
root 下 4-queue TUN 收发验证通过; 非 root 环境 graceful skip); buffer pool 所有权
验证通过(ADR-001 v2: per-shard pool, `SetBufferPool` 纯虚注入,
`SetOwnerThread` 在 shard `Run()` 中调用) ✅。

已识别并处理的前置问题:

1. ✅ **Buffer pool 所有权**(ADR-001 v2): 删除 `GlobalTapPool()`,
   改为 `IPacketQueue::SetBufferPool()` 纯虚注入。每 shard 一个独立
   `PktBufferPool`(不再共享单一 runtime pool), `SetOwnerThread()` 在
   shard `Run()` 开头调用, 热路径 owner-local uncontended(mutex 仍获取,
   但仅 owner shard 线程竞争)。`Runtime::Start()` 不再接收外部
   pool 参数, 内部创建 per-shard pool。
2. ✅ **`SetBufferPool` 纯虚**: 防止后端忘记注入 pool 却静默编译通过。
3. ✅ **注释与实现一致性**: `tap_io.h`/`tap_io.cpp` 注释从
   "readv/writev" 修正为"逐包 read/write syscall 循环"。
4. ✅ **TUN multiqueue 门禁**(ADR-002): Tier 1 (code review) 完成;
   Tier 2 (真实 root TUN multiqueue 测试) **已满足** —
   `TapMultiqueueTier2RootTest` 在 root 下创建 4-queue TUN, 配置
   `10.222.0.1/24`, 注入 UDP-to-self, 轮询 4 个 queue 接收, 三套构建
   全部 PASS。非 root 环境 graceful skip, 不影响 CI。

冻结内容: public header 精确签名; Buffer 所有权; Packet I/O ownership
transfer; Session partial-send; callback 生命周期; shard message;
config schema; error enums; shutdown 语义。

冻结后签名变更必须: 提交 ADR; 说明兼容性; 提供迁移; 更新 consumer
contract test。

## 4. 后续里程碑顺序

```text
NETSTACK2-002H Buffer/Packet I/O hardening ✅
        ↓
NETSTACK2-003 TapPacketIo ✅ (ADR-001 v2: per-shard pool, ADR-002: Tier 2 ✅)
  + NETSTACK2-004 Dispatcher/StackShard ✅
  + OpenPPP2 compile-only adapter spike ✅ (ADR-003)
        ↓
NETSTACK2-API-FREEZE-001 ✅
        ↓
P3A-01 IPv4/IPv6 parser + checksum ✅
  → P3A-02 ICMPv4/ICMPv6 parser + PMTU cache ✅
  → P3A-03 fragment reassembly ✅
  → P3B-1 PCB + passive handshake ✅
  → P3B-2 receive path ✅
  → P3B-3 send path (retransmission, SACK, wiring) ✅
        ↓
P3B-4 FIN/close/TIME-WAIT ✅
        ↓
P3C TCP 互操作与性能
        ↓
P4 OpenPPP2 集成(真实构建与运行时接线)
        ↓
P5 TC/eBPF、hairpin、AF_XDP、DPDK/netmap
        ↓
P6 Android/iOS/Windows
        ↓
P7 性能和功耗调优
```

## 5. 已知阻塞项

* **GitHub SSH 通道**: 远端 `git@github.com:Miaocchi/netstack2.git` 暂不可用,
  不阻塞 000/001。恢复流程: 获取 host key → 与官方 fingerprint 核验 →
  写入 `known_hosts` → `ssh -T git@github.com` → `git ls-remote` → 创建推送仓库。
  禁止将本地绝对路径写入 `.gitmodules`。
* **lwIP 保留**: 迁移期间 lwIP 保留为回退路径; 同一运行实例只启用一个
  TCP/IP engine, 切换在启动阶段完成, 不做运行中热切换。

## 6. 并行工作

OpenPPP2 只读对照和集成规划(`docs/integration/OPENPPP2_INTEGRATION_PLAN.md`)
与 NETSTACK2-002 并行进行, 不接 submodule、不改构建、不替换 lwIP。
真实 OpenPPP2 构建与运行时接线在 API-FREEZE-001 之后(P4)。
