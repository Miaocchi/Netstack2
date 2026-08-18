# Netstack2 vs lwIP — 性能对比与结果解释

- 对比日期：2026-08-18
- 机器：Intel Xeon E5-2680 v4 @ 2.40GHz（容器 56 vCPU）
- 构建：两者均使用 Release `-O3`
- lwIP：测试时取自 `lwIP-tcpip/lwip` master（2.2-dev），使用 `NO_SYS` 配置；报告称池参数与 Netstack2 对齐为 4096 槽、每槽 2048B

> [!IMPORTANT]
> 本文保留的是一次历史微基准结果，不是可复现的性能基线。原始 `compare.cpp`、`lwipopts.h`、构建脚本和输出只存放在 `/tmp/lwip_bench/`，没有入库；lwIP 的精确 commit、保护宏、checksum、stats、LTO 等配置也没有保存。因此可以核查实现机制和差距方向，但不能独立验证绝对数字。

## 结果总览

| 场景 | Netstack2 | lwIP | Netstack2/lwIP | 正确解读 |
|---|---:|---:|---:|---|
| 缓冲池分配/释放 | 38.7M ops/s | 570M ops/s | 0.07x | 无锁池的单线程微基准常数开销（跨线程收益见 §6） |
| 定时器 10k（插/删/推进） | 46.5K ops/s | 99.5K ops/s | 0.47x | 单一规模下 lwIP 的低常数开销占优；不能外推（见 §2） |
| RX 64B IPv4+UDP（端到端，批同步） | 3.40–3.45M pkt/s（best 3.67–3.72M） | 12.5M pkt/s | 0.27x | 无背压稳态生产者/消费者吞吐；shard 为瓶颈 |
| RX 64B IPv4+UDP（端到端，连续注入池受限） | 1.80M pkt/s | 12.5M pkt/s | 0.14x | 池容量（65536）小于注入总量时出现背压震荡 |

这些数字对应约 80ns/包（lwIP）、290–294ns/包（Netstack2 批同步端到端）和 556ns/包（Netstack2 池受限端到端）。它们只描述该机器、该配置和该 harness 下的热路径，不代表真实 NIC 吞吐。

> 早期报告中的 1.03M/1.35M RX 数字作废：bench 的 `BuildPacket()` 未清零 IPv4 校验和字段，`ParseIpv4` 拒绝了全部报文，那些数字测量的是丢弃路径（见 §5）。

## 比较边界

两侧虽然运行在同一台机器上，但执行模型不同：

- lwIP `NO_SYS=1` 不创建 `tcpip_thread`，通常由调用方在一个串行执行上下文中直接驱动 raw API。它不等于“程序只能有一个 OS 线程”，也不自动保证所有保护宏为空操作。
- Netstack2 端到端场景包含注入线程、packet queue、shard 线程、buffer pool、通用分发、流表和 session 调用。
- 因此 RX 结果主要衡量“极简同步协议核心”与“完整多线程处理架构”的固定成本差异，不能直接解释成 Netstack2 的 IPv4/UDP 协议实现比 lwIP 慢固定倍数。

## 逐场景分析

### 1. 缓冲池

#### lwIP

当 `MEMP_MEM_MALLOC=0` 时，lwIP `memp` 使用固定大小内存池。分配从单向 free-list 表头摘取节点，释放再把节点压回表头。若 benchmark 反复执行一次分配后立即释放，则通常持续复用同一个热节点，不会遍历 4096 个槽，也不会读取每槽 2048B payload。

`memp_malloc()`/`memp_free()` 仍由 `SYS_ARCH_PROTECT` 包围。只有在 `SYS_LIGHTWEIGHT_PROT=0` 或 port 将保护宏实现为空操作时，才能称为没有同步开销。由于测试使用的 `lwipopts.h` 未入库，不能确认本次 570M ops/s 是否处于这一配置。

#### Netstack2

当前版本（`da0bf70` 起）的 `PktBufferPool` 使用 tagged 64-bit CAS 无锁 free list：

- `Allocate()` 从无锁 LIFO 摘槽（一次 compare-exchange，ABA 由 tag 位防护）；
- owner 线程（shard）归还也走无锁 push；跨线程归还进 mutex 保护的 `return_queue_`，由 shard 每轮 drain；
- 每个槽还执行 `Leased`/`Free`/`Queued` 状态检查与 `outstanding_` 原子计数。

因此一个 alloc/free 对至少包含两次 tagged CAS 与状态 bookkeeping。单线程微基准下无锁版本的常数略高于旧的 mutex 版本（79.6M ops/s），但消除了跨线程竞争，是 RX 端到端提升的关键（§6）。池性能差距由同步、状态管理、容器操作和测试访问模式共同造成，不能归因成“纯 mutex 代价”（旧版本）或“纯 CAS 代价”（当前版本）。

仓库 `bench_p0` 将 allocate 和 release 分别计为一个 op。若外部对比沿用同一口径，则（本次复测，无锁池版本）：

- 38.7M ops/s 约为 25.8ns/单项操作、51.7ns/alloc+free 对；
- 570M ops/s 约为 1.75ns/单项操作、3.51ns/alloc+free 对。

原报告中的“12.6ns/对”混淆了单项操作与操作对：12.6ns 是单项操作（allocate 或 release 之一），不是 alloc/free 对。

> 注意：无锁池的跨线程收益体现在 RX 端到端（§6），而单线程 alloc/free 微基准下它比旧的 mutex 版本（79.6M ops/s）反而慢，原因是每操作两次 tagged CAS + free-count 原子更新，常数略高于 mutex 快速路径。两类数字不能互换使用。

### 2. 定时器

#### lwIP

`sys_timeout` 把 timer 插入按绝对到期时间排序的单向链表：

- 插到表头最好为 O(1)；
- 插到表尾最坏为 O(n)；
- `sys_untimeout(handler, arg)` 查找目标最坏也是 O(n)；
- 若按不利顺序批量插入 n 个 timer，建表总成本可能接近 O(n²)。

规模增大时，链表扫描和 pointer chasing 会快速增加。具体退化程度高度依赖 deadline 分布、插入顺序、取消顺序和缓存状态。

#### Netstack2

`TimerWheel` 使用 256 个 `std::list<Entry>` 槽，并用 `std::unordered_map<TimerId, SlotPos>` 定位 timer：

- `Schedule()` 和 `Cancel()` 平均为 O(1)，最坏情况仍受 hash 冲突和 rehash 影响；
- list 节点、unordered-map 节点和 hash 计算带来较高的固定成本，因此小规模时可能慢于 lwIP；
- `AdvanceTo()` 在没有任何 pending timer 时 O(1) 直接返回（本仓库已优化）；只要存在 pending timer，就会遍历全部 256 个槽及全部 pending entry，复杂度是 Θ(slot count + pending)，并不是经典时间轮的 O(到期槽数)。

本次 benchmark 使用空 callback 时，小 callable 通常会进入 `std::function` 的 small-buffer optimization；不能断言每个 timer 都由 `std::function` 额外触发一次堆分配。确定存在的分配主要来自 list 和 unordered-map 节点。

本次复测只有 10k 单一规模（46.5K vs 99.5K ops/s），在该规模下 lwIP 的有序链表常数更低。早期报告中 8k/12k/16k 多规模数据（曾出现经验交叉）未随本次复测重跑，已从总览表移除；单点数据既不能推广成产品场景的固定阈值，也不能据此声称 Netstack2 的整个定时器路径都是 O(1)。

### 3. RX 64B IPv4+UDP

#### lwIP 路径

`NO_SYS` 测试通常由同一执行上下文直接调用 `ip4_input()` 和 `udp_input()`。lwIP 仍会完成 IP 长度、地址、分片策略、可选 checksum、pbuf 调整、UDP 长度、PCB 匹配和 callback 等工作，并非“只做一次 PCB 匹配”。

不过它不会像报告对应版本的 Netstack2 那样反复调用多个完整 IPv4 parser。单 flow、单 PCB、固定 packet 的微基准还会使代码、packet 和 PCB 保持热缓存，分支预测也处于理想状态。

#### Netstack2 路径

> 本节分析的是报告对应版本（修复前，`81a535c` 前后）的路径。修复前的“约 740ns/包”来自 1.35M pkt/s 的旧测量，而那组数字本身还叠加了 bench 校验和 bug（§5）：`BuildPacket()` 未清零 IPv4/UDP 校验和字段，`ParseIpv4` 拒绝了全部报文，测的是丢弃路径。修复并优化后的真实路径数字见 §6/§7（同步核心约 228ns/包，端到端约 307ns/包）。

报告对应版本的端到端稳态路径至少包含：

1. 注入线程从 `PktBufferPool` 分配 buffer；
2. `NullPacketIo::Inject()` 把 lease 放入队列；
3. shard 每轮以最多 64 包的 batch 接收；
4. dispatcher 解析 packet、构造和 canonicalize `FlowKey`、计算 hash 并选择 shard；
5. shard 识别 TCP、UDP 和 fragment 路径；
6. UDP flow table 查找和 session 调用；
7. buffer 返回 pool。

在 Null backend 稳态下，每包大致包含：

- 一次 producer pool-allocation mutex；
- 一次 producer queue-injection mutex；
- 一次 consumer pool-return mutex；
- 每批最多 64 包再承担一次 queue mutex；
- 每轮还有 return-queue drain 的批级锁开销。

因此原报告的“每包两次 mutex”低估了实际同步次数。

更重要的是，按报告提交时的代码静态追踪，一个 IPv4+UDP 包在完整路径中最多会触发 6 次 `ParseIpv4()`：

1. `PacketDispatcher::ClassifyPacket()`；
2. `ParseIpTcpPacket()`；
3. 为取得 protocol 再解析一次；
4. `ExtractFragmentInfo()`；
5. 第一次 `ParseIpUdpPacket()`；
6. `HandleUdp()` 再调用一次 `ParseIpUdpPacket()`。

`ParseIpv4()` 每次都会重新校验 IPv4 header checksum，UDP parser 也可能重复执行 UDP checksum。原报告所称“3 次 IP 解析”低估了该版本的重复工作。

对于 64B 小包，payload 极小，mutex、checksum、hash、分支、虚调用和队列管理等固定开销无法被摊薄。因此约 80ns/包（lwIP）与数百 ns/包（Netstack2）的差距在方向上可以解释，但不能只归因于线程模型，也不能直接推广到大包、多 flow 或真实 Packet I/O backend。

## 对比过程中发现并修复的等待缺陷

commit `81a535c` 修复前，`StackShard::EventLoopIteration()` 每轮最多处理 64 个 RX 包，随后无条件执行 `control_inbox_.Wait(1)`。理想吞吐上限因此约为：

```text
64 packets / 1 ms = 64,000 packets/s
```

再扣除解析、锁和调度开销，实测约 57K pkt/s 与这个上限吻合。

“RX 包不会唤醒 control inbox”并不精确。实际行为是：

- packet queue 从空变为非空时会调用 `Wake()`；
- backlog 持续非空时，不会再产生新的 empty-to-non-empty 通知；
- 通知若发生在 shard 进入等待前可能丢失；
- `Wait()` 的 predicate 只观察 control queue，不观察 RX backlog。

因此真正的问题是：持续 RX backlog 没有新的边沿通知，而 event loop 仍在每轮结束后无条件等待。修复后，仅当本轮没有处理 RX 包时才等待；存在 backlog 时立即进入下一轮。

同一提交还把 benchmark 在 pool exhaustion 时的固定 `sleep_for(200us)` 改为 `yield()`。因此修复前后的提升主要由移除 1ms 等待上限解释，但不能把全部提升严格归因于单一改动。

## 可复现性和限制

当前结果缺少以下证据：

- 外部 `compare.cpp`、`lwipopts.h` 和构建脚本；
- lwIP 精确 commit hash；
- `SYS_LIGHTWEIGHT_PROT`、checksum、stats、debug、reassembly 等配置；
- 是否启用 LTO，以及如何防止编译器消除空 benchmark；
- timer deadline、插入和取消顺序；
- 原始输出、重复次数、中位数、方差和 CPU affinity；
- “纯处理”场景的精确计时边界。

在这些材料补齐并入库前，表中的绝对数字和倍率只能作为一次性能调查记录，不能作为 CI 门限、架构 SLA 或可独立复现的横向结论。

## 结论

可以从本次实验得出：

- lwIP 在串行、热缓存、极简 fixed-pool 和单-flow raw API 路径上具有很低的固定成本；
- Netstack2 为线程安全、跨线程注入、通用分发、流表和 session 抽象支付了显著固定成本；
- 报告对应版本的 Netstack2 UDP RX 存在严重重复解析，且 RX 等待逻辑曾制造约 64K pkt/s 的硬上限；
- lwIP 有序 timeout 链表在不利的大规模插入/取消场景下会退化；Netstack2 的 schedule/cancel 平均扩展性更好，但当前 advance 路径仍会扫描全部 pending timer。

不能从本次实验得出：

- Netstack2 的 IPv4/UDP 协议核心普遍比 lwIP 慢固定倍数；
- 缓冲池差距全部来自 mutex；
- Netstack2 定时器整体为 O(1)；
- 任何单一规模下观察到的“经验交叉”是普遍适用的定时器交叉点；
- 两侧运行参数相同就代表执行语义和比较层级相同。

后续公平比较应至少拆成三个层级：

1. 协议核心对协议核心：同线程、预分配 packet、相同 checksum 和 callback 工作量；
2. 队列端到端对队列端到端：两侧都包含 producer/consumer、背压和唤醒；
3. 真实 backend 对真实 backend：固定 CPU affinity、包大小和 flow 数，报告重复测量与置信区间。

## 实现依据

- Netstack2 buffer pool：`src/core/buffer_pool.cpp`
- Netstack2 timer wheel：`src/core/timer_wheel.cpp`、`src/core/timer_wheel.h`
- Netstack2 RX dispatch：`src/core/dispatcher.cpp`、`src/core/shard.cpp`
- Netstack2 IPv4 parser：`src/ip/ipv4.cpp`
- Netstack2 benchmark：`bench/bench_p0.cpp`、`bench/README.md`
- lwIP `NO_SYS` 配置：<https://github.com/lwip-tcpip/lwip/blob/3d896ba0a37ff3ce73270ca5e230707fe47f60e3/src/include/lwip/opt.h#L82-L92>
- lwIP fixed pool：<https://github.com/lwip-tcpip/lwip/blob/3d896ba0a37ff3ce73270ca5e230707fe47f60e3/src/core/memp.c>
- lwIP timeout list：<https://github.com/lwip-tcpip/lwip/blob/3d896ba0a37ff3ce73270ca5e230707fe47f60e3/src/core/timeouts.c>
- lwIP IPv4/UDP input：<https://github.com/lwip-tcpip/lwip/blob/3d896ba0a37ff3ce73270ca5e230707fe47f60e3/src/core/ipv4/ip4.c>、<https://github.com/lwip-tcpip/lwip/blob/3d896ba0a37ff3ce73270ca5e230707fe47f60e3/src/core/udp.c>

## 5. 早期 RX 数字作废：bench 校验和 bug

早于本次复测的 RX 吞吐数字（1.03M / 1.35M pkt/s）全部作废。原因：

- `/tmp/lwip_bench/rx_diag.cpp` 的 `BuildPacket()` 用 0xAB 填充整个缓冲区，其中 IPv4 头的校验和字段（offset 10–11）与 UDP 头的校验和字段（offset 26–27）没有在计算前清零；
- `InternetChecksum()` 对“字段仍为 0xABAB”的头部计算出的校验和写回后，`ParseIpv4`/`ParseUdpDatagram` 校验必然失败（校验和 = ~acc，acc 含错误字段）；
- 实测 `[rx_diag] dropped=82432 udp=0`：全部报文被丢弃，所有 RX 数字测量的是快速失败/丢弃路径；
- 修复：写入校验和字段前先清零（`p[10]=p[11]=0`、`p[26]=p[27]=0`），复测 `dropped=0`，才进入真实 UDP 交付路径。

## 6. 优化措施与效果（本机复测）

在真实 RX 路径（校验和有效、`dropped=0`）上做减法实验定位开销，逐项优化：

| 优化 | 内容 | 效果 |
|---|---|---|
| 修复重复解析 | `ParseIpTcpPacket` 单次解析填充 `TcpInputResult`（ip_version/protocol/fragment/payload/src/dst），TCP/UDP/ICMP 共享；修复前一个 IPv4+UDP 包最多触发 6 次 `ParseIpv4`（§3），优化后仅 1 次 | 解析不再是大头（净收益小） |
| 单 shard 跳过分发 | `RouteRxPacket`/`HandleUdp` 在 `ShardCount()==1` 时跳过 `Dispatch`/`FlowShard`（省掉一次完整 IP+传输头重解析） | 消除分发开销 |
| 无锁 SPSC RX 队列 | `NullPacketIo::SetFastQueue()`：注入端 `Push` 与 shard `Pop` 走 `SpscRing`（acquire/release，无锁） | 消除队列 mutex 竞争 |
| 无锁缓冲池 | `PktBufferPool` free list 改为 tagged 64-bit CAS LIFO（ABA 防护），owner 线程 alloc/return 无锁；`return_queue_` 仍用 mutex（低频跨线程释放） | 消除 shard 与注入端在 pool mutex 上的竞争（RX 端到端关键） |
| 空闲轮纯轮询 | 空闲时 `Wait(0)` 立即循环（RX 包不唤醒 control inbox，park 会按超时限流吞吐） | 端到端 2.03M → 3.19–3.26M（+57%） |
| Wait(0) 无 futex 快路径 | `InboxMpsc::Wait(0)` 特判为纯锁内队列检查，不再走 `cv_.wait_for(0)`（该调用每次仍付 ~10–13us futex 系统调用） | 空闲轮 12.8us → 0.8us |
| 时间有界空闲轮询 + 周期 park | 排空后先对 RX 队列忙轮询至多 800us（覆盖生产者突发间隙），再 park 1ms 一次 | e2e 3.40–3.45M avg / best 3.67–3.72M；sync 直调 3.63M（纯轮询下被空闲 shard 干扰掉到 ~1M）；空闲 shard CPU ~44%（纯轮询为 100%） |
| TimerWheel 空轮快速返回 | `AdvanceTo` 在 `pending_==0` 时跳过 256 槽扫描 | 轮次固定开销下降（约 +4%） |
| inbound lane 非空预检 | 每轮先检查 lanes 是否有数据，跳过 64 次空 pop | 轮次固定开销下降 |

### 结果分解（sync 直调与 e2e 的差距来源）

- 处理路径本身（解析 42ns + HandleUdp 35ns + 循环固定开销）约 228ns/包（同步直调）；
- 端到端多出的部分：SPSC 队列 push/pop、跨线程缓存行乒乓、轮次固定开销、空闲轮轮询；
- lwIP 单线程无锁直调 80ns/包。剩余差距主要来自完整结构化解析（边界检查）、FlowKey/IpAddress 大结构拷贝、flow 表线性查找、session 虚函数抽象，以及跨线程无锁同步的缓存行代价。

## 7. 公平性结论（更新）

- lwIP `NO_SYS` 是单线程、无锁、极简 C 路径；Netstack2 是线程安全、跨线程注入、完整解析 + 流表 + session 抽象的现代 C++ 栈；
- 苹果对苹果比较是“同步核心处理”（约 3.63M pkt/s，sync 直调测量；该测量中调用线程非池 owner，lease 归还走加锁 return queue，实际 owner 侧处理约 144ns/包）对 lwIP 80ns/包（12.5M），约 3.4x；端到端（含跨线程）3.4M pkt/s 对 12.5M，约 3.7x；
- 差距不是“IPv4/UDP 实现慢固定倍数”，而是架构取舍（线程安全、抽象层、检查型解析）的固定成本。要追平 lwIP 需要无检查 fast-path 解析器、零拷贝注入与极简 flow 路径，属架构级重构，不在本次范围。
