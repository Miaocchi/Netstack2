# Netstack2 vs lwIP — 性能对比

对比日期:2026-08-18
机器:Intel Xeon E5-2680 v4 @ 2.40GHz(容器 56 vCPU)
构建:两者均 Release 优化(`-O3`),同一台机器、同一个对比程序、完全相同的参数。
lwIP 版本:GitHub `lwIP-tcpip/lwip` master(2.2-dev),`NO_SYS` 单线程配置,池参数与 Netstack2 对齐(4096 槽、2048B 槽)。

> 复现材料在 `/tmp/lwip_bench/`(compare.cpp、lwipopts.h、build_lwip_bench.sh),依赖外部 lwIP 源码,故不入库。

## 结果总览

| 场景 | Netstack2 | lwIP | Netstack2/lwIP | 说明 |
|---|---|---|---|---|
| 缓冲池 分配/释放 | 79.6M ops/s | 578M ops/s | 0.14x | 线程安全 mutex vs 无锁单线程 |
| 定时器 8k 插入+取消+推进 | 74.1K ops/s | 120.6K ops/s | 0.61x | lwIP 小规模快 |
| 定时器 12k | 58.1K ops/s | 50.7K ops/s | 1.15x | 交叉点 |
| 定时器 16k | 50.6K ops/s | 30.5K ops/s | 1.66x | Netstack2 O(1) 哈希轮反超 |
| RX 64B IPv4+UDP(端到端) | 1.03M pkt/s | 12.5M pkt/s | 0.08x | 含注入线程同步 |
| RX 64B IPv4+UDP(纯处理) | 1.35M pkt/s | 12.5M pkt/s | 0.11x | 不含注入端 |

lwIP 单包处理 ~80ns;Netstack2 纯处理 ~740ns/包、端到端 ~970ns/包(含跨线程注入与锁)。

## 逐场景分析

### 1. 缓冲池(0.14x)
- lwIP `memp` 是 C 固定池,单线程无锁,alloc/free ~1.7ns。
- Netstack2 `PktBufferPool` 用 `std::mutex` 保证线程安全(任意线程可跨核分配/归还,ADR-001 的 owner-thread 快路径仍要持锁),~12.6ns/对。
- **差距即线程安全代价(~7x)**:lwIP 需要调用方自保证单线程;Netstack2 开箱即多线程安全。

### 2. 定时器(架构差异,规模越大越有利)
- lwIP `sys_timeout` 按绝对时间插入**有序链表**:插入 O(n)、取消 O(n)。8k→16k 规模性能从 120K 退化到 30K ops/s(4x 退化)。
- Netstack2 `TimerWheel` 是 256 槽哈希轮:插入/取消 O(1),推进按 ms 摊销。8k→16k 仅从 74K 缓降到 50K。
- **交叉点 ~11k 定时器**:低于它 lwIP 省(裸链表 + 池分配 vs `std::function` 堆分配);高于它 Netstack2 明显占优。产品场景(每连接多个超时)通常远超 11k。

### 3. RX 包处理(0.08x 端到端 / 0.11x 纯处理)
差异主要来自三个真实因素:
1. **线程模型**:lwIP 单线程同步调用(无锁、无跨线程同步);Netstack2 是注入线程 + shard 线程,每包两次 mutex(packet 队列 + 缓冲池)。测量端到端含注入端开销,纯处理 1.35M vs 12.5M(9.3x)。
2. **重复解析**:Netstack2 当前 UDP 快路径对每个包做 3 次 IP 头解析/校验(ParseIpTcpPacket → ExtractFragmentInfo → ParseIpUdpPacket);lwIP 解析一次。这是明确的优化点。
3. **通用性**:Netstack2 每包走 FlowKey 流表查找、会话分发、计数器;lwIP 只做 UDP PCB 匹配。

**注意:该数字包含本次对比中发现并已修复的一个严重缺陷**——修复前 Netstack2 RX 被锁死在 ~57K pkt/s(shard 每轮后固定等待 1ms,见下文)。修复后纯处理 1.35M,端到端 1.03M。

## 对比过程中发现并修复的引擎缺陷

基准测试暴露了第三个真实 bug(commit `81a535c`):

- `StackShard::EventLoopIteration()` 每轮结尾无条件 `control_inbox_.Wait(1)`。RX 包到达 packet 队列,**不会唤醒** control-inbox 等待,于是忙碌的 shard 每处理 64 个包就白白阻塞 1ms —— 吞吐被数学上锁死在 ~64 包/ms ≈ 64K pkt/s。
- 修复:仅当本轮没有处理任何包(空闲)才 `Wait(1)`;有 RX 积压时立即进入下一轮。忙等风险由"空闲时才等待"规避。
- 效果:纯处理吞吐 57K → **1.35M pkt/s**(23.7x),bench `shard-dispatch` 记录 57K → **927K ops/s**。

## 结论

- **架构定位不同**:lwIP 以最小内存/单线程为设计目标,微基准(池、小规模定时器、同步 RX)领先;Netstack2 以多线程吞吐、类型安全 C++、可观测性为目标,付出锁与通用性代价。
- **Netstack2 当前明确的优化空间**:UDP 快路径的重复解析、RX 路径锁粒度、`std::function` 定时器分配。
- **定时器维度 Netstack2 架构占优**(O(1) vs O(n)),规模越大差距越大。
