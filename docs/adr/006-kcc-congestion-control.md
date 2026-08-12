# ADR-006: 拥塞控制集成策略（HybridBdpAimd，原名 KCC）

**Status:** Accepted
**Date:** 2026-08-11
**Supersedes:** —

## 1. 背景

项目原始需求要求：

> 拥塞控制算法用 KCC，KCC + BBR 可切换。

当前 `src/tcp/congestion.h` 中已定义：

```cpp
enum class CongestionAlgorithm {
    Aimd,
    Bbr,
    HybridBdpAimd,    ///< Hybrid BDP-based (BBR-style cwnd) + AIMD loss response.
};
```

`AimdController` 和 `BbrController` 已实现并通过测试。原 `KccController`（后更名为
`HybridBdpAimdController`）之前为 stub，现已实现。

## 2. 目标与约束

目标：

1. 在 Netstack2 的 TCP 发送路径中提供 `CongestionAlgorithm::HybridBdpAimd` 可选实现。
2. 保持与 `AimdController`/`BbrController` 相同的接口契约。
3. 不引入外部依赖（Boost、Asio、OpenSSL 已明确禁止）。
4. 不破坏现有公共 API 冻结（ADR-004）。

约束：

- `HybridBdpAimdController` 必须与 `TcpSendBuffer` 内部使用 `std::variant<AimdController, BbrController, HybridBdpAimdController>` 兼容。
- `HybridBdpAimdController` 必须与 `DeliveryRateSampler` 产出的 `RateSample` 兼容。
- 不能启动独立线程；所有回调由 shard event loop 驱动。
- 不能引入全局锁。

## 3. UCP/KCC 调研结论

> **重要更正**：经搜索 `/home/openppp2` 全部源码树，OpenPPP2 中不存在 "KCC" 或 "KCP" 拥塞控制算法。
> OpenPPP2 唯一真正的 TCP 拥塞控制是 lwIP 的标准 New Reno (RFC 5681)。UCP 仓库
> (`https://github.com/liulilittle/ucp`) 提到 KCC2.0 Geodesic 状态机，但在 OpenPPP2
> 本地源码中没有对应实现。

因此，原计划"从 UCP 移植 KCC 算法"的前提不成立。该控制器被重新设计为
**purpose-designed hybrid controller**，不依赖任何外部源码移植，并更名为
`HybridBdpAimdController`（`CongestionAlgorithm::HybridBdpAimd`）以避免
"KCC" 名称带来的误导。

## 4. 决策

### 4.1 不直接引入 UCP 源码

原因：

- UCP 依赖 Boost.Asio 做网络 I/O 和定时器；
- UCP 内部有独立线程模型；
- UCP 的 KCP 协议与 TCP 重复；
- OpenPPP2 本地不存在 KCC 拥塞控制实现可供移植。

### 4.2 采用 purpose-designed hybrid controller

`HybridBdpAimdController` 结合 BBR 式带宽估计和 AIMD 式丢包响应：

**带宽估计（BBR 风格）：**
- BtlBw：**有限窗口 max-filter**（bytes/sec）。每个 round 记录该 round 内的
  最大带宽样本；round 完成（约一个 cwnd 的数据被 ACK）时折叠进 10-slot 环形
  窗口，BtlBw = 窗口内最大值。窗口有限，因此过期的高峰样本最终会衰退出估计。
- RTprop：**带时间戳的 min-filter**（ms）。保存最近 16 个 RTT 样本，样本在
  10 秒（`kRtpropWindowMs`）后过期，min 只对窗口内有效样本计算。路径变化后
  旧的最小 RTT 会过期，估计值能重新测量。
- BDP = BtlBw × RTprop。
- 正常 cwnd = max(BDP, 4 × MSS)，只要 BtlBw 与 RTprop 均已知就立即生效
  （不再受 ssthresh 门控，避免"永久慢启动"缺陷）。

**丢包响应（AIMD 风格）：**
- Fast retransmit / fast recovery 与 `AimdController` 接口一致。
- ssthresh = max(flight / 2, 2 × MSS)。
- Fast recovery 进入时 cwnd = ssthresh + 3 × MSS；每个 dup-ACK 膨胀 1 MSS。
- Fast recovery 退出时 cwnd = ssthresh。
- RTO 时 cwnd = 1 × MSS，同时清空 BtlBw/RTprop 估计与过滤器，令流重新测量路径。

**Pacing：**
- pacing_rate = BtlBw × 1.0（保守，无 gain 膨胀）。
- 与 BBR 不同，不使用 STARTUP/DRAIN/PROBE_BW 状态机，不做带宽探测 gain。
- 带宽估计是被动观察的，不主动 inflate。

**初始状态：**
- cwnd = 2 × MSS（保守初始窗口）。
- ssthresh = UINT32_MAX（无限制，直到首次丢包）。

接口与 `AimdController`/`BbrController` 保持一致：

```cpp
class HybridBdpAimdController {
public:
    HybridBdpAimdController(std::uint16_t mss) noexcept;

    void OnPacketSent(std::uint64_t bytes) noexcept;
    void OnAck(const RateSample& rs) noexcept;
    void OnLoss(const LossEvent& ev) noexcept;
    void OnRto() noexcept;

    std::uint32_t CongestionWindow() const noexcept;
    std::uint32_t Ssthresh() const noexcept;
    std::uint32_t PacingRate() const noexcept;

    static const char* AlgorithmId() noexcept;  // "hybrid_bdp_aimd_v1"

    void OnFastRecoveryEntry(std::uint32_t flight) noexcept;
    void OnDupAck() noexcept;
    void OnFastRecoveryExit() noexcept;
    bool InFastRecovery() const noexcept;

    void UpdateMss(std::uint16_t mss, bool pristine) noexcept;
    void Reset() noexcept;
};
```

### 4.3 复用现有指标

`HybridBdpAimdController` 使用 `RateSample` 提供的：

- `DeliveryRate()`：字节/秒；
- `RttMs()` / `MinRttMs()`：RTT 估计；
- `IsAppLimited()`：发送受应用限制；
- `PriorDelivered` / `Interval`：带宽估计。

这些指标由 `DeliveryRateSampler` 在每次 ACK 时计算，不需要额外的采样逻辑。

## 5. 设计原理

### 5.1 为什么选择 hybrid 而非纯 BBR 或纯 AIMD

- **BBR 的带宽探测**在 userspace TCP 中可能导致 bufferbloat 或与 kernel TCP 竞争
  时过度激进。Hybrid 保守地观察带宽而不主动 inflate，避免这些问题。
- **AIMD 的丢包响应**是成熟的 TCP 拥塞控制机制，与现有 `TcpSendBuffer` 的
  fast retransmit/recovery 路径完全兼容。
- **BDP-based cwnd** 比纯 AIMD 的 cwnd 更准确地反映路径容量，减少 unnecessary
  RTO 和 underutilization。

### 5.2 与 BBR 的区别

| 特性 | BBRv1 | HybridBdpAimd |
|------|-------|-----|
| 带宽探测 | STARTUP 2× gain, PROBE_BW 1.25× gain | 被动观察, 无 gain |
| 状态机 | 4 状态 (STARTUP/DRAIN/PROBE_BW/PROBE_RTT) | 无独立状态机 |
| BtlBw 滤波 | 10-round max-filter | 有限 10-slot 窗口 max-filter（可衰减） |
| RTprop 滤波 | min-filter | 带 10s 过期的 timestamped min-filter |
| cwnd | BDP × cwnd_gain | max(BDP, 4×MSS)，一旦 BDP 已知立即生效 |
| 丢包响应 | 不直接响应丢包 | AIMD fast retransmit/recovery |
| Pacing rate | BtlBw × pacing_gain | BtlBw × 1.0 |

## 6. 实现内容

### 6.1 `HybridBdpAimdController` (src/tcp/congestion.h, congestion.cpp)

- BBR 式 BtlBw **有限窗口 max-filter**（10-slot round 窗口，round 内取 max，round
  结束时折叠进窗口）。
- RTprop **timestamped min-filter**（最近 16 个样本，10 秒过期，仅对有效样本求 min）。
- BDP 计算：`BtlBw * RTprop / 1000`。
- 正常 cwnd = `max(BDP, 4 * MSS)`，BtlBw 与 RTprop 均已知时立即生效。
- AIMD 式 fast recovery：`OnFastRecoveryEntry(flight)` 设 ssthresh 和 cwnd；
  `OnDupAck()` 膨胀 1 MSS；`OnFastRecoveryExit()` 设 cwnd = ssthresh。
- RTO：cwnd = 1 MSS，ssthresh = max(flight/2, 2*MSS)，并清空 BtlBw/RTprop 估计。
- Pacing rate = BtlBw（保守，无膨胀）。
- `AlgorithmId()` 返回 `"hybrid_bdp_aimd_v1"`。

### 6.2 `TcpSendBuffer` 接线 (src/tcp/send.h, send.cpp)

- `CongestionController` variant 扩展为 `std::variant<AimdController, BbrController, HybridBdpAimdController>`。
- 所有 `std::get<AimdController>` 路径扩展为同时处理 `HybridBdpAimdController`
  （fast recovery 接口相同）。
- `InFastRecovery()` 检查使用 `if constexpr` 同时匹配 `AimdController` 和 `HybridBdpAimdController`。
- `Ssthresh()` accessor 扩展为返回 hybrid ssthresh。
- 构造函数根据 `CongestionAlgorithm::HybridBdpAimd` 选择 `HybridBdpAimdController`。

### 6.3 测试 (tests/unit/tcp/congestion_test.cpp)

新增 hybrid 测试覆盖：
- 初始 cwnd = 2×MSS, ssthresh = UINT32_MAX, pacing_rate = 0。
- ACK 驱动 BtlBw/RTprop 更新和 cwnd 增长。
- 丢包触发 fast retransmit/recovery。
- RTO 回退到 1×MSS 并清空估计。
- Fast recovery entry/exit 正确设置 cwnd。
- Pacing rate 在 BtlBw 非零时等于 BtlBw。
- `AlgorithmId()` 返回 `"hybrid_bdp_aimd_v1"`。
- `UpdateMss()` 和 `Reset()` 行为。
- App-limited 不更新 BtlBw。
- 有限窗口 max-filter 的衰减（历史峰值最终离开窗口）。
- RTprop 样本过期后 min-filter 能重新测量。

## 7. 与现有 `CongestionController` 的关系

`TcpSendBuffer` 使用 `std::variant<AimdController, BbrController, HybridBdpAimdController>`。
`std::visit` 调用 `OnAck`/`OnLoss`/`OnRto`/`CongestionWindow`/`PacingRate`，保持
热路径无虚函数调用。Fast recovery 相关方法（`OnFastRecoveryEntry`/`OnDupAck`/
`OnFastRecoveryExit`/`InFastRecovery`）通过 `if constexpr` 在 `AimdController` 和
`HybridBdpAimdController` 上统一处理，`BbrController` 不参与 fast recovery。

## 8. 测试与验证

### 已完成

- Hybrid 单元测试：初始状态、ACK 增长、丢包/fast recovery、RTO 回退、pacing rate、
  AlgorithmId、UpdateMss、Reset、app-limited、有限窗口滤波衰减、RTprop 过期重测。
- `TcpSendBuffer` 集成：Hybrid 作为 `CongestionController` variant 成员编译通过，
  fast recovery 路径与 AIMD 共享。
- 三套构建（普通/ASan+UBSan/TSan）全量 37/37 通过。
- `congestion_test.cpp` 扩展覆盖 AIMD/BBR/hybrid 三种算法。

### 后续

- 不同 RTT/丢包矩阵下的稳定性测试（需要 netem/真实 TUN）。
- HybridBdpAimd vs BBR vs AIMD 的吞吐和延迟对比基准（需要 `bench/` 框架）。
- ECN 支持（当前 hybrid 与 AIMD/BBR 一样不处理 ECN）。

## 9. 风险提示

- Hybrid 的 BBR 式带宽估计在路径动态变化时可能不如 BBR 的 PROBE_BW 周期灵敏，
  因为 Hybrid 不主动探测。在长期稳定路径上表现良好，但在突发变化时可能需要更多
  RTT 才能收敛（有限窗口 max-filter 比无限 max-filter 收敛更快）。
- Hybrid 的 AIMD 式丢包响应在高丢包率（>5%）下可能过于激进（cwnd 减半），与纯 BBR
  的不响应丢包策略相比吞吐更低。这是有意的设计选择：Hybrid 优先与 kernel TCP
  coexist，不做 bufferbloat。
- Hybrid pacing rate 使用 BtlBw × 1.0（无 gain），在 BDP 估计不精确时可能导致
  underutilization。后续可考虑加入保守的 pacing gain（如 1.1×）。
- Global KF（Kalman filter）在第一版关闭，避免跨 shard 全局原子状态影响可扩展性。
  后续可考虑 per-shard cohort。

## 10. 相关文件

- `src/tcp/congestion.h` — `HybridBdpAimdController` 声明
- `src/tcp/congestion.cpp` — `HybridBdpAimdController` 实现
- `src/tcp/send.h` — `CongestionController` variant 定义
- `src/tcp/send.cpp` — Hybrid 接线点
- `src/tcp/rate_sampler.h` — `RateSample` 定义
- `tests/unit/tcp/congestion_test.cpp` — Hybrid 单元测试

## 11. 落地状态

**已实现并验证**（2026-08-11，v2.0 更新）：

- `HybridBdpAimdController` 完整实现，包含 BBR 式带宽估计和 AIMD 式丢包响应。
- `TcpSendBuffer` 接线完成，`CongestionAlgorithm::HybridBdpAimd` 在 flow 创建时可选。
- 单元测试覆盖核心路径。
- 三套构建（普通/ASan+UBSan/TSan）全量通过。

## 12. 变更记录

- **v1.0** (2026-08-11, Proposed): 初始 ADR，计划从 UCP 移植 KCC 算法。
- **v1.1** (2026-08-11, Accepted): 调研发现 OpenPPP2 中不存在 KCC 实现，重新设计
  为 purpose-designed hybrid controller。实现完成，三套构建通过。
- **v1.2** (2026-08-11, Accepted): 修复 round-start 逻辑（round 内不再重复设置
  `round_target_bytes_`，改为只在 round 开始时记录，避免部分 ACK 提前关闭 round）。
- **v2.0** (2026-08-11, Accepted): 更名为 `HybridBdpAimdController`
  （`CongestionAlgorithm::HybridBdpAimd`），`AlgorithmId()` 返回
  `"hybrid_bdp_aimd_v1"`。修复两个滤波器缺陷：① BtlBw 无限 max-filter 改为
  有限 10-slot 窗口 max-filter，历史峰值可衰减；② RTprop 无过期 min-filter 改为
  带时间戳的 10s 过期 min-filter，路径变化后能重新测量。移除 cwnd 增长对 ssthresh
  的门控，BDP 已知即生效。RTO 现在清空 BtlBw/RTprop 估计，令流重新测量路径。
