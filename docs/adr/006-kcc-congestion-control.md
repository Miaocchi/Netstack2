# ADR-006: KCC 拥塞控制集成策略

**Status:** Proposed
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
    Kcc,    ///< UCP KCC (stub — not yet implemented).
};
```

`AimdController` 和 `BbrController` 已实现并通过测试；`Kcc` 仍是 stub。参考实现 UCP KCP 位于 `https://github.com/liulilittle/ucp`（以下简称 ucp），其设计基于 UDP 不可靠信道，包含 FEC、KCP 可靠传输和自定义拥塞控制。

## 2. 目标与约束

目标：

1. 在 Netstack2 的 TCP 发送路径中提供 `CongestionAlgorithm::Kcc` 可选实现。
2. 保持与 `AimdController`/`BbrController` 相同的接口契约。
3. 不引入外部依赖（Boost、Asio、OpenSSL 已明确禁止）。
4. 不破坏现有公共 API 冻结（ADR-004）。

约束：

- `KccController` 必须与 `TcpSendBuffer` 内部使用 `std::variant<AimdController, BbrController, KccController>` 兼容。
- `KccController` 必须与 `DeliveryRateSampler` 产出的 `RateSample` 兼容。
- 不能启动独立线程；所有回调由 shard event loop 驱动。
- 不能引入全局锁。

## 3. UCP 与 TCP 的适配边界

UCP 的核心是面向 UDP 的可靠传输，包含：

- KCP 协议（ARQ、窗口、rudp 模式）；
- FEC（可选）；
- 拥塞控制算法（默认/快速/线速/KCP 原生等）。

Netstack2 已经提供：

- TCP 状态机（`TcpFlow` / `TcpSendBuffer` / `TcpReceiveBuffer`）；
- 可靠传输、ACK、重传、RTO；
- `DeliveryRateSampler` 和 `RateSample`；
- `AimdController` 和 `BbrController` 的 pluggable 接口。

因此 Netstack2 不需要 UCP 的 KCP 协议部分；只需要复用/移植其 **拥塞控制算法**。

## 4. 决策

### 4.1 不直接引入 UCP 源码

原因：

- UCP 依赖 Boost.Asio 做网络 I/O 和定时器；
- UCP 内部有独立线程模型；
- UCP 的 KCP 协议与 TCP 重复。

### 4.2 采用“算法移植 + 接口适配”策略

将 UCP 中的 KCC 拥塞控制算法提炼为纯算法逻辑，封装成 `KccController`。

`KccController` 接口与 `AimdController`/`BbrController` 保持一致：

```cpp
class KccController {
public:
    KccController(std::uint16_t mss) noexcept;

    void OnPacketSent(std::uint64_t bytes) noexcept;
    void OnAck(const RateSample& rs) noexcept;
    void OnLoss(const LossEvent& ev) noexcept;
    void OnRto() noexcept;

    std::uint32_t CongestionWindow() const noexcept;
    std::uint32_t PacingRate() const noexcept;

    void UpdateMss(std::uint16_t mss, bool pristine) noexcept;
    void Reset() noexcept;
};
```

### 4.3 复用现有指标

`KccController` 使用 `RateSample` 提供的：

- `DeliveryRate()`：字节/秒；
- `RttMs()` / `MinRttMs()`：RTT 估计；
- `IsAppLimited()`：发送受应用限制；
- `PriorDelivered` / `Interval`：带宽估计。

这些指标由 `DeliveryRateSampler` 在每次 ACK 时计算，不需要 UCP 的采样逻辑。

## 5. 移植内容

从 UCP 中可提炼的关键机制（待验证）：

1. **拥塞窗口调整**：不同于 AIMD 的线性增长/乘性减，KCC 可能使用基于时延或丢包的混合算法。
2. **快速恢复**：dup ACK / SACK 触发 cwnd 调整。
3. **慢启动阈值**：与 `ssthresh` 类似，但触发条件和增长速度不同。
4. ** pacing**：KCC 是否需要 pacing 由算法内部决定；接口通过 `PacingRate()` 暴露。

## 6. 实现步骤

1. **调研阶段**：阅读 ucp 源码，提取其拥塞控制核心逻辑，确认输入输出。
2. **设计阶段**：定义 `KccController` 内部状态机，对齐 `RateSample`。
3. **单元测试**：参考 `tests/unit/tcp/congestion_bbr_test.cpp`，新增 `tests/unit/tcp/congestion_kcc_test.cpp`。
4. **集成测试**：在 `tests/unit/tcp/send_test.cpp` 等已有测试中增加 `CongestionAlgorithm::Kcc` 分支。
5. **性能基准**：在 `bench/` 中对比 AIMD/BBR/KCC。

## 7. 与现有 `CongestionController` 的关系

当前 `TcpSendBuffer` 使用 `std::variant<AimdController, BbrController>`。实现 KCC 后应扩展为：

```cpp
using CongestionController = std::variant<AimdController, BbrController, KccController>;
```

`std::visit` 调用 `OnAck`/`OnLoss`/`OnRto`/`CongestionWindow`/`PacingRate`，保持热路径无虚函数调用。

## 8. 测试与验证

- 单元测试覆盖：
  - 初始 cwnd 和 pacing rate；
  - ACK 驱动增长；
  - 丢包/快速恢复；
  - RTO 回退；
  - 与 AIMD/BBR 的等价对比（某些场景下应有相似表现）。
- 集成测试：
  - `CongestionAlgorithm::Kcc` 在 `TcpSendBuffer` 中可正常切换；
  - 不同 RTT/丢包矩阵下的稳定性。

## 9. 风险提示

- UCP 的 KCC 算法是为 UDP/游戏场景设计，可能假设了与 TCP 不同的 RTT 分布和丢包模型，直接移植可能不适用于高带宽高时延网络。
- 如果 UCP 算法与 `RateSample` 的语义不完全兼容，需要额外设计适配层。
- KCC  pacing 行为可能与 BBR 冲突，需要明确 `TcpSendBuffer` 如何同时支持两种 pacing 风格。

## 10. 相关文件

- `src/tcp/congestion.h`
- `src/tcp/congestion.cpp`
- `src/tcp/rate_sampler.h`
- `src/tcp/send.h`
- `tests/unit/tcp/congestion_aimd_test.cpp`
- `tests/unit/tcp/congestion_bbr_test.cpp`
- 待新增：`tests/unit/tcp/congestion_kcc_test.cpp`

## 11. 结论

在 Netstack2 中实现 `CongestionAlgorithm::Kcc` 不采用直接引入 UCP 的方式，而是将 UCP 的 KCC 拥塞控制算法移植为独立的 `KccController`，保持与 `AimdController`/`BbrController` 的接口一致性，并复用 Netstack2 的 `DeliveryRateSampler`。

下一步：对 UCP 源码进行详细阅读，提取可移植的算法逻辑，形成具体实现 PR。
