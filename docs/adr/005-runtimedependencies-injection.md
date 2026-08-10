# ADR-005: RuntimeDependencies 注入与 Start 签名变更

**Status:** Accepted
**Date:** 2026-08-11
**Supersedes:** ADR-004 第 2.6 条 (`Netstack2::Start(IPacketIo*)`)

## 1. 背景

ADR-004 (NETSTACK2-API-FREEZE-001) 冻结了公共 API，其中包括：

```cpp
class Netstack2 {
public:
    bool Start(IPacketIo* packet_io);
    ...
};
```

该签名在 P3A–P3C 阶段足够使用：Runtime 只需要一个 `IPacketIo` 来收发数据包。然而 P4 (OpenPPP2 集成) 要求 Netstack2 在运行时获得以下依赖：

- `IPacketIo*`：数据包 I/O 后端（已支持）。
- `ISessionFactory*`：将 TCP flow 关联到 OpenPPP2 的远端传输会话。
- `IClock*`：可测试/可替换的时间源，用于 RTT/RTO/BBR 估计。
- `IEventSink*`：生命周期事件和统计指标输出，用于 OpenPPP2 集成可观测性。

继续使用 `Start(IPacketIo*)` 会导致以下问题：

1. P4 实现不得不在 `NetstackConfig` 中塞入 session factory / clock / event sink 指针，破坏配置对象的可复制性和纯数据语义。
2. `ISessionFactory` 已经在 `include/tcpip2/session_factory.h` 中冻结，但 Runtime 无法获得它。
3. 测试需要伪造 clock 和 event sink，不能依赖真实系统时钟。

因此必须扩展 `Start` 的注入能力。

## 2. 决策

### 2.1 新的入口点

引入一个独立的结构体 `RuntimeDependencies`，并新增 `Start` 重载：

```cpp
struct RuntimeDependencies {
    IPacketIo* packet_io = nullptr;
    ISessionFactory* session_factory = nullptr;
    IClock* clock = nullptr;
    IEventSink* event_sink = nullptr;

    bool Validate() const noexcept;  // at least packet_io must be non-null
};

class Netstack2 {
public:
    // Frozen overload kept for backward compatibility; delegates to RuntimeDependencies.
    bool Start(IPacketIo* packet_io);

    // New primary entry point.
    bool Start(const RuntimeDependencies& deps);
    ...
};
```

### 2.2 兼容性

- `Start(IPacketIo*)` 保留，内部调用 `Start(RuntimeDependencies{packet_io})`。
- 旧调用点不需要修改。
- consumer compile-contract test 增加 `static_assert(sizeof(RuntimeDependencies) > 0)` 和可 trivially copyable 验证。

### 2.3 新增公共类型

需要在 `include/tcpip2/` 下新增：

- `clock.h`：`IClock` 接口（纯虚 `NowMs()`、`NowUs()`）。
- `events.h`：`IEventSink` 接口（纯虚 `OnFlowEvent(...)` / `OnMetricSnapshot(...)`）。

这些头在 ADR-005 之后加入公共 API，因此它们本身受冻结规则约束；后续签名变更需要新的 ADR。

### 2.4 默认行为

- `session_factory == nullptr`：Runtime 启动失败，`Start` 返回 `false`（P4 之后不允许无 factory 运行）。
- `clock == nullptr`：使用内部 `SystemClock` 实现。
- `event_sink == nullptr`：事件静默丢弃（null object pattern）。

## 3. 影响

- `src/core/netstack.cpp` 和 `src/core/runtime.cpp` 需要修改以存储并分发 `RuntimeDependencies`。
- `StackShard` 构造函数需要接收 `ISessionFactory*`、`IClock*`、`IEventSink*`。
- 现有 `Start(IPacketIo*)` 测试继续通过。
- OpenPPP2 adapter 在 P4 中传入完整 `RuntimeDependencies`。

## 4. 替代方案

| 方案 | 优点 | 缺点 | 结论 |
|------|------|------|------|
| 仅通过 `NetstackConfig` 注入指针 | 不改动 Start 签名 | 破坏 config 可复制性、引入所有权混淆 | 拒绝 |
| 保留 `Start(IPacketIo*)`，新增 `SetSessionFactory()` 等 setter | 改动小 | 状态机复杂，部分构造容易出错 | 拒绝 |
| `Start(RuntimeDependencies)` 重载 | 语义清晰、可扩展、向后兼容 | 需要新增两个公共头 | 采纳 |

## 5. 测试证据

- consumer compile-contract test 更新，验证 `RuntimeDependencies` 为 standard layout / trivially copyable。
- 新增单元测试：
  - `Start(nullptr)` 失败；
  - `Start(packet_io)` 仍成功（向后兼容）；
  - `Start(RuntimeDependencies{packet_io, fake_factory, fake_clock, fake_sink})` 成功；
  - fake clock 推进后 RTO 按预期触发。

## 6. 相关文件

- `include/tcpip2/netstack.h`
- `include/tcpip2/clock.h` (new)
- `include/tcpip2/events.h` (new)
- `src/core/netstack.cpp`
- `src/core/runtime.cpp`
- `src/core/runtime.h`
- `tests/unit/consumer/compile_contract_test.cpp`

## 7. 冻结后变更流程

本 ADR 按 ADR-004 规定的冻结后变更流程执行：

1. 提交本 ADR；
2. 兼容性分析（保留旧签名）；
3. 提供迁移路径（旧调用无需改动）；
4. 更新 consumer compile-contract test；
5. 所有测试通过（default / ASan / TSan）后合并。

## 8. 落地状态

- IClock 接口设计：已完成（见 §2.3）。
- IEventSink 接口设计：已完成（见 §2.3）。
- RuntimeDependencies 结构体：已设计，待实现。
- SystemClock 默认实现：待实现。
- 全量 steady_clock 替换：待执行。
- StackShard 构造/事件分发：待修改。

详细实施步骤见 `docs/plans/P4_OPENPPP2_INTEGRATION_PLAN.md`。

## 9. 变更记录

| 版本 | 日期 | 说明 |
|------|------|------|
| 1.0 | 2026-08-11 | 初始 Accepted 版本 |
| 1.1 | 2026-08-11 | 增加 IClock/IEventSink 设计细节和 P4 后续工作指引 |
