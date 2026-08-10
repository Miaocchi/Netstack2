# P4 OpenPPP2 集成实施计划

> **状态**: 计划中
> **目标**: 让 Netstack2 成为 OpenPPP2 的可选 TCP/IP 引擎，同时保持 Netstack2 独立可编译测试。
> **前置**: ADR-005 `RuntimeDependencies` 注入落地；`ISessionFactory` 公共接口已冻结。
> **主要文件**: `include/tcpip2/netstack.h`, `src/core/runtime.cpp`, `src/core/netstack.cpp`, `src/core/shard.cpp`。

## 1. 总体目标

P4 完成后，OpenPPP2 可以通过以下方式启动 Netstack2：

```cpp
tcpip2::RuntimeDependencies deps;
deps.packet_io = packet_io;
deps.session_factory = session_factory;
deps.clock = clock;                 // 可选，nullptr 使用系统时钟
deps.event_sink = event_sink;       // 可选，nullptr 静默丢弃

Netstack2 netstack(config);
netstack.Start(deps);
```

OpenPPP2 只需要：
- 提供一个 `IPacketIo` 实现，把 VEthernet 收到的包交给 Netstack2；
- 提供一个 `ISessionFactory` 实现，把 TCP flow 映射到 OpenPPP2 的传输路径；
- 可选提供 `IClock` / `IEventSink`。

## 2. 接口落地（ADR-005 实施）

### 2.1 新增公共头

```text
include/tcpip2/clock.h
include/tcpip2/events.h
include/tcpip2/netstack.h (扩展)
```

`clock.h`:
```cpp
class IClock {
public:
    virtual ~IClock() = default;
    virtual std::uint64_t NowMs() const = 0;
    virtual std::uint64_t NowUs() const = 0;
};
```

`events.h`:
```cpp
enum class FlowEventType { Established, Closed, Reset };
struct FlowEvent { FlowId flow; FlowEventType type; };
struct MetricSnapshot { std::uint64_t rx_packets = 0; std::uint64_t tx_packets = 0; ... };

class IEventSink {
public:
    virtual ~IEventSink() = default;
    virtual void OnFlowEvent(const FlowEvent& ev) = 0;
    virtual void OnMetricSnapshot(const MetricSnapshot& snapshot) = 0;
};
```

### 2.2 RuntimeDependencies 结构

```cpp
struct RuntimeDependencies {
    IPacketIo* packet_io = nullptr;
    ISessionFactory* session_factory = nullptr;
    IClock* clock = nullptr;
    IEventSink* event_sink = nullptr;

    bool Validate() const noexcept {
        return packet_io != nullptr && session_factory != nullptr;
    }
};
```

### 2.3 Netstack2 接口变更

```cpp
class Netstack2 {
public:
    // 保留向后兼容
    bool Start(IPacketIo* packet_io) {
        return Start(RuntimeDependencies{packet_io});
    }

    // 新主入口
    bool Start(const RuntimeDependencies& deps);
    ...
};
```

## 3. Runtime 改造

`src/core/runtime.h` / `runtime.cpp`:

- `Runtime` 新增成员：
  - `ISessionFactory* session_factory_`;
  - `IClock* clock_`;
  - `IEventSink* event_sink_`;
- 构造函数从 `RuntimeDependencies` 接收这些指针；
- 提供访问器：
  - `ISessionFactory* SessionFactory()`;
  - `IClock* Clock()`;
  - `IEventSink* EventSink()`。

### 3.1 IClock 分发

所有当前调用 `std::chrono::steady_clock` 的地方，改为：

```cpp
std::uint64_t now_ms = runtime_.Clock()->NowMs();
```

需要替换的位置：
- `src/core/shard.cpp` 事件循环中获取当前时间；
- `src/tcp/send.cpp` RTO / pacing 计算；
- `src/tcp/handshake.cpp` SYN-ACK 重传定时；
- `src/ip/pmtu.cpp` PMTU 缓存过期；
- `src/ip/fragment.cpp` 分片重组超时。

### 3.2 IEventSink 分发

在以下位置触发事件：
- TCP 连接建立 → `OnFlowEvent({flow_id, Established})`；
- TCP 连接关闭 → `OnFlowEvent({flow_id, Closed})`；
- TCP 收到 RST → `OnFlowEvent({flow_id, Reset})`。

指标快照：
- 每 N 毫秒或每事件循环轮次，汇总 shard 的 rx/tx packets/bytes、flow count、drop count，调用 `OnMetricSnapshot`。

如果 `event_sink == nullptr`，事件静默丢弃。

## 4. ISessionFactory 接入 TCP

当前 TCP 是 passive 监听模型（`TcpHandshake`）。P4 第一阶段只支持 **passive open**：OpenPPP2 告诉 Netstack2 监听某个端口，当 SYN 到达时，Netstack2 通过 `ISessionFactory::OpenTcp()` 请求 OpenPPP2 创建一个 `ITransportSession`。

### 4.1 监听端口注册

在 `Netstack2` 或 `Runtime` 增加：

```cpp
bool Listen(const IpEndpoint& local_endpoint);
```

当 `StackShard` 收到目的端口匹配的 SYN 时，调用 `ISessionFactory::OpenTcp(request)`。

### 4.2 OpenTcp 请求构造

```cpp
TcpOpenRequest request;
request.local_endpoint  = local_endpoint;
request.remote_endpoint = remote_endpoint;
request.flow_id         = flow_id;
```

### 4.3 Session 回调

`ITransportSession` 创建后：
- `TrySend()` 由 TCP 引擎在需要发送数据时调用；
- `SetDataCallback()` 接收远端数据；
- `SetWritableCallback()` 在 backpressure 恢复时触发；
- `SetClosedCallback()` 在远端关闭/重置时触发。

所有 callback 必须投递回 owner shard。

## 5. OpenPPP2 侧改动

OpenPPP2 需要：

1. 实现 `OpenPppPacketIo`（把 `VEthernet::PacketInput` 收到的包交给 Netstack2）；
2. 实现 `OpenPppSessionFactory`（创建 OpenPPP2 的传输会话）；
3. 在 `VEthernet` 中增加 `--stack=netstack2` 分支；
4. 保证 lwIP 路径同时存在，启动期二选一。

### 5.1 OpenPppPacketIo

- 实现 `IPacketIo` 接口；
- 从 `VEthernet` 接收 raw IP 包；
- 调用 `Netstack2::Start(deps)`；
- 把包注入 Netstack2 的 RX queue。

### 5.2 OpenPppSessionFactory

- 实现 `ISessionFactory` 接口；
- `OpenTcp()` 返回一个 `KernelSocketSession`（Linux）或平台对应的 Session；
- 把 `ITransportSession` 的数据转发到 OpenPPP2 的 transmission 路径。

## 6. 验收标准

- `tests/unit/runtime_test.cpp` 通过 `RuntimeDependencies` 注入 fake clock / fake event sink / fake session factory；
- `tests/integration/openppp2_smoke_test.cpp` 用 `NullPacketIo` 模拟 OpenPPP2 收发，完成 SYN → SYN-ACK → ESTABLISHED → 数据 → FIN 全流程；
- consumer compile-contract test 更新，验证 `RuntimeDependencies` 大小/布局稳定；
- 普通/ASan/TSan 三套构建全绿。

## 7. 工作分解

| 步骤 | 内容 | 文件 | 预计工作量 |
|------|------|------|-----------|
| P4-1 | 新增 `clock.h` / `events.h` 公共头 | `include/tcpip2/clock.h`, `events.h` | 半天 |
| P4-2 | 实现 `RuntimeDependencies` 和 `Start` 重载 | `include/tcpip2/netstack.h`, `src/core/netstack.cpp`, `src/core/runtime.cpp` | 1 天 |
| P4-3 | 用 `IClock` 替换所有 `steady_clock` 调用 | `src/core/shard.cpp`, `src/tcp/*.cpp`, `src/ip/*.cpp` | 2 天 |
| P4-4 | 接入 `ISessionFactory` 被动监听 | `src/tcp/handshake.cpp`, `src/core/shard.cpp` | 2 天 |
| P4-5 | 接入 `IEventSink` | `src/core/shard.cpp`, `src/tcp/handshake.cpp`, `src/tcp/send.cpp` | 1 天 |
| P4-6 | 更新 consumer contract test | `tests/unit/compile_contract_test.cpp` | 半天 |
| P4-7 | 新增 OpenPPP2 smoke test | `tests/integration/openppp2_smoke_test.cpp` | 2 天 |
| P4-8 | OpenPPP2 侧 adapter | `ppp/ethernet/VNetstack.cpp` 等 | 3 天 |

## 8. 风险提示

- ADR-005 修改了公共 API 签名，需要按冻结后变更流程走；
- `ISessionFactory` 接口已在公共头冻结，不能再改；
- `IClock` 和 `IEventSink` 是新公共头，需要仔细设计避免后续再变；
- OpenPPP2 侧改动不在本仓库，需要单独 PR。
