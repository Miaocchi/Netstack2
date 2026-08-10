# 高性能后端扩展通用接口设计

> **范围**: AF_XDP / Onload / DPDK 等高性能后端如何接入 Netstack2 的 `IPacketIo` / `ITransportSession` 体系。
> **目标**: 定义一组通用扩展接口，使新后端只需要实现少量纯虚接口即可接入，而不修改核心引擎。
> **状态**: 设计中

## 1. 设计原则

- **不破坏公共 API 冻结**: 新后端通过已有 `IPacketIo` 和 `ITransportSession` 扩展，不修改核心签名；
- **能力探测**: 每个后端通过 `PacketIoCapabilities` 报告能力，核心代码按能力降级；
- **零拷贝优先**: 允许后端直接提供外部 buffer，通过 `BufferLease` / `BufferRef` 适配；
- **线程模型一致**: 每个 queue 绑定到一个 owner shard，后端回调必须投递回 owner shard；
- **可选依赖**: DPDK/Onload 等专有库放在独立 target 或子模块，核心库不直接依赖。

## 2. 现有接口回顾

### 2.1 IPacketIo

```cpp
class IPacketIo {
public:
    virtual ~IPacketIo() = default;
    virtual IPacketQueue* Queue(std::size_t index) = 0;
    virtual std::size_t QueueCount() const = 0;
    virtual PacketIoCapabilities Capabilities() const = 0;
    virtual bool Open() = 0;
    virtual void Close() = 0;
    virtual bool IsOpen() const = 0;
};

class IPacketQueue {
public:
    virtual ~IPacketQueue() = default;
    virtual std::size_t RecvBatch(BufferLease out[], std::size_t count) = 0;
    virtual std::size_t SendBatch(BufferLease packets[], std::size_t count) = 0;
    virtual void SetBufferPool(PktBufferPool* pool) = 0;
    virtual std::uint32_t QueueId() const = 0;
};
```

`IPacketIo` 已经抽象了多队列、能力探测、批量收发。AF_XDP / DPDK / Onload 都需要实现这个接口。

### 2.2 ITransportSession

```cpp
class ITransportSession {
public:
    virtual ~ITransportSession() = default;
    virtual SendResult TrySend(BufferView data) = 0;
    virtual void ShutdownWrite() = 0;
    virtual void Abort(SessionError error) = 0;
    virtual void SetWritableCallback(WritableCallback cb) = 0;
    virtual void SetDataCallback(DataCallback cb) = 0;
    virtual void SetClosedCallback(ClosedCallback cb) = 0;
};
```

Onload / kernel socket / DPDK 都需要实现这个接口。

## 3. 通用扩展接口

为了降低新后端接入成本，定义一组 **可选的 mixin 接口**。核心代码通过 `dynamic_cast` 或显式能力位判断是否使用。

### 3.1 IExternalBufferAdapter

允许后端直接管理 buffer，而不是从 `PktBufferPool` 分配。

```cpp
class IExternalBufferAdapter {
public:
    virtual ~IExternalBufferAdapter() = default;

    // 将后端拥有的外部 buffer 包装成 BufferLease，生命周期由 adapter 管理。
    virtual BufferLease WrapExternalBuffer(void* handle, std::uint8_t* data, std::size_t size) = 0;

    // 通知 adapter 一个 BufferLease 已经释放，可以回收外部 buffer。
    virtual void OnBufferReleased(void* handle) = 0;
};
```

适用：AF_XDP zero-copy UMEM、DPDK mbuf。

### 3.2 IQueueAffinity

允许后端绑定 queue 到特定 NUMA node / CPU core。

```cpp
struct QueueAffinityHint {
    int numa_node = -1;
    int cpu_core = -1;
};

class IQueueAffinity {
public:
    virtual ~IQueueAffinity() = default;
    virtual QueueAffinityHint AffinityForQueue(std::uint32_t queue_id) const = 0;
};
```

`Runtime` 在创建 shard 后，根据 hint 设置线程 affinity。

### 3.3 IOffloadCapabilities

报告 NIC 卸载能力。

```cpp
struct OffloadCapabilities {
    bool rx_checksum = false;
    bool tx_checksum = false;
    bool rx_timestamp = false;
    bool tx_timestamp = false;
    bool gro = false;
    bool gso = false;
    bool tso = false;
    bool lro = false;
};

class IOffloadCapabilities {
public:
    virtual ~IOffloadCapabilities() = default;
    virtual OffloadCapabilities Offloads() const = 0;
};
```

核心引擎在构造 packet 时跳过已卸载的 checksum/TCP 分段。

### 3.4 IPacingBackend

允许后端提供硬件 pacing 能力（如 DPDK QoS / Onload 加速）。

```cpp
class IPacingBackend {
public:
    virtual ~IPacingBackend() = default;

    // 返回该后端是否支持基于 pacing rate 的硬件调度。
    virtual bool SupportsHardwarePacing() const = 0;

    // 设置 flow 的 pacing rate（bytes/sec）。
    virtual bool SetPacingRate(FlowId flow, std::uint64_t bytes_per_sec) = 0;
};
```

如果后端支持，核心 `TcpSendBuffer` 的 pacing gate 可以简化或绕过。

### 3.5 IKernelBypassSocket

为 DPDK / Onload 等提供内核旁路 socket 抽象。

```cpp
class IKernelBypassSocket {
public:
    virtual ~IKernelBypassSocket() = default;

    // 发送一个 packet 到远端， bypass 内核。
    virtual SendResult SendPacket(const BufferView& packet) = 0;

    // 注册收到远端 packet 时的回调。
    virtual void SetPacketReceivedCallback(std::function<void(BufferLease)> cb) = 0;
};
```

`DpdkSession` / `OnloadSocketSession` 可以内部持有这个接口。

## 4. 后端实现规划

### 4.1 AF_XDP

- 实现 `AfxdpPacketIo : public IPacketIo`，内部管理 XDP socket / UMEM / fill/complete/RX/TX rings；
- 可选实现 `IExternalBufferAdapter`（zero-copy 模式）；
- 实现 `IOffloadCapabilities`（checksum offload、timestamp）；
- 实现 `IQueueAffinity`（queue→CPU/NUMA mapping）。

### 4.2 DPDK

- 实现 `DpdkPacketIo : public IPacketIo`，内部管理 EAL / port / queue；
- 实现 `IExternalBufferAdapter`（mbuf → BufferLease 适配）；
- 实现 `IOffloadCapabilities`（TSO/GRO/checksum）；
- 实现 `IPacingBackend`（如果 DPDK QoS 可用）；
- 可选实现 `IKernelBypassSocket`（用于纯用户态 TCP）。

### 4.3 Onload

- 实现 `OnloadSocketSession : public ITransportSession`；
- 内部使用 Solarflare OpenOnload API；
- 实现 `IOffloadCapabilities` 和 `IPacingBackend`（如果底层支持）；
- 不需要自己实现 `IPacketIo`，因为 Onload 走的是 socket API，由 OpenPPP2 控制。

## 5. 能力探测与降级

`PacketIoCapabilities` 已经包含基本能力位。扩展能力通过 `dynamic_cast` 获取：

```cpp
auto* offload = dynamic_cast<IOffloadCapabilities*>(packet_io);
if (offload && offload->Offloads().tx_checksum) {
    // 不计算 TCP checksum
}

auto* affinity = dynamic_cast<IQueueAffinity*>(packet_io);
if (affinity) {
    auto hint = affinity->AffinityForQueue(queue_id);
    shard.SetAffinity(hint);
}
```

如果后端没有实现某个扩展接口，核心代码回退到默认软件实现。

## 6. 新增目录结构

```text
src/packetio/
├── null_io.cpp
├── tap_io.cpp
├── afxdp_io.cpp          # AF_XDP backend (P5)
├── afxdp_io.h
├── dpdk_io.cpp           # DPDK backend (P5)
├── dpdk_io.h
└── onload_packet_io.cpp  # 如果 Onload 需要独立 packet I/O (P5A)

src/session/
├── kernel_socket_session.cpp   # P4
├── onload_socket_session.cpp   # P5A
└── dpdk_session.cpp            # P5B
```

## 7. 扩展接口冻结说明

这些 mixin 接口目前还不是公共 API 的一部分，属于 **半稳定的扩展协议**：
- 它们以 `include/tcpip2/extensions/` 或 `src/packetio/extensions/` 形式存在；
- 不进入 `include/tcpip2/` 主目录；
- 在 P5 完成前可以自由修改，不需要 ADR。

## 8. 验收标准

- `NullPacketIo` 和 `TapPacketIo` 不需要任何扩展接口也能工作；
- 新增扩展接口不会破坏 consumer compile-contract test；
- AF_XDP copy-mode backend 通过基本收发测试；
- DPDK backend 在 CI 中可编译（即使无 DPDK 环境也提供 stub target）。

## 9. 相关文件

- `include/tcpip2/packet_io.h`
- `include/tcpip2/transport_session.h`
- `docs/adr/005-runtimedependencies-injection.md`
- `docs/plans/P4_OPENPPP2_INTEGRATION_PLAN.md`
