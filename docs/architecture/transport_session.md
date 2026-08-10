# Transport Session 抽象

> **范围**: `ITransportSession` 及其子类。
> **相关文件**: `include/tcpip2/transport_session.h`。
> **状态**: 接口已冻结于 NETSTACK2-API-FREEZE-001；具体实现类在 P4/P6/P7 引入。

## 1. 设计目标

`ITransportSession` 是 Netstack2 TCP 引擎与“远端传输机制”之间的边界：

- TCP 引擎只关心“把字节发出去”和“从远端接收字节”；
- 具体如何到达远端（内核 socket、Solarflare Onload、DPDK、EF_VI）由 Session 实现隐藏；
- 背压必须明确反馈回 TCP 引擎，影响 advertised window 和内部缓存。

## 2. 类层次

```text
ITransportSession
│
├── SocketSession          # 基于操作系统 socket API
│   ├── KernelSocketSession   # 普通内核 socket / VpnService / utun / Wintun
│   └── OnloadSocketSession   # Solarflare OpenOnload 加速 socket
│
└── UserspaceSession       # 纯用户态路径
    ├── DpdkSession           # DPDK 用户态网络栈
    └── EfViSession           # Solarflare EF_VI 内核旁路
```

当前代码仅包含 `ITransportSession` 接口，所有实现类在后续工作包中完成。

## 3. 核心接口

```cpp
using WritableCallback = std::function<void()>;
using DataCallback     = std::function<void(BufferLease)>;
using ClosedCallback   = std::function<void(SessionError)>;

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

### 3.1 TrySend

- `BufferView` 是 caller 提供的非 owning 只读视图；
- Session 可以部分接收，返回 `accepted_bytes`；
- 返回 `SendStatus::WouldBlock` 后，Session 必须在可写时调用 `WritableCallback`；
- `TrySend()` 返回后，Session 不得继续引用传入的 `BufferView`；
- 如果已经关闭，返回 `SendStatus::Closed`。

### 3.2 回调

所有回调必须先投递回 owner shard，在 shard event loop 中执行，才能修改 `TcpFlow` 状态：

- `WritableCallback`：从 `WouldBlock` 恢复；
- `DataCallback`：远端数据到达，以 owning `BufferLease` 传递；
- `ClosedCallback`：远端关闭、reset 或超时。

## 4. 背压与 TCP advertised window

Session 阻塞时，TCP 引擎必须：

- 停止增大 advertised receive window；
- 不分配更多内部缓存；
- 在 `WritableCallback` 触发后恢复发送。

这是 TCP 正确性和内存安全的硬约束，不是性能调优。

## 5. 实现类说明

### 5.1 KernelSocketSession

- 基于 `read`/`write` 或 `send`/`recv`；
- 用于 Android VpnService、iOS utun、Windows Wintun、Linux TUN；
- completion 线程把事件投递回 owner shard。

### 5.2 OnloadSocketSession

- 复用 Solarflare OpenOnload API；
- 形式上仍是 socket，但走 kernel bypass；
- 与 `KernelSocketSession` 共享大部分回调逻辑，差异在初始化和能力探测。

### 5.3 DpdkSession

- 纯用户态出站；
- 依赖 DPDK mbuf 和 TX queue；
- 需要 zero-copy buffer 与 `PktBufferPool` 的适配层。

### 5.4 EfViSession

- Solarflare EF_VI kernel bypass；
- 需要 event queue 和 TX completion 处理；
- 与 DPDK 类似，需要 buffer 所有权适配。

## 6. 与 Buffer 所有权模型的关系

- `TrySend()` 接收 `BufferView`（非 owning），实现类需要立即拷贝或发送；
- `DataCallback` 传递 `BufferLease`（owning），TCP 引擎获得数据所有权；
- 重传队列使用 `BufferRef` 保留原始 payload，不依赖 Session 状态。

## 7. 冻结语义

NETSTACK2-API-FREEZE-001 冻结：

- `TrySend()` 部分接收语义；
- `BufferView` 返回后不再被 Session 引用；
- `WouldBlock` 必须通过 `WritableCallback` 恢复；
- `DataCallback` 传递 owning `BufferLease`；
- callback 必须经 owner shard 投递；
- Session 背压必须反馈到 TCP advertised window 和内部缓存上限。

新增实现类（`KernelSocketSession`、`DpdkSession` 等）不破坏接口签名即可加入。
