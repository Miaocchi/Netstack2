# Buffer 所有权模型

> **范围**: `PktBuffer`, `PktBufferPool`, `BufferLease`, `BufferSlice`, `BufferRef`。
> **相关文件**: `include/tcpip2/buffer.h`。
> **状态**: 已冻结于 NETSTACK2-API-FREEZE-001。

## 1. 设计目标

- **无每包原子引用计数**：热路径引用计数由 shard-local 的非原子计数承担。
- **跨线程释放安全**：`BufferLease`/`BufferRef` 可以在任何线程释放，最终通过 owner return queue 回到所属 pool。
- **生命周期明确**：所有非 owning view 的生命周期必须由 owning handle 保证。
- **可检测 double-release**：pool 维护 slot 状态机，非法状态转换触发 abort。

## 2. 所有权分类

### 2.1 PktBuffer

Pool 内部对象，不公开构造/析构接口。

- 固定容量、固定布局；
- 记录 owner pool、slot、data 指针、容量、长度；
- 引用计数由 `BufferRef` 内部修改，外部不直接操作；
- 状态机：`Free → Leased → Retained → Queued → Free`。

### 2.2 BufferLease — 唯一所有权

- `move-only`，不可复制；
- 析构时归还 owner pool；
- 可跨线程移动；跨线程释放时 buffer 先进入 owner return queue，等 owner shard 调用 `DrainReturnQueue()` 才真正回到 free list；
- noexcept move constructible/assignable。

典型使用：IPacketQueue 从 pool 分配的包、ITransportSession::DataCallback 传递的包。

### 2.3 BufferSlice — 非 owning 只读视图

- trivially copyable；
- 包含 `(data_, size_)`；
- 必须保证不超出原始 buffer 范围；
- 生命周期不得超过产生它的 `BufferLease` 或 `BufferRef`。

典型使用：TCP segment parser 查看 payload、TxSegment 指向已发送但未确认的数据。

### 2.4 BufferRef — shard-local retained handle

- 可复制，引用计数非原子；
- 用于 payload 需要比单次 TX 生命周期更长的地方：
  - TCP 重传队列；
  - 乱序重组；
  - 分段发送；
  - 一个 payload 被多个 `TxSegment` 引用。
- **不应用于跨 shard 通用共享**。

`TxSegment` 结构：

```cpp
struct TxSegment {
    std::uint32_t seq;
    std::uint32_t len;
    BufferRef owner;
    BufferSlice data;
};
```

`BufferRef` 保证 `BufferSlice` 在重传队列生命周期内有效。

## 3. 状态转换

```text
Free
  │ Allocate()
  ▼
Leased  <────── BufferLease move/copy into scope
  │ Retain(lease)
  ▼
Retained  <──── BufferRef copies
  │ last BufferRef destroyed
  │ foreign-thread release
  ▼
Queued  <──── DrainReturnQueue() on owner thread
  │
  ▼
Free
```

- `BufferLease` 析构：`Leased → Free`（owner thread）或 `Leased → Queued`（foreign thread）。
- `BufferRef` 析构且引用计数归零：`Retained → Free` 或 `Retained → Queued`。
- `DrainReturnQueue()` 把 `Queued` slot 批量移回 `Free`。

## 4. 线程模型

- `PktBufferPool::Allocate()` 和 `ReturnBuffer()` 内部加锁，允许跨线程释放；
- owner thread id 在 shard `Run()` 启动时通过 `SetOwnerThread()` 设置；
- 同一 pool 的热路径由 owner shard 单线程执行，保证大多数 `Allocate()` 无竞争；
- 跨线程释放仅把 slot 放进 queue，不立即归还，避免 false sharing 和锁竞争。

## 5. 零拷贝原则

正式目标定义为 **copy-minimized**，而不是承诺所有路径绝对零拷贝。

- TUN/AF_XDP/DPDK 收包直接进入池化 buffer；
- header parser 使用 view；
- TCP payload 不做整包复制；
- 重传引用原始 payload；
- 仅在重组、加密、平台 API 限制或聚合时复制；
- AF_XDP/DPDK 在条件允许时实现 DMA buffer 复用。

## 6. Shutdown

`Runtime::Stop(const StopOptions&)` first changes state to `Stopping`, closes
RX, quiesces Session callbacks, joins shards, and drains every queue's accepted
TX leases. It then drains every pool return queue and verifies that both TX and
pool outstanding counts are zero before destroying queues or pools. A timeout
or drain failure returns `StopResult` and retains the Runtime/pools for retry;
the destructor uses an unbounded final drain rather than freeing a referenced
pool.

## 7. 测试与验证

- `static_assert(std::is_move_constructible_v<BufferLease>)`；
- `static_assert(!std::is_copy_constructible_v<BufferLease>)`；
- `static_assert(std::is_nothrow_move_constructible_v<BufferLease>)`；
- double-release 触发 death test；
- ASan/UBSan/TSan 验证无泄漏、无 data race。
