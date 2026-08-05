# Netstack2 Roadmap

> 本文记录里程碑状态、工作包范围、前置依赖、验收门禁、当前 commit/tag 和已知阻塞项。
> 架构设计与边界见 `docs/architecture/NETSTACK2_ARCHITECTURE.md`; 本文只记录任务进度,
> 不混入架构决策。OpenPPP2 集成细节见 `docs/integration/OPENPPP2_INTEGRATION_PLAN.md`。

## 1. 里程碑状态

| 里程碑 | 状态 | 说明 |
|------|------|------|
| NETSTACK2-000 | **Completed** | 开仓 + 测试底座, commit `628eb60`, tag `v0.1.0` |
| NETSTACK2-001 | Planned | P0 测量框架, 不阻塞 002–004 |
| NETSTACK2-002 | **In Progress** | Buffer 与 Packet I/O 契约 |
| NETSTACK2-003 | Blocked by 002 | Linux TapPacketIo |
| NETSTACK2-004 | Blocked by 003 | Dispatcher 与 StackShard |
| NETSTACK2-API-FREEZE-001 | Blocked by 002–004 | 精确冻结公共 API |
| P3A / P3B / P3C | Planned | IPv4/IPv6/L3 → TCP 状态机 → 互操作与性能 |
| P4 | Planned | OpenPPP2 集成(在 API-FREEZE 之后接线) |
| P5–P7 | Planned | 高性能 Packet I/O、平台铺开、调优 |

## 2. 提交与标签

| 里程碑 | commit | tag |
|------|--------|-----|
| NETSTACK2-000 | `628eb60` | `v0.1.0`(annotated) |

规则:

* `v0.1.0` 固定指向 `628eb60`, 不移动、不重打。
* 架构文档和 roadmap 单独提交, 不混入 NETSTACK2-002 实现。
* NETSTACK2-002 完成时只提交 commit, 不打 tag。
* 下一个版本 tag `v0.2.0` 放在 002–004 完成且通过 `NETSTACK2-API-FREEZE-001` 之后。

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

### NETSTACK2-002: Buffer 和 Packet I/O (In Progress)

范围: PktBuffer; PktBufferPool; BufferLease(move-only, noexcept, 析构归还
owner pool, 跨线程归还走 owner return queue); BufferSlice(trivially
copyable 只读视图); BufferRef(shard-local retained handle); TxSegment;
owner return queue; NullPacketIo; IPacketIo/IPacketQueue;
SendBatch/RecvBatch 所有权语义(prefix transfer); TX completion 模拟;
buffer 上限和统计。

前置: NETSTACK2-000。

门禁: 所有 buffer 测试从占位变为真实实现; ASan/UBSan 全绿; TSan 全绿;
泄漏为 0; double-release 可检测(death test); 热路径无每包 atomic refcount。

当前文件: `include/tcpip2/packet_io.h`、`src/packetio/null_io.cpp`、
`tests/unit/buffer_pool_test.cpp`(未提交, 完成门禁后单独提交)。

### NETSTACK2-003: Linux TapPacketIo (Blocked by 002)

范围: `/dev/net/tun`; TUN; 可选 TAP; `IFF_MULTI_QUEUE`; 每 queue 一个
IPacketQueue; 单/多队列; batch read/write; owner shard 固定; shutdown;
fd 错误处理; 与 `TapLinux::Ssmt/SsmtMQ` 行为对齐。第一版用稳定系统调用,
不强制 io_uring。

前置: NETSTACK2-002。

门禁: 无 root 环境自动 skip TUN 集成测试; NullPacketIo 单元测试始终执行;
root 环境 TUN loopback 冒烟; 多队列路由; shutdown/drain; fd 泄漏检查。

### NETSTACK2-004: Dispatcher 和 StackShard (Blocked by 003)

范围: IPv4/IPv6 FlowKey; 稳定 hash; PacketDispatcher; queue→shard 映射;
StackShard 线程; event loop; flow table; timer wheel; SPSC data queue;
MPSC control inbox; typed message; shutdown/drain; CPU affinity;
load statistics; owner assertion; session callback 回投; bounded queue。

前置: NETSTACK2-003。

门禁: 多 producer 控制消息压测; 多 queue 输入; 无 flow 跨 shard 修改;
shutdown 后无悬挂回调; drain 无泄漏; TSan 全绿; 线程数量变化时行为确定;
同一 FlowKey 永远映射相同 shard。

### NETSTACK2-API-FREEZE-001 (Blocked by 002–004)

触发条件: 002/003/004 完成; 普通/ASan/UBSan/TSan 全绿;
至少一个真实 Linux TUN multiqueue 测试通过。

冻结内容: public header 精确签名; Buffer 所有权; Packet I/O ownership
transfer; Session partial-send; callback 生命周期; shard message;
config schema; error enums; shutdown 语义。

冻结后签名变更必须: 提交 ADR; 说明兼容性; 提供迁移; 更新 consumer
contract test。

## 4. 后续里程碑顺序

```text
NETSTACK2-002 Buffer/Packet I/O
        ↓
NETSTACK2-003 Linux TapPacketIo
        ↓
NETSTACK2-004 Dispatcher/StackShard
        ↓
NETSTACK2-API-FREEZE-001
        ↓
P3A IPv4/IPv6/L3
        ↓
P3B TCP 基础状态机
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
* **NETSTACK2-002 未提交**: 三个文件已改动但未提交, 待实现和门禁完整后
  单独提交, 不并入架构文档提交。
* **lwIP 保留**: 迁移期间 lwIP 保留为回退路径; 同一运行实例只启用一个
  TCP/IP engine, 切换在启动阶段完成, 不做运行中热切换。

## 6. 并行工作

OpenPPP2 只读对照和集成规划(`docs/integration/OPENPPP2_INTEGRATION_PLAN.md`)
与 NETSTACK2-002 并行进行, 不接 submodule、不改构建、不替换 lwIP。
真实 OpenPPP2 构建与运行时接线在 API-FREEZE-001 之后(P4)。
