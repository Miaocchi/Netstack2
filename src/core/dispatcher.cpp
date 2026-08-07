/**
 * @file dispatcher.cpp
 * @brief PacketDispatcher routing logic.
 * @license GPL-3.0
 *
 * Dispatch() computes the flow's owning shard and the queue's home shard.
 * If they match, the packet is direct (the caller processes it locally).
 * Otherwise the packet is handed to the target shard's SPSC inbox.
 */

#include <core/dispatcher.h>
#include <core/shard.h>

#include <tcpip2/flow.h>

namespace tcpip2 {

bool PacketDispatcher::Dispatch(std::size_t rx_queue_id, FlowKey key,
                                StackShard* shards[]) noexcept {
    const std::size_t queue_shard = QueueShard(rx_queue_id);
    const std::size_t flow_shard = FlowShard(key);
    if (flow_shard == queue_shard) {
        return true;  // direct: caller keeps and processes the packet
    }
    // Redirect: the actual packet handoff is done by the caller via
    // shards[flow_shard]->PostPacket(). Dispatch() returns false so the
    // caller knows to hand off instead of processing locally.
    (void)shards;
    return false;
}

} // namespace tcpip2
