#pragma once

/**
 * @file send.h
 * @brief TCP send buffer with retransmission queue and RTO (RFC 6298).
 * @license GPL-3.0
 *
 * Single-owner send buffer. Manages unsent application data, in-flight
 * segments awaiting ACK, and RFC 6298 retransmission timeout with Karn's
 * rule. Congestion control is delegated to a pluggable controller (AIMD
 * or BBRv1); the retransmit-queue contract is unchanged (P3C).
 *
 * Ownership model: each in-flight send record holds a BufferRef (shard-local
 * retained handle) that keeps its payload backing alive until ACKed or lost.
 * The caller creates this backing independently from the wire BufferLease
 * transferred to IPacketQueue: a pool slot cannot be both leased for TX and
 * retained at the same time. The backing may contain only the TCP payload.
 */

#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <variant>
#include <vector>

#include <tcpip2/buffer.h>
#include <tcp/congestion.h>
#include <tcp/rate_sampler.h>
#include <tcp/receive.h>

namespace tcpip2 {

struct TcpSendConfig {
    std::uint16_t initial_mss = 1460;
    std::uint8_t window_scale = 0;
    std::size_t send_queue_limit = 256 * 1024;     ///< Max unsent bytes buffered.
    std::size_t retransmit_queue_limit = 256 * 1024; ///< Max in-flight bytes.
    std::uint64_t min_rto_ms = 200;
    std::uint64_t max_rto_ms = 120000;
    std::uint64_t initial_rto_ms = 1000;
    std::uint64_t persist_timer_base_ms = 500;     ///< Zero-window probe interval.
    std::uint64_t persist_timer_max_ms = 60000;
    std::size_t max_retransmissions = 15;          ///< RFC 1122 §4.2.2.13.
    std::size_t max_persist_probes = 15;           ///< Abort after this many unanswered probes.
    CongestionAlgorithm cc_algorithm = CongestionAlgorithm::Aimd;

    bool Validate() const noexcept;
};

/// Result of NextSegment: describes what to transmit.
struct TcpSendNextResult {
    bool has_segment = false;           ///< True if there is something to send.
    bool is_retransmission = false;     ///< True if this is a retransmit, not new data.
    bool is_zero_window_probe = false;  ///< True if this is a persist-timer probe.
    bool is_fin = false;                ///< True if this segment carries the FIN flag.
    const std::uint8_t* payload = nullptr;
    std::size_t payload_length = 0;
    std::uint32_t sequence = 0;         ///< TCP sequence number for this segment.
};

/// Outcome of processing an incoming ACK.
struct TcpSendAckResult {
    std::size_t newly_acked = 0;        ///< Bytes newly acknowledged.
    bool duplicate = false;             ///< Duplicate ACK (snd_una unchanged).
    bool fast_retransmit = false;       ///< Trigger fast retransmit.
    bool fully_acked = false;           ///< All in-flight data ACKed.
    bool unacceptable = false;          ///< ACK is beyond SND.NXT/SND.MAX.
    std::size_t retransmit_queue_bytes = 0; ///< Remaining in-flight bytes.
};

/**
 * Single-owner TCP send path. Manages:
 *   - Unsent data queue (application -> wire)
 *   - In-flight retransmission queue (wire -> ACK)
 *   - RFC 6298 RTO with Karn's rule and exponential backoff
 *   - Pluggable congestion control (AIMD or BBRv1) via controller
 *   - Delivery-rate sampling for BBR/KCC
 *   - Zero-window persist timer
 *   - FIN scheduling
 *
 * Thread-safety: single-threaded, shard-local. No internal locking.
 */
class TcpSendBuffer final {
public:
    TcpSendBuffer(std::uint32_t initial_sequence,
                  std::uint16_t mss,
                  std::uint8_t window_scale,
                  std::size_t queue_limit,
                  std::size_t retransmit_limit,
                  std::uint64_t initial_rto_ms,
                  std::uint64_t min_rto_ms,
                  std::uint64_t max_rto_ms,
                  std::uint64_t persist_base_ms,
                  std::uint64_t persist_max_ms,
                  std::size_t max_retransmissions,
                  std::size_t max_persist_probes,
                  CongestionAlgorithm cc_algorithm = CongestionAlgorithm::Aimd);

    ~TcpSendBuffer() = default;

    TcpSendBuffer(const TcpSendBuffer&) = delete;
    TcpSendBuffer& operator=(const TcpSendBuffer&) = delete;

    // ---- Application -> send buffer ----

    /// Enqueue application data. Returns bytes accepted (0 if full/closed).
    std::size_t Enqueue(const std::uint8_t* data, std::size_t length) noexcept;

    /// Request FIN after all queued data is sent. Returns false if already requested.
    bool RequestFin() noexcept;

    // ---- Send path (called by shard each iteration) ----

    /**
     * Determine the next segment to transmit (new data, retransmission, or
     * zero-window probe). The caller must call OnSent() immediately after
     * serializing and queuing the segment for TX, passing the independent
     * BufferRef that retains the payload backing and its payload offset.
     *
     * @param peer_window  Scaled peer window (SND.WND).
     * @param now_ms       Current monotonic time.
     */
    TcpSendNextResult NextSegment(std::uint32_t peer_window,
                                  std::uint64_t now_ms) noexcept;

    /**
     * Record that the segment from NextSegment() was serialized and queued.
     * Takes ownership of @p owner (the BufferRef retaining payload backing).
     * @p payload_offset is the byte offset of the TCP payload within the
     * retained buffer; the retransmit queue stores a BufferSlice pointing
     * at owner.Data() + payload_offset so retransmissions read from the
     * retained buffer, not the (now-consumed) send queue.
     *
     * For retransmissions, @p owner may be empty (the original BufferRef is
     * still held in the retransmit queue); @p payload_offset is ignored.
     */
    void OnSent(BufferRef owner, std::size_t payload_offset,
                std::uint64_t now_ms) noexcept;

    // ---- ACK processing ----

    /**
     * Process an incoming ACK. Updates snd_una, removes ACKed segments from
     * the retransmit queue, handles duplicate ACKs and fast retransmit.
     */
    TcpSendAckResult OnAck(std::uint32_t acknowledgment,
                           std::uint32_t peer_window,
                           std::uint64_t now_ms,
                           bool ack_only = true) noexcept;

    /**
     * Process incoming SACK blocks from a duplicate ACK.
     * Marks in-flight records covered by SACK blocks, tracks the SACKed
     * pipe for congestion-window accounting, and triggers fast retransmit
     * when 3+ consecutive records are SACKed.
     * Returns the number of bytes newly SACKed by this call.
     */
    std::size_t OnSack(const TcpSackBlockList& sack_blocks,
                       std::uint64_t now_ms) noexcept;

    // ---- Timer-driven actions ----

    /// Returns true if the retransmission timer has expired and a retransmit is due.
    bool RetransmitExpired(std::uint64_t now_ms) const noexcept;

    /// Returns the next retransmit deadline (0 if none pending).
    std::uint64_t RetransmitDeadline() const noexcept { return rto_deadline_ms_; }

    /// Returns the absolute time before which new (non-retransmit) data
    /// must not be sent due to pacing.  Returns 0 when no pacing gate is
    /// active (i.e. pacing_rate == 0 or deadline already passed).
    std::uint64_t PacingDeadline() const noexcept { return next_send_time_ms_; }

    /// Returns true if persist timer has expired (zero-window probe needed).
    bool PersistExpired(std::uint64_t now_ms) const noexcept;

    /// Returns the next persist probe deadline (0 if not in persist mode).
    std::uint64_t PersistDeadline() const noexcept { return persist_deadline_ms_; }

    /// Schedule persist timer for zero-window probing.
    void ArmPersistTimer(std::uint64_t now_ms) noexcept;

    // ---- Queries ----

    std::uint32_t SndUna() const noexcept { return snd_una_; }
    std::uint32_t SndNxt() const noexcept { return snd_nxt_; }
    std::uint32_t SndMax() const noexcept { return snd_max_; }
    std::size_t UnsntBytes() const noexcept { return send_queue_.size(); }
    std::size_t InFlightBytes() const noexcept { return in_flight_bytes_; }
    std::size_t RetransmitQueueSize() const noexcept { return retransmit_queue_.size(); }
    std::uint32_t CongestionWindow() const noexcept;
    std::uint32_t Ssthresh() const noexcept;
    std::uint32_t PacingRate() const noexcept;
    std::uint16_t Mss() const noexcept { return mss_; }
    void UpdateMss(std::uint16_t mss) noexcept;
    bool FinRequested() const noexcept { return fin_requested_; }
    bool FinSent() const noexcept { return fin_sent_; }
    bool FinAcked() const noexcept { return fin_acked_; }
    bool IsClosed() const noexcept { return closed_; }
    std::size_t DupAckCount() const noexcept { return dup_ack_count_; }
    std::size_t RetransmissionCount() const noexcept { return retransmission_count_; }
    bool PersistActive() const noexcept { return persist_deadline_ms_ != 0; }
    std::size_t PersistProbeCount() const noexcept { return persist_probe_count_; }
    std::uint64_t CurrentRto() const noexcept { return rto_ms_; }
    std::size_t SackedBytes() const noexcept { return sacked_bytes_; }
    std::uint32_t SackedSequence() const noexcept { return sacked_sequence_; }
    bool InFastRecovery() const noexcept;

    /// @return The selected congestion algorithm.
    CongestionAlgorithm Algorithm() const noexcept { return cc_algorithm_; }

    /// True if all sent data (including FIN) has been ACKed and no unsent data remains.
    bool AllAcked() const noexcept;

    /// Cancel all timers (called on RST or PCB removal).
    void CancelTimers() noexcept;

    /// Clear pending send state without committing (called when TX allocation
    /// fails between NextSegment and OnSent).
    void ResetPending() noexcept;

private:
    struct SendRecord {
        std::uint32_t seq = 0;
        std::uint32_t logical_length = 0;
        BufferRef owner;
        BufferSlice data;
        std::uint64_t sent_time_ms = 0;
        std::size_t rto_attempts = 0;
        bool retransmitted = false;
        bool sacked = false;
        PacketDeliveryState delivery;
    };

    enum class PendingKind {
        None,
        NewData,
        RtoRetransmit,
        FastRetransmit,
        PersistNew,
        PersistRetry,
        PersistExisting,
        PersistPromote,
    };

    void RecomputeRto(std::uint64_t rtt_ms) noexcept;
    void BackoffRto() noexcept;
    std::size_t UsableWindow(std::uint32_t peer_window) const noexcept;
    bool CanSendNew(std::uint32_t peer_window) const noexcept;
    void ArmRto(std::uint64_t now_ms) noexcept;
    void CancelPersist() noexcept;
    void ScheduleNextPersist(std::uint64_t now_ms) noexcept;
    void Close() noexcept;
    bool StoreNewRecord(BufferRef owner, std::size_t payload_offset,
                        std::uint64_t now_ms) noexcept;

    // Send queue (unsent application data)
    std::vector<std::uint8_t> send_queue_;
    std::size_t send_queue_limit_;

    // Retransmission queue (in-flight segments)
    std::deque<SendRecord> retransmit_queue_;
    std::size_t retransmit_limit_;
    std::size_t retransmit_bytes_ = 0;
    std::size_t in_flight_bytes_ = 0;
    std::size_t in_flight_sequence_ = 0;
    std::optional<SendRecord> persist_probe_;

    // SACK scoreboard
    std::size_t sacked_bytes_ = 0;
    std::uint32_t sacked_sequence_ = 0;

    // Sequence numbers
    std::uint32_t snd_una_;    ///< Lowest unacknowledged sequence.
    std::uint32_t snd_nxt_;    ///< Next sequence to assign.
    std::uint32_t snd_max_;    ///< Highest sequence ever sent (+1).

    // Congestion control (pluggable: AIMD, BBRv1, or KCC hybrid)
    CongestionAlgorithm cc_algorithm_;
    std::variant<AimdController, BbrController, KccController> controller_;
    DeliveryRateSampler sampler_;
    std::uint16_t mss_;        ///< Maximum segment size.

    // RTO (RFC 6298 with Karn's rule)
    std::uint64_t rto_ms_;         ///< Current RTO value.
    std::uint64_t rto_deadline_ms_; ///< Absolute deadline for next retransmit.
    std::uint64_t min_rto_ms_;
    std::uint64_t max_rto_ms_;
    bool rto_running_ = false;

    // RTT estimation (RFC 6298 §2)
    bool srtt_valid_ = false;
    std::uint64_t srtt_ms_ = 0;    ///< Smoothed RTT.
    std::uint64_t rttvar_ms_ = 0;  ///< RTT variation.

    // Duplicate ACK tracking
    std::size_t dup_ack_count_ = 0;
    std::uint32_t last_peer_window_ = 0;
    bool peer_window_valid_ = false;

    // Fast retransmit pending
    bool fast_retransmit_pending_ = false;

    // Retransmission tracking
    std::size_t retransmission_count_ = 0;
    std::size_t max_retransmissions_ = 0;

    // Persist timer (zero-window probe)
    std::uint64_t persist_deadline_ms_ = 0;
    std::uint64_t persist_base_ms_ = 0;
    std::uint64_t persist_max_ms_ = 0;
    std::uint64_t persist_current_ms_ = 0;
    std::size_t persist_probe_count_ = 0;
    std::size_t max_persist_probes_ = 0;

    // FIN state
    bool fin_requested_ = false;
    bool fin_sent_ = false;
    bool fin_acked_ = false;

    // Closed (too many retransmissions)
    bool closed_ = false;

    // Pacing gate (P3C-03): new data is delayed until next_send_time_ms_.
    // Retransmissions and persist probes bypass pacing.  A value of 0 means
    // "no gate active" (send immediately).  When pacing_rate_ == 0 (AIMD or
    // BBR before BtlBw is known), pacing is disabled entirely.
    std::uint64_t next_send_time_ms_ = 0;

    // Pending send state (between NextSegment and OnSent)
    PendingKind pending_kind_ = PendingKind::None;
    bool pending_is_fin_ = false;
    std::uint32_t pending_seq_ = 0;
    std::size_t pending_len_ = 0;
};

} // namespace tcpip2
