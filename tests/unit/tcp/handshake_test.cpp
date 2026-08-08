#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include "Test.h"
#include <core/timer_wheel.h>
#include <ip/checksum.h>
#include <ip/ipv4.h>
#include <ip/ipv6.h>
#include <tcp/handshake.h>
#include <tcp/input.h>
#include <tcp/isn.h>
#include <tcp/options.h>
#include <tcp/output.h>
#include <tcp/segment.h>

using namespace tcpip2;

namespace {

const std::array<std::uint64_t, 2> kSecret{{
    0x0706050403020100ULL,
    0x0f0e0d0c0b0a0908ULL,
}};

FlowKey MakeFlow(std::uint16_t source_port = 40000,
                 std::uint16_t destination_port = 443) {
    FlowKey flow;
    flow.source = IpAddress::Ipv4(10, 0, 0, 1);
    flow.destination = IpAddress::Ipv4(10, 0, 0, 2);
    flow.source_port = source_port;
    flow.destination_port = destination_port;
    flow.protocol = 6;
    return flow;
}

FlowKey Reverse(const FlowKey& flow) {
    FlowKey reversed;
    reversed.source = flow.destination;
    reversed.destination = flow.source;
    reversed.source_port = flow.destination_port;
    reversed.destination_port = flow.source_port;
    reversed.protocol = flow.protocol;
    return reversed;
}

void Write16(std::uint8_t* data, std::uint16_t value) {
    data[0] = static_cast<std::uint8_t>(value >> 8);
    data[1] = static_cast<std::uint8_t>(value & 0xffu);
}

void Write32(std::uint8_t* data, std::uint32_t value) {
    data[0] = static_cast<std::uint8_t>(value >> 24);
    data[1] = static_cast<std::uint8_t>((value >> 16) & 0xffu);
    data[2] = static_cast<std::uint8_t>((value >> 8) & 0xffu);
    data[3] = static_cast<std::uint8_t>(value & 0xffu);
}

std::vector<std::uint8_t> BuildTcpSegment(
    const FlowKey& flow, std::uint32_t sequence, std::uint32_t acknowledgment,
    std::uint8_t flags, const std::vector<std::uint8_t>& options = {},
    const std::vector<std::uint8_t>& payload = {}) {
    std::size_t padded_options = options.size();
    while ((padded_options % 4) != 0) ++padded_options;
    const std::size_t header_length = 20 + padded_options;
    std::vector<std::uint8_t> bytes(header_length + payload.size(), 0);
    Write16(bytes.data(), flow.source_port);
    Write16(bytes.data() + 2, flow.destination_port);
    Write32(bytes.data() + 4, sequence);
    Write32(bytes.data() + 8, acknowledgment);
    bytes[12] = static_cast<std::uint8_t>((header_length / 4) << 4);
    bytes[13] = flags;
    Write16(bytes.data() + 14, 32768);
    for (std::size_t i = 0; i < options.size(); ++i) bytes[20 + i] = options[i];
    for (std::size_t i = 0; i < payload.size(); ++i) bytes[header_length + i] = payload[i];

    std::uint32_t seed = 0;
    if (flow.source.IsIpv4()) {
        seed = Ipv4PseudoHeaderSeed(
            flow.source.Bytes(), flow.destination.Bytes(), 6,
            static_cast<std::uint16_t>(bytes.size()));
    } else {
        seed = Ipv6PseudoHeaderSeed(
            flow.source.Bytes(), flow.destination.Bytes(), 6,
            static_cast<std::uint32_t>(bytes.size()));
    }
    Write16(bytes.data() + 16, InternetChecksum(bytes.data(), bytes.size(), seed));
    return bytes;
}

TcpSegmentView MakeView(const FlowKey& flow, std::uint32_t sequence,
                        std::uint32_t acknowledgment, std::uint8_t flags,
                        const std::vector<std::uint8_t>& options = {}) {
    TcpSegmentView segment;
    segment.flow = flow;
    segment.sequence = sequence;
    segment.acknowledgment = acknowledgment;
    segment.flags = flags;
    segment.window = 32768;
    segment.options = options.data();
    segment.options_length = options.size();
    return segment;
}

std::vector<std::uint8_t> AllSynOptions() {
    return {
        2, 4, 0x05, 0xb4,
        1,
        3, 3, 15,
        4, 2,
        1, 1,
        8, 10, 0, 0, 0, 42, 0, 0, 0, 0,
    };
}

std::vector<std::uint8_t> TimestampOption(std::uint32_t value,
                                          std::uint32_t echo) {
    std::vector<std::uint8_t> option = {8, 10, 0, 0, 0, 0, 0, 0, 0, 0};
    Write32(option.data() + 2, value);
    Write32(option.data() + 6, echo);
    return option;
}

} // namespace

TCPIP2_TEST(ParseIpv4AndIpv6TcpSegments) {
    const FlowKey ipv4 = MakeFlow();
    const auto bytes4 = BuildTcpSegment(ipv4, 100, 0, TcpFlag::Syn);
    const auto parsed4 = ParseTcpSegment(
        ipv4.source, ipv4.destination, bytes4.data(), bytes4.size());
    TCPIP2_EXPECT_EQ(TcpParseError::None, parsed4.error);
    TCPIP2_EXPECT_EQ(ipv4, parsed4.segment.flow);
    TCPIP2_EXPECT_EQ(std::uint32_t{100}, parsed4.segment.sequence);
    TCPIP2_EXPECT_TRUE(parsed4.segment.HasFlag(TcpFlag::Syn));

    std::uint8_t src6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                             0, 0, 0, 0, 0, 0, 0, 1};
    std::uint8_t dst6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                             0, 0, 0, 0, 0, 0, 0, 2};
    FlowKey ipv6;
    ipv6.source = IpAddress::Ipv6(src6);
    ipv6.destination = IpAddress::Ipv6(dst6);
    ipv6.source_port = 50000;
    ipv6.destination_port = 80;
    ipv6.protocol = 6;
    const auto bytes6 = BuildTcpSegment(ipv6, 200, 0, TcpFlag::Syn);
    const auto parsed6 = ParseTcpSegment(
        ipv6.source, ipv6.destination, bytes6.data(), bytes6.size());
    TCPIP2_EXPECT_EQ(TcpParseError::None, parsed6.error);
    TCPIP2_EXPECT_EQ(ipv6, parsed6.segment.flow);
}

TCPIP2_TEST(ParseRejectsMalformedTcpSegments) {
    const FlowKey flow = MakeFlow();
    auto bytes = BuildTcpSegment(flow, 100, 0, TcpFlag::Syn);
    TCPIP2_EXPECT_EQ(
        TcpParseError::TooShort,
        ParseTcpSegment(flow.source, flow.destination, bytes.data(), 19).error);

    bytes[12] = 0x40;
    TCPIP2_EXPECT_EQ(
        TcpParseError::BadDataOffset,
        ParseTcpSegment(flow.source, flow.destination, bytes.data(), bytes.size()).error);

    bytes = BuildTcpSegment(flow, 100, 0, TcpFlag::Syn);
    bytes[5] ^= 1;
    TCPIP2_EXPECT_EQ(
        TcpParseError::BadChecksum,
        ParseTcpSegment(flow.source, flow.destination, bytes.data(), bytes.size()).error);

    bytes = BuildTcpSegment(flow, 100, 0, TcpFlag::Syn);
    bytes[12] |= 0x02;
    Write16(bytes.data() + 16, 0);
    const std::uint32_t seed = Ipv4PseudoHeaderSeed(
        flow.source.Bytes(), flow.destination.Bytes(), 6,
        static_cast<std::uint16_t>(bytes.size()));
    Write16(bytes.data() + 16, InternetChecksum(bytes.data(), bytes.size(), seed));
    TCPIP2_EXPECT_EQ(
        TcpParseError::None,
        ParseTcpSegment(flow.source, flow.destination, bytes.data(), bytes.size()).error);
}

TCPIP2_TEST(ParseTcpSynOptionsNegotiatesKnownOptions) {
    const auto bytes = AllSynOptions();
    const auto result = ParseTcpSynOptions(bytes.data(), bytes.size());
    TCPIP2_EXPECT_EQ(TcpOptionError::None, result.error);
    TCPIP2_EXPECT_TRUE(result.options.mss_present);
    TCPIP2_EXPECT_EQ(std::uint16_t{1460}, result.options.mss);
    TCPIP2_EXPECT_TRUE(result.options.window_scale_present);
    TCPIP2_EXPECT_EQ(std::uint8_t{14}, result.options.window_scale);
    TCPIP2_EXPECT_TRUE(result.options.sack_permitted);
    TCPIP2_EXPECT_TRUE(result.options.timestamp_present);
    TCPIP2_EXPECT_EQ(std::uint32_t{42}, result.options.timestamp_value);
}

TCPIP2_TEST(ParseTcpSynOptionsRejectsMalformedAndDuplicateOptions) {
    const std::vector<std::uint8_t> truncated = {2, 4, 0x05};
    TCPIP2_EXPECT_EQ(
        TcpOptionError::Truncated,
        ParseTcpSynOptions(truncated.data(), truncated.size()).error);

    const std::vector<std::uint8_t> invalid_length = {3, 1};
    TCPIP2_EXPECT_EQ(
        TcpOptionError::InvalidLength,
        ParseTcpSynOptions(invalid_length.data(), invalid_length.size()).error);

    const std::vector<std::uint8_t> duplicate = {
        2, 4, 0x05, 0xb4, 2, 4, 0x04, 0x00,
    };
    TCPIP2_EXPECT_EQ(
        TcpOptionError::DuplicateOption,
        ParseTcpSynOptions(duplicate.data(), duplicate.size()).error);

    const std::vector<std::uint8_t> eol = {0, 2, 1};
    TCPIP2_EXPECT_EQ(
        TcpOptionError::None,
        ParseTcpSynOptions(eol.data(), eol.size()).error);
}

TCPIP2_TEST(SecureIsnIsTupleKeyedAndTimeVarying) {
    const TcpIsnGenerator generator(kSecret);
    const FlowKey first = MakeFlow(40000);
    const FlowKey second = MakeFlow(40001);
    const std::uint32_t a = generator.Generate(first, 1000);
    TCPIP2_EXPECT_EQ(std::uint32_t{3594882978u}, a);
    TCPIP2_EXPECT_EQ(a + 1, generator.Generate(first, 1000));
    TCPIP2_EXPECT_NE(a, generator.Generate(second, 1000));
    TCPIP2_EXPECT_NE(a, generator.Generate(first, 999));
    TCPIP2_EXPECT_NE(a, generator.Generate(Reverse(first), 1000));
}

TCPIP2_TEST(SystemCsrngProvidesIsnSecret) {
    std::array<std::uint64_t, 2> secret{};
#if defined(__linux__)
    TCPIP2_EXPECT_TRUE(LoadTcpIsnSecret(secret));
#else
    TCPIP2_EXPECT_FALSE(LoadTcpIsnSecret(secret));
#endif
}

TCPIP2_TEST(SynCreatesBoundedPcbAndNegotiatedSynAck) {
    TimerWheel timers;
    TcpHandshakeConfig config;
    TcpHandshakeEngine engine(config, TcpIsnGenerator(kSecret), timers);
    const FlowKey flow = MakeFlow();
    const auto options = AllSynOptions();

    const auto result = engine.OnSegment(
        MakeView(flow, 1000, 0, TcpFlag::Syn, options), 5000);
    TCPIP2_EXPECT_EQ(TcpHandshakeError::None, result.error);
    TCPIP2_EXPECT_TRUE(result.state_changed);
    TCPIP2_EXPECT_TRUE(result.response.valid);
    TCPIP2_EXPECT_EQ(Reverse(flow), result.response.flow);
    TCPIP2_EXPECT_EQ(std::uint32_t{1001}, result.response.acknowledgment);
    TCPIP2_EXPECT_EQ(
        static_cast<std::uint8_t>(TcpFlag::Syn | TcpFlag::Ack),
        result.response.flags);
    TCPIP2_EXPECT_EQ(std::uint16_t{65535}, result.response.window);
    TCPIP2_EXPECT_EQ(std::uint16_t{1460}, result.response.syn_options.mss);
    TCPIP2_EXPECT_EQ(std::uint8_t{1}, result.response.syn_options.window_scale);
    TCPIP2_EXPECT_TRUE(result.response.syn_options.sack_permitted);
    TCPIP2_EXPECT_EQ(std::uint32_t{42}, result.response.syn_options.timestamp_echo);
    TCPIP2_EXPECT_EQ(std::size_t{1}, engine.PcbCount());
    TCPIP2_EXPECT_EQ(std::size_t{1}, engine.HalfOpenCount());
    TCPIP2_EXPECT_EQ(std::size_t{1}, timers.PendingCount());

    TcpPcbSnapshot pcb;
    TCPIP2_EXPECT_TRUE(engine.Find(flow, pcb));
    TCPIP2_EXPECT_EQ(TcpState::SynReceived, pcb.state);
    TCPIP2_EXPECT_EQ(std::uint16_t{1460}, pcb.options.peer_mss);
    TCPIP2_EXPECT_EQ(std::uint8_t{14}, pcb.options.send_window_scale);
}

TCPIP2_TEST(FinalAckEstablishesAndCancelsRetry) {
    TimerWheel timers;
    TcpHandshakeEngine engine(TcpHandshakeConfig{}, TcpIsnGenerator(kSecret), timers);
    const FlowKey flow = MakeFlow();
    const auto syn = engine.OnSegment(MakeView(flow, 1000, 0, TcpFlag::Syn), 100);
    const auto ack = engine.OnSegment(
        MakeView(flow, 1001, syn.response.sequence + 1, TcpFlag::Ack), 101);

    TCPIP2_EXPECT_TRUE(ack.state_changed);
    TCPIP2_EXPECT_FALSE(ack.response.valid);
    TCPIP2_EXPECT_EQ(std::size_t{0}, engine.HalfOpenCount());
    TCPIP2_EXPECT_EQ(std::size_t{1}, engine.EstablishedCount());
    TCPIP2_EXPECT_EQ(std::size_t{0}, timers.PendingCount());

    TcpPcbSnapshot pcb;
    TCPIP2_EXPECT_TRUE(engine.Find(flow, pcb));
    TCPIP2_EXPECT_EQ(TcpState::Established, pcb.state);
    TCPIP2_EXPECT_EQ(pcb.snd_nxt, pcb.snd_una);
}

TCPIP2_TEST(DuplicateSynReusesPcbIsnAndTimer) {
    TimerWheel timers;
    TcpHandshakeEngine engine(TcpHandshakeConfig{}, TcpIsnGenerator(kSecret), timers);
    const FlowKey flow = MakeFlow();
    const auto options = AllSynOptions();
    const auto first = engine.OnSegment(
        MakeView(flow, 1000, 0, TcpFlag::Syn, options), 100);
    const auto duplicate = engine.OnSegment(
        MakeView(flow, 1000, 0, TcpFlag::Syn), 200);

    TCPIP2_EXPECT_TRUE(duplicate.response.valid);
    TCPIP2_EXPECT_EQ(first.response.sequence, duplicate.response.sequence);
    TCPIP2_EXPECT_NE(first.response.syn_options.timestamp_value,
                     duplicate.response.syn_options.timestamp_value);
    TCPIP2_EXPECT_EQ(std::size_t{1}, engine.PcbCount());
    TCPIP2_EXPECT_EQ(std::size_t{1}, timers.PendingCount());

    const auto changed = engine.OnSegment(
        MakeView(flow, 2000, 0, TcpFlag::Syn), 201);
    TCPIP2_EXPECT_EQ(TcpHandshakeError::InvalidFlags, changed.error);
    TCPIP2_EXPECT_EQ(std::size_t{1}, engine.PcbCount());
}

TCPIP2_TEST(NegotiatedTimestampRequiredOnFinalAck) {
    TimerWheel timers;
    TcpHandshakeEngine engine(TcpHandshakeConfig{}, TcpIsnGenerator(kSecret), timers);
    const FlowKey flow = MakeFlow();
    const auto syn_options = TimestampOption(42, 0);
    const auto syn = engine.OnSegment(
        MakeView(flow, 1000, 0, TcpFlag::Syn, syn_options), 100);

    const auto missing = engine.OnSegment(
        MakeView(flow, 1001, syn.response.sequence + 1, TcpFlag::Ack), 101);
    TCPIP2_EXPECT_EQ(TcpHandshakeError::InvalidOptions, missing.error);
    TCPIP2_EXPECT_EQ(std::size_t{1}, engine.HalfOpenCount());

    const auto ack_options = TimestampOption(
        43, syn.response.syn_options.timestamp_value);
    const auto accepted = engine.OnSegment(
        MakeView(flow, 1001, syn.response.sequence + 1, TcpFlag::Ack, ack_options), 102);
    TCPIP2_EXPECT_TRUE(accepted.state_changed);
    TCPIP2_EXPECT_EQ(std::size_t{1}, engine.EstablishedCount());
}

TCPIP2_TEST(WrongAckResetsWithoutEstablishing) {
    TimerWheel timers;
    TcpHandshakeEngine engine(TcpHandshakeConfig{}, TcpIsnGenerator(kSecret), timers);
    const FlowKey flow = MakeFlow();
    const auto syn = engine.OnSegment(MakeView(flow, 1000, 0, TcpFlag::Syn), 100);
    const auto wrong = engine.OnSegment(
        MakeView(flow, 1001, syn.response.sequence + 2, TcpFlag::Ack), 101);
    TCPIP2_EXPECT_TRUE(wrong.response.valid);
    TCPIP2_EXPECT_EQ(TcpFlag::Rst, wrong.response.flags);
    TCPIP2_EXPECT_EQ(std::size_t{1}, engine.HalfOpenCount());
    TCPIP2_EXPECT_EQ(std::size_t{0}, engine.EstablishedCount());
}

TCPIP2_TEST(ValidRstRemovesHalfOpenAndUnknownRstIsIgnored) {
    TimerWheel timers;
    TcpHandshakeEngine engine(TcpHandshakeConfig{}, TcpIsnGenerator(kSecret), timers);
    const FlowKey flow = MakeFlow();
    engine.OnSegment(MakeView(flow, 1000, 0, TcpFlag::Syn), 100);

    const auto invalid = engine.OnSegment(MakeView(flow, 999, 0, TcpFlag::Rst), 101);
    TCPIP2_EXPECT_FALSE(invalid.state_changed);
    TCPIP2_EXPECT_EQ(std::size_t{1}, engine.PcbCount());

    const auto valid = engine.OnSegment(MakeView(flow, 1001, 0, TcpFlag::Rst), 102);
    TCPIP2_EXPECT_TRUE(valid.state_changed);
    TCPIP2_EXPECT_EQ(std::size_t{0}, engine.PcbCount());
    TCPIP2_EXPECT_EQ(std::size_t{0}, timers.PendingCount());

    const auto unknown = engine.OnSegment(
        MakeView(MakeFlow(40001), 1, 0, TcpFlag::Rst), 103);
    TCPIP2_EXPECT_FALSE(unknown.response.valid);
}

TCPIP2_TEST(UnknownAckProducesRst) {
    TimerWheel timers;
    TcpHandshakeEngine engine(TcpHandshakeConfig{}, TcpIsnGenerator(kSecret), timers);
    const FlowKey flow = MakeFlow();
    const auto result = engine.OnSegment(MakeView(flow, 10, 77, TcpFlag::Ack), 100);
    TCPIP2_EXPECT_TRUE(result.response.valid);
    TCPIP2_EXPECT_EQ(TcpFlag::Rst, result.response.flags);
    TCPIP2_EXPECT_EQ(std::uint32_t{77}, result.response.sequence);
    TCPIP2_EXPECT_EQ(std::size_t{0}, engine.PcbCount());
}

TCPIP2_TEST(BacklogAndHalfOpenLimitsAreIndependent) {
    TimerWheel backlog_timers;
    TcpHandshakeConfig backlog_config;
    backlog_config.backlog_limit = 2;
    backlog_config.half_open_limit = 4;
    TcpHandshakeEngine backlog(backlog_config, TcpIsnGenerator(kSecret), backlog_timers);
    backlog.OnSegment(MakeView(MakeFlow(40000), 1, 0, TcpFlag::Syn), 0);
    backlog.OnSegment(MakeView(MakeFlow(40001), 1, 0, TcpFlag::Syn), 0);
    const auto backlog_full = backlog.OnSegment(
        MakeView(MakeFlow(40002), 1, 0, TcpFlag::Syn), 0);
    TCPIP2_EXPECT_EQ(TcpHandshakeError::BacklogFull, backlog_full.error);

    TimerWheel half_open_timers;
    TcpHandshakeConfig half_open_config;
    half_open_config.backlog_limit = 4;
    half_open_config.half_open_limit = 2;
    TcpHandshakeEngine half_open(
        half_open_config, TcpIsnGenerator(kSecret), half_open_timers);
    half_open.OnSegment(MakeView(MakeFlow(41000), 1, 0, TcpFlag::Syn), 0);
    half_open.OnSegment(MakeView(MakeFlow(41001), 1, 0, TcpFlag::Syn), 0);
    const auto half_open_full = half_open.OnSegment(
        MakeView(MakeFlow(41002), 1, 0, TcpFlag::Syn), 0);
    TCPIP2_EXPECT_EQ(TcpHandshakeError::HalfOpenLimit, half_open_full.error);
}

TCPIP2_TEST(SynAckRetriesAndTimeoutReleaseCapacity) {
    TimerWheel timers;
    TcpHandshakeConfig config;
    config.syn_ack_retry_intervals_ms = {{10, 20, 40, 80}};
    TcpHandshakeEngine engine(config, TcpIsnGenerator(kSecret), timers);
    const FlowKey flow = MakeFlow();
    const auto initial = engine.OnSegment(MakeView(flow, 1000, 0, TcpFlag::Syn), 0);

    TCPIP2_EXPECT_EQ(std::size_t{0}, timers.AdvanceTo(9));
    TCPIP2_EXPECT_EQ(std::size_t{1}, timers.AdvanceTo(10));
    TcpResponse retry;
    TCPIP2_EXPECT_TRUE(engine.PopPendingResponse(retry));
    TCPIP2_EXPECT_EQ(initial.response.sequence, retry.sequence);

    timers.AdvanceTo(30);
    TCPIP2_EXPECT_TRUE(engine.PopPendingResponse(retry));
    timers.AdvanceTo(70);
    TCPIP2_EXPECT_TRUE(engine.PopPendingResponse(retry));
    timers.AdvanceTo(150);
    TCPIP2_EXPECT_TRUE(engine.PopPendingResponse(retry));
    TCPIP2_EXPECT_EQ(std::size_t{1}, engine.HalfOpenCount());

    timers.AdvanceTo(230);
    TCPIP2_EXPECT_EQ(std::size_t{0}, engine.PcbCount());
    TCPIP2_EXPECT_EQ(std::size_t{0}, engine.HalfOpenCount());
    TCPIP2_EXPECT_EQ(std::size_t{0}, timers.PendingCount());
}

TCPIP2_TEST(MalformedSynOptionsDoNotAllocatePcb) {
    TimerWheel timers;
    TcpHandshakeEngine engine(TcpHandshakeConfig{}, TcpIsnGenerator(kSecret), timers);
    const std::vector<std::uint8_t> malformed = {2, 3, 0};
    const auto result = engine.OnSegment(
        MakeView(MakeFlow(), 100, 0, TcpFlag::Syn, malformed), 0);
    TCPIP2_EXPECT_EQ(TcpHandshakeError::InvalidOptions, result.error);
    TCPIP2_EXPECT_EQ(std::size_t{0}, engine.PcbCount());
    TCPIP2_EXPECT_EQ(std::size_t{0}, timers.PendingCount());
}

TCPIP2_TEST(SynFloodNeverExceedsConfiguredBounds) {
    TimerWheel timers;
    TcpHandshakeConfig config;
    config.backlog_limit = 4;
    config.half_open_limit = 4;
    config.pcb_limit = 4;
    config.pending_response_limit = 2;
    TcpHandshakeEngine engine(config, TcpIsnGenerator(kSecret), timers);

    for (std::uint16_t i = 0; i < 1000; ++i) {
        engine.OnSegment(
            MakeView(MakeFlow(static_cast<std::uint16_t>(10000 + i)),
                     i, 0, TcpFlag::Syn), 0);
    }
    TCPIP2_EXPECT_EQ(std::size_t{4}, engine.PcbCount());
    TCPIP2_EXPECT_EQ(std::size_t{4}, engine.HalfOpenCount());
    TCPIP2_EXPECT_EQ(std::size_t{4}, timers.PendingCount());

    timers.AdvanceTo(1000);
    TCPIP2_EXPECT_EQ(std::size_t{2}, engine.PendingResponseCount());
    TCPIP2_EXPECT_EQ(std::size_t{2}, engine.DroppedResponseCount());
}

TCPIP2_TEST(ShutdownCancelsAllHandshakeTimers) {
    TimerWheel timers;
    TcpHandshakeEngine engine(TcpHandshakeConfig{}, TcpIsnGenerator(kSecret), timers);
    engine.OnSegment(MakeView(MakeFlow(40000), 1, 0, TcpFlag::Syn), 0);
    engine.OnSegment(MakeView(MakeFlow(40001), 1, 0, TcpFlag::Syn), 0);
    engine.Shutdown();
    TCPIP2_EXPECT_EQ(std::size_t{0}, engine.PcbCount());
    TCPIP2_EXPECT_EQ(std::size_t{0}, timers.PendingCount());
    const auto after_shutdown = engine.OnSegment(
        MakeView(MakeFlow(40002), 1, 0, TcpFlag::Syn), 1);
    TCPIP2_EXPECT_EQ(TcpHandshakeError::Shutdown, after_shutdown.error);
}

TCPIP2_TEST(DetachedDueRetryCannotOutliveEngine) {
    TimerWheel timers;
    std::unique_ptr<TcpHandshakeEngine> engine;
    timers.Schedule(1000, [&engine] { engine.reset(); });
    engine = std::make_unique<TcpHandshakeEngine>(
        TcpHandshakeConfig{}, TcpIsnGenerator(kSecret), timers);
    engine->OnSegment(MakeView(MakeFlow(), 1, 0, TcpFlag::Syn), 0);

    TCPIP2_EXPECT_EQ(std::size_t{2}, timers.AdvanceTo(1000));
    TCPIP2_EXPECT_FALSE(static_cast<bool>(engine));
    TCPIP2_EXPECT_EQ(std::size_t{0}, timers.PendingCount());
}

TCPIP2_TEST(SynAckSerializesToValidIpv4Packet) {
    TimerWheel timers;
    TcpHandshakeEngine engine(TcpHandshakeConfig{}, TcpIsnGenerator(kSecret), timers);
    const FlowKey flow = MakeFlow();
    const auto options = AllSynOptions();
    const auto handshake = engine.OnSegment(
        MakeView(flow, 1000, 0, TcpFlag::Syn, options), 100);

    std::array<std::uint8_t, 128> packet{};
    const auto built = BuildTcpControlPacket(
        handshake.response, packet.data(), packet.size(), 77, 55);
    TCPIP2_EXPECT_EQ(TcpOutputError::None, built.error);

    const auto ip = ParseIpv4(packet.data(), built.packet_length);
    TCPIP2_EXPECT_EQ(Ipv4ParseError::None, ip.error);
    TCPIP2_EXPECT_TRUE(ip.checksum_ok);
    TCPIP2_EXPECT_EQ(std::uint16_t{77}, ip.header.identification);
    TCPIP2_EXPECT_EQ(std::uint8_t{55}, ip.header.ttl);

    const auto tcp = ParseTcpSegment(
        handshake.response.flow.source, handshake.response.flow.destination,
        ip.payload, ip.header.payload_length);
    TCPIP2_EXPECT_EQ(TcpParseError::None, tcp.error);
    TCPIP2_EXPECT_EQ(handshake.response.sequence, tcp.segment.sequence);
    TCPIP2_EXPECT_EQ(handshake.response.acknowledgment, tcp.segment.acknowledgment);
    TCPIP2_EXPECT_EQ(handshake.response.flags, tcp.segment.flags);
    TCPIP2_EXPECT_EQ(std::uint16_t{65535}, tcp.segment.window);
    const auto parsed_options = ParseTcpSynOptions(
        tcp.segment.options, tcp.segment.options_length);
    TCPIP2_EXPECT_EQ(TcpOptionError::None, parsed_options.error);
    TCPIP2_EXPECT_TRUE(parsed_options.options.mss_present);
    TCPIP2_EXPECT_TRUE(parsed_options.options.window_scale_present);
    TCPIP2_EXPECT_TRUE(parsed_options.options.sack_permitted);
    TCPIP2_EXPECT_TRUE(parsed_options.options.timestamp_present);
}

TCPIP2_TEST(SynAckSerializesToValidIpv6Packet) {
    std::uint8_t src[16] = {0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 1};
    std::uint8_t dst[16] = {0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 2};
    FlowKey flow;
    flow.source = IpAddress::Ipv6(src);
    flow.destination = IpAddress::Ipv6(dst);
    flow.source_port = 40000;
    flow.destination_port = 443;
    flow.protocol = 6;

    TimerWheel timers;
    TcpHandshakeEngine engine(TcpHandshakeConfig{}, TcpIsnGenerator(kSecret), timers);
    const auto handshake = engine.OnSegment(
        MakeView(flow, 2000, 0, TcpFlag::Syn), 100);
    std::array<std::uint8_t, 128> packet{};
    const auto built = BuildTcpControlPacket(
        handshake.response, packet.data(), packet.size(), 0, 44);
    TCPIP2_EXPECT_EQ(TcpOutputError::None, built.error);

    const auto ip = ParseIpv6(packet.data(), built.packet_length);
    TCPIP2_EXPECT_EQ(Ipv6ParseResult::Error::None, ip.error);
    TCPIP2_EXPECT_EQ(std::uint8_t{6}, ip.final_next_header);
    TCPIP2_EXPECT_EQ(std::uint8_t{44}, ip.header.hop_limit);
    const auto tcp = ParseTcpSegment(
        handshake.response.flow.source, handshake.response.flow.destination,
        ip.payload, ip.payload_length);
    TCPIP2_EXPECT_EQ(TcpParseError::None, tcp.error);
    TCPIP2_EXPECT_EQ(handshake.response.flags, tcp.segment.flags);
    const auto parsed_options = ParseTcpSynOptions(
        tcp.segment.options, tcp.segment.options_length);
    TCPIP2_EXPECT_EQ(TcpOptionError::None, parsed_options.error);
    TCPIP2_EXPECT_EQ(std::uint16_t{1440}, parsed_options.options.mss);
}

TCPIP2_TEST(RstSerializationHasNoSynOptionsAndIsBounded) {
    TimerWheel timers;
    TcpHandshakeEngine engine(TcpHandshakeConfig{}, TcpIsnGenerator(kSecret), timers);
    const auto reset = engine.OnSegment(
        MakeView(MakeFlow(), 10, 77, TcpFlag::Ack), 100);
    std::array<std::uint8_t, 64> packet{};
    const auto too_small = BuildTcpControlPacket(
        reset.response, packet.data(), 39);
    TCPIP2_EXPECT_EQ(TcpOutputError::BufferTooSmall, too_small.error);

    const auto built = BuildTcpControlPacket(
        reset.response, packet.data(), packet.size());
    TCPIP2_EXPECT_EQ(TcpOutputError::None, built.error);
    TCPIP2_EXPECT_EQ(std::size_t{40}, built.packet_length);
    const auto ip = ParseIpv4(packet.data(), built.packet_length);
    const auto tcp = ParseTcpSegment(
        reset.response.flow.source, reset.response.flow.destination,
        ip.payload, ip.header.payload_length);
    TCPIP2_EXPECT_EQ(TcpParseError::None, tcp.error);
    TCPIP2_EXPECT_EQ(TcpFlag::Rst, tcp.segment.flags);
    TCPIP2_EXPECT_EQ(std::size_t{0}, tcp.segment.options_length);
}

TCPIP2_TEST(IpTcpInputValidatesChecksumsAndFragments) {
    TimerWheel timers;
    TcpHandshakeEngine engine(TcpHandshakeConfig{}, TcpIsnGenerator(kSecret), timers);
    const auto handshake = engine.OnSegment(
        MakeView(MakeFlow(), 1000, 0, TcpFlag::Syn), 100);
    std::array<std::uint8_t, 128> packet{};
    const auto built = BuildTcpControlPacket(
        handshake.response, packet.data(), packet.size());

    const auto valid = ParseIpTcpPacket(packet.data(), built.packet_length);
    TCPIP2_EXPECT_EQ(TcpInputError::None, valid.error);
    TCPIP2_EXPECT_EQ(handshake.response.flow, valid.segment.flow);

    packet[10] ^= 1;
    TCPIP2_EXPECT_EQ(
        TcpInputError::BadIpv4Checksum,
        ParseIpTcpPacket(packet.data(), built.packet_length).error);
    packet[10] ^= 1;

    packet[6] = 0x20;
    packet[10] = 0;
    packet[11] = 0;
    Write16(packet.data() + 10, InternetChecksum(packet.data(), 20));
    TCPIP2_EXPECT_EQ(
        TcpInputError::FragmentRequiresReassembly,
        ParseIpTcpPacket(packet.data(), built.packet_length).error);

    std::array<std::uint8_t, 68> ipv6_fragment{};
    ipv6_fragment[0] = 0x60;
    Write16(ipv6_fragment.data() + 4, 28);
    ipv6_fragment[6] = Ipv6ExtHeaderType::Fragment;
    ipv6_fragment[7] = 64;
    ipv6_fragment[40] = 6;
    ipv6_fragment[43] = 1;
    TCPIP2_EXPECT_EQ(
        TcpInputError::FragmentRequiresReassembly,
        ParseIpTcpPacket(ipv6_fragment.data(), ipv6_fragment.size()).error);
}

TCPIP2_TEST_MAIN()
