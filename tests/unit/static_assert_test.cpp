/**
 * @file static_assert_test.cpp
 * @brief Re-state the ownership contract at the test site.
 * @license GPL-3.0
 *
 * The library itself static_asserts these properties at build time
 * (src/core/buffer.cpp). Re-asserting them in a test documents the contract
 * next to the tests and guards the public header if the internal check is
 * ever moved. Trivially-copyable views are also verified at runtime via
 * memcpy round trips.
 */

#include <cstdint>
#include <cstring>
#include <type_traits>

#include <tcpip2/buffer.h>
#include <tcpip2/transport_session.h>

#include <core/shard.h>

#include "Test.h"

using namespace tcpip2;

static_assert(std::is_move_constructible_v<BufferLease>,
              "BufferLease must be move constructible");
static_assert(!std::is_copy_constructible_v<BufferLease>,
              "BufferLease must be move-only");
static_assert(!std::is_copy_assignable_v<BufferLease>,
              "BufferLease must be move-only");
static_assert(std::is_nothrow_move_constructible_v<BufferLease>,
              "BufferLease move must be noexcept");
static_assert(std::is_trivially_copyable_v<BufferSlice>,
              "BufferSlice must be trivially copyable");
static_assert(std::is_trivially_copyable_v<BufferView>,
              "BufferView must be trivially copyable");
static_assert(std::is_standard_layout_v<PktBuffer>,
              "PktBuffer must keep a fixed standard layout");
static_assert(std::is_trivially_destructible_v<PktBuffer>,
              "PktBuffer must be trivially destructible");
static_assert(std::is_move_constructible_v<ShardMessage>,
              "ShardMessage must be move constructible");
static_assert(!std::is_copy_constructible_v<ShardMessage>,
              "ShardMessage must be move-only");

TCPIP2_TEST(TriviallyCopyableViews) {
    const std::uint8_t raw[4] = {1, 2, 3, 4};
    BufferSlice a(raw, 4);
    BufferSlice b;
    std::memcpy(&b, &a, sizeof(BufferSlice));
    TCPIP2_EXPECT_EQ(a.Data(), b.Data());
    TCPIP2_EXPECT_EQ(a.Size(), b.Size());

    BufferView va(raw, 4);
    BufferView vb;
    std::memcpy(&vb, &va, sizeof(BufferView));
    TCPIP2_EXPECT_EQ(va.Data(), vb.Data());
    TCPIP2_EXPECT_EQ(va.Size(), vb.Size());
}

TCPIP2_TEST_MAIN();
