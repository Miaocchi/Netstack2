/**
 * @file buffer.cpp
 * @brief Compile-time ownership contract for the buffer types.
 * @license GPL-3.0
 *
 * These static_asserts make the ownership model a build-time contract: the
 * library itself fails to compile if a change breaks move-only BufferLease,
 * trivially copyable views, or the fixed standard layout of PktBuffer.
 */

#include <tcpip2/buffer.h>
#include <tcpip2/transport_session.h>

#include <type_traits>

namespace tcpip2 {

static_assert(std::is_move_constructible_v<BufferLease>, "BufferLease must be move constructible");
static_assert(!std::is_copy_constructible_v<BufferLease>, "BufferLease must be move-only (unique ownership)");
static_assert(!std::is_copy_assignable_v<BufferLease>, "BufferLease must be move-only (unique ownership)");
static_assert(std::is_nothrow_move_constructible_v<BufferLease>, "BufferLease move construction must not throw");
static_assert(std::is_trivially_copyable_v<BufferSlice>, "BufferSlice must be a trivially copyable view");
static_assert(std::is_trivially_copyable_v<BufferView>, "BufferView must be a trivially copyable view");
static_assert(std::is_standard_layout_v<PktBuffer>, "PktBuffer must keep a fixed standard layout");
static_assert(std::is_trivially_destructible_v<PktBuffer>, "PktBuffer must be trivially destructible");
static_assert(std::is_copy_constructible_v<BufferRef>, "BufferRef must be copyable (RAII retain count)");
static_assert(std::is_move_constructible_v<BufferRef>, "BufferRef must be move constructible");

} // namespace tcpip2
