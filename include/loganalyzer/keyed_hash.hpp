#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <random>

namespace loganalyzer {
namespace detail {

// Hash-table keys that come from log text are attacker-controlled. std::hash<std::string> is no
// defense: MSVC's is unseeded FNV-1a with a power-of-two bucket mask, so a few hundred KB of
// crafted text pile every key into one bucket and turn each insert and lookup quadratic. A keyed
// hash fixes that: without the key nobody can predict which strings collide. Every hash table
// that is keyed by log text uses siphash24 with a random per-table key from fresh_hash_keys().

// SipHash-2-4 (Aumasson & Bernstein, 2012), a keyed 64-bit hash. Written from the paper and
// checked against its published test vectors.
constexpr std::uint64_t rotl64(std::uint64_t x, unsigned bits) noexcept { return (x << bits) | (x >> (64 - bits)); }

inline std::uint64_t siphash24(std::uint64_t key0, std::uint64_t key1, const char* data, std::size_t length) noexcept {
    std::uint64_t v0 = key0 ^ 0x736f6d6570736575ULL;
    std::uint64_t v1 = key1 ^ 0x646f72616e646f6dULL;
    std::uint64_t v2 = key0 ^ 0x6c7967656e657261ULL;
    std::uint64_t v3 = key1 ^ 0x7465646279746573ULL;
    const auto sip_round = [&]() noexcept {
        v0 += v1;
        v1 = rotl64(v1, 13);
        v1 ^= v0;
        v0 = rotl64(v0, 32);
        v2 += v3;
        v3 = rotl64(v3, 16);
        v3 ^= v2;
        v0 += v3;
        v3 = rotl64(v3, 21);
        v3 ^= v0;
        v2 += v1;
        v1 = rotl64(v1, 17);
        v1 ^= v2;
        v2 = rotl64(v2, 32);
    };

    const auto* bytes = reinterpret_cast<const unsigned char*>(data);
    const std::size_t whole = length - length % 8;
    for (std::size_t i = 0; i < whole; i += 8) {
        std::uint64_t block = 0;  // little-endian, whatever the host byte order
        for (std::size_t b = 0; b < 8; ++b) block |= std::uint64_t{bytes[i + b]} << (8 * b);
        v3 ^= block;
        sip_round();
        sip_round();
        v0 ^= block;
    }
    std::uint64_t last = static_cast<std::uint64_t>(length & 0xff) << 56;
    for (std::size_t b = 0; b < length % 8; ++b) last |= std::uint64_t{bytes[whole + b]} << (8 * b);
    v3 ^= last;
    sip_round();
    sip_round();
    v0 ^= last;
    v2 ^= 0xff;
    sip_round();
    sip_round();
    sip_round();
    sip_round();
    return v0 ^ v1 ^ v2 ^ v3;
}

// splitmix64's finalizer: spreads a few weak entropy sources over all 64 bits.
constexpr std::uint64_t mix64(std::uint64_t x) noexcept {
    x += 0x9e3779b97f4a7c15ULL;
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
    x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
    return x ^ (x >> 31);
}

/// The 128-bit key of one hash table.
struct HashKeys {
    std::uint64_t key0 = 0;
    std::uint64_t key1 = 0;
};

/// A new random key for every call (OS entropy when available; otherwise the clock, a stack
/// address and a process-wide counter, which still differ per call and are hard to predict).
inline HashKeys fresh_hash_keys() {
    static std::atomic<std::uint64_t> counter{0};
    std::uint64_t entropy[2] = {0, 0};
    try {
        std::random_device device;
        for (std::uint64_t& word : entropy) word = (std::uint64_t{device()} << 32) ^ device();
    } catch (...) {
        // No entropy source: fall through to the weaker sources below.
    }
    const std::uint64_t unique = counter.fetch_add(1, std::memory_order_relaxed);
    const auto clock = static_cast<std::uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count());
    const auto address = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(&unique));
    HashKeys keys;
    keys.key0 = mix64(entropy[0] ^ mix64(clock) ^ unique);
    keys.key1 = mix64(entropy[1] ^ mix64(address ^ mix64(unique)));
    return keys;
}

}  // namespace detail
}  // namespace loganalyzer
