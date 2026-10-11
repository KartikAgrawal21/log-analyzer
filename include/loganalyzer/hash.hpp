#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace loganalyzer {

/// splitmix64 finalizer: a bijection on 64-bit integers with strong avalanche (every input
/// bit flips about half of the output bits). Handy to turn a counter or a weak hash into a
/// well-mixed one, and to derive several independent-looking hashes from one.
constexpr std::uint64_t mix64(std::uint64_t x) noexcept {
    x += 0x9e3779b97f4a7c15ULL;
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
    x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
    return x ^ (x >> 31);
}

/// 64-bit non-cryptographic hash of a byte string (the MurmurHash64A construction, written
/// here from scratch): eight bytes per step through a multiply / xor-shift / multiply round,
/// then the 1-7 byte tail, then a final avalanche.
///
/// Properties the sketches rely on:
///  - deterministic and identical on every platform and compiler: the input is read as
///    little-endian words assembled byte by byte (no unaligned loads, no host endianness),
///    never through std::hash (whose values are implementation-defined and may differ per run);
///  - every output bit, high and low, is well distributed (HyperLogLog counts leading zeros
///    of the high bits and picks a register from the low bits; Count-Min slices the word into
///    several indices), so no bit position needs to be mixed again by callers;
///  - `seed` gives independent hash functions: hash64(x, s1) and hash64(x, s2) are unrelated.
///
/// Not collision-resistant and not secure: an adversary who knows the seed can build
/// collisions. Do not use it to hash untrusted keys into a table whose behaviour matters for
/// safety; for statistics over log text it is exactly what is needed.
constexpr std::uint64_t hash64(std::string_view data, std::uint64_t seed = 0) noexcept {
    constexpr std::uint64_t kMul = 0xc6a4a7935bd1e995ULL;
    constexpr int kShift = 47;

    std::uint64_t h = seed ^ (static_cast<std::uint64_t>(data.size()) * kMul);
    std::size_t i = 0;
    for (; i + 8 <= data.size(); i += 8) {
        std::uint64_t k = 0;
        for (int b = 7; b >= 0; --b) k = (k << 8) | static_cast<unsigned char>(data[i + static_cast<std::size_t>(b)]);
        k *= kMul;
        k ^= k >> kShift;
        k *= kMul;
        h ^= k;
        h *= kMul;
    }
    const std::size_t tail = data.size() - i;
    if (tail != 0) {
        for (std::size_t b = tail; b > 0; --b) {
            h ^= static_cast<std::uint64_t>(static_cast<unsigned char>(data[i + b - 1])) << (8 * (b - 1));
        }
        h *= kMul;
    }
    h ^= h >> kShift;
    h *= kMul;
    h ^= h >> kShift;
    return h;
}

}  // namespace loganalyzer
