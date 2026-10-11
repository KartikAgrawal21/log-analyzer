#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "loganalyzer/hash.hpp"
#include "testkit.hpp"

using loganalyzer::hash64;
using loganalyzer::mix64;

namespace {

int popcount64(std::uint64_t x) {
    int n = 0;
    while (x != 0) {
        x &= x - 1;
        ++n;
    }
    return n;
}

std::string all_bytes() {
    std::string s;
    for (int i = 0; i < 256; ++i) s.push_back(static_cast<char>(i));
    return s;
}

}  // namespace

// Known answers computed independently with a ~20-line Python implementation of the same
// algorithm (MurmurHash64A: 64-bit little-endian words, multiplier 0xc6a4a7935bd1e995, shift 47).
// They pin the exact bits, so a change of platform, compiler or endianness cannot silently
// change every sketch built on this hash.
TEST(Hash, KnownAnswerVectors) {
    struct Vector {
        std::string data;
        std::uint64_t seed;
        std::uint64_t expected;
    };
    const std::vector<Vector> vectors = {
        {"", 0, 0x0000000000000000ULL},
        {"", 1, 0xc6a4a7935bd064dcULL},
        {"a", 0, 0x071717d2d36b6b11ULL},
        {"abc", 0, 0x9cc9c33498a95efbULL},
        {"abcdefg", 0, 0x241aa52b0a62005dULL},
        {"abcdefgh", 0, 0xafdb0257ff41aa98ULL},
        {"abcdefghi", 0, 0xc9b9d84356146ac2ULL},
        {"hello world", 0, 0xd3ba2368a832afceULL},
        {"hello world", 12345, 0x1de184f1bff87d0bULL},
        {"The quick brown fox jumps over the lazy dog", 0, 0x5589ca33042a861bULL},
        {all_bytes(), 0, 0xaeebf3780095c6c1ULL},
        {std::string(9, '\0'), 0, 0x16e52185673c1a24ULL},
        {"\xff\xfe\xfd", 7, 0x102f7c6cb64b2c8eULL},
        {"payment-service", 0xDEADBEEFCAFEBABEULL, 0x74fb6feb23680562ULL},
    };
    for (const Vector& v : vectors) {
        const std::uint64_t got = hash64(v.data, v.seed);
        if (got != v.expected) {
            throw testkit::Failure{"hash64 of a " + std::to_string(v.data.size()) + "-byte input with seed " +
                                   std::to_string(v.seed) + " does not match the reference"};
        }
    }
}

TEST(Hash, Mix64KnownAnswers) {
    CHECK_EQ(mix64(0), std::uint64_t{0xe220a8397b1dcdafULL});  // the well-known first splitmix64 output
    CHECK_EQ(mix64(1), std::uint64_t{0x910a2dec89025cc1ULL});
    CHECK_EQ(mix64(2), std::uint64_t{0x975835de1c9756ceULL});
    CHECK_EQ(mix64(0xFFFFFFFFFFFFFFFFULL), std::uint64_t{0xe4d971771b652c20ULL});
    CHECK_EQ(mix64(0x123456789ABCDEF0ULL), std::uint64_t{0x161922c645ce50e8ULL});
}

TEST(Hash, IsUsableInConstantExpressions) {
    static_assert(hash64("", 0) == 0, "empty input with seed 0 hashes to 0 (a property of the construction)");
    static_assert(hash64("a", 0) == 0x071717d2d36b6b11ULL, "constexpr evaluation matches the runtime result");
    static_assert(mix64(0) == 0xe220a8397b1dcdafULL, "mix64 is constexpr");
    CHECK(true);
}

TEST(Hash, IsDeterministicAndSeedsAreIndependent) {
    CHECK_EQ(hash64("payment-service"), hash64("payment-service"));
    int equal = 0;
    for (std::uint64_t seed = 1; seed <= 1000; ++seed) {
        if (hash64("payment-service", seed) == hash64("payment-service", seed + 1)) ++equal;
    }
    CHECK_EQ(equal, 0);
    CHECK(hash64("a") != hash64("b"));
    CHECK(hash64("ab") != hash64("ba"));
    CHECK(hash64(std::string("a\0b", 3)) != hash64("ab"));  // embedded NULs count
    CHECK(hash64(std::string(8, 'x')) != hash64(std::string(9, 'x')));
}

TEST(Hash, SingleBitFlipsChangeAboutHalfTheOutputBits) {
    std::uint64_t state = 99;
    std::uint64_t total_distance = 0;
    std::uint64_t trials = 0;
    int worst_low = 64, worst_high = 0;
    for (int round = 0; round < 400; ++round) {
        const std::size_t length = 1 + static_cast<std::size_t>(mix64(state++) % 40);
        std::string input;
        for (std::size_t i = 0; i < length; ++i) input.push_back(static_cast<char>(mix64(state++) & 0xFF));
        const std::uint64_t base = hash64(input);
        for (std::size_t bit = 0; bit < length * 8; bit += 3) {
            std::string flipped = input;
            flipped[bit / 8] = static_cast<char>(static_cast<unsigned char>(flipped[bit / 8]) ^ (1u << (bit % 8)));
            const int distance = popcount64(base ^ hash64(flipped));
            total_distance += static_cast<std::uint64_t>(distance);
            ++trials;
            worst_low = std::min(worst_low, distance);
            worst_high = std::max(worst_high, distance);
        }
    }
    const double mean = static_cast<double>(total_distance) / static_cast<double>(trials);
    CHECK(mean > 31.0 && mean < 33.0);  // ideal: 32
    CHECK(worst_low >= 8);              // no input pair leaves most bits unchanged
    CHECK(worst_high <= 56);
}

namespace {

double chi_square(const std::vector<std::uint64_t>& hashes, int shift) {
    std::vector<double> bucket(256, 0.0);
    for (std::uint64_t h : hashes) bucket[(h >> shift) & 0xFF] += 1.0;
    const double expected = static_cast<double>(hashes.size()) / 256.0;
    double chi = 0.0;
    for (double b : bucket) chi += (b - expected) * (b - expected) / expected;
    return chi;  // ~ chi-square with 255 degrees of freedom: mean 255, sd about 22.6
}

}  // namespace

TEST(Hash, EveryByteOfTheOutputIsUniformOnSequentialKeys) {
    std::vector<std::uint64_t> hashes;
    for (int i = 0; i < 200000; ++i) hashes.push_back(hash64("key" + std::to_string(i)));
    for (int shift = 0; shift < 64; shift += 8) {
        const double chi = chi_square(hashes, shift);
        if (!(chi > 180.0 && chi < 340.0)) {
            throw testkit::Failure{"output byte " + std::to_string(shift / 8) + " is not uniform: chi-square " +
                                   std::to_string(chi) + " (expected about 255)"};
        }
    }
}

TEST(Hash, NoCollisionsAmongAMillionDistinctKeys) {
    std::vector<std::uint64_t> hashes;
    hashes.reserve(1'000'000);
    for (int i = 0; i < 1'000'000; ++i) hashes.push_back(hash64(std::to_string(i)));
    std::sort(hashes.begin(), hashes.end());
    CHECK(std::adjacent_find(hashes.begin(), hashes.end()) == hashes.end());
}

TEST(Hash, LeadingZeroCountsFollowAGeometricDistribution) {
    // HyperLogLog depends on this: P(top bits are k zeros then a one) = 2^-(k+1).
    std::vector<int> count(65, 0);
    const int n = 400000;
    for (int i = 0; i < n; ++i) {
        const std::uint64_t h = hash64("user-" + std::to_string(i));
        int zeros = 0;
        while (zeros < 64 && ((h >> (63 - zeros)) & 1) == 0) ++zeros;
        ++count[static_cast<std::size_t>(zeros)];
    }
    for (int k = 0; k < 8; ++k) {
        const double expected = static_cast<double>(n) / static_cast<double>(1 << (k + 1));
        const double sd = std::sqrt(expected);
        if (std::abs(static_cast<double>(count[static_cast<std::size_t>(k)]) - expected) > 5.0 * sd) {
            throw testkit::Failure{"leading-zero count " + std::to_string(k) + " is off: got " +
                                   std::to_string(count[static_cast<std::size_t>(k)]) + ", expected about " +
                                   std::to_string(expected)};
        }
    }
}
