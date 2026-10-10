#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "loganalyzer/level.hpp"
#include "loganalyzer/log_entry.hpp"

namespace loganalyzer {

// ---------------------------------------------------------------------------
// Portable pseudo-random numbers.
//
// <random> distributions are implementation-defined, so the same seed gives different
// numbers on MSVC, libstdc++ and libc++. These two generators are fully specified
// integer arithmetic (wrapping uint64), identical everywhere.
// ---------------------------------------------------------------------------

/// splitmix64 (Vigna). Used to expand one 64-bit seed into xoshiro's 256-bit state.
class SplitMix64 {
public:
    explicit constexpr SplitMix64(std::uint64_t seed) noexcept : state_(seed) {}

    constexpr std::uint64_t next() noexcept {
        state_ += 0x9E3779B97F4A7C15ULL;
        std::uint64_t z = state_;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        return z ^ (z >> 31);
    }

private:
    std::uint64_t state_;
};

/// xoshiro256** (Blackman & Vigna): 256-bit state, period 2^256 - 1, ~1 ns per number.
/// The state is never all zero: splitmix64 is a bijection on its counter, so at most one
/// of four consecutive outputs can be 0.
class Xoshiro256 {
public:
    explicit constexpr Xoshiro256(std::uint64_t seed) noexcept : s_{0, 0, 0, 0} {
        SplitMix64 expander(seed);
        for (std::uint64_t& word : s_) word = expander.next();
    }

    constexpr std::uint64_t next() noexcept {
        const std::uint64_t result = rotl(s_[1] * 5, 7) * 9;
        const std::uint64_t t = s_[1] << 17;
        s_[2] ^= s_[0];
        s_[3] ^= s_[1];
        s_[1] ^= s_[2];
        s_[0] ^= s_[3];
        s_[2] ^= t;
        s_[3] = rotl(s_[3], 45);
        return result;
    }

    /// Uniform integer in [0, bound), exactly unbiased (Lemire's multiply-shift with
    /// rejection; the division only runs in the rare case a draw lands in the biased zone).
    /// bound == 0 returns 0.
    constexpr std::uint32_t below(std::uint32_t bound) noexcept {
        std::uint64_t product = static_cast<std::uint64_t>(next32()) * bound;
        std::uint32_t low = static_cast<std::uint32_t>(product);
        if (low < bound) {
            const std::uint32_t threshold = (0u - bound) % bound;  // 2^32 mod bound
            while (low < threshold) {
                product = static_cast<std::uint64_t>(next32()) * bound;
                low = static_cast<std::uint32_t>(product);
            }
        }
        return static_cast<std::uint32_t>(product >> 32);
    }

    /// Uniform in [0, 2^53): the exact-integer way to get a double-precision uniform draw
    /// without ever converting to floating point.
    constexpr std::uint64_t next53() noexcept { return next() >> 11; }

private:
    static constexpr std::uint64_t rotl(std::uint64_t x, int k) noexcept {
        return (x << k) | (x >> (64 - k));
    }
    constexpr std::uint32_t next32() noexcept { return static_cast<std::uint32_t>(next() >> 32); }

    std::uint64_t s_[4];
};

// ---------------------------------------------------------------------------
// Deterministic log generator
// ---------------------------------------------------------------------------

struct GeneratorConfig {
    std::uint64_t seed = 42;
    std::vector<std::string> services = {"auth-service", "payment-service", "order-service",
                                         "inventory-service", "notification-service"};
    std::int64_t start_ms = 1791590400000;  ///< 2026-10-10T00:00:00Z
    std::int64_t mean_gap_ms = 50;
    double error_rate = 0.05;
    double warn_rate = 0.10;
    double debug_rate = 0.15;  ///< the remainder (1 - error - warn - debug) is INFO
};

/// Produces reproducible, realistic per-service log streams (the input to the k-way merge,
/// Top-K signature and search modules, and the 1M-entry benchmarks).
///
/// Determinism: output depends only on the config. It is byte-for-byte identical on every
/// platform and compiler (own PRNG, integer arithmetic, no <random>, no locale), and a
/// different seed gives a different output.
///
/// Streams. Service i owns an independent PRNG stream seeded from (seed, i) and its own
/// clock. generate_service() CONTINUES that service's stream where the previous call
/// stopped, so splitting a run into batches does not change the data:
/// generate_service(i, 100) followed by generate_service(i, 50) returns the same 150
/// entries as one generate_service(i, 150), and generate_all() equals calling
/// generate_service for every index in any order. Services never influence each other.
/// Construct a new LogGenerator to restart from the beginning.
///
/// Time. The first entry of a stream is stamped exactly start_ms; every next entry adds a
/// gap drawn uniformly from the integers [0, 2 * mean_gap_ms], so the mean gap is
/// mean_gap_ms, timestamps are non-decreasing and ties (gap 0) do occur - including between
/// services at start_ms, which is what exercises the merge module's tie-breaking.
///
/// Levels. Each entry is ERROR with probability error_rate, WARN with warn_rate, DEBUG with
/// debug_rate and INFO otherwise. The rates are converted to exact 2^-53 integer
/// thresholds, so level choice involves no floating-point comparison.
///
/// Messages. Each level of each service has a pool of templates (the texts are listed in
/// src/log_generator.cpp and available at run time from message_templates()). A template
/// is literal text with {placeholders} filled from the PRNG, so the same KIND of message
/// has many distinct concrete texts:
///
///   {ms}    duration, integer 1..30000          "after 3000ms"
///   {n}     count / code, integer 1..999
///   {id}    entity id, integer 1000..999999999
///   {ip}    IPv4 with port                      "10.0.12.7:5432"
///   {hex}   32-bit hex id, "0x" + 8 lower-case digits   "0x7f3a9c21"
///   {uuid}  random (version 4) UUID, lower case         "3b241101-e2bb-4255-8caf-4136c566a962"
///
/// Template literals never contain digits, so after replacing numbers / IPs / hex ids /
/// UUIDs by tokens, every message of one template normalizes to the same signature.
/// Templates within a pool are ranked and chosen with Zipf-like weights: rank k (0-based)
/// has probability proportional to 1/(k+1), so the first ERROR template accounts for about a
/// third of all errors and the Top-K over error signatures is interesting. Every service has
/// 10 ERROR templates (at least 8 distinct signatures), and 4-5 each for WARN / INFO / DEBUG.
/// Messages never contain '\n' or '\r'.
///
/// Not thread safe (generate_* mutate the stream state).
class LogGenerator {
public:
    /// Throws std::invalid_argument if: the service list is empty or has an empty name or a
    /// name containing whitespace (it could not be parsed back); a rate is negative or NaN;
    /// the three rates sum to more than 1 (1e-9 tolerance for rounding); mean_gap_ms is
    /// negative or above 1e9; or start_ms is outside +/- 2^62 (timestamps could overflow).
    explicit LogGenerator(GeneratorConfig config = {});

    const GeneratorConfig& config() const noexcept { return config_; }

    /// Next `count` entries of service `service_index`, in timestamp order, with
    /// entry.service == config().services[service_index]. Throws std::out_of_range for a
    /// bad index.
    std::vector<LogEntry> generate_service(std::size_t service_index, std::size_t count);

    /// Next `count_per_service` entries of every service; result[i] is service i's stream.
    std::vector<std::vector<LogEntry>> generate_all(std::size_t count_per_service);

    /// The template texts (with {placeholders}) the service uses for `level`, most frequent
    /// first. Throws std::out_of_range for a bad index. The views point to static storage.
    std::vector<std::string_view> message_templates(std::size_t service_index, Level level) const;

private:
    struct Stream {
        Xoshiro256 rng;
        std::int64_t next_timestamp_ms;
        std::size_t catalog_index;  ///< which template set this service uses
    };

    GeneratorConfig config_;
    // Level thresholds on a uniform draw in [0, 2^53): [0, error) ERROR, then WARN, then DEBUG.
    std::uint64_t error_cut_ = 0;
    std::uint64_t warn_cut_ = 0;
    std::uint64_t debug_cut_ = 0;
    std::vector<Stream> streams_;
};

}  // namespace loganalyzer
