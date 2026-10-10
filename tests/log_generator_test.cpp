#include <algorithm>
#include <cstddef>
#include <cmath>
#include <cstdint>
#include <iterator>
#include <limits>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#include "loganalyzer/log_generator.hpp"
#include "loganalyzer/log_parser.hpp"
#include "testkit.hpp"

using namespace loganalyzer;

namespace {

const std::vector<std::string> kDefaultServices = {"auth-service", "payment-service", "order-service",
                                                   "inventory-service", "notification-service"};

// --- Template matcher ----------------------------------------------------------------
// Checks that a message is exactly a template with every {placeholder} replaced by a value
// of the documented shape and range. Every number matched is appended to `numbers`.

bool is_digit(char c) { return c >= '0' && c <= '9'; }
bool is_lower_hex(char c) { return is_digit(c) || (c >= 'a' && c <= 'f'); }

bool match_number(std::string_view m, std::size_t& pos, std::size_t min_digits, std::size_t max_digits,
                  std::uint64_t lo, std::uint64_t hi, std::vector<std::uint64_t>* numbers) {
    std::size_t n = 0;
    while (pos + n < m.size() && is_digit(m[pos + n])) ++n;
    if (n < min_digits || n > max_digits) return false;
    if (m[pos] == '0' && n > 1) return false;  // no leading zeros
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < n; ++i) v = v * 10 + static_cast<std::uint64_t>(m[pos + i] - '0');
    if (v < lo || v > hi) return false;
    pos += n;
    if (numbers != nullptr) numbers->push_back(v);
    return true;
}

bool match_char(std::string_view m, std::size_t& pos, char c) {
    if (pos >= m.size() || m[pos] != c) return false;
    ++pos;
    return true;
}

bool match_param(std::string_view kind, std::string_view m, std::size_t& pos, std::vector<std::uint64_t>* numbers) {
    if (kind == "ms") return match_number(m, pos, 1, 5, 1, 30000, numbers);
    if (kind == "n") return match_number(m, pos, 1, 3, 1, 999, numbers);
    if (kind == "id") return match_number(m, pos, 4, 9, 1000, 999999999, numbers);
    if (kind == "ip") {
        if (!match_char(m, pos, '1') || !match_char(m, pos, '0') || !match_char(m, pos, '.')) return false;
        if (!match_number(m, pos, 1, 3, 0, 255, numbers) || !match_char(m, pos, '.')) return false;
        if (!match_number(m, pos, 1, 3, 0, 255, numbers) || !match_char(m, pos, '.')) return false;
        if (!match_number(m, pos, 1, 3, 1, 254, numbers) || !match_char(m, pos, ':')) return false;
        std::vector<std::uint64_t> port;
        if (!match_number(m, pos, 2, 5, 80, 27017, &port)) return false;
        static const std::set<std::uint64_t> kPorts = {80, 443, 3306, 5432, 6379, 8080, 9092, 27017};
        if (kPorts.count(port[0]) == 0) return false;
        if (numbers != nullptr) numbers->push_back(port[0]);
        return true;
    }
    if (kind == "hex") {
        if (!match_char(m, pos, '0') || !match_char(m, pos, 'x')) return false;
        for (int i = 0; i < 8; ++i) {
            if (pos >= m.size() || !is_lower_hex(m[pos])) return false;
            ++pos;
        }
        return true;
    }
    if (kind == "uuid") {
        if (pos + 36 > m.size()) return false;
        for (std::size_t i = 0; i < 36; ++i) {
            const char c = m[pos + i];
            if (i == 8 || i == 13 || i == 18 || i == 23) {
                if (c != '-') return false;
            } else if (!is_lower_hex(c)) {
                return false;
            }
        }
        if (m[pos + 14] != '4') return false;                                     // version 4
        if (m[pos + 19] != '8' && m[pos + 19] != '9' && m[pos + 19] != 'a' && m[pos + 19] != 'b') return false;  // variant
        pos += 36;
        return true;
    }
    return false;
}

bool template_matches(std::string_view tmpl, std::string_view message, std::vector<std::uint64_t>* numbers = nullptr) {
    std::size_t t = 0;
    std::size_t pos = 0;
    while (t < tmpl.size()) {
        if (tmpl[t] == '{') {
            const std::size_t close = tmpl.find('}', t);
            if (close == std::string_view::npos) return false;
            if (!match_param(tmpl.substr(t + 1, close - t - 1), message, pos, numbers)) return false;
            t = close + 1;
        } else {
            if (!match_char(message, pos, tmpl[t])) return false;
            ++t;
        }
    }
    return pos == message.size();
}

// Index of the single template that matches, or -1 when none (or more than one) does.
int matching_rank(const std::vector<std::string_view>& templates, std::string_view message,
                  std::vector<std::uint64_t>* numbers = nullptr) {
    int found = -1;
    for (std::size_t i = 0; i < templates.size(); ++i) {
        std::vector<std::uint64_t> local;
        if (template_matches(templates[i], message, &local)) {
            if (found != -1) return -1;
            found = static_cast<int>(i);
            if (numbers != nullptr) *numbers = local;
        }
    }
    return found;
}

GeneratorConfig only_level(Level level) {
    GeneratorConfig c;
    c.error_rate = level == Level::Error ? 1.0 : 0.0;
    c.warn_rate = level == Level::Warn ? 1.0 : 0.0;
    c.debug_rate = level == Level::Debug ? 1.0 : 0.0;
    return c;
}

std::uint64_t fnv1a_of_lines(const std::vector<LogEntry>& entries) {
    std::uint64_t h = 0xcbf29ce484222325ULL;
    for (const LogEntry& e : entries) {
        std::string line = format_entry(e);
        line.push_back('\n');
        for (char c : line) {
            h ^= static_cast<unsigned char>(c);
            h *= 0x100000001b3ULL;
        }
    }
    return h;
}

bool same_stream_ignoring_service(const std::vector<LogEntry>& a, const std::vector<LogEntry>& b) {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (a[i].timestamp_ms != b[i].timestamp_ms || a[i].level != b[i].level || a[i].message != b[i].message) {
            return false;
        }
    }
    return true;
}

}  // namespace

// ---------------------------------------------------------------------------
// PRNG
// ---------------------------------------------------------------------------

TEST(LogGenerator, SplitMix64MatchesReferenceVectors) {
    // splitmix64(0) is the published reference sequence; seed 42 computed with an independent
    // Python implementation.
    SplitMix64 zero(0);
    CHECK_EQ(zero.next(), std::uint64_t{0xe220a8397b1dcdafULL});
    CHECK_EQ(zero.next(), std::uint64_t{0x6e789e6aa1b965f4ULL});
    CHECK_EQ(zero.next(), std::uint64_t{0x06c45d188009454fULL});
    CHECK_EQ(zero.next(), std::uint64_t{0xf88bb8a8724c81ecULL});
    SplitMix64 s42(42);
    CHECK_EQ(s42.next(), std::uint64_t{0xbdd732262feb6e95ULL});
    CHECK_EQ(s42.next(), std::uint64_t{0x28efe333b266f103ULL});
    CHECK_EQ(s42.next(), std::uint64_t{0x47526757130f9f52ULL});
}

TEST(LogGenerator, Xoshiro256MatchesIndependentImplementation) {
    Xoshiro256 zero(0);
    CHECK_EQ(zero.next(), std::uint64_t{0x99ec5f36cb75f2b4ULL});
    CHECK_EQ(zero.next(), std::uint64_t{0xbf6e1f784956452aULL});
    CHECK_EQ(zero.next(), std::uint64_t{0x1a5f849d4933e6e0ULL});
    Xoshiro256 s42(42);
    CHECK_EQ(s42.next(), std::uint64_t{0x15780b2e0c2ec716ULL});
    CHECK_EQ(s42.next(), std::uint64_t{0x6104d9866d113a7eULL});
    CHECK_EQ(s42.next(), std::uint64_t{0xae17533239e499a1ULL});
    CHECK_EQ(s42.next(), std::uint64_t{0xecb8ad4703b360a1ULL});
    CHECK_EQ(s42.next(), std::uint64_t{0xfde6dc7fe2ec5e64ULL});
}

TEST(LogGenerator, BoundedDrawsMatchIndependentImplementation) {
    Xoshiro256 a(42);
    const std::uint32_t expected_a[] = {83, 378, 680, 924, 991, 769, 719, 850};
    for (std::uint32_t v : expected_a) CHECK_EQ(a.below(1000), v);
    Xoshiro256 b(7);
    const std::uint32_t expected_b[] = {70, 28, 84, 99, 100, 88, 6, 10};
    for (std::uint32_t v : expected_b) CHECK_EQ(b.below(101), v);
    Xoshiro256 c(123456789);
    const std::uint32_t expected_c[] = {2460142322u, 246274658u, 1602509380u, 2602255423u};
    for (std::uint32_t v : expected_c) CHECK_EQ(c.below(3000000000u), v);  // bound > 2^31
    Xoshiro256 d(5);
    const std::uint64_t expected_d[] = {2597777399433881ULL, 5423075542279364ULL, 5850596827338615ULL};
    for (std::uint64_t v : expected_d) CHECK_EQ(d.next53(), v);
}

TEST(LogGenerator, BoundedDrawsStayInRangeAndAreUniform) {
    Xoshiro256 rng(2024);
    for (int i = 0; i < 1000; ++i) {
        CHECK_EQ(rng.below(1), 0u);
        CHECK_EQ(rng.below(0), 0u);
    }
    std::uint32_t counts[6] = {0, 0, 0, 0, 0, 0};
    for (int i = 0; i < 600000; ++i) {
        const std::uint32_t v = rng.below(6);
        CHECK(v < 6);
        ++counts[v];
    }
    for (std::uint32_t c : counts) CHECK(c > 98000 && c < 102000);  // expected 100000, sigma ~ 290
    for (int i = 0; i < 100000; ++i) {
        CHECK(rng.below(2000000001u) < 2000000001u);
        CHECK(rng.next53() < (std::uint64_t{1} << 53));
    }
}

// ---------------------------------------------------------------------------
// Config validation
// ---------------------------------------------------------------------------

TEST(LogGenerator, DefaultConfigMatchesTheSpecification) {
    const GeneratorConfig c;
    CHECK_EQ(c.seed, std::uint64_t{42});
    CHECK(c.services == kDefaultServices);
    CHECK_EQ(c.start_ms, std::int64_t{1791590400000});
    CHECK_EQ(format_iso8601_utc(c.start_ms), std::string("2026-10-10T00:00:00.000Z"));
    CHECK_EQ(c.mean_gap_ms, std::int64_t{50});
    CHECK_EQ(c.error_rate, 0.05);
    CHECK_EQ(c.warn_rate, 0.10);
    CHECK_EQ(c.debug_rate, 0.15);
    const LogGenerator g;
    CHECK(g.config().services == kDefaultServices);
    CHECK_EQ(g.config().seed, std::uint64_t{42});
}

TEST(LogGenerator, ConfigAccessorReturnsTheGivenConfig) {
    GeneratorConfig c;
    c.seed = 99;
    c.services = {"a", "b"};
    c.start_ms = 5;
    c.mean_gap_ms = 7;
    c.error_rate = 0.2;
    const LogGenerator g(c);
    CHECK_EQ(g.config().seed, std::uint64_t{99});
    CHECK((g.config().services == std::vector<std::string>{"a", "b"}));
    CHECK_EQ(g.config().start_ms, std::int64_t{5});
    CHECK_EQ(g.config().mean_gap_ms, std::int64_t{7});
    CHECK_EQ(g.config().error_rate, 0.2);
}

TEST(LogGenerator, RejectsInvalidConfigs) {
    {
        GeneratorConfig c;
        c.services.clear();
        CHECK_THROWS(LogGenerator(c), std::invalid_argument);
    }
    {
        GeneratorConfig c;
        c.error_rate = -0.01;
        CHECK_THROWS(LogGenerator(c), std::invalid_argument);
    }
    {
        GeneratorConfig c;
        c.warn_rate = -0.5;
        CHECK_THROWS(LogGenerator(c), std::invalid_argument);
    }
    {
        GeneratorConfig c;
        c.debug_rate = -1e-12;
        CHECK_THROWS(LogGenerator(c), std::invalid_argument);
    }
    {
        GeneratorConfig c;
        c.error_rate = 0.5;
        c.warn_rate = 0.5;
        c.debug_rate = 0.5;  // sums to 1.5
        CHECK_THROWS(LogGenerator(c), std::invalid_argument);
    }
    {
        GeneratorConfig c;
        c.error_rate = 1.0;
        c.warn_rate = 0.0;
        c.debug_rate = 0.001;  // just over 1
        CHECK_THROWS(LogGenerator(c), std::invalid_argument);
    }
    {
        GeneratorConfig c;
        c.error_rate = 2.0;
        c.warn_rate = 0.0;
        c.debug_rate = 0.0;
        CHECK_THROWS(LogGenerator(c), std::invalid_argument);
    }
    {
        GeneratorConfig c;
        const double nan = std::numeric_limits<double>::quiet_NaN();
        c.warn_rate = nan;
        CHECK_THROWS(LogGenerator(c), std::invalid_argument);
    }
    {
        GeneratorConfig c;
        c.mean_gap_ms = -1;
        CHECK_THROWS(LogGenerator(c), std::invalid_argument);
    }
    {
        GeneratorConfig c;
        c.mean_gap_ms = 2'000'000'000;  // would overflow the 32-bit gap draw
        CHECK_THROWS(LogGenerator(c), std::invalid_argument);
    }
    {
        GeneratorConfig c;
        c.services = {"ok", ""};
        CHECK_THROWS(LogGenerator(c), std::invalid_argument);
    }
    {
        GeneratorConfig c;
        c.services = {"has space"};
        CHECK_THROWS(LogGenerator(c), std::invalid_argument);
    }
    {
        GeneratorConfig c;
        c.start_ms = INT64_MAX;
        CHECK_THROWS(LogGenerator(c), std::invalid_argument);
    }
}

TEST(LogGenerator, AcceptsBoundaryConfigs) {
    for (const std::vector<double>& r : std::vector<std::vector<double>>{
             {0.0, 0.0, 0.0}, {1.0, 0.0, 0.0}, {0.0, 1.0, 0.0}, {0.0, 0.0, 1.0}, {0.5, 0.3, 0.2},
             {0.1, 0.2, 0.7}, {0.7, 0.2, 0.1}, {1.0 / 3, 1.0 / 3, 1.0 / 3}, {0.05, 0.10, 0.15}}) {
        GeneratorConfig c;
        c.error_rate = r[0];
        c.warn_rate = r[1];
        c.debug_rate = r[2];
        LogGenerator g(c);
        CHECK_EQ(g.generate_service(0, 100).size(), std::size_t{100});
    }
    GeneratorConfig c;
    c.mean_gap_ms = 0;
    CHECK_EQ(LogGenerator(c).generate_service(0, 3).size(), std::size_t{3});
    c.mean_gap_ms = 1'000'000'000;
    CHECK_EQ(LogGenerator(c).generate_service(0, 3).size(), std::size_t{3});
    c.mean_gap_ms = 50;
    c.start_ms = 0;
    const auto from_zero = LogGenerator(c).generate_service(0, 3);
    CHECK_EQ(from_zero.front().timestamp_ms, std::int64_t{0});
    c.services = {"only-one"};
    CHECK_EQ(LogGenerator(c).generate_all(4).size(), std::size_t{1});
}

TEST(LogGenerator, BadServiceIndexThrowsOutOfRange) {
    LogGenerator g;
    CHECK_THROWS(g.generate_service(5, 10), std::out_of_range);
    CHECK_THROWS(g.generate_service(100, 10), std::out_of_range);
    CHECK_THROWS(g.generate_service(static_cast<std::size_t>(-1), 0), std::out_of_range);
    CHECK_THROWS(g.message_templates(5, Level::Error), std::out_of_range);
    CHECK_THROWS(g.message_templates(0, static_cast<Level>(9)), std::invalid_argument);
    // valid indices keep working afterwards
    CHECK_EQ(g.generate_service(4, 1).size(), std::size_t{1});
}

// ---------------------------------------------------------------------------
// Determinism and stream structure
// ---------------------------------------------------------------------------

TEST(LogGenerator, SameConfigGivesIdenticalOutput) {
    LogGenerator a;
    LogGenerator b;
    const auto sa = a.generate_all(2000);
    const auto sb = b.generate_all(2000);
    CHECK(sa == sb);
    CHECK_EQ(sa.size(), std::size_t{5});

    GeneratorConfig custom;
    custom.seed = 123456789;
    custom.services = {"x", "y", "z"};
    custom.mean_gap_ms = 7;
    CHECK(LogGenerator(custom).generate_all(500) == LogGenerator(custom).generate_all(500));
}

TEST(LogGenerator, DifferentSeedGivesDifferentOutput) {
    GeneratorConfig c1;
    GeneratorConfig c2;
    c2.seed = 43;
    LogGenerator a(c1);
    LogGenerator b(c2);
    for (std::size_t s = 0; s < 5; ++s) {
        const auto x = a.generate_service(s, 500);
        const auto y = b.generate_service(s, 500);
        CHECK(!same_stream_ignoring_service(x, y));
        std::size_t equal_messages = 0;
        for (std::size_t i = 0; i < x.size(); ++i) equal_messages += x[i].message == y[i].message ? 1 : 0;
        CHECK(equal_messages < 50);  // parameters differ even when the same template is chosen
    }
}

TEST(LogGenerator, EveryServiceHasItsOwnStream) {
    LogGenerator g;
    const auto streams = g.generate_all(500);
    for (std::size_t i = 0; i < streams.size(); ++i) {
        for (std::size_t j = i + 1; j < streams.size(); ++j) {
            CHECK(!same_stream_ignoring_service(streams[i], streams[j]));
        }
    }
    // Same service name twice: still independent streams (seeded by index).
    GeneratorConfig c;
    c.services = {"dup", "dup"};
    LogGenerator d(c);
    CHECK(d.generate_service(0, 200) != d.generate_service(1, 200));
}

TEST(LogGenerator, GenerateAllEqualsGenerateServiceInAnyOrder) {
    LogGenerator all_gen;
    const auto all = all_gen.generate_all(300);
    LogGenerator one_by_one;
    // reverse order: services must not influence each other
    std::vector<std::vector<LogEntry>> reversed(5);
    for (std::size_t i = 5; i-- > 0;) reversed[i] = one_by_one.generate_service(i, 300);
    CHECK(all == reversed);
}

TEST(LogGenerator, StreamContinuesAcrossCallsAndIsIndependentOfBatching) {
    LogGenerator whole;
    const auto full = whole.generate_service(2, 1500);

    LogGenerator batched;
    auto part = batched.generate_service(2, 100);
    for (std::size_t n : {std::size_t{0}, std::size_t{1}, std::size_t{399}, std::size_t{1000}}) {
        auto next = batched.generate_service(2, n);
        part.insert(part.end(), next.begin(), next.end());
    }
    CHECK_EQ(part.size(), full.size());
    CHECK(part == full);

    // Timestamps are non-decreasing across the batch boundary too.
    LogGenerator g;
    const auto first = g.generate_service(0, 50);
    const auto second = g.generate_service(0, 50);
    CHECK(second.front().timestamp_ms >= first.back().timestamp_ms);
    CHECK(first != second);
}

TEST(LogGenerator, CopiedGeneratorContinuesFromTheSameState) {
    LogGenerator a;
    (void)a.generate_service(1, 25);
    LogGenerator b = a;
    CHECK(a.generate_service(1, 40) == b.generate_service(1, 40));
}

TEST(LogGenerator, ZeroCountReturnsEmptyAndDoesNotAdvance) {
    LogGenerator a;
    CHECK(a.generate_service(3, 0).empty());
    LogGenerator b;
    CHECK(a.generate_service(3, 30) == b.generate_service(3, 30));
    CHECK(LogGenerator().generate_all(0).size() == 5);
    for (const auto& s : LogGenerator().generate_all(0)) CHECK(s.empty());
}

TEST(LogGenerator, EntriesCarryTheirServiceName) {
    LogGenerator g;
    const auto streams = g.generate_all(300);
    CHECK_EQ(streams.size(), kDefaultServices.size());
    for (std::size_t i = 0; i < streams.size(); ++i) {
        CHECK_EQ(streams[i].size(), std::size_t{300});
        for (const LogEntry& e : streams[i]) CHECK_EQ(e.service, kDefaultServices[i]);
    }
}

TEST(LogGenerator, TimestampsStartAtStartMsAndNeverDecrease) {
    LogGenerator g;
    for (const auto& stream : g.generate_all(20000)) {
        CHECK_EQ(stream.front().timestamp_ms, std::int64_t{1791590400000});
        for (std::size_t i = 1; i < stream.size(); ++i) {
            const std::int64_t gap = stream[i].timestamp_ms - stream[i - 1].timestamp_ms;
            CHECK(gap >= 0 && gap <= 100);  // [0, 2 * mean_gap_ms]
        }
    }
    GeneratorConfig c;
    c.start_ms = 1234567890123;
    const auto shifted = LogGenerator(c).generate_service(2, 5);
    CHECK_EQ(shifted.front().timestamp_ms, std::int64_t{1234567890123});
}

TEST(LogGenerator, GapsAreUniformOnZeroToTwiceTheMeanAndTiesOccur) {
    LogGenerator g;
    const std::size_t n = 100000;
    const auto stream = g.generate_service(0, n);
    std::int64_t zero_gaps = 0;
    std::int64_t min_gap = 1000;
    std::int64_t max_gap = -1;
    for (std::size_t i = 1; i < n; ++i) {
        const std::int64_t gap = stream[i].timestamp_ms - stream[i - 1].timestamp_ms;
        zero_gaps += gap == 0 ? 1 : 0;
        min_gap = std::min(min_gap, gap);
        max_gap = std::max(max_gap, gap);
    }
    const double mean = static_cast<double>(stream.back().timestamp_ms - stream.front().timestamp_ms) /
                        static_cast<double>(n - 1);
    CHECK(mean > 49.0 && mean < 51.0);
    CHECK_EQ(min_gap, std::int64_t{0});
    CHECK_EQ(max_gap, std::int64_t{100});
    CHECK(zero_gaps > 600 && zero_gaps < 1400);  // P(gap == 0) = 1/101, so about 990 ties
}

TEST(LogGenerator, MeanGapEdgeValues) {
    GeneratorConfig c;
    c.mean_gap_ms = 0;
    c.start_ms = 1000;
    for (const LogEntry& e : LogGenerator(c).generate_service(1, 500)) CHECK_EQ(e.timestamp_ms, std::int64_t{1000});

    c.mean_gap_ms = 1;
    const auto s = LogGenerator(c).generate_service(1, 3000);
    std::set<std::int64_t> gaps;
    for (std::size_t i = 1; i < s.size(); ++i) gaps.insert(s[i].timestamp_ms - s[i - 1].timestamp_ms);
    CHECK((gaps == std::set<std::int64_t>{0, 1, 2}));
}

TEST(LogGenerator, ServicesTieAtStartMsWhichExercisesMergeTieBreaking) {
    LogGenerator g;
    const auto streams = g.generate_all(10);
    for (const auto& s : streams) CHECK_EQ(s.front().timestamp_ms, g.config().start_ms);
}

// ---------------------------------------------------------------------------
// Levels
// ---------------------------------------------------------------------------

TEST(LogGenerator, LevelsFollowTheConfiguredRates) {
    LogGenerator g;
    const std::size_t n = 100000;
    const double total = static_cast<double>(n);
    for (std::size_t service = 0; service < 2; ++service) {
        const auto stream = g.generate_service(service, n);
        double counts[4] = {0, 0, 0, 0};
        for (const LogEntry& e : stream) counts[static_cast<int>(e.level)] += 1;
        CHECK(std::abs(counts[static_cast<int>(Level::Error)] / total - 0.05) < 0.005);
        CHECK(std::abs(counts[static_cast<int>(Level::Warn)] / total - 0.10) < 0.005);
        CHECK(std::abs(counts[static_cast<int>(Level::Debug)] / total - 0.15) < 0.005);
        CHECK(std::abs(counts[static_cast<int>(Level::Info)] / total - 0.70) < 0.005);
    }

    GeneratorConfig c;
    c.seed = 5;
    c.error_rate = 0.30;
    c.warn_rate = 0.20;
    c.debug_rate = 0.10;
    const auto stream = LogGenerator(c).generate_service(4, n);
    double counts[4] = {0, 0, 0, 0};
    for (const LogEntry& e : stream) counts[static_cast<int>(e.level)] += 1;
    CHECK(std::abs(counts[static_cast<int>(Level::Error)] / total - 0.30) < 0.007);
    CHECK(std::abs(counts[static_cast<int>(Level::Warn)] / total - 0.20) < 0.007);
    CHECK(std::abs(counts[static_cast<int>(Level::Debug)] / total - 0.10) < 0.007);
    CHECK(std::abs(counts[static_cast<int>(Level::Info)] / total - 0.40) < 0.007);
}

TEST(LogGenerator, DegenerateRatesProduceASingleLevel) {
    for (Level only : {Level::Error, Level::Warn, Level::Debug}) {
        for (const LogEntry& e : LogGenerator(only_level(only)).generate_service(0, 3000)) CHECK(e.level == only);
    }
    GeneratorConfig info_only;
    info_only.error_rate = info_only.warn_rate = info_only.debug_rate = 0.0;
    for (const LogEntry& e : LogGenerator(info_only).generate_service(0, 3000)) CHECK(e.level == Level::Info);
}

TEST(LogGenerator, RatesSummingToOneLeaveNoInfoBeyondRounding) {
    GeneratorConfig c;
    c.error_rate = 0.5;
    c.warn_rate = 0.3;
    c.debug_rate = 0.2;
    std::size_t info = 0;
    for (const LogEntry& e : LogGenerator(c).generate_service(0, 100000)) info += e.level == Level::Info ? 1 : 0;
    CHECK_EQ(info, std::size_t{0});
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

TEST(LogGenerator, EveryServiceHasAtLeastEightDistinctErrorTemplates) {
    LogGenerator g;
    std::vector<std::set<std::string>> per_service;
    for (std::size_t s = 0; s < 5; ++s) {
        const auto errors = g.message_templates(s, Level::Error);
        CHECK(errors.size() >= 8);
        const std::set<std::string> unique(errors.begin(), errors.end());
        CHECK_EQ(unique.size(), errors.size());
        per_service.push_back(unique);
        for (Level level : {Level::Warn, Level::Info, Level::Debug}) {
            const auto others = g.message_templates(s, level);
            CHECK(others.size() >= 3);
            const std::set<std::string> distinct(others.begin(), others.end());
            CHECK_EQ(distinct.size(), others.size());
        }
    }
    for (std::size_t i = 0; i < 5; ++i) {
        for (std::size_t j = i + 1; j < 5; ++j) {
            std::vector<std::string> shared;
            std::set_intersection(per_service[i].begin(), per_service[i].end(), per_service[j].begin(),
                                  per_service[j].end(), std::back_inserter(shared));
            CHECK(shared.empty());  // different services have different error vocabularies
        }
    }
}

TEST(LogGenerator, TemplateLiteralsContainNoDigitsOrLineBreaks) {
    // Guarantees that a normalizer replacing every number / ip / hex / uuid by a token maps
    // all messages of one template to one signature.
    LogGenerator g;
    for (std::size_t s = 0; s < 5; ++s) {
        for (Level level : {Level::Debug, Level::Info, Level::Warn, Level::Error}) {
            for (std::string_view t : g.message_templates(s, level)) {
                bool in_placeholder = false;
                for (char c : t) {
                    if (c == '{') in_placeholder = true;
                    else if (c == '}') in_placeholder = false;
                    else if (!in_placeholder) CHECK(!is_digit(c));
                    CHECK(c != '\n' && c != '\r');
                }
                CHECK(!in_placeholder);
            }
        }
    }
}

TEST(LogGenerator, ErrorTemplatesMixAllParameterKinds) {
    LogGenerator g;
    for (std::size_t s = 0; s < 5; ++s) {
        std::string all;
        for (std::string_view t : g.message_templates(s, Level::Error)) {
            all.append(t);
            all.push_back('\n');
        }
        for (const char* kind : {"{ms}", "{n}", "{id}", "{ip}", "{hex}", "{uuid}"}) {
            CHECK(all.find(kind) != std::string::npos);
        }
    }
}

TEST(LogGenerator, EveryMessageMatchesOneTemplateOfItsServiceAndLevel) {
    // Per level, a config that only emits that level, so every template of every pool is hit.
    for (Level level : {Level::Debug, Level::Info, Level::Warn, Level::Error}) {
        LogGenerator g(only_level(level));
        std::vector<std::vector<std::size_t>> hits(5);
        for (std::size_t s = 0; s < 5; ++s) {
            const auto templates = g.message_templates(s, level);
            hits[s].assign(templates.size(), 0);
            for (const LogEntry& e : g.generate_service(s, 30000)) {
                CHECK(e.level == level);
                CHECK(!e.message.empty());
                CHECK(e.message.find('\n') == std::string::npos);
                CHECK(e.message.find('\r') == std::string::npos);
                const int rank = matching_rank(templates, e.message);
                if (rank < 0) CHECK_EQ(e.message, std::string("<matches no unique template of its pool>"));
                ++hits[s][static_cast<std::size_t>(rank)];
            }
            for (std::size_t count : hits[s]) CHECK(count > 0);  // every template is reachable
        }
    }
}

TEST(LogGenerator, ErrorTemplatesAreChosenWithZipfWeights) {
    GeneratorConfig c = only_level(Level::Error);
    LogGenerator g(c);
    const auto templates = g.message_templates(0, Level::Error);
    const std::size_t n = 200000;
    const double total = static_cast<double>(n);
    std::vector<double> counts(templates.size(), 0.0);
    for (const LogEntry& e : g.generate_service(0, n)) {
        const int rank = matching_rank(templates, e.message);
        CHECK(rank >= 0);
        counts[static_cast<std::size_t>(rank)] += 1;
    }
    double harmonic = 0;
    for (std::size_t k = 0; k < templates.size(); ++k) harmonic += 1.0 / static_cast<double>(k + 1);
    for (std::size_t k = 0; k < templates.size(); ++k) {
        const double expected = 1.0 / static_cast<double>(k + 1) / harmonic;
        CHECK(std::abs(counts[k] / total - expected) < 0.006);
    }
    CHECK(counts[0] > counts[1] && counts[1] > counts[2] && counts[2] > counts[3]);
    CHECK(counts[0] / total > 0.30);                  // the head template is about a third of all errors
    CHECK(counts[0] > 8 * counts.back() * 0.9);   // and the tail is roughly 10x rarer
}

TEST(LogGenerator, SameKindOfErrorHasManyDistinctConcreteTexts) {
    LogGenerator g(only_level(Level::Error));
    const auto errors = g.generate_service(1, 5000);
    std::unordered_set<std::string> distinct;
    for (const LogEntry& e : errors) distinct.insert(e.message);
    CHECK(distinct.size() > 4500);
    CHECK(distinct.size() > 100 * g.message_templates(1, Level::Error).size());
}

TEST(LogGenerator, ParametersCoverTheirDocumentedRanges) {
    // payment-service's most frequent ERROR: "Timeout calling bank gateway {ip} after {ms}ms"
    LogGenerator g(only_level(Level::Error));
    const auto templates = g.message_templates(1, Level::Error);
    CHECK_EQ(std::string(templates[0]), std::string("Timeout calling bank gateway {ip} after {ms}ms"));
    std::set<std::uint64_t> ports;
    std::uint64_t min_ms = 1000000, max_ms = 0, min_a = 1000, max_a = 0, min_c = 1000, max_c = 0;
    std::size_t seen = 0;
    for (const LogEntry& e : g.generate_service(1, 100000)) {
        std::vector<std::uint64_t> numbers;
        if (matching_rank(templates, e.message, &numbers) != 0) continue;
        CHECK_EQ(numbers.size(), std::size_t{5});  // a, b, c, port, ms
        ++seen;
        min_a = std::min(min_a, numbers[0]);
        max_a = std::max(max_a, numbers[0]);
        min_c = std::min(min_c, numbers[2]);
        max_c = std::max(max_c, numbers[2]);
        ports.insert(numbers[3]);
        min_ms = std::min(min_ms, numbers[4]);
        max_ms = std::max(max_ms, numbers[4]);
    }
    CHECK(seen > 25000);
    CHECK_EQ(ports.size(), std::size_t{8});
    CHECK(min_ms <= 20 && max_ms >= 29980);
    CHECK(min_a <= 3 && max_a >= 252);
    CHECK(min_c >= 1 && min_c <= 4 && max_c >= 251 && max_c <= 254);
}

TEST(LogGenerator, UuidsAreVersion4WithAllFourVariantsAndNoRepeats) {
    // payment-service ERROR rank 2: "Payment {uuid} failed: insufficient funds"
    LogGenerator g(only_level(Level::Error));
    const auto templates = g.message_templates(1, Level::Error);
    CHECK_EQ(std::string(templates[2]), std::string("Payment {uuid} failed: insufficient funds"));
    std::set<char> variants;
    std::set<std::string> uuids;
    std::size_t seen = 0;
    for (const LogEntry& e : g.generate_service(1, 60000)) {
        if (e.message.compare(0, 8, "Payment ") != 0) continue;
        const std::string uuid = e.message.substr(8, 36);
        CHECK(template_matches("{uuid}", uuid));  // shape, version nibble, variant nibble
        variants.insert(uuid[19]);
        uuids.insert(uuid);
        ++seen;
    }
    CHECK(seen > 3000);
    CHECK((variants == std::set<char>{'8', '9', 'a', 'b'}));
    CHECK_EQ(uuids.size(), seen);
}

TEST(LogGenerator, FallbackCatalogsForCustomAndReorderedServices) {
    GeneratorConfig c;
    c.services = {"alpha", "beta", "payment-service", "auth-service"};
    LogGenerator custom(c);
    LogGenerator defaults;
    // unknown names fall back to catalog (index % 5); known names keep their own catalog
    CHECK(custom.message_templates(0, Level::Error) == defaults.message_templates(0, Level::Error));
    CHECK(custom.message_templates(1, Level::Error) == defaults.message_templates(1, Level::Error));
    CHECK(custom.message_templates(2, Level::Error) == defaults.message_templates(1, Level::Error));  // payment
    CHECK(custom.message_templates(3, Level::Warn) == defaults.message_templates(0, Level::Warn));    // auth
    const auto e = custom.generate_service(2, 200);
    for (const LogEntry& entry : e) {
        CHECK_EQ(entry.service, std::string("payment-service"));
        CHECK(matching_rank(custom.message_templates(2, entry.level), entry.message) >= 0);
    }
    // more services than catalogs
    GeneratorConfig many;
    many.services.clear();
    for (int i = 0; i < 12; ++i) many.services.push_back("svc-" + std::to_string(i));
    LogGenerator g(many);
    const auto all = g.generate_all(50);
    CHECK_EQ(all.size(), std::size_t{12});
    CHECK(g.message_templates(7, Level::Info) == defaults.message_templates(2, Level::Info));
}

// ---------------------------------------------------------------------------
// Interplay with the parser, and golden output
// ---------------------------------------------------------------------------

TEST(LogGenerator, GeneratedLinesRoundTripThroughTheParser) {
    LogGenerator g;
    const auto streams = g.generate_all(3000);
    std::string text;
    std::vector<LogEntry> flat;
    for (const auto& stream : streams) {
        for (const LogEntry& e : stream) {
            const std::string line = format_entry(e);
            const auto back = parse_line(line);
            CHECK(back.has_value());
            CHECK(*back == e);
            text += line;
            text += '\n';
            flat.push_back(e);
        }
    }
    std::istringstream in(text);
    std::size_t malformed = 1;
    const auto parsed = parse_stream(in, &malformed);
    CHECK_EQ(malformed, std::size_t{0});
    CHECK(parsed == flat);
}

// The expected values below come from an independent Python re-implementation of the whole
// pipeline (PRNG, level thresholds, Zipf template choice, parameter rendering). If these
// fail on another compiler or platform, the generator is not portable.
TEST(LogGenerator, GoldenOutputIsIdenticalOnEveryPlatform) {
    LogGenerator g;
    const auto s0 = g.generate_service(0, 2000);
    CHECK_EQ(format_entry(s0[0]), std::string("2026-10-10T00:00:00.000Z INFO auth-service User 447359880 logged out"));
    CHECK_EQ(format_entry(s0[1]),
             std::string("2026-10-10T00:00:00.010Z INFO auth-service User 286486971 logged in from 10.31.157.173:443"));
    CHECK_EQ(format_entry(s0[2]),
             std::string("2026-10-10T00:00:00.035Z DEBUG auth-service Cache lookup for session "
                         "b75b3f8d-1982-4ebc-9d80-b43a9a7e3e25 took 13169ms"));
    CHECK_EQ(fnv1a_of_lines(s0), std::uint64_t{0xd247978a6620996fULL});
    CHECK_EQ(fnv1a_of_lines(g.generate_service(3, 2000)), std::uint64_t{0x320e47a7da22b267ULL});

    GeneratorConfig c;
    c.seed = 7;
    c.services = {"auth-service", "payment-service"};
    c.start_ms = 0;
    c.mean_gap_ms = 3;
    c.error_rate = 0.3;
    c.warn_rate = 0.2;
    c.debug_rate = 0.1;
    LogGenerator custom(c);
    const auto s1 = custom.generate_service(1, 1500);
    CHECK_EQ(format_entry(s1[0]),
             std::string("1970-01-01T00:00:00.000Z ERROR payment-service Timeout calling bank gateway "
                         "10.37.120.175:8080 after 8676ms"));
    CHECK_EQ(fnv1a_of_lines(s1), std::uint64_t{0x8aa2b6da3ce167e1ULL});

    GeneratorConfig f;
    f.seed = 9;
    f.services = {"x-service", "payment-service", "y"};
    LogGenerator fallback(f);
    CHECK_EQ(fnv1a_of_lines(fallback.generate_service(0, 500)), std::uint64_t{0xa18fbbd92b7d98f6ULL});
    CHECK_EQ(fnv1a_of_lines(fallback.generate_service(1, 500)), std::uint64_t{0x0f08549248e2a690ULL});
    CHECK_EQ(fnv1a_of_lines(fallback.generate_service(2, 500)), std::uint64_t{0xb8d7959709d37feeULL});
}
