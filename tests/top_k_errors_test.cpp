#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <random>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "loganalyzer/error_signature.hpp"
#include "loganalyzer/level.hpp"
#include "loganalyzer/log_entry.hpp"
#include "loganalyzer/top_k_errors.hpp"
#include "testkit.hpp"

using loganalyzer::Level;
using loganalyzer::LogEntry;
using loganalyzer::normalize_signature;
using loganalyzer::SignatureCount;
using loganalyzer::TopKErrors;

namespace {

LogEntry make_entry(std::int64_t ts, Level level, std::string service, std::string message) {
    LogEntry e;
    e.timestamp_ms = ts;
    e.level = level;
    e.service = std::move(service);
    e.message = std::move(message);
    return e;
}

LogEntry err(std::int64_t ts, std::string service, std::string message) {
    return make_entry(ts, Level::Error, std::move(service), std::move(message));
}

std::string describe(const SignatureCount& g) {
    std::ostringstream os;
    os << "[" << g.service << " | " << g.signature << " | n=" << g.count << " | "
       << g.first_seen_ms << ".." << g.last_seen_ms << " | " << g.example << "]";
    return os.str();
}

std::string describe(const std::vector<SignatureCount>& groups) {
    std::string out;
    for (const auto& g : groups) out += describe(g);
    return out;
}

// Trivially-correct oracle: std::map for grouping, std::sort over ALL groups for ranking.
struct Reference {
    explicit Reference(Level level) : min_level(level) {}

    void add(const LogEntry& e) {
        if (e.level < min_level) return;
        ++total;
        const auto key = std::make_pair(e.service, normalize_signature(e.message));
        auto it = groups.find(key);
        if (it == groups.end()) {
            SignatureCount g;
            g.service = key.first;
            g.signature = key.second;
            g.count = 1;
            g.first_seen_ms = g.last_seen_ms = e.timestamp_ms;
            g.example = e.message;
            groups.emplace(key, std::move(g));
        } else {
            ++it->second.count;
            it->second.first_seen_ms = std::min(it->second.first_seen_ms, e.timestamp_ms);
            it->second.last_seen_ms = std::max(it->second.last_seen_ms, e.timestamp_ms);
        }
    }

    std::vector<SignatureCount> sorted() const {
        std::vector<SignatureCount> all;
        for (const auto& kv : groups) all.push_back(kv.second);
        std::sort(all.begin(), all.end(), [](const SignatureCount& a, const SignatureCount& b) {
            if (a.count != b.count) return a.count > b.count;
            if (a.signature != b.signature) return a.signature < b.signature;
            return a.service < b.service;
        });
        return all;
    }

    std::vector<SignatureCount> top(std::size_t k) const {
        std::vector<SignatureCount> all = sorted();
        if (all.size() > k) all.resize(k);
        return all;
    }

    Level min_level;
    std::uint64_t total = 0;
    std::map<std::pair<std::string, std::string>, SignatureCount> groups;
};

std::string hex_digits(std::mt19937& rng, std::size_t n) {
    static const char kHex[] = "0123456789abcdef";
    std::uniform_int_distribution<int> d(0, 15);
    std::string s;
    for (std::size_t i = 0; i < n; ++i) s.push_back(kHex[d(rng)]);
    return s;
}

// Messages from a handful of templates whose variable parts normalize away, so many raw
// messages share a signature and the counts have plenty of ties.
std::string random_message(std::mt19937& rng) {
    std::uniform_int_distribution<int> which(0, 8);
    std::uniform_int_distribution<int> number(0, 99999);
    std::uniform_int_distribution<int> octet(0, 255);
    std::uniform_int_distribution<int> kind('A', 'H');
    switch (which(rng)) {
        case 0: return "Timeout calling gateway after " + std::to_string(number(rng)) + "ms";
        case 1:
            return "Connection refused by " + std::to_string(octet(rng)) + "." +
                   std::to_string(octet(rng)) + "." + std::to_string(octet(rng)) + "." +
                   std::to_string(octet(rng)) + ":" + std::to_string(number(rng) % 65536);
        case 2: return "NullPointerException at line " + std::to_string(number(rng));
        case 3: return "User " + std::to_string(number(rng)) + " not found";
        case 4: return "Cache miss for key " + hex_digits(rng, 8);
        case 5:
            return "Order " + hex_digits(rng, 8) + "-" + hex_digits(rng, 4) + "-" +
                   hex_digits(rng, 4) + "-" + hex_digits(rng, 4) + "-" + hex_digits(rng, 12) +
                   " rejected";
        case 6: return std::string("Error type ") + static_cast<char>(kind(rng));
        case 7: return "disk   full\ton /var";
        default: return "  disk full on /var ";
    }
}

std::string random_service(std::mt19937& rng) {
    static const std::vector<std::string> services = {"api", "db", "auth", "cache", "web",
                                                      "svc-1", "svc-2"};
    std::uniform_int_distribution<std::size_t> pick(0, services.size() - 1);
    return services[pick(rng)];
}

Level random_level(std::mt19937& rng) {
    std::uniform_int_distribution<int> d(0, 3);
    return static_cast<Level>(d(rng));
}

// "a", "b", ..., "z", "ba", "bb", ...: digit-free names so signatures stay distinct.
std::string letters_name(unsigned v) {
    std::string s;
    do {
        s.push_back(static_cast<char>('a' + v % 26));
        v /= 26;
    } while (v != 0);
    return s;
}

void check_matches_reference(const TopKErrors& actual, const Reference& expected,
                             const std::vector<std::size_t>& ks, const std::string& label) {
    CHECK_EQ(actual.distinct(), expected.groups.size());
    CHECK_EQ(actual.total(), expected.total);
    for (std::size_t k : ks) {
        const std::string ctx = label + " k=" + std::to_string(k) + ": ";
        const std::vector<SignatureCount> got = actual.top_k(k);
        const std::vector<SignatureCount> want = expected.top(k);
        CHECK_EQ(ctx + "size " + std::to_string(got.size()),
                 ctx + "size " + std::to_string(want.size()));
        for (std::size_t i = 0; i < want.size(); ++i) {  // report only the first mismatch
            const std::string at = ctx + "#" + std::to_string(i) + " ";
            CHECK_EQ(at + describe(got[i]), at + describe(want[i]));
        }
    }
}

}  // namespace

TEST(TopKErrors, EmptyStateHasNothingToReport) {
    TopKErrors tk;
    CHECK_EQ(tk.distinct(), std::size_t{0});
    CHECK_EQ(tk.total(), std::uint64_t{0});
    CHECK(tk.top_k(0).empty());
    CHECK(tk.top_k(1).empty());
    CHECK(tk.top_k(100).empty());
    CHECK(tk.top_k(std::numeric_limits<std::size_t>::max()).empty());
}

TEST(TopKErrors, RanksGroupsByFrequencyAndFillsEveryField) {
    TopKErrors tk;
    tk.add(err(1000, "api", "Timeout after 100ms"));
    tk.add(err(1100, "api", "Disk full"));
    tk.add(err(1200, "api", "Timeout after 250ms"));
    tk.add(err(1300, "api", "Null pointer"));
    tk.add(err(1400, "api", "Disk full"));
    tk.add(err(1500, "api", "Timeout after 7ms"));

    CHECK_EQ(tk.distinct(), std::size_t{3});
    CHECK_EQ(tk.total(), std::uint64_t{6});

    const auto top = tk.top_k(10);
    CHECK_EQ(top.size(), std::size_t{3});

    CHECK_EQ(top[0].service, std::string("api"));
    CHECK_EQ(top[0].signature, std::string("Timeout after <N>ms"));
    CHECK_EQ(top[0].count, std::uint64_t{3});
    CHECK_EQ(top[0].first_seen_ms, std::int64_t{1000});
    CHECK_EQ(top[0].last_seen_ms, std::int64_t{1500});
    CHECK_EQ(top[0].example, std::string("Timeout after 100ms"));

    CHECK_EQ(top[1].signature, std::string("Disk full"));
    CHECK_EQ(top[1].count, std::uint64_t{2});
    CHECK_EQ(top[1].first_seen_ms, std::int64_t{1100});
    CHECK_EQ(top[1].last_seen_ms, std::int64_t{1400});

    CHECK_EQ(top[2].signature, std::string("Null pointer"));
    CHECK_EQ(top[2].count, std::uint64_t{1});
    CHECK_EQ(top[2].first_seen_ms, top[2].last_seen_ms);
}

TEST(TopKErrors, MessagesDifferingOnlyInVariablePartsShareAGroup) {
    TopKErrors tk;
    tk.add(err(1, "pay", "Order 550e8400-e29b-41d4-a716-446655440000 failed from 10.0.0.1:80"));
    tk.add(err(2, "pay", "Order 123e4567-e89b-12d3-a456-426614174000 failed from 192.168.0.9"));
    tk.add(err(3, "pay", "Order  123e4567-e89b-12d3-a456-426614174000   failed from 1.2.3.4:1 "));
    CHECK_EQ(tk.distinct(), std::size_t{1});
    const auto top = tk.top_k(1);
    CHECK_EQ(top[0].signature, std::string("Order <UUID> failed from <IP>"));
    CHECK_EQ(top[0].count, std::uint64_t{3});
    CHECK_EQ(top[0].example,
             std::string("Order 550e8400-e29b-41d4-a716-446655440000 failed from 10.0.0.1:80"));
}

TEST(TopKErrors, SameMessageInDifferentServicesIsSeparateGroups) {
    TopKErrors tk;
    tk.add(err(1, "api", "Disk full"));
    tk.add(err(2, "db", "Disk full"));
    tk.add(err(3, "db", "Disk full"));
    CHECK_EQ(tk.distinct(), std::size_t{2});
    const auto top = tk.top_k(5);
    CHECK_EQ(top[0].service, std::string("db"));
    CHECK_EQ(top[0].count, std::uint64_t{2});
    CHECK_EQ(top[1].service, std::string("api"));
    CHECK_EQ(top[1].count, std::uint64_t{1});
}

TEST(TopKErrors, ServiceNamesAreKeptVerbatimNotNormalized) {
    TopKErrors tk;
    tk.add(err(1, "worker-1", "Boom"));
    tk.add(err(2, "worker-2", "Boom"));
    CHECK_EQ(tk.distinct(), std::size_t{2});
}

TEST(TopKErrors, TracksFirstAndLastSeenWhenEntriesArriveOutOfOrder) {
    TopKErrors tk;
    tk.add(err(500, "svc", "Boom 1"));
    tk.add(err(100, "svc", "Boom 2"));
    tk.add(err(900, "svc", "Boom 3"));
    tk.add(err(300, "svc", "Boom 4"));
    const auto top = tk.top_k(1);
    CHECK_EQ(top[0].signature, std::string("Boom <N>"));
    CHECK_EQ(top[0].count, std::uint64_t{4});
    CHECK_EQ(top[0].first_seen_ms, std::int64_t{100});
    CHECK_EQ(top[0].last_seen_ms, std::int64_t{900});
    // The example is the first entry ADDED, not the earliest by timestamp.
    CHECK_EQ(top[0].example, std::string("Boom 1"));
}

TEST(TopKErrors, SingleEntryHasEqualFirstAndLastSeen) {
    TopKErrors tk;
    tk.add(err(-42, "svc", "Boom"));
    const auto top = tk.top_k(1);
    CHECK_EQ(top[0].first_seen_ms, std::int64_t{-42});
    CHECK_EQ(top[0].last_seen_ms, std::int64_t{-42});
}

TEST(TopKErrors, HandlesExtremeAndNegativeTimestamps) {
    TopKErrors tk;
    const std::int64_t lo = std::numeric_limits<std::int64_t>::min();
    const std::int64_t hi = std::numeric_limits<std::int64_t>::max();
    tk.add(err(0, "svc", "Boom"));
    tk.add(err(hi, "svc", "Boom"));
    tk.add(err(lo, "svc", "Boom"));
    tk.add(err(-5, "svc", "Boom"));
    const auto top = tk.top_k(1);
    CHECK_EQ(top[0].first_seen_ms, lo);
    CHECK_EQ(top[0].last_seen_ms, hi);
}

TEST(TopKErrors, DefaultMinLevelIgnoresEverythingBelowError) {
    TopKErrors tk;
    tk.add(make_entry(1, Level::Debug, "svc", "msg debug"));
    tk.add(make_entry(2, Level::Info, "svc", "msg info"));
    tk.add(make_entry(3, Level::Warn, "svc", "msg warn"));
    CHECK_EQ(tk.total(), std::uint64_t{0});
    CHECK_EQ(tk.distinct(), std::size_t{0});
    CHECK(tk.top_k(10).empty());

    tk.add(make_entry(4, Level::Error, "svc", "msg error"));
    CHECK_EQ(tk.total(), std::uint64_t{1});
    CHECK_EQ(tk.distinct(), std::size_t{1});
    const auto top = tk.top_k(10);  // a named vector: CHECK_EQ binds references to its operands
    CHECK_EQ(top.size(), std::size_t{1});
    CHECK_EQ(top[0].signature, std::string("msg error"));
}

TEST(TopKErrors, LowerMinLevelsIncludeMoreLevels) {
    const std::vector<LogEntry> entries = {
        make_entry(1, Level::Debug, "svc", "msg debug"),
        make_entry(2, Level::Info, "svc", "msg info"),
        make_entry(3, Level::Warn, "svc", "msg warn"),
        make_entry(4, Level::Error, "svc", "msg error"),
    };
    const std::pair<Level, std::uint64_t> expectations[] = {
        {Level::Error, 1}, {Level::Warn, 2}, {Level::Info, 3}, {Level::Debug, 4}};
    for (const auto& [min_level, expected_total] : expectations) {
        TopKErrors tk(min_level);
        for (const auto& e : entries) tk.add(e);
        CHECK_EQ(tk.total(), expected_total);
        CHECK_EQ(tk.distinct(), static_cast<std::size_t>(expected_total));
    }

    TopKErrors warn(Level::Warn);
    for (const auto& e : entries) warn.add(e);
    const auto top = warn.top_k(10);
    CHECK_EQ(top.size(), std::size_t{2});
    CHECK_EQ(top[0].signature, std::string("msg error"));  // tie on count: signature ascending
    CHECK_EQ(top[1].signature, std::string("msg warn"));
}

TEST(TopKErrors, IgnoredEntriesLeaveNoTraceInGroupStatistics) {
    TopKErrors tk;
    tk.add(make_entry(1, Level::Warn, "svc", "Slow call 10"));  // ignored: below Error
    tk.add(err(50, "svc", "Slow call 20"));
    tk.add(err(70, "svc", "Slow call 30"));
    const auto top = tk.top_k(1);
    CHECK_EQ(top[0].count, std::uint64_t{2});
    CHECK_EQ(top[0].first_seen_ms, std::int64_t{50});
    CHECK_EQ(top[0].example, std::string("Slow call 20"));
    CHECK_EQ(tk.total(), std::uint64_t{2});
}

TEST(TopKErrors, KZeroIsEmptyAndKBeyondDistinctReturnsEverything) {
    TopKErrors tk;
    for (int i = 0; i < 5; ++i) tk.add(err(i, "svc", "kind " + std::string(1, static_cast<char>('a' + i))));
    CHECK_EQ(tk.distinct(), std::size_t{5});

    CHECK(tk.top_k(0).empty());
    CHECK_EQ(tk.top_k(1).size(), std::size_t{1});
    CHECK_EQ(tk.top_k(4).size(), std::size_t{4});
    CHECK_EQ(tk.top_k(5).size(), std::size_t{5});
    CHECK_EQ(tk.top_k(6).size(), std::size_t{5});
    CHECK_EQ(tk.top_k(1000000).size(), std::size_t{5});
    // Must not try to reserve k slots up front.
    CHECK_EQ(tk.top_k(std::numeric_limits<std::size_t>::max()).size(), std::size_t{5});
}

TEST(TopKErrors, TieBreaksByCountThenSignatureThenService) {
    TopKErrors tk;
    // Deliberately scrambled insertion order; every pair below is added twice (count 2)
    // except where noted.
    const std::vector<std::pair<std::string, std::string>> twice = {
        {"svcB", "alpha"}, {"svcC", "alpha"}, {"svcA", "beta"},
        {"svcA", "alpha"}, {"svcA", "Zeta"},
    };
    std::int64_t ts = 0;
    for (int round = 0; round < 2; ++round) {
        for (const auto& [service, message] : twice) tk.add(err(ts++, service, message));
    }
    tk.add(err(ts++, "svcA", "low"));
    for (int i = 0; i < 5; ++i) tk.add(err(ts++, "svcZ", "top"));

    const std::vector<std::pair<std::string, std::string>> expected = {
        {"svcZ", "top"},    // count 5
        {"svcA", "Zeta"},   // count 2: 'Z' sorts before 'a'
        {"svcA", "alpha"},  // same signature: service ascending
        {"svcB", "alpha"},
        {"svcC", "alpha"},
        {"svcA", "beta"},
        {"svcA", "low"},    // count 1
    };
    const auto all = tk.top_k(100);
    CHECK_EQ(all.size(), expected.size());
    for (std::size_t i = 0; i < expected.size(); ++i) {
        CHECK_EQ(all[i].service, expected[i].first);
        CHECK_EQ(all[i].signature, expected[i].second);
    }

    // Cutting inside a run of ties must keep exactly the first k of the full order.
    for (std::size_t k = 0; k <= expected.size() + 1; ++k) {
        const auto cut = tk.top_k(k);
        const std::size_t want = std::min(k, expected.size());
        CHECK_EQ(cut.size(), want);
        for (std::size_t i = 0; i < want; ++i) {
            CHECK_EQ(cut[i].service, expected[i].first);
            CHECK_EQ(cut[i].signature, expected[i].second);
        }
    }
}

TEST(TopKErrors, AllEqualCountsOrderBySignatureThenServiceRegardlessOfInsertionOrder) {
    const std::vector<std::pair<std::string, std::string>> groups = {
        {"s2", "b"}, {"s1", "b"}, {"s3", "a"}, {"s1", "a"}, {"s2", "a"}, {"s1", "c"}};
    const std::vector<std::pair<std::string, std::string>> expected = {
        {"s1", "a"}, {"s2", "a"}, {"s3", "a"}, {"s1", "b"}, {"s2", "b"}, {"s1", "c"}};

    std::vector<std::size_t> order = {0, 1, 2, 3, 4, 5};
    std::mt19937 rng(7);
    for (int round = 0; round < 25; ++round) {
        std::shuffle(order.begin(), order.end(), rng);
        TopKErrors tk;
        std::int64_t ts = 0;
        for (std::size_t i : order) tk.add(err(ts++, groups[i].first, groups[i].second));
        for (std::size_t k : {std::size_t{1}, std::size_t{4}, std::size_t{6}}) {
            const auto top = tk.top_k(k);
            CHECK_EQ(top.size(), k);
            for (std::size_t i = 0; i < k; ++i) {
                CHECK_EQ(top[i].service, expected[i].first);
                CHECK_EQ(top[i].signature, expected[i].second);
            }
        }
    }
}

TEST(TopKErrors, ServiceAndSignatureCannotBleedIntoEachOther) {
    // Naive `service + signature` keys would merge several of these.
    TopKErrors tk;
    tk.add(err(1, "ab", "c"));
    tk.add(err(2, "a", "bc"));
    tk.add(err(3, "a|b", "c"));
    tk.add(err(4, "a", "b|c"));
    tk.add(err(5, "", "x"));
    tk.add(err(6, "x", ""));
    tk.add(err(7, std::string("a\0b", 3), "c"));
    tk.add(err(8, "a", std::string("b\0c", 3)));
    CHECK_EQ(tk.distinct(), std::size_t{8});
    CHECK_EQ(tk.total(), std::uint64_t{8});
    for (const auto& g : tk.top_k(100)) CHECK_EQ(g.count, std::uint64_t{1});

    // Re-adding the very same pairs hits the existing groups, not new ones.
    tk.add(err(9, "ab", "c"));
    tk.add(err(10, "a", "bc"));
    CHECK_EQ(tk.distinct(), std::size_t{8});
    const auto top = tk.top_k(2);
    CHECK_EQ(top[0].count, std::uint64_t{2});
    CHECK_EQ(top[1].count, std::uint64_t{2});
}

TEST(TopKErrors, TopKIsRepeatableAndAddingAfterwardsKeepsWorking) {
    TopKErrors tk;
    tk.add(err(1, "svc", "a"));
    tk.add(err(2, "svc", "b"));
    tk.add(err(3, "svc", "b"));
    const std::string first = describe(tk.top_k(5));
    CHECK_EQ(describe(tk.top_k(5)), first);
    CHECK_EQ(tk.total(), std::uint64_t{3});

    tk.add(err(4, "svc", "a"));
    tk.add(err(5, "svc", "a"));
    const auto top = tk.top_k(1);
    CHECK_EQ(top[0].signature, std::string("a"));
    CHECK_EQ(top[0].count, std::uint64_t{3});
    CHECK_EQ(tk.total(), std::uint64_t{5});
}

TEST(TopKErrors, TotalEqualsSumOfGroupCountsAndGroupsAreWellFormed) {
    std::mt19937 rng(99);
    TopKErrors tk(Level::Info);
    std::uint64_t expected_total = 0;
    std::uniform_int_distribution<std::int64_t> ts(-1000000, 1000000000000LL);
    for (int i = 0; i < 5000; ++i) {
        const Level level = random_level(rng);
        if (level >= Level::Info) ++expected_total;
        tk.add(make_entry(ts(rng), level, random_service(rng), random_message(rng)));
    }
    CHECK_EQ(tk.total(), expected_total);

    const auto all = tk.top_k(tk.distinct());
    CHECK_EQ(all.size(), tk.distinct());
    std::uint64_t sum = 0;
    for (const auto& g : all) {
        sum += g.count;
        CHECK(g.count >= 1);
        CHECK(g.first_seen_ms <= g.last_seen_ms);
        CHECK(!g.service.empty());
        CHECK_EQ(g.signature, normalize_signature(g.example));
    }
    CHECK_EQ(sum, tk.total());
    for (std::size_t i = 1; i < all.size(); ++i) CHECK(all[i - 1].count >= all[i].count);
}

TEST(TopKErrors, MatchesSortEverythingReferenceOnRandomInputs) {
    for (unsigned seed = 1; seed <= 60; ++seed) {
        std::mt19937 rng(seed);
        const Level min_level = random_level(rng);
        std::uniform_int_distribution<int> size(0, 700);
        std::uniform_int_distribution<std::int64_t> ts(-1000000, 1000000000000LL);

        TopKErrors tk(min_level);
        Reference ref(min_level);
        for (int i = 0, n = size(rng); i < n; ++i) {
            const LogEntry e = make_entry(ts(rng), random_level(rng), random_service(rng),
                                          random_message(rng));
            tk.add(e);
            ref.add(e);
        }

        const std::size_t d = ref.groups.size();
        std::vector<std::size_t> ks = {0, 1, 2, 3, 5, 8, 13, 21, d, d + 1, 1000};
        if (d > 0) ks.push_back(d - 1);
        if (d > 1) ks.push_back(d / 2);
        check_matches_reference(tk, ref, ks,
                                "seed=" + std::to_string(seed) + " min=" +
                                    std::string(loganalyzer::to_string(min_level)));
    }
}

TEST(TopKErrors, MatchesReferenceWithManySkewedGroupsAndHeavyTies) {
    for (unsigned seed = 1; seed <= 6; ++seed) {
        std::mt19937 rng(1000 + seed);
        std::uniform_real_distribution<double> unit(0.0, 1.0);
        std::uniform_int_distribution<int> side(0, 1);
        std::uniform_int_distribution<std::int64_t> ts(0, 1000000);

        TopKErrors tk;
        Reference ref(Level::Error);
        for (int i = 0; i < 20000; ++i) {
            const double u = unit(rng);
            // Cubing skews towards low ids: a few hot groups and a long tail of count-1/2 ties.
            const auto id = static_cast<unsigned>(u * u * u * 3000.0);
            const LogEntry e = err(ts(rng), side(rng) != 0 ? "alpha" : "beta",
                                   "Error kind " + letters_name(id));
            tk.add(e);
            ref.add(e);
        }
        const std::size_t d = ref.groups.size();
        CHECK(d > 500);  // otherwise the test is not exercising what it claims to
        check_matches_reference(tk, ref, {1, 2, 10, 50, 100, 1000, d - 1, d, d + 5},
                                "seed=" + std::to_string(seed));
    }
}

TEST(TopKErrors, ManyDistinctGroupsWithSmallK) {
    TopKErrors tk;
    Reference ref(Level::Error);
    for (unsigned id = 0; id < 100000; ++id) {
        // group `id` gets 1 + (id % 3) entries, so ranks are dominated by ties
        const LogEntry e = err(id, "svc", "Error kind " + letters_name(id));
        for (unsigned rep = 0; rep <= id % 3; ++rep) {
            tk.add(e);
            ref.add(e);
        }
    }
    CHECK_EQ(tk.distinct(), std::size_t{100000});
    check_matches_reference(tk, ref, {1, 3, 10, 100}, "100k groups");
}

TEST(TopKErrors, MovedFromObjectIsEmptyAndReusable) {
    TopKErrors a;
    a.add(err(1, "svc", "boom 1"));
    a.add(err(2, "svc", "boom 2"));
    CHECK_EQ(a.total(), std::uint64_t{2});

    TopKErrors b(std::move(a));
    CHECK_EQ(b.total(), std::uint64_t{2});
    CHECK_EQ(b.distinct(), std::size_t{1});
    // Regression: total_ used to stay at 2 while the groups were gone.
    CHECK_EQ(a.total(), std::uint64_t{0});
    CHECK_EQ(a.distinct(), std::size_t{0});
    CHECK(a.top_k(5).empty());

    a.add(err(3, "svc", "fresh 9"));
    CHECK_EQ(a.total(), std::uint64_t{1});
    CHECK_EQ(a.distinct(), std::size_t{1});

    TopKErrors c;
    c = std::move(b);
    CHECK_EQ(c.total(), std::uint64_t{2});
    CHECK_EQ(b.total(), std::uint64_t{0});
    CHECK_EQ(b.distinct(), std::size_t{0});
}
