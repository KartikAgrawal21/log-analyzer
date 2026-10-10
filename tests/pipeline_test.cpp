// End-to-end: generator -> format -> parse -> k-way merge -> Top-K, with all modules together.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "loganalyzer/error_signature.hpp"
#include "loganalyzer/level.hpp"
#include "loganalyzer/log_entry.hpp"
#include "loganalyzer/log_generator.hpp"
#include "loganalyzer/log_merger.hpp"
#include "loganalyzer/log_parser.hpp"
#include "loganalyzer/top_k_errors.hpp"
#include "testkit.hpp"

using namespace loganalyzer;

namespace {
constexpr std::size_t kPerService = 2000;
}

TEST(Pipeline, FormatThenParseRoundTripsEveryGeneratedEntry) {
    LogGenerator gen;
    for (const std::vector<LogEntry>& stream : gen.generate_all(kPerService)) {
        std::ostringstream text;
        for (const LogEntry& e : stream) text << format_entry(e) << '\n';
        std::istringstream in(text.str());
        std::size_t malformed = 99;
        std::vector<LogEntry> parsed = parse_stream(in, &malformed);
        CHECK_EQ(malformed, std::size_t{0});
        CHECK(parsed == stream);
    }
}

TEST(Pipeline, MergeKeepsEverythingAndSortsByTime) {
    LogGenerator gen;
    std::vector<std::vector<LogEntry>> streams = gen.generate_all(kPerService);
    const std::size_t services = streams.size();

    std::vector<LogEntry> merged = merge_sorted(std::move(streams));
    CHECK_EQ(merged.size(), services * kPerService);
    CHECK(std::is_sorted(merged.begin(), merged.end(), [](const LogEntry& a, const LogEntry& b) {
        return a.timestamp_ms < b.timestamp_ms;
    }));

    // Each service contributes exactly its own entries, in its original order.
    LogGenerator again;
    std::vector<std::vector<LogEntry>> reference = again.generate_all(kPerService);
    for (std::size_t s = 0; s < services; ++s) {
        std::vector<LogEntry> only_this;
        for (const LogEntry& e : merged) {
            if (e.service == again.config().services[s]) only_this.push_back(e);
        }
        CHECK(only_this == reference[s]);
    }
}

TEST(Pipeline, TopKCountsEveryErrorAndNormalizationCollapsesTheVariableParts) {
    LogGenerator gen;
    std::vector<LogEntry> merged = merge_sorted(gen.generate_all(kPerService));

    std::uint64_t errors = 0;
    TopKErrors counter;
    for (const LogEntry& e : merged) {
        if (e.level == Level::Error) ++errors;
        counter.add(e);
    }
    CHECK(errors > 0);
    CHECK_EQ(counter.total(), errors);

    // Every service has 10 ERROR templates; however many ids, IPs, hex values and UUIDs the
    // messages carry, each template must collapse to ONE signature.
    const std::vector<SignatureCount> all = counter.top_k(counter.distinct());
    CHECK_EQ(all.size(), counter.distinct());

    std::uint64_t sum = 0;
    for (const SignatureCount& g : all) {
        sum += g.count;
        for (char c : g.signature) {
            CHECK(!(c >= '0' && c <= '9'));  // templates contain no digits: any digit left means a leak
        }
        CHECK(g.first_seen_ms <= g.last_seen_ms);
        CHECK(normalize_signature(g.example) == g.signature);
    }
    CHECK_EQ(sum, errors);

    for (const std::string& service : gen.config().services) {
        std::size_t groups = 0;
        for (const SignatureCount& g : all) {
            if (g.service == service) ++groups;
        }
        CHECK(groups >= 3);   // Zipf weights: the head templates certainly occur
        CHECK(groups <= 10);  // never more groups than ERROR templates
    }
}

TEST(Pipeline, ZipfSkewShowsUpAtTheTopOfTheRanking) {
    LogGenerator gen;
    TopKErrors counter;
    for (const LogEntry& e : merge_sorted(gen.generate_all(kPerService))) counter.add(e);
    std::vector<SignatureCount> top = counter.top_k(5);
    CHECK_EQ(top.size(), std::size_t{5});
    for (std::size_t i = 1; i < top.size(); ++i) CHECK(top[i - 1].count >= top[i].count);
    CHECK(top.front().count > top.back().count);  // skewed, not flat
}
