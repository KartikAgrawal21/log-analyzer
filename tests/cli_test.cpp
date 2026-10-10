#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <sstream>
#include <string>
#include <vector>

#include "loganalyzer/alert_engine.hpp"
#include "loganalyzer/cli.hpp"
#include "loganalyzer/log_entry.hpp"
#include "loganalyzer/log_generator.hpp"
#include "loganalyzer/log_merger.hpp"
#include "loganalyzer/log_parser.hpp"
#include "loganalyzer/top_k_errors.hpp"
#include "testkit.hpp"

using loganalyzer::GeneratorConfig;
using loganalyzer::LogEntry;
using loganalyzer::LogGenerator;
using loganalyzer::run_cli;

namespace fs = std::filesystem;

namespace {

struct Result {
    int code = -1;
    std::string out;
    std::string err;
};

Result run(const std::vector<std::string>& args) {
    std::ostringstream out;
    std::ostringstream err;
    Result r;
    r.code = run_cli(args, out, err);
    r.out = out.str();
    r.err = err.str();
    return r;
}

/// A fresh scratch directory under the system temp dir, removed on scope exit.
class TempDir {
public:
    explicit TempDir(const std::string& tag)
        : path_(fs::temp_directory_path() / ("loganalyzer_cli_test_" + tag)) {
        std::error_code ec;
        fs::remove_all(path_, ec);
        fs::create_directories(path_);
    }
    ~TempDir() {
        std::error_code ec;
        fs::remove_all(path_, ec);
    }
    fs::path path() const { return path_; }
    std::string file(const std::string& name) const { return (path_ / name).string(); }

private:
    fs::path path_;
};

std::vector<LogEntry> read_entries(const std::string& path, std::size_t* malformed = nullptr) {
    std::ifstream in(path, std::ios::binary);
    return loganalyzer::parse_stream(in, malformed);
}

std::size_t count_lines(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    std::size_t n = 0;
    std::string line;
    while (std::getline(in, line)) ++n;
    return n;
}

void write_text(const std::string& path, const std::string& text) {
    std::ofstream out(path, std::ios::binary);
    out << text;
}

bool is_time_sorted(const std::vector<LogEntry>& v) {
    return std::is_sorted(v.begin(), v.end(), [](const LogEntry& a, const LogEntry& b) {
        return a.timestamp_ms < b.timestamp_ms;
    });
}

}  // namespace

TEST(Cli, HelpPrintsUsageAndSucceeds) {
    for (const char* flag : {"help", "--help", "-h"}) {
        Result r = run({flag});
        CHECK_EQ(r.code, 0);
        CHECK(r.out.find("loganalyzer generate") != std::string::npos);
        CHECK(r.out.find("top-errors") != std::string::npos);
    }
}

TEST(Cli, UsageErrorsReturnTwo) {
    CHECK_EQ(run({}).code, 2);
    CHECK_EQ(run({"frobnicate"}).code, 2);
    CHECK_EQ(run({"generate"}).code, 2);                                   // missing --out-dir
    CHECK_EQ(run({"generate", "--out-dir", "x", "--count", "abc"}).code, 2);
    CHECK_EQ(run({"generate", "--out-dir", "x", "--count", "0"}).code, 2);
    CHECK_EQ(run({"generate", "--out-dir", "x", "--bogus", "1"}).code, 2);
    CHECK_EQ(run({"generate", "--out-dir"}).code, 2);                      // option without value
    CHECK_EQ(run({"merge"}).code, 2);
    CHECK_EQ(run({"top-errors"}).code, 2);
    CHECK_EQ(run({"bench", "stray"}).code, 2);
    Result r = run({"frobnicate"});
    CHECK(r.err.find("unknown command: frobnicate") != std::string::npos);
}

TEST(Cli, GenerateRejectsUnsafeOrDuplicateServiceNames) {
    TempDir dir("unsafe");
    CHECK_EQ(run({"generate", "--out-dir", dir.file("o"), "--services", "../evil"}).code, 2);
    CHECK_EQ(run({"generate", "--out-dir", dir.file("o"), "--services", "a/b"}).code, 2);
    CHECK_EQ(run({"generate", "--out-dir", dir.file("o"), "--services", "a,,b"}).code, 2);
    CHECK_EQ(run({"generate", "--out-dir", dir.file("o"), "--services", "a,a"}).code, 2);
    CHECK(!fs::exists(dir.path() / "o" / "a.log"));
}

TEST(Cli, GenerateWritesOneSortedFilePerServiceMatchingTheGenerator) {
    TempDir dir("generate");
    Result r = run({"generate", "--out-dir", dir.file("logs"), "--count", "200", "--seed", "7",
                    "--services", "auth-svc,pay-svc"});
    CHECK_EQ(r.code, 0);
    CHECK_EQ(count_lines(dir.file("logs/auth-svc.log")), std::size_t{200});
    CHECK_EQ(count_lines(dir.file("logs/pay-svc.log")), std::size_t{200});

    GeneratorConfig config;
    config.seed = 7;
    config.services = {"auth-svc", "pay-svc"};
    LogGenerator expected(config);
    std::size_t malformed = 99;
    CHECK(read_entries(dir.file("logs/auth-svc.log"), &malformed) == expected.generate_service(0, 200));
    CHECK_EQ(malformed, std::size_t{0});
    CHECK(read_entries(dir.file("logs/pay-svc.log")) == expected.generate_service(1, 200));
}

TEST(Cli, MergeProducesGloballySortedCompleteOutput) {
    TempDir dir("merge");
    CHECK_EQ(run({"generate", "--out-dir", dir.file("logs"), "--count", "300", "--services", "a,b,c"}).code, 0);

    Result r = run({"merge", dir.file("logs/a.log"), dir.file("logs/b.log"), dir.file("logs/c.log"),
                    "--out", dir.file("merged.log")});
    CHECK_EQ(r.code, 0);
    CHECK(r.err.find("merged 900 entries from 3 files (0 malformed skipped)") != std::string::npos);

    std::vector<LogEntry> merged = read_entries(dir.file("merged.log"));
    CHECK_EQ(merged.size(), std::size_t{900});
    CHECK(is_time_sorted(merged));

    // Same answer as the library call on the same data (deterministic order incl. ties).
    GeneratorConfig config;
    config.services = {"a", "b", "c"};
    LogGenerator gen(config);
    CHECK(merged == loganalyzer::merge_sorted(gen.generate_all(300)));
}

TEST(Cli, MergeWritesToStdoutByDefault) {
    TempDir dir("merge_stdout");
    CHECK_EQ(run({"generate", "--out-dir", dir.file("logs"), "--count", "50", "--services", "a,b"}).code, 0);
    Result r = run({"merge", dir.file("logs/a.log"), dir.file("logs/b.log")});
    CHECK_EQ(r.code, 0);
    std::istringstream in(r.out);
    std::vector<LogEntry> merged = loganalyzer::parse_stream(in);
    CHECK_EQ(merged.size(), std::size_t{100});
    CHECK(is_time_sorted(merged));
}

TEST(Cli, MergeFailsCleanlyOnMissingFile) {
    TempDir dir("merge_missing");
    Result r = run({"merge", dir.file("does-not-exist.log")});
    CHECK_EQ(r.code, 1);
    CHECK(r.err.find("does-not-exist.log") != std::string::npos);
}

TEST(Cli, MergeRejectsAnUnsortedFileAndNamesIt) {
    TempDir dir("merge_unsorted");
    write_text(dir.file("bad.log"),
               "2026-10-10T00:00:02.000Z INFO svc second\n"
               "2026-10-10T00:00:01.000Z INFO svc first\n");
    Result r = run({"merge", dir.file("bad.log")});
    CHECK_EQ(r.code, 1);
    CHECK(r.err.find("bad.log") != std::string::npos);
    CHECK(r.err.find("not sorted") != std::string::npos);
}

TEST(Cli, MergeCountsAndSkipsMalformedLines) {
    TempDir dir("merge_malformed");
    write_text(dir.file("mixed.log"),
               "2026-10-10T00:00:01.000Z INFO svc ok\n"
               "this is not a log line\n"
               "2026-10-10T00:00:02.000Z WARN svc ok too\n");
    Result r = run({"merge", dir.file("mixed.log")});
    CHECK_EQ(r.code, 0);
    CHECK(r.err.find("merged 2 entries from 1 files (1 malformed skipped)") != std::string::npos);
}

TEST(Cli, TopErrorsRanksTheMostFrequentSignatureFirst) {
    TempDir dir("top");
    CHECK_EQ(run({"generate", "--out-dir", dir.file("logs"), "--count", "2000", "--services", "a,b"}).code, 0);

    // Expected answer straight from the library.
    GeneratorConfig config;
    config.services = {"a", "b"};
    LogGenerator gen(config);
    loganalyzer::TopKErrors expected;
    for (const auto& stream : gen.generate_all(2000)) {
        for (const LogEntry& e : stream) expected.add(e);
    }
    const auto best = expected.top_k(3);
    CHECK_EQ(best.size(), std::size_t{3});

    Result r = run({"top-errors", dir.file("logs/a.log"), dir.file("logs/b.log"), "--k", "3"});
    CHECK_EQ(r.code, 0);
    CHECK(r.out.find("Top 3 of " + std::to_string(expected.distinct())) != std::string::npos);
    // The first data row carries rank 1, the best group's count, service and signature.
    const std::size_t rank1 = r.out.find("   1  ");
    CHECK(rank1 != std::string::npos);
    const std::string row = r.out.substr(rank1, r.out.find('\n', rank1) - rank1);
    CHECK(row.find(std::to_string(best[0].count)) != std::string::npos);
    CHECK(row.find(best[0].service) != std::string::npos);
    CHECK(row.find(best[0].signature) != std::string::npos);
    CHECK(r.out.find("e.g. ") != std::string::npos);
}

TEST(Cli, TopErrorsMinLevelWidensTheCount) {
    TempDir dir("top_level");
    CHECK_EQ(run({"generate", "--out-dir", dir.file("logs"), "--count", "500", "--services", "a"}).code, 0);
    Result errors = run({"top-errors", dir.file("logs/a.log"), "--k", "1"});
    Result warns = run({"top-errors", dir.file("logs/a.log"), "--k", "1", "--min-level", "warn"});
    CHECK_EQ(errors.code, 0);
    CHECK_EQ(warns.code, 0);
    CHECK(errors.out.find("level >= ERROR") != std::string::npos);
    CHECK(warns.out.find("level >= WARN") != std::string::npos);
    CHECK(run({"top-errors", dir.file("logs/a.log"), "--min-level", "FATAL"}).code == 2);
    CHECK(run({"top-errors", dir.file("logs/a.log"), "--k", "0"}).code == 2);
}

TEST(Cli, TopErrorsOnAFileWithoutErrorsSaysSo) {
    TempDir dir("top_none");
    write_text(dir.file("quiet.log"), "2026-10-10T00:00:01.000Z INFO svc all good\n");
    Result r = run({"top-errors", dir.file("quiet.log")});
    CHECK_EQ(r.code, 0);
    CHECK(r.out.find("no entries at level ERROR") != std::string::npos);
}

TEST(Cli, BenchRunsEveryStageAndSelfChecks) {
    Result r = run({"bench", "--count", "5000"});
    CHECK_EQ(r.code, 0);
    for (const char* stage : {"generate", "format", "parse", "merge", "top-k"}) {
        CHECK(r.out.find(stage) != std::string::npos);
    }
    CHECK(r.out.find("benchmark: 5000 entries") != std::string::npos);
}

TEST(Cli, AlertsOutputMatchesTheLibraryEngineLineForLine) {
    TempDir dir("alerts");
    CHECK_EQ(run({"generate", "--out-dir", dir.file("logs"), "--count", "3000", "--services", "a,b,c"}).code, 0);

    const std::string spec = "name=burst,threshold=5,window=10s,cooldown=30s";
    Result r = run({"alerts", dir.file("logs/a.log"), dir.file("logs/b.log"), dir.file("logs/c.log"), "--rule", spec});
    CHECK_EQ(r.code, 0);

    // Expected: the same stream through the same engine, formatted the same way.
    GeneratorConfig config;
    config.services = {"a", "b", "c"};
    LogGenerator gen(config);
    loganalyzer::AlertEngine engine;
    engine.add_rule(loganalyzer::parse_rule_spec(spec));
    std::ostringstream expected;
    std::size_t alerts = 0;
    for (const LogEntry& e : loganalyzer::merge_sorted(gen.generate_all(3000))) {
        for (const loganalyzer::Alert& a : engine.process(e)) {
            ++alerts;
            expected << loganalyzer::format_iso8601_utc(a.fired_at_ms) << " ALERT rule=" << a.rule
                     << " service=" << a.service << " count=" << a.count
                     << " since=" << loganalyzer::format_iso8601_utc(a.first_event_ms)
                     << " suppressed=" << a.suppressed << "\n";
        }
    }
    CHECK(alerts > 0);  // 5 errors in 10 s fires on this traffic
    CHECK_EQ(r.out, expected.str());
    CHECK(r.err.find("processed 9000 entries with 1 rules: " + std::to_string(alerts) + " alerts") !=
          std::string::npos);
}

TEST(Cli, AlertsAcceptsSeveralRulesAndARulesFile) {
    TempDir dir("alerts_rules");
    write_text(dir.file("a.log"),
               "2026-10-10T00:00:00.000Z ERROR svc boom\n"
               "2026-10-10T00:00:00.100Z ERROR svc boom\n"
               "2026-10-10T00:00:00.200Z WARN svc careful\n");
    write_text(dir.file("rules.txt"),
               "# comment line\n"
               "\n"
               "name=warns,threshold=3,window=1s,level=WARN\r\n"
               "   name=indented,threshold=2,window=1s   \n");
    Result r = run({"alerts", dir.file("a.log"), "--rule", "name=pair,threshold=2,window=1s", "--rules-file",
                    dir.file("rules.txt")});
    CHECK_EQ(r.code, 0);
    CHECK(r.out.find("rule=pair") != std::string::npos);
    CHECK(r.out.find("rule=indented") != std::string::npos);
    CHECK(r.out.find("rule=warns") != std::string::npos);  // 2 errors + 1 warn are >= WARN: 3 within 1 s
    CHECK(r.err.find("with 3 rules: 3 alerts") != std::string::npos);
}

TEST(Cli, AlertsUsageAndRuntimeErrors) {
    TempDir dir("alerts_errors");
    write_text(dir.file("a.log"), "2026-10-10T00:00:00.000Z ERROR svc boom\n");
    CHECK_EQ(run({"alerts"}).code, 2);                                           // no file
    CHECK_EQ(run({"alerts", dir.file("a.log")}).code, 2);                        // no rule
    CHECK_EQ(run({"alerts", dir.file("a.log"), "--rule", "name=x"}).code, 2);    // incomplete rule
    CHECK_EQ(run({"alerts", dir.file("a.log"), "--rule", "name=x,threshold=0,window=1s"}).code, 2);
    CHECK_EQ(run({"alerts", dir.file("a.log"), "--rule", "name=x,threshold=1,window=1s", "--rule",
                  "name=x,threshold=2,window=1s"}).code, 2);                     // duplicate rule name
    Result bad = run({"alerts", dir.file("a.log"), "--rule", "name=x,threshold=1,window=soon"});
    CHECK_EQ(bad.code, 2);
    CHECK(bad.err.find("bad --rule") != std::string::npos);

    write_text(dir.file("rules.txt"), "name=ok,threshold=1,window=1s\nthis is wrong\n");
    Result file_error = run({"alerts", dir.file("a.log"), "--rules-file", dir.file("rules.txt")});
    CHECK_EQ(file_error.code, 2);
    CHECK(file_error.err.find("rules.txt:2:") != std::string::npos);

    CHECK_EQ(run({"alerts", dir.file("missing.log"), "--rule", "name=x,threshold=1,window=1s"}).code, 1);
    CHECK_EQ(run({"alerts", dir.file("a.log"), "--rules-file", dir.file("nope.txt")}).code, 1);
}
