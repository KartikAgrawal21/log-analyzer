#include <algorithm>
#include <chrono>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <ostream>
#include <sstream>
#include <streambuf>
#include <string>
#include <vector>

#include "loganalyzer/alert_engine.hpp"
#include "loganalyzer/cli.hpp"
#include "loganalyzer/error_signature.hpp"
#include "loganalyzer/log_entry.hpp"
#include "loganalyzer/log_generator.hpp"
#include "loganalyzer/log_merger.hpp"
#include "loganalyzer/log_parser.hpp"
#include "loganalyzer/top_k_errors.hpp"
#include "loganalyzer/trie.hpp"
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

/// Unique per call, so two test processes running at once never share a scratch directory.
std::string unique_suffix() {
    static int counter = 0;
    return std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + "_" +
           std::to_string(++counter);
}

/// A fresh scratch directory under the system temp dir, removed on scope exit.
class TempDir {
public:
    explicit TempDir(const std::string& tag)
        : path_(fs::temp_directory_path() / ("loganalyzer_cli_test_" + tag + "_" + unique_suffix())) {
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

// ---- added after review -----------------------------------------------------------------

namespace {

/// A stream buffer that refuses every write, to simulate a full disk or a closed pipe.
class FailingBuf : public std::streambuf {
protected:
    int_type overflow(int_type) override { return traits_type::eof(); }
    std::streamsize xsputn(const char*, std::streamsize) override { return 0; }
};

}  // namespace

TEST(Cli, InputWildcardsExpandInSortedOrder) {
    TempDir dir("glob");
    CHECK_EQ(run({"generate", "--out-dir", dir.file("logs"), "--count", "40", "--services", "b,a,c"}).code, 0);
    write_text(dir.file("logs/notes.txt"), "not a log\n");

    Result globbed = run({"merge", dir.file("logs") + "/*.log"});
    CHECK_EQ(globbed.code, 0);
    CHECK(globbed.err.find("merged 120 entries from 3 files") != std::string::npos);

    // Same result as naming the files explicitly in name order (a, b, c): the expansion is sorted.
    Result explicit_files = run({"merge", dir.file("logs/a.log"), dir.file("logs/b.log"), dir.file("logs/c.log")});
    CHECK_EQ(explicit_files.code, 0);
    CHECK_EQ(globbed.out, explicit_files.out);

    Result single_char = run({"merge", dir.file("logs") + "/?.log"});
    CHECK_EQ(single_char.code, 0);
    CHECK_EQ(single_char.out, explicit_files.out);

    CHECK_EQ(run({"top-errors", dir.file("logs") + "/*.log", "--k", "2"}).code, 0);
    CHECK_EQ(run({"alerts", dir.file("logs") + "/*.log", "--rule", "name=x,threshold=3,window=5s"}).code, 0);
}

TEST(Cli, WildcardErrors) {
    TempDir dir("glob_errors");
    CHECK_EQ(run({"generate", "--out-dir", dir.file("logs"), "--count", "5", "--services", "a"}).code, 0);
    Result none = run({"merge", dir.file("logs") + "/*.zzz"});
    CHECK_EQ(none.code, 1);
    CHECK(none.err.find("no files match") != std::string::npos);
    CHECK_EQ(run({"merge", dir.file("lo*") + "/a.log"}).code, 2);  // wildcards only in the file name
    CHECK_EQ(run({"merge", dir.file("missing-dir") + "/*.log"}).code, 1);
}

TEST(Cli, RulesFileToleratesAUtf8Bom) {
    TempDir dir("rules_bom");
    write_text(dir.file("a.log"), "2026-10-10T00:00:00.000Z ERROR svc boom\n");
    write_text(dir.file("rules.txt"),
               "\xEF\xBB\xBF"
               "# written by PowerShell\n"
               "name=one,threshold=1,window=1s\n");
    Result r = run({"alerts", dir.file("a.log"), "--rules-file", dir.file("rules.txt")});
    CHECK_EQ(r.code, 0);
    CHECK(r.err.find("with 1 rules: 1 alerts") != std::string::npos);

    write_text(dir.file("rules2.txt"),
               "\xEF\xBB\xBF"
               "name=two,threshold=1,window=1s\n");
    CHECK_EQ(run({"alerts", dir.file("a.log"), "--rules-file", dir.file("rules2.txt")}).code, 0);
}

TEST(Cli, RulesFileInUtf16IsRejectedWithAClearMessage) {
    TempDir dir("rules_utf16");
    write_text(dir.file("a.log"), "2026-10-10T00:00:00.000Z ERROR svc boom\n");
    std::string utf16("\xFF\xFE", 2);  // little-endian byte-order mark, then two bytes per character
    for (char c : std::string("name=a,threshold=1,window=1s\n")) {
        utf16 += c;
        utf16 += '\0';
    }
    write_text(dir.file("rules.txt"), utf16);
    Result r = run({"alerts", dir.file("a.log"), "--rules-file", dir.file("rules.txt")});
    CHECK_EQ(r.code, 1);
    CHECK(r.err.find("UTF-16") != std::string::npos);
}

TEST(Cli, RulesFileWithAStrayControlZIsAnErrorNotASilentTruncation) {
    TempDir dir("rules_ctrlz");
    write_text(dir.file("a.log"), "2026-10-10T00:00:00.000Z ERROR svc boom\n");
    write_text(dir.file("rules.txt"),
               "name=a,threshold=2,window=1s\n"
               "\x1A\n"
               "name=b,threshold=1,window=1s\n");
    Result r = run({"alerts", dir.file("a.log"), "--rules-file", dir.file("rules.txt")});
    CHECK_EQ(r.code, 2);  // used to exit 0 with rule b silently dropped
    CHECK(r.err.find("rules.txt:2:") != std::string::npos);
}

TEST(Cli, AlertsRejectsAnEmptyServiceInARule) {
    TempDir dir("alerts_empty_service");
    write_text(dir.file("a.log"), "2026-10-10T00:00:00.000Z ERROR svc boom\n");
    Result r = run({"alerts", dir.file("a.log"), "--rule", "name=x,threshold=1,window=1s,service="});
    CHECK_EQ(r.code, 2);
    CHECK(r.err.find("service must not be empty") != std::string::npos);
}

TEST(Cli, AlertsSummaryReportsSuppressedCrossingsAfterTheLastAlert) {
    TempDir dir("alerts_tail");
    write_text(dir.file("a.log"),
               "2026-10-10T00:00:00.000Z ERROR svc boom\n"
               "2026-10-10T00:00:00.001Z ERROR svc boom\n"
               "2026-10-10T00:00:00.002Z ERROR svc boom\n");
    Result r = run({"alerts", dir.file("a.log"), "--rule", "name=x,threshold=1,window=1s,cooldown=1m"});
    CHECK_EQ(r.code, 0);
    CHECK(r.err.find("1 alerts") != std::string::npos);
    CHECK(r.err.find("2 suppressed crossings after the last alert") != std::string::npos);
}

TEST(Cli, AlertsFailsWhenTheOutputCannotBeWritten) {
    TempDir dir("alerts_write_fail");
    write_text(dir.file("a.log"), "2026-10-10T00:00:00.000Z ERROR svc boom\n");
    FailingBuf buffer;
    std::ostream broken(&buffer);
    std::ostringstream err;
    const int code = run_cli({"alerts", dir.file("a.log"), "--rule", "name=x,threshold=1,window=1s"}, broken, err);
    CHECK_EQ(code, 1);  // used to exit 0 with the alert lost
    CHECK(err.str().find("write failed") != std::string::npos);
}

// ---- Week 3: grep / search / complete ---------------------------------------------------

namespace {

/// Five hand-written entries used by the search tests (document ids 0..4, in file order).
const char* const kSearchLog =
    "2026-10-10T00:00:00.000Z ERROR payment-service Timeout calling bank gateway\n"
    "2026-10-10T00:00:01.000Z ERROR payment-service Connection refused to db-3\n"
    "2026-10-10T00:00:02.000Z INFO auth-service User logged in\n"
    "2026-10-10T00:00:03.000Z WARN payment-service Retry scheduled after timeout\n"
    "2026-10-10T00:00:04.000Z ERROR auth-service Token refused\n";

/// Messages (the part after "service ") of the lines in `out`, in order.
std::vector<std::string> messages_of(const std::string& out) {
    std::vector<std::string> result;
    std::istringstream in(out);
    std::string line;
    while (std::getline(in, line)) {
        // "{timestamp} {LEVEL} {service} {message}": skip three spaces.
        std::size_t pos = 0;
        for (int i = 0; i < 3; ++i) pos = line.find(' ', pos) + 1;
        result.push_back(line.substr(pos));
    }
    return result;
}

}  // namespace

TEST(Cli, GrepCountMatchesABruteForceScan) {
    TempDir dir("grep_count");
    CHECK_EQ(run({"generate", "--out-dir", dir.file("logs"), "--count", "3000", "--services", "a,b"}).code, 0);

    GeneratorConfig config;
    config.services = {"a", "b"};
    LogGenerator gen(config);
    std::size_t expected = 0;
    std::size_t expected_ci = 0;
    for (const auto& stream : gen.generate_all(3000)) {
        for (const LogEntry& e : stream) {
            if (e.message.find("order") != std::string::npos) ++expected;
            std::string lower = e.message;
            for (char& c : lower) {
                if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
            }
            if (lower.find("order") != std::string::npos) ++expected_ci;
        }
    }
    CHECK(expected > 0);

    Result exact = run({"grep", "order", dir.file("logs") + "/*.log", "--count"});
    CHECK_EQ(exact.code, 0);
    CHECK_EQ(exact.out, std::to_string(expected) + "\n");
    Result folded = run({"grep", "ORDER", dir.file("logs") + "/*.log", "--count", "--ignore-case"});
    CHECK_EQ(folded.code, 0);
    CHECK_EQ(folded.out, std::to_string(expected_ci) + "\n");
    Result wrong_case = run({"grep", "ORDER", dir.file("logs") + "/*.log", "--count"});
    CHECK_EQ(wrong_case.out, std::string("0\n"));
}

TEST(Cli, GrepFiltersByLevelAndServiceAndLimitsOutput) {
    TempDir dir("grep_filters");
    write_text(dir.file("a.log"), kSearchLog);

    Result all = run({"grep", "refused", dir.file("a.log")});
    CHECK_EQ(all.code, 0);
    CHECK_EQ(messages_of(all.out), (std::vector<std::string>{"Connection refused to db-3", "Token refused"}));
    CHECK(all.err.find("matched 2 of 5 entries") != std::string::npos);

    Result only_auth = run({"grep", "refused", dir.file("a.log"), "--service", "auth-service"});
    CHECK_EQ(messages_of(only_auth.out), (std::vector<std::string>{"Token refused"}));

    // --level is a MINIMUM: WARN and ERROR entries both qualify.
    Result warn_up = run({"grep", "timeout", dir.file("a.log"), "--level", "warn", "--ignore-case"});
    CHECK_EQ(messages_of(warn_up.out),
             (std::vector<std::string>{"Timeout calling bank gateway", "Retry scheduled after timeout"}));
    Result error_only = run({"grep", "timeout", dir.file("a.log"), "--level", "error", "--ignore-case"});
    CHECK_EQ(messages_of(error_only.out), (std::vector<std::string>{"Timeout calling bank gateway"}));

    Result limited = run({"grep", "e", dir.file("a.log"), "--max", "2"});
    CHECK_EQ(limited.code, 0);
    CHECK_EQ(messages_of(limited.out).size(), std::size_t{2});
    CHECK(limited.err.find("showing the first 2") != std::string::npos);
}

TEST(Cli, GrepUsageErrors) {
    TempDir dir("grep_errors");
    write_text(dir.file("a.log"), kSearchLog);
    CHECK_EQ(run({"grep"}).code, 2);
    CHECK_EQ(run({"grep", "x"}).code, 2);                                  // no file
    CHECK_EQ(run({"grep", "", dir.file("a.log")}).code, 2);                // empty pattern
    CHECK_EQ(run({"grep", "x", dir.file("a.log"), "--count=1"}).code, 2);  // flag with a value
    CHECK_EQ(run({"grep", "x", dir.file("a.log"), "--level", "loud"}).code, 2);
    CHECK_EQ(run({"grep", "x", dir.file("a.log"), "--max", "0"}).code, 2);
    CHECK_EQ(run({"grep", "x", dir.file("missing.log")}).code, 1);
}

TEST(Cli, SearchSupportsAndOrNotAndServiceAndLevelTerms) {
    TempDir dir("search");
    write_text(dir.file("a.log"), kSearchLog);
    const std::string file = dir.file("a.log");

    auto msgs = [&](const std::string& query) {
        Result r = run({"search", query, file});
        CHECK_EQ(r.code, 0);
        return messages_of(r.out);
    };

    CHECK_EQ(msgs("timeout"), (std::vector<std::string>{"Timeout calling bank gateway", "Retry scheduled after timeout"}));
    CHECK_EQ(msgs("TIMEOUT"), msgs("timeout"));  // case-insensitive
    CHECK_EQ(msgs("payment error"), (std::vector<std::string>{"Timeout calling bank gateway", "Connection refused to db-3"}));
    CHECK_EQ(msgs("timeout|refused").size(), std::size_t{4});
    CHECK_EQ(msgs("timeout|refused -retry"),
             (std::vector<std::string>{"Timeout calling bank gateway", "Connection refused to db-3", "Token refused"}));
    CHECK_EQ(msgs("-payment"), (std::vector<std::string>{"User logged in", "Token refused"}));
    CHECK_EQ(msgs("service").size(), std::size_t{5});  // every service name contains "service"
    CHECK_EQ(msgs("zzzz").size(), std::size_t{0});
    CHECK_EQ(msgs("db-3"), (std::vector<std::string>{"Connection refused to db-3"}));  // db AND 3
}

TEST(Cli, SearchCountLimitAndSummary) {
    TempDir dir("search_limit");
    write_text(dir.file("a.log"), kSearchLog);
    Result count = run({"search", "service", dir.file("a.log"), "--count"});
    CHECK_EQ(count.code, 0);
    CHECK_EQ(count.out, std::string("5\n"));
    Result limited = run({"search", "service", dir.file("a.log"), "--limit", "2"});
    CHECK_EQ(limited.code, 0);
    CHECK_EQ(messages_of(limited.out).size(), std::size_t{2});
    CHECK(limited.err.find("5 matches among 5 entries") != std::string::npos);
    CHECK(limited.err.find("showing the first 2") != std::string::npos);
}

TEST(Cli, SearchUsageErrors) {
    TempDir dir("search_errors");
    write_text(dir.file("a.log"), kSearchLog);
    CHECK_EQ(run({"search"}).code, 2);
    CHECK_EQ(run({"search", "x"}).code, 2);
    CHECK_EQ(run({"search", "x", dir.file("a.log"), "--limit", "0"}).code, 2);
    CHECK_EQ(run({"search", "x", dir.file("missing.log")}).code, 1);
    CHECK_EQ(run({"search", "|", dir.file("a.log")}).code, 0);  // odd queries are not errors
}

TEST(Cli, CompleteRanksServicesByCountThenName) {
    TempDir dir("complete_service");
    CHECK_EQ(run({"generate", "--out-dir", dir.file("logs"), "--count", "20", "--services", "zeta,alpha,mid"}).code, 0);
    Result top = run({"complete", dir.file("logs") + "/*.log", "--field", "service", "--k", "2"});
    CHECK_EQ(top.code, 0);
    CHECK(top.out.find("Top 2 service completions of ''") != std::string::npos);
    // All three have 20 entries, so the tie is broken by name: alpha, mid (zeta is cut off).
    CHECK(top.out.find("alpha") != std::string::npos);
    CHECK(top.out.find("mid") != std::string::npos);
    CHECK(top.out.find("zeta") == std::string::npos);
    CHECK(top.out.find("alpha") < top.out.find("mid"));

    Result prefixed = run({"complete", dir.file("logs") + "/*.log", "--field", "service", "--prefix", "m"});
    CHECK(prefixed.out.find("mid") != std::string::npos);
    CHECK(prefixed.out.find("alpha") == std::string::npos);
    Result none = run({"complete", dir.file("logs") + "/*.log", "--field", "service", "--prefix", "q"});
    CHECK_EQ(none.code, 0);
    CHECK(none.out.find("no service starts with 'q'") != std::string::npos);
}

TEST(Cli, CompleteSignaturesMatchesTheLibraryTrie) {
    TempDir dir("complete_signature");
    CHECK_EQ(run({"generate", "--out-dir", dir.file("logs"), "--count", "3000", "--services", "a,b"}).code, 0);

    GeneratorConfig config;
    config.services = {"a", "b"};
    LogGenerator gen(config);
    loganalyzer::Trie trie;
    for (const auto& stream : gen.generate_all(3000)) {
        for (const LogEntry& e : stream) {
            const std::string signature = loganalyzer::normalize_signature(e.message);
            if (!signature.empty()) trie.insert(signature);
        }
    }
    const std::vector<loganalyzer::Completion> expected = trie.complete("Payment", 2);
    CHECK_EQ(expected.size(), std::size_t{2});  // three "Payment ..." signatures exist; k cuts it to two

    Result r = run({"complete", dir.file("logs") + "/*.log", "--prefix", "Payment", "--k", "2"});
    CHECK_EQ(r.code, 0);
    std::size_t cursor = 0;
    for (const loganalyzer::Completion& c : expected) {
        const std::size_t at = r.out.find(std::to_string(c.weight) + "  " + c.key + "\n", cursor);
        CHECK(at != std::string::npos);  // rows appear in the library's order
        cursor = at;
    }
}

TEST(Cli, CompleteWordsIsCaseInsensitiveAndMinLevelFilters) {
    TempDir dir("complete_word");
    write_text(dir.file("a.log"),
               "2026-10-10T00:00:00.000Z ERROR svc Timeout one\n"
               "2026-10-10T00:00:01.000Z ERROR svc Timeout two\n"
               "2026-10-10T00:00:02.000Z INFO svc Timeout three\n"
               "2026-10-10T00:00:03.000Z INFO svc Timer fired\n");
    Result r = run({"complete", dir.file("a.log"), "--field", "word", "--prefix", "TIM"});
    CHECK_EQ(r.code, 0);
    CHECK(r.out.find("3  timeout") != std::string::npos);
    CHECK(r.out.find("1  timer") != std::string::npos);
    CHECK(r.out.find("timeout") < r.out.find("timer"));

    Result errors_only = run({"complete", dir.file("a.log"), "--field", "word", "--prefix", "tim", "--min-level", "error"});
    CHECK(errors_only.out.find("2  timeout") != std::string::npos);
    CHECK(errors_only.out.find("timer") == std::string::npos);
}

TEST(Cli, CompleteUsageErrors) {
    TempDir dir("complete_errors");
    write_text(dir.file("a.log"), kSearchLog);
    CHECK_EQ(run({"complete"}).code, 2);
    CHECK_EQ(run({"complete", dir.file("a.log"), "--field", "bogus"}).code, 2);
    CHECK_EQ(run({"complete", dir.file("a.log"), "--k", "0"}).code, 2);
    CHECK_EQ(run({"complete", dir.file("a.log"), "--min-level", "loud"}).code, 2);
    CHECK_EQ(run({"complete", dir.file("missing.log")}).code, 1);
}

// ---- Week 4: report ----------------------------------------------------------------------

namespace {

std::string read_text(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

std::size_t occurrences(const std::string& haystack, const std::string& needle) {
    std::size_t n = 0;
    for (std::size_t pos = haystack.find(needle); pos != std::string::npos; pos = haystack.find(needle, pos + needle.size())) ++n;
    return n;
}

}  // namespace

TEST(Cli, ReportWritesASelfContainedHtmlFile) {
    TempDir dir("report");
    CHECK_EQ(run({"generate", "--out-dir", dir.file("logs"), "--count", "500", "--services", "a,b"}).code, 0);
    Result r = run({"report", dir.file("logs") + "/*.log", "--out", dir.file("report.html"), "--title", "My <report>",
                    "--top", "3", "--buckets", "20"});
    CHECK_EQ(r.code, 0);
    CHECK(r.err.find("report: 1000 entries, 0 alerts") != std::string::npos);

    const std::string html = read_text(dir.file("report.html"));
    CHECK(html.compare(0, 15, "<!doctype html>") == 0);
    CHECK(html.find("<title>My &lt;report&gt;</title>") != std::string::npos);
    CHECK_EQ(occurrences(html, "<g class=\"bucket\">"), std::size_t{20});
    CHECK(html.find("<b>1000</b><span>entries</span>") != std::string::npos);
    CHECK(html.find("Top error signatures") != std::string::npos);
    CHECK(html.find("<script") == std::string::npos);
    CHECK(html.find("http://") == std::string::npos && html.find("https://") == std::string::npos);  // no external resources
}

TEST(Cli, ReportWithRulesListsTheAlertsTheyFire) {
    TempDir dir("report_rules");
    write_text(dir.file("a.log"),
               "2026-10-10T00:00:00.000Z ERROR svc boom 1\n"
               "2026-10-10T00:00:00.100Z ERROR svc boom 2\n"
               "2026-10-10T00:00:00.200Z ERROR svc boom 3\n");
    Result r = run({"report", dir.file("a.log"), "--out", dir.file("r.html"), "--rule", "name=burst,threshold=3,window=1s"});
    CHECK_EQ(r.code, 0);
    CHECK(r.err.find("3 entries, 1 alerts") != std::string::npos);
    const std::string html = read_text(dir.file("r.html"));
    CHECK(html.find("<b>1</b><span>alerts fired</span>") != std::string::npos);
    CHECK(html.find("<td>burst</td>") != std::string::npos);
}

TEST(Cli, ReportToStdoutAndErrors) {
    TempDir dir("report_errors");
    write_text(dir.file("a.log"), "2026-10-10T00:00:01.000Z INFO svc fine\n");
    Result r = run({"report", dir.file("a.log")});
    CHECK_EQ(r.code, 0);
    CHECK(r.out.compare(0, 15, "<!doctype html>") == 0);
    CHECK(r.out.find("No ERROR entries.") != std::string::npos);

    CHECK_EQ(run({"report"}).code, 2);
    CHECK_EQ(run({"report", dir.file("a.log"), "--top", "0"}).code, 2);
    CHECK_EQ(run({"report", dir.file("a.log"), "--buckets", "401"}).code, 2);
    CHECK_EQ(run({"report", dir.file("a.log"), "--rule", "name=x"}).code, 2);
    CHECK_EQ(run({"report", dir.file("missing.log")}).code, 1);
    CHECK_EQ(run({"report", dir.file("a.log"), "--out", dir.file("no-such-dir") + "/r.html"}).code, 1);

    // Unsorted input is fine for a plain report (nothing needs the order), an error once rules do.
    write_text(dir.file("unsorted.log"),
               "2026-10-10T00:00:02.000Z INFO svc second\n"
               "2026-10-10T00:00:01.000Z INFO svc first\n");
    CHECK_EQ(run({"report", dir.file("unsorted.log")}).code, 0);
    CHECK_EQ(run({"report", dir.file("unsorted.log"), "--rule", "name=x,threshold=1,window=1s"}).code, 1);
}
