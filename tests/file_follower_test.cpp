// GCC 15 assumes a replaced operator new touches no program state and may move allocations across the
// reads of the allocation counters; see kmp_test.cpp.
#if defined(__GNUC__) && !defined(__clang__) && __GNUC__ >= 15
#pragma GCC optimize("no-assume-sane-operators-new-delete")
#endif
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <locale>
#include <new>
#include <random>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

// Two tests need the platform: making a file unreadable without deleting it (a sharing violation on
// Windows, chmod 000 elsewhere) and creating a FIFO. The code under test is plain standard C++.
#if defined(_MSC_VER)
#include <share.h>
#elif defined(__unix__) || defined(__APPLE__)
#define FOLLOWER_TEST_POSIX 1
#include <sys/stat.h>
#include <unistd.h>
#endif

#include "alloc_probe.hpp"
#include "loganalyzer/file_follower.hpp"
#include "loganalyzer/log_generator.hpp"
#include "loganalyzer/log_parser.hpp"
#include "testkit.hpp"

using namespace loganalyzer;

// ---------------------------------------------------------------------------
// Allocation probe
//
// The global operator new is replaced for the whole test program (see alloc_probe.hpp). It counts
// the bytes that are requested and can be told to fail the Nth next allocation with
// std::bad_alloc. That is what lets the tests observe a poll's heap use (not only the size of what
// the follower says it buffers) and drive std::bad_alloc through every allocation of a poll.
// ---------------------------------------------------------------------------

namespace {

namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// Scratch files
// ---------------------------------------------------------------------------

// A private directory under the system temp dir, removed again when the test ends (also when a
// CHECK throws). The name carries a counter, the clock and a random number, so tests running in
// parallel processes cannot collide.
class Scratch {
public:
    Scratch() {
        static unsigned counter = 0;
        std::random_device entropy;
        const auto ticks = std::chrono::steady_clock::now().time_since_epoch().count();
        dir_ = fs::temp_directory_path() / ("loganalyzer_follow_" + std::to_string(ticks) + "_" +
                                            std::to_string(++counter) + "_" + std::to_string(entropy()));
        fs::create_directories(dir_);
    }
    ~Scratch() {
        std::error_code ec;
        fs::remove_all(dir_, ec);
    }
    Scratch(const Scratch&) = delete;
    Scratch& operator=(const Scratch&) = delete;

    std::string path(const std::string& name) const { return (dir_ / name).string(); }

private:
    fs::path dir_;
};

void write_file(const std::string& path, const std::string& data) {  // create or replace
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(data.data(), static_cast<std::streamsize>(data.size()));
    out.flush();
    CHECK(static_cast<bool>(out));
}

void append_file(const std::string& path, const std::string& data) {  // creates the file if needed
    std::ofstream out(path, std::ios::binary | std::ios::app);
    out.write(data.data(), static_cast<std::streamsize>(data.size()));
    out.flush();
    CHECK(static_cast<bool>(out));
}

void remove_file(const std::string& path) {
    std::error_code ec;
    CHECK(fs::remove(path, ec));
    CHECK(!ec);
}

std::uint64_t size_of(const std::string& path) { return static_cast<std::uint64_t>(fs::file_size(path)); }

// ---------------------------------------------------------------------------
// Log text
// ---------------------------------------------------------------------------

LogEntry make_entry(int n) {
    LogEntry e;
    e.timestamp_ms = 1791590400000 + static_cast<std::int64_t>(n) * 1000;
    e.level = Level::Info;
    e.service = "svc";
    e.message = "m" + std::to_string(n);
    return e;
}

// "2026-10-10T00:00:0N.000Z INFO svc mN" + '\n': 37 bytes for N in 1..9, 38 for 10..99.
std::string line_of(int n) { return format_entry(make_entry(n)) + "\n"; }

std::string lines_of(int first, int last) {
    std::string text;
    for (int n = first; n <= last; ++n) text += line_of(n);
    return text;
}

// The messages of the entries, space separated: readable in a failing CHECK_EQ.
std::string names(const std::vector<LogEntry>& entries) {
    std::string text;
    for (const LogEntry& e : entries) {
        if (!text.empty()) text += ' ';
        text += e.message;
    }
    return text;
}

const std::string kBomText = "\xEF\xBB\xBF";

void check_same_entries(const std::vector<LogEntry>& actual, const std::vector<LogEntry>& expected) {
    CHECK_EQ(actual.size(), expected.size());
    for (std::size_t i = 0; i < expected.size(); ++i) {
        if (actual[i] != expected[i]) {
            throw testkit::Failure{"entry " + std::to_string(i) + " differs: got '" + format_entry(actual[i]) +
                                   "', expected '" + format_entry(expected[i]) + "'"};
        }
    }
}

struct Parsed {
    std::vector<LogEntry> entries;
    std::size_t malformed = 0;
};

Parsed parse_whole(const std::string& text) {
    std::istringstream in(text);
    Parsed result;
    result.entries = parse_stream(in, &result.malformed);
    return result;
}

FollowerOptions from_end() {
    FollowerOptions options;
    options.from_start = false;
    return options;
}

// Polls until the backlog is gone and appends everything delivered to `all`.
void poll_all(FileFollower& f, std::vector<LogEntry>& all) {
    int guard = 0;
    do {
        std::vector<LogEntry> got = f.poll();
        all.insert(all.end(), std::make_move_iterator(got.begin()), std::make_move_iterator(got.end()));
        CHECK(++guard < 100000);
    } while (f.backlog());
}

// ---------------------------------------------------------------------------
// Files that exist but cannot be opened
// ---------------------------------------------------------------------------

// Makes a file impossible to open for reading, without deleting or hiding it, until release() or
// the destruction: the situation of a log that a virus scanner or a writer with an exclusive share
// mode holds. On Windows the file is held open with share mode "deny read and write"; elsewhere
// its permissions are cleared. A superuser can still read such a file, in which case active() is
// false and the test has nothing to test.
class ReadLock {
public:
    explicit ReadLock(const std::string& path) : path_(path) {
#ifdef _MSC_VER
        held_.open(path.c_str(), std::ios::binary | std::ios::app, _SH_DENYRW);
        active_ = held_.is_open();
#else
        std::error_code ec;
        saved_ = fs::status(path, ec).permissions();
        if (ec) return;
        fs::permissions(path, fs::perms::none, ec);
        if (ec) return;
        active_ = !std::ifstream(path, std::ios::binary).is_open();
        if (!active_) fs::permissions(path, saved_, ec);
#endif
    }
    ~ReadLock() { release(); }
    ReadLock(const ReadLock&) = delete;
    ReadLock& operator=(const ReadLock&) = delete;

    bool active() const { return active_; }

    void release() {
        if (!active_) return;
        active_ = false;
#ifdef _MSC_VER
        held_.close();
#else
        std::error_code ec;
        fs::permissions(path_, saved_, ec);
#endif
    }

private:
    std::string path_;
    bool active_ = false;
#ifdef _MSC_VER
    std::ofstream held_;
#else
    fs::perms saved_ = fs::perms::none;
#endif
};

bool locking_works(const ReadLock& lock) {
    if (lock.active()) return true;
    std::cerr << "    (skipped: this account or platform cannot make a file unreadable)\n";
    return false;
}

// ---------------------------------------------------------------------------
// Allocation probe helpers (see the replaced operator new above)
// ---------------------------------------------------------------------------

// Makes the Nth next allocation fail, until destroyed. fired() says whether it did.
class AllocationFault {
public:
    explicit AllocationFault(long n) { alloc_probe::fail_in.store(n); }
    ~AllocationFault() { alloc_probe::fail_in.store(0); }
    AllocationFault(const AllocationFault&) = delete;
    AllocationFault& operator=(const AllocationFault&) = delete;
    bool fired() const { return alloc_probe::fail_in.load() == 0; }
};

struct AllocationUse {
    long long total = 0;  // bytes requested while `body` ran
    long long peak = 0;   // the most that was live at once, above what was live before
};

template <class Body>
AllocationUse measure(Body&& body) {
    const long long live_before = alloc_probe::live.load();
    const long long total_before = alloc_probe::total.load();
    alloc_probe::peak.store(live_before);
    body();
    AllocationUse use;
    use.total = alloc_probe::total.load() - total_before;
    use.peak = alloc_probe::peak.load() - live_before;
    return use;
}

// ---------------------------------------------------------------------------
// A program-wide locale with an unusual narrow-character facet
// ---------------------------------------------------------------------------

// Turns lowercase ASCII into uppercase while reading, one byte for one byte, standing in for the
// "exotic but legal" locale a host application might install with std::locale::global.
class ShoutingCodecvt : public std::codecvt<char, char, std::mbstate_t> {
protected:
    bool do_always_noconv() const noexcept override { return false; }
    int do_encoding() const noexcept override { return 1; }
    int do_max_length() const noexcept override { return 1; }
    int do_length(std::mbstate_t&, const char* from, const char* end, std::size_t max) const override {
        return static_cast<int>(std::min<std::size_t>(max, static_cast<std::size_t>(end - from)));
    }
    result do_in(std::mbstate_t&, const char* from, const char* from_end, const char*& from_next, char* to,
                 char* to_end, char*& to_next) const override {
        while (from < from_end && to < to_end) {
            const char c = *from++;
            *to++ = (c >= 'a' && c <= 'z') ? static_cast<char>(c - 'a' + 'A') : c;
        }
        from_next = from;
        to_next = to;
        return from == from_end ? ok : partial;
    }
    result do_out(std::mbstate_t&, const char* from, const char* from_end, const char*& from_next, char* to,
                  char* to_end, char*& to_next) const override {
        while (from < from_end && to < to_end) *to++ = *from++;
        from_next = from;
        to_next = to;
        return from == from_end ? ok : partial;
    }
};

class GlobalLocale {
public:
    explicit GlobalLocale(const std::locale& locale) : previous_(std::locale::global(locale)) {}
    ~GlobalLocale() { std::locale::global(previous_); }
    GlobalLocale(const GlobalLocale&) = delete;
    GlobalLocale& operator=(const GlobalLocale&) = delete;

private:
    std::locale previous_;
};

#ifdef FOLLOWER_TEST_POSIX
// Turns a poll() that blocks forever into a crash with a clear signal instead of a hung build.
class WatchDog {
public:
    WatchDog() { ::alarm(60); }
    ~WatchDog() { ::alarm(0); }
    WatchDog(const WatchDog&) = delete;
    WatchDog& operator=(const WatchDog&) = delete;
};
#endif

// ---------------------------------------------------------------------------
// Property-test inputs
// ---------------------------------------------------------------------------

// Generated log lines mixed with what real files contain: LF and CRLF endings, blank and
// blank-looking lines, junk, a bad level, a line with NUL and high bytes, and optionally a BOM.
struct MessyText {
    std::string text;
    std::vector<std::size_t> newlines;  // offset of every '\n'
};

MessyText make_messy_text(std::uint64_t seed, std::vector<std::string> services, std::size_t per_service, bool bom) {
    std::mt19937_64 rng(seed);
    GeneratorConfig config;
    config.seed = seed;
    config.services = std::move(services);
    LogGenerator generator(config);

    MessyText result;
    std::string& text = result.text;
    if (bom) text += kBomText;
    int index = 0;
    for (const std::vector<LogEntry>& stream : generator.generate_all(per_service)) {
        for (const LogEntry& entry : stream) {
            ++index;
            switch (rng() % 14) {
                case 0: text += "\n"; break;
                case 1: text += "  \t \r\n"; break;
                case 2: text += "not a log line " + std::to_string(index) + "\n"; break;
                case 3: text += "2026-10-10T00:00:00Z TRACE svc bad level\n"; break;
                case 4: {
                    std::string odd = "2026-10-10T00:00:00Z INFO " + config.services.front() + " nul";
                    odd.push_back('\0');
                    odd += "byte \xFF" "\x80" " \xC3\xA9 end\n";
                    text += odd;
                    break;
                }
                default: break;
            }
            text += format_entry(entry);
            text += (rng() % 4 == 0) ? "\r\n" : "\n";
        }
    }
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (text[i] == '\n') result.newlines.push_back(i);
    }
    return result;
}

// Offsets at which the text is cut into the pieces a writer produces, past the first `existing`
// bytes. Per line, with the given probability, one cut at a place that is hard for a line
// assembler: inside the timestamp, right before the LF (between CR and LF in a CRLF line), right
// after the LF, or anywhere in the line; a BOM is cut inside; and `extra` uniformly random cuts.
// Every poll costs real time here (a virus scanner looks at a file that was just written, 3-13 ms
// per poll on the development machine), so the tests cut at the interesting places instead of
// at every byte.
std::vector<std::size_t> choose_cuts(std::mt19937_64& rng, const MessyText& messy, std::size_t existing,
                                     unsigned percent_of_lines, std::size_t extra) {
    const std::string& text = messy.text;
    std::set<std::size_t> cuts;
    if (text.compare(0, kBomText.size(), kBomText) == 0) {
        cuts.insert(1);
        cuts.insert(2);
    }
    std::size_t start = 0;
    for (const std::size_t end : messy.newlines) {
        if (rng() % 100 < percent_of_lines) {
            const std::size_t length = end - start;
            switch (rng() % 4) {
                case 0:
                    if (length > 0) cuts.insert(start + 1 + rng() % std::min<std::size_t>(24, length));
                    break;
                case 1: cuts.insert(end); break;
                case 2: cuts.insert(end + 1); break;
                default: cuts.insert(start + rng() % (length + 1)); break;
            }
        }
        start = end + 1;
    }
    for (std::size_t i = 0; i < extra; ++i) cuts.insert(rng() % text.size());

    std::vector<std::size_t> result;
    for (const std::size_t cut : cuts) {
        if (cut > existing && cut < text.size()) result.push_back(cut);
    }
    return result;
}

// text[existing, size) cut at `cuts` (ascending, all inside it).
std::vector<std::string> split_at(const std::string& text, std::size_t existing, const std::vector<std::size_t>& cuts) {
    std::vector<std::string> pieces;
    std::size_t pos = existing;
    for (const std::size_t cut : cuts) {
        pieces.push_back(text.substr(pos, cut - pos));
        pos = cut;
    }
    if (pos < text.size()) pieces.push_back(text.substr(pos));
    return pieces;
}

// What a follower started with from_start == false should deliver for a file that held
// text[0, cut) at that moment: the rest, except that a line cut in two is skipped as a whole,
// and a file holding only a BOM counts as empty.
std::string text_after_snapshot(const std::string& text, std::size_t cut) {
    if (cut == 0 || cut >= text.size()) return cut == 0 ? text : std::string();
    if (cut == kBomText.size() && text.compare(0, cut, kBomText) == 0) return text.substr(cut);
    if (text[cut - 1] == '\n') return text.substr(cut);
    const std::size_t newline = text.find('\n', cut);
    return newline == std::string::npos ? std::string() : text.substr(newline + 1);
}

}  // namespace

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

TEST(FileFollower, ConstructorRejectsInvalidArguments) {
    CHECK_THROWS(FileFollower(std::vector<std::string>{}), std::invalid_argument);
    CHECK_THROWS(FileFollower(std::vector<std::string>{""}), std::invalid_argument);
    CHECK_THROWS(FileFollower(std::vector<std::string>{"a.log", ""}), std::invalid_argument);
    CHECK_THROWS(FileFollower(std::vector<std::string>{"", "a.log"}), std::invalid_argument);

    FollowerOptions no_line;
    no_line.max_line_bytes = 0;
    CHECK_THROWS(FileFollower(std::vector<std::string>{"a.log"}, no_line), std::invalid_argument);
    FollowerOptions no_poll;
    no_poll.max_bytes_per_poll = 0;
    CHECK_THROWS(FileFollower(std::vector<std::string>{"a.log"}, no_poll), std::invalid_argument);

    // The smallest legal values are legal.
    FollowerOptions tiny;
    tiny.max_line_bytes = 1;
    tiny.max_bytes_per_poll = 1;
    FileFollower f(std::vector<std::string>{"a.log", "b.log", "c.log"}, tiny);
    CHECK_EQ(f.file_count(), std::size_t{3});
    CHECK(!f.backlog());
    CHECK_EQ(f.buffered_bytes(), std::size_t{0});
}

TEST(FileFollower, ConstructorDefaultsAndDoesNotTouchTheFiles) {
    const FollowerOptions defaults{};
    CHECK(defaults.from_start);
    CHECK_EQ(defaults.max_line_bytes, std::size_t{1} << 20);
    CHECK_EQ(defaults.max_bytes_per_poll, std::size_t{16} << 20);

    Scratch dir;
    const std::string path = dir.path("not-yet.log");
    FileFollower f({path});
    CHECK_EQ(f.file_count(), std::size_t{1});
    CHECK(!fs::exists(path));  // constructing does not create anything
    const FollowStats& stats = f.stats();
    CHECK_EQ(stats.entries, std::uint64_t{0});
    CHECK_EQ(stats.malformed, std::uint64_t{0});
    CHECK_EQ(stats.bytes, std::uint64_t{0});
    CHECK_EQ(stats.rotations, std::uint64_t{0});
}

// ---------------------------------------------------------------------------
// Basic following
// ---------------------------------------------------------------------------

TEST(FileFollower, FromStartDeliversExistingContentThenOnlyAppends) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    write_file(path, lines_of(1, 3));

    FileFollower f({path});
    CHECK_EQ(names(f.poll()), std::string("m1 m2 m3"));
    CHECK_EQ(names(f.poll()), std::string());  // nothing new
    CHECK_EQ(names(f.poll()), std::string());

    append_file(path, lines_of(4, 5));
    CHECK_EQ(names(f.poll()), std::string("m4 m5"));
    CHECK_EQ(names(f.poll()), std::string());

    CHECK_EQ(f.stats().entries, std::uint64_t{5});
    CHECK_EQ(f.stats().malformed, std::uint64_t{0});
    CHECK_EQ(f.stats().bytes, size_of(path));
    CHECK_EQ(f.stats().rotations, std::uint64_t{0});
    CHECK(!f.backlog());
    CHECK_EQ(f.buffered_bytes(), std::size_t{0});
}

TEST(FileFollower, EntriesAreTheSameAsParseLineProduces) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    const std::string text = "2026-10-10T12:00:00.123Z error payment-service  Timeout  after 3000ms \n";
    write_file(path, text);
    FileFollower f({path});
    const std::vector<LogEntry> got = f.poll();
    CHECK_EQ(got.size(), std::size_t{1});
    const auto expected = parse_line(text.substr(0, text.size() - 1));
    CHECK(expected.has_value());
    CHECK(got[0] == *expected);
    CHECK(got[0].level == Level::Error);
    CHECK_EQ(got[0].message, std::string(" Timeout  after 3000ms "));
}

TEST(FileFollower, FromStartFalseSkipsExistingContent) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    write_file(path, lines_of(1, 3));

    FileFollower f({path}, from_end());
    CHECK_EQ(names(f.poll()), std::string());  // the first poll only records where the file ends
    CHECK_EQ(f.stats().bytes, std::uint64_t{0});
    CHECK_EQ(f.stats().entries, std::uint64_t{0});
    CHECK_EQ(names(f.poll()), std::string());

    append_file(path, lines_of(4, 5));
    CHECK_EQ(names(f.poll()), std::string("m4 m5"));
    CHECK_EQ(f.stats().entries, std::uint64_t{2});
    CHECK_EQ(f.stats().bytes, size_of(path) - lines_of(1, 3).size());  // the skipped part is not counted
    CHECK_EQ(f.stats().rotations, std::uint64_t{0});
}

TEST(FileFollower, FromStartFalseSkipsALineThatWasOnlyHalfWrittenAtTheFirstPoll) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    const std::string third = line_of(3);
    write_file(path, lines_of(1, 2) + third.substr(0, 20));

    FileFollower f({path}, from_end());
    CHECK_EQ(names(f.poll()), std::string());
    // The rest of line 3 is not a line of its own: it is skipped, silently, with line 3's head.
    append_file(path, third.substr(20) + lines_of(4, 4));
    CHECK_EQ(names(f.poll()), std::string("m4"));
    CHECK_EQ(f.stats().malformed, std::uint64_t{0});
    CHECK_EQ(f.stats().entries, std::uint64_t{1});
}

TEST(FileFollower, FromStartFalseTreatsAFileHoldingOnlyABomAsEmpty) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    write_file(path, kBomText);
    FileFollower f({path}, from_end());
    CHECK_EQ(names(f.poll()), std::string());
    append_file(path, lines_of(1, 2));
    CHECK_EQ(names(f.poll()), std::string("m1 m2"));
    CHECK_EQ(f.stats().malformed, std::uint64_t{0});
}

TEST(FileFollower, FromStartFalseEmptyFileDeliversEverythingLater) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    write_file(path, "");
    FileFollower f({path}, from_end());
    CHECK_EQ(names(f.poll()), std::string());
    append_file(path, kBomText + lines_of(1, 2));  // the BOM is still at the start of the file
    CHECK_EQ(names(f.poll()), std::string("m1 m2"));
    CHECK_EQ(f.stats().malformed, std::uint64_t{0});
}

TEST(FileFollower, FromStartFalseReadsFilesThatAppearLaterFromTheirFirstByte) {
    Scratch dir;
    const std::string present = dir.path("present.log");
    const std::string later = dir.path("later.log");
    write_file(present, lines_of(1, 2));

    FileFollower f({later, present}, from_end());
    CHECK_EQ(names(f.poll()), std::string());  // "later" does not exist; "present" is recorded

    write_file(later, lines_of(10, 11));  // appears with content already in it
    append_file(present, lines_of(3, 3));
    CHECK_EQ(names(f.poll()), std::string("m10 m11 m3"));  // whole new file, then the append
    CHECK_EQ(f.stats().rotations, std::uint64_t{0});        // a first appearance is not a rotation
}

TEST(FileFollower, MissingFilesAreNotErrors) {
    Scratch dir;
    FileFollower f({dir.path("nope.log"), dir.path("nor-this.log")});
    for (int i = 0; i < 3; ++i) CHECK(f.poll().empty());
    CHECK(!f.backlog());
    CHECK_EQ(f.stats().bytes, std::uint64_t{0});
    CHECK_EQ(f.stats().entries, std::uint64_t{0});
    CHECK_EQ(f.stats().rotations, std::uint64_t{0});
}

TEST(FileFollower, AFileThatAppearsLaterIsReadFromTheStart) {
    Scratch dir;
    const std::string path = dir.path("late.log");
    FileFollower f({path});
    CHECK(f.poll().empty());
    CHECK(f.poll().empty());
    write_file(path, lines_of(1, 2));
    CHECK_EQ(names(f.poll()), std::string("m1 m2"));
    append_file(path, lines_of(3, 3));
    CHECK_EQ(names(f.poll()), std::string("m3"));
    CHECK_EQ(f.stats().rotations, std::uint64_t{0});
}

TEST(FileFollower, ADirectoryInPlaceOfAFileIsHarmless) {
    Scratch dir;
    const std::string path = dir.path("dir.log");
    fs::create_directory(path);
    FileFollower f({path});
    for (int i = 0; i < 3; ++i) {
        CHECK(f.poll().empty());
        CHECK(!f.backlog());  // an unreadable path must never make a `while (backlog())` loop spin
    }
    CHECK_EQ(f.stats().bytes, std::uint64_t{0});
}

TEST(FileFollower, HoldsNoFileHandleBetweenPolls) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    const std::string moved = dir.path("a.log.1");
    write_file(path, lines_of(1, 2));
    FileFollower f({path});
    CHECK_EQ(names(f.poll()), std::string("m1 m2"));

    // On Windows both would fail if the follower still had the file open.
    std::error_code ec;
    fs::rename(path, moved, ec);
    CHECK(!ec);
    remove_file(moved);
    CHECK(f.poll().empty());
}

TEST(FileFollower, IdlePollsDoNotChangeAnything) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    write_file(path, lines_of(1, 2));
    FileFollower f({path});
    f.poll();
    const FollowStats before = f.stats();
    for (int i = 0; i < 50; ++i) CHECK(f.poll().empty());
    CHECK_EQ(f.stats().entries, before.entries);
    CHECK_EQ(f.stats().bytes, before.bytes);
    CHECK_EQ(f.stats().malformed, before.malformed);
    CHECK_EQ(f.stats().rotations, before.rotations);
}

// ---------------------------------------------------------------------------
// Partial lines, CRLF, BOM, blank and malformed lines
// ---------------------------------------------------------------------------

TEST(FileFollower, PartialLineIsCompletedAcrossThreePolls) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    const std::string line = line_of(1);  // 37 bytes with the newline
    write_file(path, line.substr(0, 10));  // inside the timestamp

    FileFollower f({path});
    CHECK(f.poll().empty());
    CHECK_EQ(f.buffered_bytes(), std::size_t{10});

    append_file(path, line.substr(10, 20));
    CHECK(f.poll().empty());
    CHECK_EQ(f.buffered_bytes(), std::size_t{30});

    append_file(path, line.substr(30));  // the rest, with the terminating newline
    CHECK_EQ(names(f.poll()), std::string("m1"));
    CHECK_EQ(f.buffered_bytes(), std::size_t{0});
    CHECK_EQ(f.stats().entries, std::uint64_t{1});
    CHECK_EQ(f.stats().malformed, std::uint64_t{0});
    CHECK_EQ(f.stats().bytes, std::uint64_t{37});
}

TEST(FileFollower, ACompleteLineIsDeliveredWhileTheNextOneStaysBuffered) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    const std::string second = line_of(2);
    write_file(path, line_of(1) + second.substr(0, 15));
    FileFollower f({path});
    CHECK_EQ(names(f.poll()), std::string("m1"));
    CHECK_EQ(f.buffered_bytes(), std::size_t{15});
    append_file(path, second.substr(15));
    CHECK_EQ(names(f.poll()), std::string("m2"));
}

TEST(FileFollower, AFinalLineWithoutANewlineIsNeverDelivered) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    const std::string last = format_entry(make_entry(2));  // no '\n'
    write_file(path, line_of(1) + last);
    FileFollower f({path});
    CHECK_EQ(names(f.poll()), std::string("m1"));
    CHECK(f.poll().empty());
    CHECK_EQ(f.buffered_bytes(), last.size());
    CHECK_EQ(f.stats().bytes, size_of(path));  // consumed (buffered), just not delivered

    append_file(path, "\n");  // the writer finishes the line later
    CHECK_EQ(names(f.poll()), std::string("m2"));
}

TEST(FileFollower, CrlfLinesAreAcceptedAsParseLineAcceptsThem) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    write_file(path,
               "2026-10-10T00:00:01Z INFO svc first\r\n"
               "2026-10-10T00:00:02Z WARN svc second \r\n"
               "\r\n"
               "2026-10-10T00:00:03Z ERROR svc\r\n"      // trailing space trimmed: empty message
               "2026-10-10T00:00:04Z INFO svc twice\r\r\n");  // only one CR is a line ending
    FileFollower f({path});
    const std::vector<LogEntry> got = f.poll();
    CHECK_EQ(got.size(), std::size_t{4});
    CHECK_EQ(got[0].message, std::string("first"));
    CHECK_EQ(got[1].message, std::string("second "));  // the space stays, only the CR is gone
    CHECK_EQ(got[2].message, std::string());
    CHECK_EQ(got[3].message, std::string("twice\r"));
    CHECK_EQ(f.stats().malformed, std::uint64_t{0});
}

TEST(FileFollower, ACarriageReturnAndItsLineFeedMayArriveInDifferentPolls) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    write_file(path, format_entry(make_entry(1)) + "\r");  // CR written, LF not yet
    FileFollower f({path});
    CHECK(f.poll().empty());
    append_file(path, "\n");
    const std::vector<LogEntry> got = f.poll();
    CHECK_EQ(got.size(), std::size_t{1});
    CHECK_EQ(got[0].message, std::string("m1"));  // no '\r' left in the message
    CHECK_EQ(f.stats().malformed, std::uint64_t{0});
}

TEST(FileFollower, Utf8BomAtTheStartOfTheFileIsSkipped) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    write_file(path, kBomText + lines_of(1, 2));
    FileFollower f({path});
    CHECK_EQ(names(f.poll()), std::string("m1 m2"));
    CHECK_EQ(f.stats().malformed, std::uint64_t{0});
    CHECK_EQ(f.stats().bytes, size_of(path));  // the BOM counts as consumed
}

TEST(FileFollower, ABomWrittenInPiecesIsStillRecognised) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    write_file(path, "\xEF");
    FileFollower f({path});
    CHECK(f.poll().empty());
    append_file(path, "\xBB");
    CHECK(f.poll().empty());
    append_file(path, std::string("\xBF") + line_of(1));
    CHECK_EQ(names(f.poll()), std::string("m1"));
    CHECK_EQ(f.stats().malformed, std::uint64_t{0});
}

TEST(FileFollower, OnlyTheLeadingBomIsSkipped) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    write_file(path, line_of(1) + kBomText + line_of(2));
    FileFollower f({path});
    CHECK_EQ(names(f.poll()), std::string("m1"));  // the second line starts with the BOM: malformed
    CHECK_EQ(f.stats().malformed, std::uint64_t{1});

    // A BOM-only first line is just a blank line; a truncated BOM is junk.
    const std::string only = dir.path("only.log");
    write_file(only, kBomText + "\n\r\n");
    const std::string cut = dir.path("cut.log");
    write_file(cut, std::string("\xEF\xBB\n") + line_of(1));
    FileFollower g({only, cut});
    CHECK_EQ(names(g.poll()), std::string("m1"));
    CHECK_EQ(g.stats().malformed, std::uint64_t{1});
}

TEST(FileFollower, ABomAfterAFromStartFalseSnapshotOfANonEmptyFileIsNotAtTheFileStart) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    write_file(path, lines_of(1, 2));
    FileFollower f({path}, from_end());
    CHECK(f.poll().empty());
    append_file(path, kBomText + line_of(3) + line_of(4));  // the BOM is mid-file: part of line 3
    CHECK_EQ(names(f.poll()), std::string("m4"));
    CHECK_EQ(f.stats().malformed, std::uint64_t{1});
}

TEST(FileFollower, ANewFileAfterARotationMayStartWithABomToo) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    write_file(path, lines_of(1, 2));
    FileFollower f({path});
    CHECK_EQ(names(f.poll()), std::string("m1 m2"));
    remove_file(path);
    write_file(path, kBomText + lines_of(5, 6));
    CHECK_EQ(names(f.poll()), std::string("m5 m6"));
    CHECK_EQ(f.stats().malformed, std::uint64_t{0});
    CHECK_EQ(f.stats().rotations, std::uint64_t{1});
}

TEST(FileFollower, BlankAndMalformedLinesAreSkippedAndCounted) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    write_file(path,
               line_of(1) +
               "garbage\n"
               "\n"
               "   \n"
               "\t\n"
               "\r\n"
               "2026-13-10T00:00:00Z INFO svc bad month\n" +
               line_of(2) +
               "2026-10-10T00:00:00Z TRACE svc bad level\n"
               "2026-10-10T00:00:00Z INFO\n");  // no service
    FileFollower f({path});
    CHECK_EQ(names(f.poll()), std::string("m1 m2"));
    CHECK_EQ(f.stats().entries, std::uint64_t{2});
    CHECK_EQ(f.stats().malformed, std::uint64_t{4});  // blank lines are not malformed
    CHECK_EQ(f.stats().bytes, size_of(path));

    append_file(path, "more junk\n" + line_of(3));
    CHECK_EQ(names(f.poll()), std::string("m3"));
    CHECK_EQ(f.stats().entries, std::uint64_t{3});
    CHECK_EQ(f.stats().malformed, std::uint64_t{5});  // totals accumulate over polls
}

TEST(FileFollower, EmptyFileAndFileOfOnlyNewlines) {
    Scratch dir;
    const std::string empty = dir.path("empty.log");
    const std::string blank = dir.path("blank.log");
    write_file(empty, "");
    write_file(blank, "\n\n\n\r\n\n  \n");
    FileFollower f({empty, blank});
    CHECK(f.poll().empty());
    CHECK_EQ(f.stats().entries, std::uint64_t{0});
    CHECK_EQ(f.stats().malformed, std::uint64_t{0});
    CHECK_EQ(f.stats().bytes, size_of(blank));
    CHECK_EQ(f.buffered_bytes(), std::size_t{0});

    append_file(empty, lines_of(1, 1));  // the empty file wakes up
    append_file(blank, lines_of(2, 2));
    CHECK_EQ(names(f.poll()), std::string("m1 m2"));
}

TEST(FileFollower, NulBytesAndBytesAbove127AreKeptVerbatim) {
    Scratch dir;
    const std::string path = dir.path("a.log");

    std::string message = "nul:";
    message.push_back('\0');
    message += "after \xFF" "\xFE" "\x80" " caf\xC3\xA9 \xE2\x82\xAC";
    const std::string valid = "2026-10-10T00:00:01Z WARN sv\xC3\xA9 " + message;  // high bytes in the service too

    std::string nul_in_timestamp = "2026-10-10T00:00:0";
    nul_in_timestamp.push_back('\0');
    nul_in_timestamp += "Z INFO svc x";

    std::string nul_line;  // a line that is just a NUL: not blank, so malformed
    nul_line.push_back('\0');

    const std::string text = valid + "\n" + nul_in_timestamp + "\n" + nul_line + "\n" + valid + "\n";
    write_file(path, text);

    FileFollower f({path});
    const std::vector<LogEntry> got = f.poll();
    CHECK_EQ(got.size(), std::size_t{2});
    CHECK_EQ(got[0].message, message);
    CHECK_EQ(got[0].service, std::string("sv\xC3\xA9"));
    CHECK(got[0] == got[1]);
    CHECK_EQ(f.stats().malformed, std::uint64_t{2});
    CHECK_EQ(f.stats().bytes, static_cast<std::uint64_t>(text.size()));

    const Parsed whole = parse_whole(text);  // and exactly what parse_stream makes of it
    check_same_entries(got, whole.entries);
    CHECK_EQ(whole.malformed, std::size_t{2});
}

// ---------------------------------------------------------------------------
// Over-long lines and memory
// ---------------------------------------------------------------------------

namespace {

// A valid line of exactly `length` bytes (without the newline).
std::string line_of_length(std::size_t length) {
    LogEntry e = make_entry(1);
    const std::size_t base = format_entry(e).size() - e.message.size();
    e.message.assign(length - base, 'a');
    std::string text = format_entry(e);
    CHECK_EQ(text.size(), length);
    return text;
}

FollowerOptions with_line_limit(std::size_t limit) {
    FollowerOptions options;
    options.max_line_bytes = limit;
    return options;
}

}  // namespace

TEST(FileFollower, AnOverLongLineIsDiscardedAndCountedOnce) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    write_file(path, line_of(1) + std::string(500, 'x') + "\n" + line_of(2));
    FileFollower f({path}, with_line_limit(100));
    CHECK_EQ(names(f.poll()), std::string("m1 m2"));
    CHECK_EQ(f.stats().malformed, std::uint64_t{1});
    CHECK_EQ(f.stats().entries, std::uint64_t{2});
    CHECK_EQ(f.stats().bytes, size_of(path));
    CHECK_EQ(f.buffered_bytes(), std::size_t{0});
}

TEST(FileFollower, AnOverLongLineThatBecomesCompleteInALaterPollIsCountedOnce) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    write_file(path, line_of(1));
    FileFollower f({path}, with_line_limit(100));
    CHECK_EQ(names(f.poll()), std::string("m1"));

    append_file(path, std::string(60, 'x'));
    CHECK(f.poll().empty());
    CHECK_EQ(f.buffered_bytes(), std::size_t{60});
    CHECK_EQ(f.stats().malformed, std::uint64_t{0});

    append_file(path, std::string(60, 'x'));  // 120 > 100: the line is now known to be too long
    CHECK(f.poll().empty());
    CHECK_EQ(f.buffered_bytes(), std::size_t{0});  // dropped, not kept
    CHECK_EQ(f.stats().malformed, std::uint64_t{1});

    append_file(path, std::string(1000, 'x'));  // still the same line
    CHECK(f.poll().empty());
    CHECK_EQ(f.buffered_bytes(), std::size_t{0});
    CHECK_EQ(f.stats().malformed, std::uint64_t{1});

    append_file(path, "x\n" + line_of(2));  // its newline, then a good line
    CHECK_EQ(names(f.poll()), std::string("m2"));
    CHECK_EQ(f.stats().malformed, std::uint64_t{1});
    CHECK_EQ(f.stats().entries, std::uint64_t{2});
    CHECK_EQ(f.stats().bytes, size_of(path));
}

TEST(FileFollower, AnOverLongCompleteLineCompletingABufferedFragmentIsCountedOnce) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    write_file(path, std::string(50, 'x'));
    FileFollower f({path}, with_line_limit(100));
    CHECK(f.poll().empty());
    CHECK_EQ(f.buffered_bytes(), std::size_t{50});

    append_file(path, std::string(60, 'x') + "\n" + line_of(1));  // 50 + 60 > 100, newline in the same read
    CHECK_EQ(names(f.poll()), std::string("m1"));
    CHECK_EQ(f.stats().malformed, std::uint64_t{1});
    CHECK_EQ(f.buffered_bytes(), std::size_t{0});
}

TEST(FileFollower, ALineOfExactlyTheLimitIsKeptOneByteMoreIsNot) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    const std::string exact = line_of_length(100);
    const std::string over = line_of_length(101);
    FileFollower f({path}, with_line_limit(100));

    write_file(path, exact + "\n");
    CHECK_EQ(f.poll().size(), std::size_t{1});
    CHECK_EQ(f.stats().malformed, std::uint64_t{0});

    append_file(path, over + "\n");
    CHECK(f.poll().empty());
    CHECK_EQ(f.stats().malformed, std::uint64_t{1});

    // The same two lengths, with the newline arriving in a later poll.
    append_file(path, exact);
    CHECK(f.poll().empty());
    CHECK_EQ(f.buffered_bytes(), std::size_t{100});
    append_file(path, "\n");
    CHECK_EQ(f.poll().size(), std::size_t{1});
    CHECK_EQ(f.buffered_bytes(), std::size_t{0});

    append_file(path, over.substr(0, 100));
    CHECK(f.poll().empty());
    CHECK_EQ(f.buffered_bytes(), std::size_t{100});
    append_file(path, over.substr(100) + "\n");  // the 101st byte
    CHECK(f.poll().empty());
    CHECK_EQ(f.buffered_bytes(), std::size_t{0});
    CHECK_EQ(f.stats().malformed, std::uint64_t{2});
    CHECK_EQ(f.stats().entries, std::uint64_t{2});
}

TEST(FileFollower, MemoryStaysBoundedWhileAHugeLineIsWritten) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    write_file(path, "");
    FileFollower f({path}, with_line_limit(1000));

    const std::string block(64 * 1024, 'y');
    for (int i = 0; i < 24; ++i) {  // a 1.5 MiB line, one block per poll
        append_file(path, block);
        CHECK(f.poll().empty());
        CHECK(f.buffered_bytes() <= 1000);
    }
    CHECK_EQ(f.stats().malformed, std::uint64_t{1});
    append_file(path, "\n" + line_of(1));
    CHECK_EQ(names(f.poll()), std::string("m1"));
    CHECK_EQ(f.stats().malformed, std::uint64_t{1});
    CHECK_EQ(f.stats().bytes, size_of(path));
}

TEST(FileFollower, MemoryStaysBoundedWhenAHugeLineIsAlreadyInTheFile) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    write_file(path, line_of(1) + std::string(3 * 1024 * 1024, 'z'));  // 3 MiB, never terminated
    FileFollower f({path}, with_line_limit(4096));
    CHECK_EQ(names(f.poll()), std::string("m1"));
    CHECK(f.buffered_bytes() <= 4096);
    CHECK_EQ(f.stats().malformed, std::uint64_t{1});
    CHECK_EQ(f.stats().bytes, size_of(path));
}

TEST(FileFollower, ALineLimitOfOneByteDiscardsAlmostEverythingWithoutCrashing) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    write_file(path, "x\n" + std::string("yy\n") + "\n" + line_of(1));
    FileFollower f({path}, with_line_limit(1));
    CHECK(f.poll().empty());
    // "x" fits the limit but is junk, "yy" and the real line are over it, the empty line is blank.
    CHECK_EQ(f.stats().malformed, std::uint64_t{3});
    CHECK_EQ(f.stats().entries, std::uint64_t{0});
    CHECK(f.buffered_bytes() <= 1);
}

// ---------------------------------------------------------------------------
// max_bytes_per_poll and backlog()
// ---------------------------------------------------------------------------

namespace {

FollowerOptions with_poll_limit(std::size_t limit) {
    FollowerOptions options;
    options.max_bytes_per_poll = limit;
    return options;
}

}  // namespace

TEST(FileFollower, PollLimitSplitsTheFileAcrossPollsAndBacklogSaysSo) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    write_file(path, lines_of(1, 9));  // 9 * 37 = 333 bytes
    CHECK_EQ(size_of(path), std::uint64_t{333});

    FileFollower f({path}, with_poll_limit(100));
    CHECK(!f.backlog());

    // First poll: bytes [0, 100): two whole lines and 26 bytes of the third, which is buffered.
    CHECK_EQ(names(f.poll()), std::string("m1 m2"));
    CHECK(f.backlog());
    CHECK_EQ(f.stats().bytes, std::uint64_t{100});
    CHECK_EQ(f.buffered_bytes(), std::size_t{26});

    std::string rest;
    std::uint64_t before = f.stats().bytes;
    int polls = 1;
    while (f.backlog()) {
        const std::vector<LogEntry> got = f.poll();
        CHECK(++polls <= 1000);  // a backlog that never drains fails here instead of hanging
        CHECK(f.stats().bytes - before <= 100);  // never more than the limit per poll
        before = f.stats().bytes;
        for (const LogEntry& e : got) rest += " " + e.message;
    }
    CHECK_EQ(polls, 4);                                 // 100 + 100 + 100 + 33
    CHECK_EQ(rest, std::string(" m3 m4 m5 m6 m7 m8 m9"));  // nothing split, lost or repeated
    CHECK_EQ(f.stats().bytes, std::uint64_t{333});
    CHECK_EQ(f.stats().entries, std::uint64_t{9});
    CHECK_EQ(f.stats().malformed, std::uint64_t{0});
    CHECK(!f.backlog());
    CHECK_EQ(f.buffered_bytes(), std::size_t{0});
}

TEST(FileFollower, BacklogIsFalseWhenTheLimitExactlyMatchesWhatWasThere) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    write_file(path, lines_of(1, 9));  // 333 bytes

    FileFollower exact({path}, with_poll_limit(333));
    CHECK_EQ(exact.poll().size(), std::size_t{9});
    CHECK(!exact.backlog());  // the limit was reached, but nothing is left

    FileFollower one_short({path}, with_poll_limit(332));
    CHECK_EQ(one_short.poll().size(), std::size_t{8});  // the last '\n' is still unread
    CHECK(one_short.backlog());
    CHECK_EQ(one_short.buffered_bytes(), std::size_t{36});
    CHECK_EQ(one_short.poll().size(), std::size_t{1});
    CHECK(!one_short.backlog());

    FileFollower roomy({path}, with_poll_limit(334));
    CHECK_EQ(roomy.poll().size(), std::size_t{9});
    CHECK(!roomy.backlog());
}

TEST(FileFollower, OneBytePerPollStillDeliversEverything) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    write_file(path, lines_of(1, 3) + "junk\n");
    FileFollower f({path}, with_poll_limit(1));
    std::vector<LogEntry> all;
    int polls = 0;
    do {
        const std::vector<LogEntry> got = f.poll();
        all.insert(all.end(), got.begin(), got.end());
        CHECK(++polls <= 1000);
    } while (f.backlog());
    CHECK_EQ(names(all), std::string("m1 m2 m3"));
    CHECK_EQ(f.stats().malformed, std::uint64_t{1});
    CHECK_EQ(static_cast<std::uint64_t>(polls), size_of(path));  // one byte each
}

TEST(FileFollower, PollLimitAppliesToEachFileSeparately) {
    Scratch dir;
    const std::string big = dir.path("big.log");
    const std::string small = dir.path("small.log");
    write_file(big, lines_of(1, 9));
    write_file(small, lines_of(20, 20));  // 38 bytes
    FileFollower f({big, small}, with_poll_limit(100));
    CHECK_EQ(names(f.poll()), std::string("m1 m2 m20"));  // the big file does not starve the small one
    CHECK(f.backlog());
    CHECK_EQ(f.stats().bytes, std::uint64_t{138});
    int polls = 1;
    while (f.backlog()) {
        f.poll();
        CHECK(++polls <= 1000);
    }
    CHECK_EQ(f.stats().entries, std::uint64_t{10});
}

TEST(FileFollower, BacklogIsRecomputedByEveryPoll) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    write_file(path, lines_of(1, 9));
    FileFollower f({path}, with_poll_limit(200));
    f.poll();
    CHECK(f.backlog());
    f.poll();
    CHECK(!f.backlog());
    f.poll();  // idle
    CHECK(!f.backlog());
}

// ---------------------------------------------------------------------------
// Rotation, truncation, deletion
// ---------------------------------------------------------------------------

TEST(FileFollower, TruncationIsDetectedAndTheFragmentIsDropped) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    write_file(path, lines_of(1, 5) + "2026-10-10T00:00:09Z INFO svc half a li");  // ends in a fragment
    FileFollower f({path});
    CHECK_EQ(names(f.poll()), std::string("m1 m2 m3 m4 m5"));
    CHECK(f.buffered_bytes() > 0);
    const std::uint64_t old_size = size_of(path);

    write_file(path, lines_of(20, 21));  // truncated, then rewritten shorter
    CHECK(size_of(path) < old_size);
    CHECK_EQ(names(f.poll()), std::string("m20 m21"));  // nothing glued onto the old fragment
    CHECK_EQ(f.stats().rotations, std::uint64_t{1});
    CHECK_EQ(f.stats().malformed, std::uint64_t{0});
    CHECK_EQ(f.buffered_bytes(), std::size_t{0});

    append_file(path, lines_of(22, 22));
    CHECK_EQ(names(f.poll()), std::string("m22"));
    CHECK_EQ(f.stats().rotations, std::uint64_t{1});
}

TEST(FileFollower, TruncationToEmptyThenRegrowth) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    write_file(path, lines_of(1, 3));
    FileFollower f({path});
    CHECK_EQ(names(f.poll()), std::string("m1 m2 m3"));

    write_file(path, "");
    CHECK(f.poll().empty());
    CHECK_EQ(f.stats().rotations, std::uint64_t{1});

    append_file(path, lines_of(1, 2));  // the same text as before: it is new content again
    CHECK_EQ(names(f.poll()), std::string("m1 m2"));
    CHECK_EQ(f.stats().rotations, std::uint64_t{1});
    CHECK_EQ(f.stats().entries, std::uint64_t{5});
}

TEST(FileFollower, ReplacementByALongerFileWithDifferentContentIsDetected) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    write_file(path, lines_of(1, 2));
    FileFollower f({path});
    CHECK_EQ(names(f.poll()), std::string("m1 m2"));

    remove_file(path);
    write_file(path, lines_of(40, 50));  // longer, so the size alone would not give it away
    CHECK(size_of(path) > lines_of(1, 2).size());
    CHECK_EQ(names(f.poll()), std::string("m40 m41 m42 m43 m44 m45 m46 m47 m48 m49 m50"));
    CHECK_EQ(f.stats().rotations, std::uint64_t{1});
}

TEST(FileFollower, ReplacementByAFileOfTheSameLengthIsDetected) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    write_file(path, lines_of(1, 3));
    FileFollower f({path});
    CHECK_EQ(names(f.poll()), std::string("m1 m2 m3"));

    write_file(path, lines_of(4, 6));  // same number of bytes, other bytes
    CHECK_EQ(size_of(path), lines_of(1, 3).size());
    CHECK_EQ(names(f.poll()), std::string("m4 m5 m6"));
    CHECK_EQ(f.stats().rotations, std::uint64_t{1});
}

TEST(FileFollower, TheFingerprintGrowsWithTheFile) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    write_file(path, line_of(1));  // 37 bytes: a short fingerprint at first
    FileFollower f({path});
    CHECK_EQ(names(f.poll()), std::string("m1"));
    append_file(path, lines_of(2, 9));  // 333 bytes now: the fingerprint must cover 256 of them
    CHECK_EQ(f.poll().size(), std::size_t{8});

    // A longer replacement that agrees with the old file on its first line, but not on the rest
    // of the first 256 bytes. Only a fingerprint that grew past the first 37 bytes sees it.
    remove_file(path);
    write_file(path, line_of(1) + lines_of(21, 29));
    CHECK(size_of(path) > 333);
    CHECK_EQ(names(f.poll()), std::string("m1 m21 m22 m23 m24 m25 m26 m27 m28 m29"));
    CHECK_EQ(f.stats().rotations, std::uint64_t{1});
}

TEST(FileFollower, ReplacementWithIdenticalFirst256BytesIsNotDetectedDocumentedLimitation) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    write_file(path, lines_of(1, 8));  // 296 bytes
    FileFollower f({path});
    CHECK_EQ(f.poll().size(), std::size_t{8});

    // Same first 256 bytes (lines 1-6 and the first 34 bytes of line 7), then different bytes,
    // and longer than before: indistinguishable from an append, so only the part beyond the old
    // offset (296) is delivered and no rotation is counted.
    std::string replacement = lines_of(1, 6) + line_of(7).substr(0, 34) + "zz\n" + line_of(8) + line_of(9) + line_of(1);
    CHECK_EQ(replacement.compare(0, 256, lines_of(1, 8), 0, 256), 0);
    CHECK(replacement.size() > 296);
    remove_file(path);
    write_file(path, replacement);
    CHECK_EQ(names(f.poll()), std::string("m9 m1"));
    CHECK_EQ(f.stats().rotations, std::uint64_t{0});
}

TEST(FileFollower, DeletionAndRecreationReadsTheNewFileFromTheStart) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    write_file(path, lines_of(1, 3) + "2026-10-10T00:00:09Z INFO svc partial");  // ends in a fragment
    FileFollower f({path});
    CHECK_EQ(names(f.poll()), std::string("m1 m2 m3"));

    remove_file(path);
    CHECK(f.poll().empty());  // a missing file is not an error
    CHECK(f.poll().empty());
    CHECK_EQ(f.stats().rotations, std::uint64_t{0});  // counted when the new file shows up
    CHECK_EQ(f.buffered_bytes(), std::size_t{0});     // the old fragment went with the file

    write_file(path, lines_of(1, 3));  // byte-for-byte the old content: still a new file
    CHECK_EQ(names(f.poll()), std::string("m1 m2 m3"));
    CHECK_EQ(f.stats().rotations, std::uint64_t{1});
    CHECK_EQ(f.stats().malformed, std::uint64_t{0});

    remove_file(path);
    CHECK(f.poll().empty());
    write_file(path, lines_of(1, 6));  // longer, same beginning
    CHECK_EQ(names(f.poll()), std::string("m1 m2 m3 m4 m5 m6"));
    CHECK_EQ(f.stats().rotations, std::uint64_t{2});

    append_file(path, lines_of(7, 7));
    CHECK_EQ(names(f.poll()), std::string("m7"));
}

TEST(FileFollower, DeletionAndRecreationIgnoresFromStartFalse) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    write_file(path, lines_of(1, 2));
    FileFollower f({path}, from_end());
    CHECK(f.poll().empty());
    remove_file(path);
    CHECK(f.poll().empty());
    write_file(path, lines_of(5, 6));
    CHECK_EQ(names(f.poll()), std::string("m5 m6"));  // all of it, though from_start is false
    CHECK_EQ(f.stats().rotations, std::uint64_t{1});
}

TEST(FileFollower, RenameAndRecreateLikeLogrotate) {
    Scratch dir;
    const std::string path = dir.path("app.log");
    write_file(path, lines_of(1, 3));
    FileFollower f({path});
    CHECK_EQ(names(f.poll()), std::string("m1 m2 m3"));

    std::error_code ec;
    fs::rename(path, dir.path("app.log.1"), ec);
    CHECK(!ec);
    write_file(path, lines_of(4, 4));  // shorter than the old file
    CHECK_EQ(names(f.poll()), std::string("m4"));
    CHECK_EQ(f.stats().rotations, std::uint64_t{1});
    append_file(path, lines_of(5, 5));
    CHECK_EQ(names(f.poll()), std::string("m5"));
}

TEST(FileFollower, RotationWhileBackloggedRestartsFromTheNewFile) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    write_file(path, lines_of(1, 9));
    FileFollower f({path}, with_poll_limit(100));
    CHECK_EQ(names(f.poll()), std::string("m1 m2"));
    CHECK(f.backlog());

    write_file(path, lines_of(60, 61));  // replaced before the backlog was drained
    std::vector<LogEntry> all;
    int polls = 0;
    do {
        const std::vector<LogEntry> got = f.poll();
        all.insert(all.end(), got.begin(), got.end());
        CHECK(++polls <= 1000);
    } while (f.backlog());
    CHECK_EQ(names(all), std::string("m60 m61"));  // the old file's remaining lines are gone with it
    CHECK_EQ(f.stats().rotations, std::uint64_t{1});
    CHECK_EQ(f.buffered_bytes(), std::size_t{0});
}

// ---------------------------------------------------------------------------
// Several files
// ---------------------------------------------------------------------------

TEST(FileFollower, FilesAreDeliveredInConstructorOrderEachInFileOrder) {
    Scratch dir;
    const std::string a = dir.path("a.log");
    const std::string b = dir.path("b.log");
    const std::string c = dir.path("c.log");  // does not exist at first
    FileFollower f({a, b, c});
    CHECK_EQ(f.file_count(), std::size_t{3});

    append_file(b, lines_of(3, 3));
    append_file(a, lines_of(1, 2));
    CHECK_EQ(names(f.poll()), std::string("m1 m2 m3"));  // a before b, whatever was written first

    append_file(b, lines_of(4, 4));
    append_file(a, lines_of(5, 5));
    append_file(b, lines_of(6, 6));
    CHECK_EQ(names(f.poll()), std::string("m5 m4 m6"));

    append_file(c, lines_of(7, 8));
    append_file(a, lines_of(9, 9));
    CHECK_EQ(names(f.poll()), std::string("m9 m7 m8"));
    CHECK_EQ(f.stats().entries, std::uint64_t{9});
}

TEST(FileFollower, PartialLinesOfDifferentFilesDoNotMix) {
    Scratch dir;
    const std::string a = dir.path("a.log");
    const std::string b = dir.path("b.log");
    const std::string la = line_of(1);
    const std::string lb = line_of(2);
    write_file(a, la.substr(0, 17));
    write_file(b, lb.substr(0, 30));
    FileFollower f({a, b});
    CHECK(f.poll().empty());
    CHECK_EQ(f.buffered_bytes(), std::size_t{47});

    append_file(b, lb.substr(30));  // b completes first
    CHECK_EQ(names(f.poll()), std::string("m2"));
    append_file(a, la.substr(17));
    CHECK_EQ(names(f.poll()), std::string("m1"));
    CHECK_EQ(f.stats().malformed, std::uint64_t{0});
}

TEST(FileFollower, OneFilesRotationDoesNotDisturbTheOthers) {
    Scratch dir;
    const std::string a = dir.path("a.log");
    const std::string b = dir.path("b.log");
    write_file(a, lines_of(1, 3));
    write_file(b, lines_of(11, 13));
    FileFollower f({a, b});
    CHECK_EQ(f.poll().size(), std::size_t{6});

    write_file(a, lines_of(4, 4));  // a is truncated and rewritten, b grows
    append_file(b, lines_of(14, 14));
    CHECK_EQ(names(f.poll()), std::string("m4 m14"));
    CHECK_EQ(f.stats().rotations, std::uint64_t{1});
}

// ---------------------------------------------------------------------------
// Copy and move
// ---------------------------------------------------------------------------

TEST(FileFollower, CopiesContinueIndependentlyFromTheSamePosition) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    const std::string second = line_of(2);
    write_file(path, line_of(1) + second.substr(0, 12));

    FileFollower original({path});
    CHECK_EQ(names(original.poll()), std::string("m1"));

    FileFollower copy = original;  // the buffered fragment and the offset are copied too
    CHECK_EQ(copy.file_count(), std::size_t{1});
    CHECK_EQ(copy.stats().entries, std::uint64_t{1});
    CHECK_EQ(copy.buffered_bytes(), std::size_t{12});

    append_file(path, second.substr(12) + line_of(3));
    CHECK_EQ(names(original.poll()), std::string("m2 m3"));
    CHECK(original.poll().empty());
    CHECK_EQ(names(copy.poll()), std::string("m2 m3"));  // not affected by the original's polls
    CHECK_EQ(original.stats().entries, std::uint64_t{3});
    CHECK_EQ(copy.stats().entries, std::uint64_t{3});

    FileFollower other({dir.path("other.log")});
    other = original;  // copy assignment
    CHECK_EQ(other.stats().entries, std::uint64_t{3});
    append_file(path, line_of(4));
    CHECK_EQ(names(other.poll()), std::string("m4"));
    CHECK_EQ(names(original.poll()), std::string("m4"));
}

TEST(FileFollower, MovedFollowersKeepFollowing) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    write_file(path, lines_of(1, 2));
    FileFollower first({path});
    CHECK_EQ(names(first.poll()), std::string("m1 m2"));

    FileFollower moved(std::move(first));
    CHECK(moved.poll().empty());
    append_file(path, lines_of(3, 3));
    CHECK_EQ(names(moved.poll()), std::string("m3"));
    CHECK_EQ(moved.stats().entries, std::uint64_t{3});

    FileFollower assigned({dir.path("elsewhere.log")});
    assigned = std::move(moved);
    CHECK_EQ(assigned.file_count(), std::size_t{1});
    append_file(path, lines_of(4, 4));
    CHECK_EQ(names(assigned.poll()), std::string("m4"));

    std::vector<FileFollower> many;  // a plain value type: fine in containers
    many.push_back(assigned);
    many.emplace_back(std::vector<std::string>{path}, FollowerOptions());
    CHECK_EQ(many.size(), std::size_t{2});
    CHECK_EQ(names(many[1].poll()), std::string("m1 m2 m3 m4"));
    CHECK(many[0].poll().empty());
}

// ---------------------------------------------------------------------------
// Property tests: random splits against parse_stream
// ---------------------------------------------------------------------------

namespace {

struct Followed {
    std::vector<LogEntry> entries;
    FollowStats stats;
    std::size_t buffered = 0;
    bool backlog = false;
};

// Writes text[0, existing) to a file (created empty when `existing` is 0 and `create_first`),
// starts a follower, then appends the pieces one at a time with a poll after each (draining any
// backlog), and returns everything the follower delivered. Without `create_first` the file does
// not exist until its first piece arrives.
Followed follow_in_pieces(const std::string& text, std::size_t existing, const std::vector<std::string>& pieces,
                          const FollowerOptions& options, bool create_first) {
    Scratch dir;
    const std::string path = dir.path("split.log");
    if (existing > 0 || create_first) write_file(path, text.substr(0, existing));
    FileFollower f({path}, options);

    Followed result;
    auto drain = [&] {
        int guard = 0;
        do {
            std::vector<LogEntry> got = f.poll();
            result.entries.insert(result.entries.end(), std::make_move_iterator(got.begin()),
                                  std::make_move_iterator(got.end()));
            CHECK(++guard < 1000000);
        } while (f.backlog());
    };
    drain();  // the first poll: the snapshot, or the existing content, or a missing file
    std::size_t index = 0;
    for (const std::string& piece : pieces) {
        append_file(path, piece);  // may create the file
        drain();
        if (++index % 4 == 0) drain();  // an idle poll now and then
    }
    drain();
    result.stats = f.stats();
    result.buffered = f.buffered_bytes();
    result.backlog = f.backlog();
    return result;
}

}  // namespace

TEST(FileFollower, RandomSplitsOfGeneratedLogsMatchParseStream) {
    struct Round {
        std::uint64_t seed;
        std::size_t services;
        std::size_t per_service;
        bool bom;
        unsigned percent_of_lines;
        std::size_t cap;  // max_bytes_per_poll, 0 for the default
        bool create_first;
    };
    const Round rounds[] = {
        {9001, 3, 100, true, 25, 0, true},   // 300 lines, BOM, default limits: ~80 pieces
        {9002, 2, 30, false, 60, 23, true},  // small file, a 23-byte limit per poll
        {9003, 2, 30, true, 60, 7, false},   // 7 bytes per poll, the file only appears with its first piece
    };
    const std::vector<std::string> names_pool = {"auth", "pay", "order"};
    for (const Round& r : rounds) {
        const MessyText messy = make_messy_text(
            r.seed, std::vector<std::string>(names_pool.begin(), names_pool.begin() + static_cast<std::ptrdiff_t>(r.services)),
            r.per_service, r.bom);
        const Parsed expected = parse_whole(messy.text);
        CHECK(expected.entries.size() >= r.services * r.per_service);
        CHECK(expected.malformed > 0);  // the junk lines are really in there

        std::mt19937_64 rng(r.seed);
        const std::vector<std::size_t> cuts = choose_cuts(rng, messy, 0, r.percent_of_lines, 5);
        const std::vector<std::string> pieces = split_at(messy.text, 0, cuts);
        CHECK(pieces.size() >= 30);
        CHECK_EQ(pieces.size(), cuts.size() + 1);

        FollowerOptions options;
        if (r.cap > 0) options.max_bytes_per_poll = r.cap;
        const Followed got = follow_in_pieces(messy.text, 0, pieces, options, r.create_first);

        check_same_entries(got.entries, expected.entries);
        CHECK_EQ(got.stats.entries, static_cast<std::uint64_t>(expected.entries.size()));
        CHECK_EQ(got.stats.malformed, static_cast<std::uint64_t>(expected.malformed));
        CHECK_EQ(got.stats.bytes, static_cast<std::uint64_t>(messy.text.size()));
        CHECK_EQ(got.stats.rotations, std::uint64_t{0});
        CHECK_EQ(got.buffered, std::size_t{0});  // every line in the text is terminated
        CHECK(!got.backlog);
    }
}

TEST(FileFollower, RandomSplitsAfterExistingContentWithFromStartMatchParseStream) {
    for (std::uint64_t seed = 4100; seed < 4103; ++seed) {
        const MessyText messy = make_messy_text(seed, {"svc-a", "svc-b"}, 25, seed == 4100);
        std::mt19937_64 rng(seed);
        const std::size_t existing = static_cast<std::size_t>(rng() % messy.text.size());  // possibly mid-line
        const std::vector<std::size_t> cuts = choose_cuts(rng, messy, existing, 60, 3);
        const Followed got =
            follow_in_pieces(messy.text, existing, split_at(messy.text, existing, cuts), FollowerOptions(), true);
        const Parsed expected = parse_whole(messy.text);
        check_same_entries(got.entries, expected.entries);
        CHECK_EQ(got.stats.malformed, static_cast<std::uint64_t>(expected.malformed));
        CHECK_EQ(got.stats.bytes, static_cast<std::uint64_t>(messy.text.size()));
    }
}

TEST(FileFollower, RandomSplitsFromEndDeliverTheSuffixAfterTheSnapshot) {
    for (int round = 0; round < 9; ++round) {
        const std::uint64_t seed = 7300 + static_cast<std::uint64_t>(round);
        const MessyText messy = make_messy_text(seed, {"svc-a", "svc-b"}, 20, round % 2 == 0 || round == 1);
        const std::string& text = messy.text;
        std::mt19937_64 rng(seed);
        std::size_t cut = static_cast<std::size_t>(rng() % (text.size() + 1));
        if (round == 0) cut = 0;                    // an empty file at the snapshot
        if (round == 1) cut = kBomText.size();      // only the BOM
        if (round == 2) cut = text.size();          // everything already there
        if (round == 3) cut = text.find('\n') + 1;  // exactly after a line
        if (round == 4) cut = text.find('\n');      // just before a LF

        const std::vector<std::size_t> cuts = choose_cuts(rng, messy, cut, 50, 2);
        const Followed got = follow_in_pieces(text, cut, split_at(text, cut, cuts), from_end(), true);
        const Parsed expected = parse_whole(text_after_snapshot(text, cut));
        check_same_entries(got.entries, expected.entries);
        CHECK_EQ(got.stats.entries, static_cast<std::uint64_t>(expected.entries.size()));
        CHECK_EQ(got.stats.malformed, static_cast<std::uint64_t>(expected.malformed));
    }
}

TEST(FileFollower, RandomSplitsOfSeveralFilesKeepPerFileOrderAndFileOrderPerPoll) {
    for (int round = 0; round < 2; ++round) {
        const std::uint64_t seed = 2500 + static_cast<std::uint64_t>(round);
        std::mt19937_64 rng(seed);
        Scratch dir;
        const std::vector<std::string> services = {"fa", "fb", "fc"};
        std::vector<std::string> paths;
        std::vector<MessyText> texts;
        std::vector<std::vector<std::string>> pieces;
        for (std::size_t i = 0; i < services.size(); ++i) {
            paths.push_back(dir.path(services[i] + ".log"));
            texts.push_back(make_messy_text(seed + i * 17, {services[i]}, 25, i == 1));
            pieces.push_back(split_at(texts[i].text, 0, choose_cuts(rng, texts[i], 0, 45, 3)));
        }
        FollowerOptions options;
        if (round == 1) options.max_bytes_per_poll = 64;
        FileFollower f(paths, options);

        std::vector<std::size_t> next_piece(services.size(), 0);
        std::vector<std::vector<LogEntry>> got(services.size());
        auto drain = [&] {
            int guard = 0;
            do {
                CHECK(++guard < 1000000);
                const std::vector<LogEntry> batch = f.poll();
                std::size_t previous = 0;
                for (const LogEntry& e : batch) {
                    const std::size_t index =
                        static_cast<std::size_t>(std::find(services.begin(), services.end(), e.service) - services.begin());
                    CHECK(index < services.size());
                    CHECK(index >= previous);  // files come in constructor order within one poll
                    previous = index;
                    got[index].push_back(e);
                }
            } while (f.backlog());
        };

        std::size_t remaining = 0;
        for (const std::vector<std::string>& p : pieces) remaining += p.size();
        while (remaining > 0) {
            std::size_t pick = static_cast<std::size_t>(rng() % services.size());
            while (next_piece[pick] == pieces[pick].size()) pick = (pick + 1) % services.size();
            append_file(paths[pick], pieces[pick][next_piece[pick]++]);
            --remaining;
            if (rng() % 2 == 0) drain();  // several files may have grown between two polls
        }
        drain();

        std::uint64_t entries = 0;
        std::uint64_t malformed = 0;
        std::uint64_t bytes = 0;
        for (std::size_t i = 0; i < services.size(); ++i) {
            const Parsed expected = parse_whole(texts[i].text);
            check_same_entries(got[i], expected.entries);
            entries += expected.entries.size();
            malformed += expected.malformed;
            bytes += texts[i].text.size();
        }
        CHECK_EQ(f.stats().entries, entries);
        CHECK_EQ(f.stats().malformed, malformed);
        CHECK_EQ(f.stats().bytes, bytes);
        CHECK_EQ(f.buffered_bytes(), std::size_t{0});
    }
}

// ---------------------------------------------------------------------------
// Files that exist but cannot be opened, and paths that are not files
// ---------------------------------------------------------------------------

TEST(FileFollower, FromStartFalseFileLockedAtTheFirstPollIsNeverReplayedFromItsStart) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    write_file(path, lines_of(1, 3));
    ReadLock lock(path);
    if (!locking_works(lock)) return;

    FileFollower f({path}, from_end());
    CHECK(f.poll().empty());
    CHECK(f.poll().empty());  // still locked: still not "a file that appeared later"
    CHECK(!f.backlog());
    CHECK_EQ(f.stats().bytes, std::uint64_t{0});

    lock.release();
    append_file(path, line_of(4));
    CHECK_EQ(names(f.poll()), std::string("m4"));  // the history, m1 to m3, is not delivered
    CHECK_EQ(f.stats().entries, std::uint64_t{1});
    CHECK_EQ(f.stats().rotations, std::uint64_t{0});
    CHECK_EQ(f.stats().bytes, static_cast<std::uint64_t>(line_of(4).size()));
    append_file(path, line_of(5));
    CHECK_EQ(names(f.poll()), std::string("m5"));
}

TEST(FileFollower, FromStartFalseLockedFileKeepsSkippingALineThatWasHalfWrittenAtTheFirstPoll) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    const std::string third = line_of(3);
    write_file(path, lines_of(1, 2) + third.substr(0, 20));
    ReadLock lock(path);
    if (!locking_works(lock)) return;

    FileFollower f({path}, from_end());
    CHECK(f.poll().empty());
    lock.release();
    append_file(path, third.substr(20) + line_of(4));
    CHECK_EQ(names(f.poll()), std::string("m4"));  // the rest of line 3 is not a line of its own
    CHECK_EQ(f.stats().malformed, std::uint64_t{0});
}

TEST(FileFollower, FromStartFalseLockedFileThatVanishesIsReadFromItsFirstByteWhenItReturns) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    write_file(path, lines_of(1, 2));
    ReadLock lock(path);
    if (!locking_works(lock)) return;

    FileFollower f({path}, from_end());
    CHECK(f.poll().empty());
    lock.release();
    remove_file(path);
    CHECK(f.poll().empty());  // seen missing: it is now a file that has not appeared yet
    write_file(path, lines_of(8, 9));
    CHECK_EQ(names(f.poll()), std::string("m8 m9"));
    CHECK_EQ(f.stats().rotations, std::uint64_t{0});
}

TEST(FileFollower, FromStartFalseLockedFileThatBecameShorterCountsAsReplaced) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    write_file(path, lines_of(1, 3));
    ReadLock lock(path);
    if (!locking_works(lock)) return;

    FileFollower f({path}, from_end());
    CHECK(f.poll().empty());
    lock.release();
    write_file(path, lines_of(7, 7));  // shorter than the size it had at the first poll
    CHECK_EQ(names(f.poll()), std::string("m7"));
    CHECK_EQ(f.stats().rotations, std::uint64_t{1});
}

TEST(FileFollower, AKnownFileThatCannotBeOpenedKeepsItsPositionAndItsPartialLine) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    const std::string third = line_of(3);
    write_file(path, lines_of(1, 2) + third.substr(0, 10));
    FileFollower f({path});
    CHECK_EQ(names(f.poll()), std::string("m1 m2"));
    ReadLock lock(path);
    if (!locking_works(lock)) return;

    for (int i = 0; i < 3; ++i) {
        CHECK(f.poll().empty());
        CHECK(!f.backlog());
    }
    CHECK_EQ(f.stats().rotations, std::uint64_t{0});
    CHECK_EQ(f.buffered_bytes(), std::size_t{10});

    lock.release();
    append_file(path, third.substr(10) + line_of(4));
    CHECK_EQ(names(f.poll()), std::string("m3 m4"));  // each exactly once: nothing was forgotten
    CHECK_EQ(f.stats().entries, std::uint64_t{4});
    CHECK_EQ(f.stats().rotations, std::uint64_t{0});
}

TEST(FileFollower, AKnownFileReplacedByADirectoryKeepsItsPositionUntilARealFileReturns) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    write_file(path, lines_of(1, 3));
    FileFollower f({path});
    CHECK_EQ(names(f.poll()), std::string("m1 m2 m3"));

    remove_file(path);
    fs::create_directory(path);
    for (int i = 0; i < 3; ++i) {
        CHECK(f.poll().empty());
        CHECK(!f.backlog());
    }
    CHECK_EQ(f.stats().rotations, std::uint64_t{0});

    remove_file(path);
    write_file(path, lines_of(20, 21));
    CHECK_EQ(names(f.poll()), std::string("m20 m21"));
    CHECK_EQ(f.stats().rotations, std::uint64_t{1});
}

TEST(FileFollower, FromStartFalseDirectoryAtTheFirstPollCountsAsAFileThatIsNotThereYet) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    fs::create_directory(path);
    FileFollower f({path}, from_end());
    CHECK(f.poll().empty());
    remove_file(path);
    write_file(path, lines_of(1, 2));
    CHECK_EQ(names(f.poll()), std::string("m1 m2"));
}

#ifdef FOLLOWER_TEST_POSIX
// poll() promises never to block, and opening a FIFO for reading blocks until a writer opens it.
TEST(FileFollower, AFifoInPlaceOfALogIsNeverOpenedSoPollCannotBlock) {
    Scratch dir;
    const std::string pipe = dir.path("pipe.log");
    CHECK(::mkfifo(pipe.c_str(), 0600) == 0);
    WatchDog dog;

    FileFollower fresh({pipe});
    FileFollower first_from_end({pipe}, from_end());
    for (int i = 0; i < 3; ++i) {
        CHECK(fresh.poll().empty());
        CHECK(first_from_end.poll().empty());
        CHECK(!fresh.backlog());
    }
    CHECK_EQ(fresh.stats().bytes, std::uint64_t{0});

    // A followed file that is swapped for a FIFO keeps its position; the real file coming back
    // later is a replacement.
    const std::string path = dir.path("a.log");
    write_file(path, lines_of(1, 3));
    FileFollower g({path});
    CHECK_EQ(names(g.poll()), std::string("m1 m2 m3"));
    remove_file(path);
    CHECK(::mkfifo(path.c_str(), 0600) == 0);
    CHECK(g.poll().empty());
    remove_file(path);
    write_file(path, lines_of(20, 21));
    CHECK_EQ(names(g.poll()), std::string("m20 m21"));
    CHECK_EQ(g.stats().rotations, std::uint64_t{1});
}
#endif

// ---------------------------------------------------------------------------
// Files larger than one read chunk, and the poll limit across chunks
// ---------------------------------------------------------------------------

namespace {

constexpr std::size_t kReadChunk = 64 * 1024;  // the follower's read size

std::string many_lines(int count) {
    std::string text;
    for (int n = 1; n <= count; ++n) text += line_of(n);
    return text;
}

}  // namespace

TEST(FileFollower, ALargeFileIsReadWithoutLosingOrRepeatingAByteUnderAnyPollLimit) {
    Scratch dir;
    const std::string path = dir.path("big.log");
    const std::string text = many_lines(9000);
    CHECK(text.size() > 5 * kReadChunk);
    write_file(path, text);
    const Parsed expected = parse_whole(text);
    CHECK_EQ(expected.entries.size(), std::size_t{9000});

    // Around the read chunk, and limits that are not a multiple of it.
    const std::size_t caps[] = {0, kReadChunk - 1, kReadChunk, kReadChunk + 1, 100000, 2 * kReadChunk + 1, 200000};
    for (const std::size_t cap : caps) {
        FollowerOptions options;
        if (cap > 0) options.max_bytes_per_poll = cap;
        FileFollower f({path}, options);

        std::vector<LogEntry> all;
        std::uint64_t previous = 0;
        int polls = 0;
        do {
            std::vector<LogEntry> got = f.poll();
            all.insert(all.end(), std::make_move_iterator(got.begin()), std::make_move_iterator(got.end()));
            const std::uint64_t used = f.stats().bytes - previous;
            previous = f.stats().bytes;
            if (cap > 0) CHECK(used <= cap);  // never more than the limit per poll
            if (f.backlog()) CHECK_EQ(used, static_cast<std::uint64_t>(cap));  // a poll cut short used all of it
            CHECK(++polls <= 100);
        } while (f.backlog());

        check_same_entries(all, expected.entries);
        CHECK_EQ(f.stats().bytes, static_cast<std::uint64_t>(text.size()));
        CHECK_EQ(f.stats().malformed, std::uint64_t{0});
        CHECK_EQ(f.buffered_bytes(), std::size_t{0});
        if (cap > 0) CHECK_EQ(static_cast<std::size_t>(polls), (text.size() + cap - 1) / cap);
    }
}

TEST(FileFollower, ALineEndingAtEveryAlignmentAroundAReadChunkBoundaryIsDeliveredWhole) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    const std::size_t ends[] = {kReadChunk - 2,     kReadChunk - 1, kReadChunk,     kReadChunk + 1,
                                kReadChunk + 2,     2 * kReadChunk - 1, 2 * kReadChunk, 2 * kReadChunk + 1};
    const char* const endings[] = {"\n", "\r\n"};
    const std::size_t caps[] = {0, kReadChunk, kReadChunk + 1};
    for (const std::size_t end : ends) {
        for (const char* ending : endings) {
            const std::string text = line_of_length(end) + ending + lines_of(1, 3);
            write_file(path, text);
            const Parsed expected = parse_whole(text);
            CHECK_EQ(expected.entries.size(), std::size_t{4});
            for (const std::size_t cap : caps) {
                FollowerOptions options;
                if (cap > 0) options.max_bytes_per_poll = cap;
                FileFollower f({path}, options);
                std::vector<LogEntry> all;
                poll_all(f, all);
                check_same_entries(all, expected.entries);
                CHECK_EQ(f.stats().bytes, static_cast<std::uint64_t>(text.size()));
                CHECK_EQ(f.stats().malformed, std::uint64_t{0});
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The fingerprint and the snapshot, byte by byte
// ---------------------------------------------------------------------------

TEST(FileFollower, ReplacementIsDetectedExactlyWhenTheFirstDifferingByteIsInsideTheFirst256Bytes) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    const std::size_t sizes[] = {1, 2, 37, 255, 256, 257, 300};
    for (const std::size_t size : sizes) {
        const std::size_t fingerprint = std::min<std::size_t>(size, 256);
        const std::set<std::size_t> positions = {0, 1, size / 2, fingerprint - 1, 255, 256, 257, size - 1};
        for (const std::size_t position : positions) {
            if (position >= size) continue;
            const std::string old_text(size, 'a');  // no newline: all of it stays buffered
            std::string new_text = old_text;
            new_text[position] = 'b';
            new_text += "zz\n";  // longer than before, so the size alone cannot give it away

            write_file(path, old_text);
            FileFollower f({path});
            CHECK(f.poll().empty());
            CHECK_EQ(f.buffered_bytes(), size);
            write_file(path, new_text);
            f.poll();

            const bool detected = position < fingerprint;
            const std::uint64_t expected_bytes = detected ? 2 * size + 3 : size + 3;
            if (f.stats().rotations != (detected ? 1u : 0u) || f.stats().bytes != expected_bytes ||
                f.stats().malformed != 1) {
                throw testkit::Failure{"old size " + std::to_string(size) + ", byte " + std::to_string(position) +
                                       " differs: rotations " + std::to_string(f.stats().rotations) + ", bytes " +
                                       std::to_string(f.stats().bytes) + ", malformed " +
                                       std::to_string(f.stats().malformed)};
            }
        }
    }
}

TEST(FileFollower, AFileThatShrankByExactlyOneByteIsATruncationNotAnAppend) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    std::string text = lines_of(1, 3);
    write_file(path, text);
    FileFollower f({path});
    CHECK_EQ(names(f.poll()), std::string("m1 m2 m3"));

    text.pop_back();  // the same head, one byte fewer: the last newline is gone
    write_file(path, text);
    CHECK_EQ(names(f.poll()), std::string("m1 m2"));  // read again from the start; line 3 is unfinished
    CHECK_EQ(f.stats().rotations, std::uint64_t{1});
    CHECK_EQ(f.buffered_bytes(), line_of(3).size() - 1);
}

TEST(FileFollower, FromStartFalseSnapshotIsRightForFilesAroundTheFingerprintLength) {
    Scratch dir;
    const std::size_t sizes[] = {255, 256, 257, 258, 1000};
    for (const std::size_t size : sizes) {
        // A snapshot that ends right after a newline: the next line is whole, and is delivered.
        const std::string whole = dir.path("whole" + std::to_string(size) + ".log");
        write_file(whole, line_of_length(size - 1) + "\n");
        CHECK_EQ(size_of(whole), static_cast<std::uint64_t>(size));
        FileFollower f({whole}, from_end());
        CHECK(f.poll().empty());
        append_file(whole, line_of(1));
        if (names(f.poll()) != "m1") {
            throw testkit::Failure{"snapshot of " + std::to_string(size) + " bytes ending in a newline lost the next line"};
        }
        CHECK_EQ(f.stats().malformed, std::uint64_t{0});

        // One that ends inside a line: that line's rest is skipped with it, the next one is delivered.
        const std::string cut = dir.path("cut" + std::to_string(size) + ".log");
        write_file(cut, line_of_length(size));
        CHECK_EQ(size_of(cut), static_cast<std::uint64_t>(size));
        FileFollower g({cut}, from_end());
        CHECK(g.poll().empty());
        append_file(cut, "tail\n" + line_of(2));
        if (names(g.poll()) != "m2") {
            throw testkit::Failure{"snapshot of " + std::to_string(size) + " bytes ending inside a line was wrong"};
        }
        CHECK_EQ(g.stats().malformed, std::uint64_t{0});
    }
}

TEST(FileFollower, RotationWhileDiscardingAnOverLongLineStartsTheNewFileClean) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    write_file(path, std::string(300, 'x'));  // never terminated: discarded from the 101st byte on
    FileFollower f({path}, with_line_limit(100));
    CHECK(f.poll().empty());
    CHECK_EQ(f.stats().malformed, std::uint64_t{1});

    write_file(path, lines_of(5, 6));  // truncated and rewritten shorter
    CHECK_EQ(names(f.poll()), std::string("m5 m6"));  // the discard did not leak into the new file
    CHECK_EQ(f.stats().rotations, std::uint64_t{1});
    CHECK_EQ(f.stats().malformed, std::uint64_t{1});

    append_file(path, std::string(300, 'y'));  // discarding again, now at offset 74
    CHECK(f.poll().empty());
    CHECK_EQ(f.stats().malformed, std::uint64_t{2});
    remove_file(path);
    write_file(path, lines_of(10, 30));  // replaced by a LONGER file with other first bytes
    CHECK(size_of(path) > 374);
    std::string expected_names;
    for (int n = 10; n <= 30; ++n) expected_names += (n > 10 ? " m" : "m") + std::to_string(n);
    CHECK_EQ(names(f.poll()), expected_names);
    CHECK_EQ(f.stats().rotations, std::uint64_t{2});
    CHECK_EQ(f.stats().malformed, std::uint64_t{2});
}

TEST(FileFollower, ABomAtTheStartOfASecondLineIsNotSkippedWhateverTheFirstLineWas) {
    Scratch dir;
    const std::string tail = kBomText + line_of(1) + line_of(2);  // the BOM line is malformed, line 2 is not
    struct Case {
        const char* what;
        std::vector<std::string> pieces;  // appended one at a time, with a poll after each
        std::uint64_t malformed;
    };
    const Case cases[] = {
        {"blank first line", {"\n" + tail}, 1},
        {"blank-looking first line", {"  \t\r\n" + tail}, 1},
        {"over-long first line, complete in one read", {std::string(300, 'x') + "\n" + tail}, 2},
        {"over-long first line, discarded across polls", {std::string(300, 'x'), "\n" + tail}, 2},
        {"over-long first line, completing a buffered part",
         {std::string(60, 'x'), std::string(60, 'x') + "\n" + tail},
         2},
    };
    int index = 0;
    for (const Case& c : cases) {
        const std::string path = dir.path("case" + std::to_string(++index) + ".log");
        FileFollower f({path}, with_line_limit(100));
        std::vector<LogEntry> all;
        for (const std::string& piece : c.pieces) {
            append_file(path, piece);
            poll_all(f, all);
        }
        if (names(all) != "m2" || f.stats().malformed != c.malformed) {
            throw testkit::Failure{std::string(c.what) + ": delivered '" + names(all) + "', malformed " +
                                   std::to_string(f.stats().malformed)};
        }
    }
}

// ---------------------------------------------------------------------------
// The line limit and CRLF
// ---------------------------------------------------------------------------

TEST(FileFollower, TheLineLimitDoesNotCountTheCarriageReturnOfACrlfEnding) {
    Scratch dir;
    const std::string exact = line_of_length(100);
    const std::string over = line_of_length(101);

    const std::string path = dir.path("a.log");
    write_file(path, exact + "\r\n" + over + "\r\n" + exact + "\n" + over + "\n" + exact + "\r\r\n");
    FileFollower f({path}, with_line_limit(100));
    CHECK_EQ(f.poll().size(), std::size_t{2});        // the exact line with CRLF and with LF
    CHECK_EQ(f.stats().malformed, std::uint64_t{3});  // both over-long ones, and "exact" plus a CR of its own

    // The CR and the LF in different polls, right at the limit.
    const std::string split = dir.path("split.log");
    FileFollower g({split}, with_line_limit(100));
    append_file(split, exact + "\r");
    CHECK(g.poll().empty());
    CHECK_EQ(g.buffered_bytes(), std::size_t{101});  // the CR may be half of a CRLF: kept
    append_file(split, "\n");
    CHECK_EQ(g.poll().size(), std::size_t{1});
    CHECK_EQ(g.buffered_bytes(), std::size_t{0});
    CHECK_EQ(g.stats().malformed, std::uint64_t{0});

    append_file(split, over + "\r");  // 101 bytes before the CR: too long whatever follows
    CHECK(g.poll().empty());
    CHECK_EQ(g.buffered_bytes(), std::size_t{0});
    CHECK_EQ(g.stats().malformed, std::uint64_t{1});
    append_file(split, "\n" + line_of(1));
    CHECK_EQ(names(g.poll()), std::string("m1"));
    CHECK_EQ(g.stats().malformed, std::uint64_t{1});

    append_file(split, exact + "\r");  // a CR that more bytes follow is content, not a line ending
    CHECK(g.poll().empty());
    CHECK_EQ(g.buffered_bytes(), std::size_t{101});
    append_file(split, "x");
    CHECK(g.poll().empty());
    CHECK_EQ(g.buffered_bytes(), std::size_t{0});
    CHECK_EQ(g.stats().malformed, std::uint64_t{2});
    append_file(split, "\n" + line_of(2));
    CHECK_EQ(names(g.poll()), std::string("m2"));
    CHECK_EQ(g.stats().malformed, std::uint64_t{2});
}

TEST(FileFollower, RandomSplitsWithASmallLineLimitFollowTheLimitRule) {
    for (std::uint64_t seed = 6100; seed < 6103; ++seed) {
        std::mt19937_64 rng(seed);
        FollowerOptions options;
        options.max_line_bytes = 34 + rng() % 10;  // valid lines are 36 or 37 bytes, plus padding

        // What lies between two LFs is `raw`; ONE trailing CR of it does not count towards the limit.
        std::string text;
        std::string kept;
        std::size_t dropped = 0;
        std::vector<std::pair<std::size_t, std::size_t>> raws;  // offset and length of every `raw` in text
        for (int i = 0; i < 40; ++i) {
            std::string body;
            switch (rng() % 5) {
                case 0:
                case 1:
                case 2: {
                    LogEntry e = make_entry(i + 1);
                    e.message += std::string(rng() % 8, 'p');
                    body = format_entry(e);
                    break;
                }
                case 3: {
                    const std::size_t n = 1 + rng() % 50;
                    for (std::size_t j = 0; j < n; ++j) body.push_back(static_cast<char>('a' + rng() % 26));
                    break;
                }
                default: body.assign(rng() % 4, ' '); break;  // blank, possibly empty
            }
            const unsigned pick = static_cast<unsigned>(rng() % 6);
            const std::string raw = body + (pick < 3 ? "" : pick < 5 ? "\r" : "\r\r");
            const std::size_t counted = raw.size() - (!raw.empty() && raw.back() == '\r' ? 1 : 0);
            raws.emplace_back(text.size(), raw.size());
            text += raw + "\n";
            if (counted > options.max_line_bytes) {
                ++dropped;
            } else {
                kept += raw + "\n";
            }
        }
        const Parsed expected = parse_whole(kept);
        CHECK(dropped > 3);
        CHECK(expected.entries.size() > 3);

        // Cuts at the places where the rule can go wrong: around the limit, before and after the
        // CR and the LF.
        std::set<std::size_t> cuts;
        for (const auto& raw : raws) {
            const std::size_t start = raw.first;
            const std::size_t end = raw.first + raw.second;  // offset of the LF
            const std::size_t limit = options.max_line_bytes;
            const std::size_t candidates[] = {start + limit - 1, start + limit, start + limit + 1, start + limit + 2,
                                              end - 1,           end,           end + 1};
            for (const std::size_t cut : candidates) {
                if (rng() % 100 < 40) cuts.insert(cut);
            }
        }
        for (int i = 0; i < 5; ++i) cuts.insert(rng() % text.size());
        std::vector<std::size_t> cut_list;
        for (const std::size_t cut : cuts) {
            if (cut > 0 && cut < text.size()) cut_list.push_back(cut);
        }
        const Followed got = follow_in_pieces(text, 0, split_at(text, 0, cut_list), options, true);

        check_same_entries(got.entries, expected.entries);
        CHECK_EQ(got.stats.entries, static_cast<std::uint64_t>(expected.entries.size()));
        CHECK_EQ(got.stats.malformed, static_cast<std::uint64_t>(expected.malformed + dropped));
        CHECK_EQ(got.stats.bytes, static_cast<std::uint64_t>(text.size()));
        CHECK_EQ(got.buffered, std::size_t{0});
    }
}

// ---------------------------------------------------------------------------
// Locale
// ---------------------------------------------------------------------------

TEST(FileFollower, AProgramWideNarrowCodecvtDoesNotChangeTheBytesThatAreRead) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    write_file(path, "2026-10-10T00:00:01Z WARN svc lower case message\n");  // written under the classic locale
    FileFollower f({path});

    std::vector<LogEntry> got;
    {
        GlobalLocale shouting(std::locale(std::locale::classic(), new ShoutingCodecvt));
        got = f.poll();
    }
    CHECK_EQ(got.size(), std::size_t{1});
    CHECK_EQ(got[0].service, std::string("svc"));
    CHECK_EQ(got[0].message, std::string("lower case message"));  // not "LOWER CASE MESSAGE"
    CHECK_EQ(f.stats().bytes, size_of(path));
}

// ---------------------------------------------------------------------------
// Heap use and allocation failures
// ---------------------------------------------------------------------------

TEST(FileFollower, AGrowingPartialLineIsNotCopiedByEveryPoll) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    write_file(path, "");
    FileFollower f({path});
    const std::size_t length = 500000;
    append_file(path, std::string(length, 'q'));
    CHECK(f.poll().empty());
    CHECK_EQ(f.buffered_bytes(), length);

    // One byte more per poll. Copying the buffered line every time would request 500 KB per poll.
    long long requested = 0;
    for (int i = 0; i < 100; ++i) {
        append_file(path, "q");
        requested += measure([&] { (void)f.poll(); }).total;
    }
    CHECK_EQ(f.buffered_bytes(), length + 100);
    CHECK(requested < static_cast<long long>(length) * 4);  // at most one geometric growth, and small change

    append_file(path, "\n");
    CHECK(f.poll().empty());  // malformed, not delivered
    CHECK_EQ(f.stats().malformed, std::uint64_t{1});
    CHECK_EQ(f.buffered_bytes(), std::size_t{0});
}

TEST(FileFollower, PeakHeapUseOfAPollDoesNotGrowWithAnUnterminatedLine) {
    Scratch dir;
    const std::string path = dir.path("a.log");
    write_file(path, line_of(1) + std::string(3 * 1024 * 1024, 'z'));  // 3 MiB, never terminated
    FileFollower f({path}, with_line_limit(4096));
    std::vector<LogEntry> got;
    const AllocationUse use = measure([&] { got = f.poll(); });
    CHECK_EQ(names(got), std::string("m1"));
    CHECK(use.peak < 200 * 1024);  // a read chunk and small change, nothing like the 3 MiB
    CHECK(f.buffered_bytes() <= 4096);
}

// Every allocation of a poll in turn fails. A std::bad_alloc that escapes must leave the follower
// as it was, and a failure that a stream swallows (it becomes a failed read) must only delay
// bytes: either way, in the end, every entry is delivered exactly once, like by a follower that
// never saw a failure.
TEST(FileFollower, AnAllocationFailureInsideAPollLosesAndDuplicatesNothing) {
    Scratch dir;
    const std::string a = dir.path("a.log");
    const std::string b = dir.path("b.log");
    const std::string c = dir.path("c.log");
    const std::string third = line_of(3);
    const std::string thirty = line_of(30);
    write_file(a, lines_of(1, 2) + third.substr(0, 20));
    write_file(b, thirty.substr(0, 12));
    write_file(c, lines_of(60, 62));
    FileFollower base({a, b, c});
    CHECK_EQ(names(base.poll()), std::string("m1 m2 m60 m61 m62"));
    CHECK_EQ(base.buffered_bytes(), std::size_t{32});  // 20 + 12

    // What the polls under test find: a's line completes (it is copied out of the buffered part)
    // and more lines follow, c was replaced by a shorter file, and b only grows by more of its
    // unfinished line (appended to the buffered part in place); later b's line is finished.
    append_file(a, third.substr(20) + "junk\n" + lines_of(4, 5));
    write_file(c, lines_of(70, 71));
    const std::string b_grown = thirty.substr(0, 22);
    const std::uint64_t bytes_without_b = size_of(a) + 114 + size_of(c);  // c: the old file's 114 bytes and the new one

    std::size_t tried = 0;
    for (long k = 1; k < 5000; ++k) {
        write_file(b, b_grown);  // b is restored, because it gets finished below
        FileFollower f = base;
        FileFollower clean = base;
        std::vector<LogEntry> got;
        std::vector<LogEntry> want;

        bool threw = false;
        bool fired = false;
        {
            AllocationFault fault(k);
            try {
                got = f.poll();
            } catch (const std::bad_alloc&) {
                threw = true;
            }
            fired = fault.fired();
        }
        if (!fired) break;  // a poll needs fewer than k allocations: every earlier k has been tried
        ++tried;
        if (threw) {  // the strong guarantee: nothing observable changed
            CHECK_EQ(f.stats().entries, base.stats().entries);
            CHECK_EQ(f.stats().malformed, base.stats().malformed);
            CHECK_EQ(f.stats().bytes, base.stats().bytes);
            CHECK_EQ(f.stats().rotations, base.stats().rotations);
            CHECK_EQ(f.buffered_bytes(), base.buffered_bytes());
            CHECK_EQ(f.backlog(), base.backlog());
            CHECK(got.empty());
        }
        poll_all(f, got);
        poll_all(clean, want);
        CHECK_EQ(names(want), std::string("m3 m4 m5 m70 m71"));
        CHECK_EQ(f.buffered_bytes(), std::size_t{22});  // b's partial line grew in place
        CHECK_EQ(clean.buffered_bytes(), std::size_t{22});

        append_file(b, thirty.substr(22));
        poll_all(f, got);
        poll_all(clean, want);
        CHECK_EQ(names(want), std::string("m3 m4 m5 m70 m71 m30"));
        check_same_entries(got, want);
        CHECK_EQ(f.buffered_bytes(), std::size_t{0});
        CHECK_EQ(f.stats().entries, std::uint64_t{11});
        CHECK_EQ(f.stats().malformed, std::uint64_t{1});
        CHECK_EQ(f.stats().rotations, std::uint64_t{1});
        CHECK_EQ(f.stats().bytes, bytes_without_b + size_of(b));
        CHECK_EQ(clean.stats().entries, f.stats().entries);
        CHECK_EQ(clean.stats().bytes, f.stats().bytes);
    }
    CHECK(tried >= 10);  // the polls really allocate, and every allocation was failed in turn
}
