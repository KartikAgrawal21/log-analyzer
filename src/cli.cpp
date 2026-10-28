#include "loganalyzer/cli.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <ostream>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "loganalyzer/alert_engine.hpp"
#include "loganalyzer/error_signature.hpp"
#include "loganalyzer/file_follower.hpp"
#include "loganalyzer/http_server.hpp"
#include "loganalyzer/hyperloglog.hpp"
#include "loganalyzer/inverted_index.hpp"
#include "loganalyzer/kmp.hpp"
#include "loganalyzer/level.hpp"
#include "loganalyzer/log_entry.hpp"
#include "loganalyzer/log_generator.hpp"
#include "loganalyzer/log_merger.hpp"
#include "loganalyzer/log_parser.hpp"
#include "loganalyzer/report.hpp"
#include "loganalyzer/serve.hpp"
#include "loganalyzer/sketch_top_k.hpp"
#include "loganalyzer/top_k_errors.hpp"
#include "loganalyzer/trie.hpp"
#include "loganalyzer/wildcard.hpp"

namespace loganalyzer {
namespace {

namespace fs = std::filesystem;

constexpr int kOk = 0;
constexpr int kRuntimeError = 1;
constexpr int kUsageError = 2;

/// Bad command line (exit code 2). Anything else that throws is a runtime failure (code 1).
struct UsageError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

constexpr const char* kHelpText = R"(loganalyzer - log analytics engine

Usage:
  loganalyzer generate --out-dir DIR [--count N] [--seed S] [--services a,b,c]
      Write one <service>.log file per service, N lines each (default 10000).
  loganalyzer merge FILE... [--out FILE]
      K-way merge time-sorted log files into one sorted stream (stdout unless --out).
  loganalyzer top-errors FILE... [--k N] [--min-level LEVEL] [--approx [--width W] [--depth D]]
      Most frequent error signatures (default: top 10 at level ERROR and above). With --approx the
      counts come from a fixed-memory Count-Min Sketch (estimates never undercount).
  loganalyzer distinct FILE... [--field service|signature|message|token] [--precision P] [--min-level LEVEL] [--exact]
      Number of distinct values, estimated with HyperLogLog (P = 4..18, default 14 = 16 KiB);
      --exact also counts them exactly with a hash set and prints the error.
  loganalyzer alerts FILE... --rule SPEC [--rule SPEC ...] [--rules-file FILE]
      Replay the merged logs through sliding-window alert rules. SPEC is comma-separated key=value:
        name=NAME,threshold=N,window=60s[,service=S][,level=ERROR][,cooldown=5m][,per-service=true]
      Fires when >= N matching entries fall inside the window; cooldown suppresses repeats.
      A rules file holds one SPEC per line; lines starting with '#' are comments.
  loganalyzer alerts FILE... --rule SPEC --follow [--from-end] [--poll-ms N] [--max-seconds N] [--max-alerts N]
      Live mode: keep watching the files (they may not exist yet) and print each alert the moment it
      fires. Existing content is replayed first unless --from-end. Polls every 250 ms; --max-alerts N
      exits after N alerts (handy in scripts), --max-seconds N after N seconds. Ctrl+C stops it.
  loganalyzer report FILE... [--out report.html] [--title T] [--top N] [--buckets N] [--rule SPEC ...] [--rules-file F]
      One self-contained HTML dashboard (no scripts, no network): summary, levels, services,
      timeline, top error signatures and, with rules, the alerts they fire. Stdout without --out.
  loganalyzer serve FILE... [--port 8080] [--bind 127.0.0.1] [--title T] [--rule SPEC ...] [--rules-file F]
                            [--allow-host NAME ...] [--max-requests N] [--follow [--refresh-ms N]]
      Dashboard over HTTP: the HTML report at / and a JSON API (/api/summary, /api/top-errors,
      /api/search?q=, /api/complete?prefix=, /api/alerts, /healthz). Loopback only by default; the
      Host header is checked (DNS-rebinding defence). --port 0 picks a free port; --max-requests
      stops after N requests (for scripts). With --follow the dashboard keeps up with growing log
      files: a request arriving more than --refresh-ms (default 1000) after the last look reads
      what was appended and rebuilds the snapshot. Press Ctrl+C to stop.
  loganalyzer grep PATTERN FILE... [--ignore-case] [--level LEVEL] [--service NAME] [--max N] [--count]
      Entries whose message contains PATTERN (KMP substring search); --level is a minimum.
  loganalyzer search QUERY FILE... [--limit N] [--count]
      Boolean search over "service LEVEL message" using an inverted index. QUERY is
      space-separated words, all required; a|b means either; -word excludes. Case-insensitive.
        e.g. "payment error timeout|refused -retry"
  loganalyzer complete FILE... [--prefix P] [--field signature|service|word] [--k N] [--min-level LEVEL]
      Most frequent completions of a prefix (trie autocomplete). Default field: signature.
  loganalyzer bench [--count N]
      Time every stage on N generated entries in total (default 1000000).
  loganalyzer help | --version

FILE arguments may contain * and ? in the file name (logs/*.log); matches are sorted by name.

Log line format:
  2026-10-10T12:00:00.123Z ERROR payment-service Timeout calling bank gateway after 3000ms
)";

// ---------------------------------------------------------------------------
// Graceful shutdown (Ctrl+C) for the long-running commands
// ---------------------------------------------------------------------------

// Set from a signal handler and from request_shutdown(), so it must be a lock-free atomic.
std::atomic<bool> g_shutdown_requested{false};
static_assert(std::atomic<bool>::is_always_lock_free, "a signal handler may only touch lock-free atomics");

void handle_interrupt(int) { g_shutdown_requested.store(true); }

bool shutdown_requested() { return g_shutdown_requested.load(); }

/// Makes Ctrl+C ask the running command to finish (so it can print its summary) instead of
/// killing the process, and restores the previous handler afterwards. Constructing it also
/// clears an earlier request: a stop requested before the command started is stale. Construct it
/// BEFORE announcing that the command is running, so anyone who reacts to the announcement
/// (a test calling request_shutdown(), a user pressing Ctrl+C) is never ignored.
class InterruptScope {
public:
    InterruptScope() {
        g_shutdown_requested.store(false);
        previous_ = std::signal(SIGINT, handle_interrupt);
    }
    ~InterruptScope() {
        if (previous_ != SIG_ERR) std::signal(SIGINT, previous_);
    }
    InterruptScope(const InterruptScope&) = delete;
    InterruptScope& operator=(const InterruptScope&) = delete;

private:
    using Handler = void (*)(int);
    Handler previous_ = SIG_ERR;
};

/// Sleeps up to `millis`, returning early when a shutdown is requested.
void sleep_unless_shutdown(std::uint64_t millis) {
    constexpr std::uint64_t kSlice = 20;
    while (millis > 0 && !shutdown_requested()) {
        const std::uint64_t step = millis < kSlice ? millis : kSlice;
        std::this_thread::sleep_for(std::chrono::milliseconds(step));
        millis -= step;
    }
}

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------

struct ParsedArgs {
    std::vector<std::string> positional;
    std::map<std::string, std::string> options;
    std::map<std::string, std::vector<std::string>> repeated;  // options that may be given many times
    std::set<std::string> flags;                               // value-less switches that were given

    bool has(const std::string& name) const { return options.count(name) != 0; }
    bool flag(const std::string& name) const { return flags.count(name) != 0; }
    const std::vector<std::string>& all(const std::string& name) const {
        static const std::vector<std::string> kNone;
        auto it = repeated.find(name);
        return it == repeated.end() ? kNone : it->second;
    }
};

/// "--name value" or "--name=value" for the names in `allowed` or `repeatable`, bare "--name"
/// for the value-less `flags`; everything else is positional. A `repeatable` option may
/// appear any number of times (see all()).
ParsedArgs parse_args(const std::vector<std::string>& args, const std::set<std::string>& allowed,
                      const std::set<std::string>& repeatable = {},
                      const std::set<std::string>& flags = {}) {
    ParsedArgs parsed;
    for (std::size_t i = 1; i < args.size(); ++i) {  // args[0] is the command
        const std::string& arg = args[i];
        if (arg.size() < 3 || arg.compare(0, 2, "--") != 0) {
            parsed.positional.push_back(arg);
            continue;
        }
        std::string name = arg;
        std::string value;
        bool has_value = false;
        const std::size_t eq = arg.find('=');
        if (eq != std::string::npos) {
            name = arg.substr(0, eq);
            value = arg.substr(eq + 1);
            has_value = true;
        }
        if (flags.count(name) != 0) {
            if (has_value) throw UsageError("option " + name + " does not take a value");
            parsed.flags.insert(name);
            continue;
        }
        const bool is_repeatable = repeatable.count(name) != 0;
        if (!is_repeatable && allowed.count(name) == 0) throw UsageError("unknown option: " + name);
        if (!has_value) {
            if (i + 1 >= args.size()) throw UsageError("option " + name + " needs a value");
            value = args[++i];
        }
        if (is_repeatable) {
            parsed.repeated[name].push_back(std::move(value));
            continue;
        }
        if (parsed.has(name)) throw UsageError("option " + name + " given more than once");
        parsed.options[name] = std::move(value);
    }
    return parsed;
}

std::uint64_t parse_uint(const std::string& option, const std::string& text,
                         std::uint64_t min_value, std::uint64_t max_value) {
    if (text.empty()) throw UsageError(option + " needs a number");
    std::uint64_t value = 0;
    for (char c : text) {
        if (c < '0' || c > '9') {
            throw UsageError(option + " must be a non-negative integer, got '" + text + "'");
        }
        const std::uint64_t digit = static_cast<std::uint64_t>(c - '0');
        if (value > (std::numeric_limits<std::uint64_t>::max() - digit) / 10) {
            throw UsageError(option + " is too large: " + text);
        }
        value = value * 10 + digit;
    }
    if (value < min_value || value > max_value) {
        throw UsageError(option + " must be between " + std::to_string(min_value) + " and " +
                         std::to_string(max_value) + ", got " + text);
    }
    return value;
}

std::uint64_t uint_option(const ParsedArgs& args, const std::string& name, std::uint64_t fallback,
                          std::uint64_t min_value, std::uint64_t max_value) {
    auto it = args.options.find(name);
    if (it == args.options.end()) return fallback;
    return parse_uint(name, it->second, min_value, max_value);
}

void reject_positional(const ParsedArgs& args, const std::string& command) {
    if (!args.positional.empty()) {
        throw UsageError(command + " takes no positional arguments, got '" + args.positional[0] + "'");
    }
}

// ---------------------------------------------------------------------------
// File helpers
// ---------------------------------------------------------------------------

std::vector<LogEntry> load_file(const std::string& path, std::size_t& malformed_total) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("cannot open file: " + path);
    std::size_t malformed = 0;
    std::vector<LogEntry> entries = parse_stream(in, &malformed);
    malformed_total += malformed;
    return entries;
}

/// The merger would also reject an unsorted source, but only by index; we want the file name.
void require_sorted(const std::string& path, const std::vector<LogEntry>& entries) {
    for (std::size_t i = 1; i < entries.size(); ++i) {
        if (entries[i].timestamp_ms < entries[i - 1].timestamp_ms) {
            throw std::runtime_error("input file is not sorted by timestamp: " + path + " (entry " +
                                     std::to_string(i + 1) + " is earlier than entry " +
                                     std::to_string(i) + ")");
        }
    }
}

/// Appends one formatted line per entry, flushing the buffer in ~1 MiB chunks.
class LineWriter {
public:
    explicit LineWriter(std::ostream& os) : os_(os) { buffer_.reserve(kFlushAt + 512); }
    ~LineWriter() { flush(); }

    void write(const LogEntry& entry) {
        buffer_ += format_entry(entry);
        buffer_ += '\n';
        if (buffer_.size() >= kFlushAt) flush();
    }

    void flush() {
        if (!buffer_.empty()) {
            os_.write(buffer_.data(), static_cast<std::streamsize>(buffer_.size()));
            buffer_.clear();
        }
    }

private:
    static constexpr std::size_t kFlushAt = 1 << 20;
    std::ostream& os_;
    std::string buffer_;
};

/// Service names become file names, so keep them to a safe alphabet (no path separators).
bool is_safe_service_name(const std::string& name) {
    if (name.empty() || name == "." || name == "..") return false;
    for (char c : name) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                        c == '-' || c == '_' || c == '.';
        if (!ok) return false;
    }
    return true;
}

std::vector<std::string> split_commas(const std::string& text) {
    std::vector<std::string> parts;
    std::size_t start = 0;
    while (true) {
        const std::size_t comma = text.find(',', start);
        parts.push_back(text.substr(start, comma == std::string::npos ? std::string::npos : comma - start));
        if (comma == std::string::npos) break;
        start = comma + 1;
    }
    return parts;
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// Neither cmd.exe nor PowerShell expands wildcards for native programs, so the tool does it:
/// an input such as logs/*.log (wildcards in the file-name part only) becomes the matching
/// regular files, sorted by name so the merge's tie-breaking order is deterministic. An input
/// without wildcards, or naming an existing file, is kept as is.
std::vector<std::string> expand_inputs(const std::vector<std::string>& inputs) {
    std::vector<std::string> result;
    for (const std::string& input : inputs) {
        std::error_code exists_ec;  // non-throwing overload: a '*' in a path is invalid on Windows
        if (input.find_first_of("*?") == std::string::npos || fs::exists(fs::path(input), exists_ec)) {
            result.push_back(input);
            continue;
        }
        const fs::path pattern(input);
        const fs::path dir = pattern.parent_path();
        if (dir.string().find_first_of("*?") != std::string::npos) {
            throw UsageError("wildcards are only supported in the file name, not in directories: " + input);
        }
        const std::string name_pattern = pattern.filename().string();
        std::error_code ec;
        fs::directory_iterator it(dir.empty() ? fs::path(".") : dir, ec);
        if (ec) throw std::runtime_error("cannot read directory for " + input + ": " + ec.message());
        std::vector<std::string> matches;
        for (const fs::directory_entry& entry : it) {
            std::error_code type_ec;
            if (!entry.is_regular_file(type_ec)) continue;
            const std::string name = entry.path().filename().string();
            if (wildcard_match(name_pattern, name)) {
                matches.push_back(dir.empty() ? name : (dir / name).string());
            }
        }
        if (matches.empty()) throw std::runtime_error("no files match: " + input);
        std::sort(matches.begin(), matches.end());
        result.insert(result.end(), matches.begin(), matches.end());
    }
    return result;
}

int cmd_generate(const std::vector<std::string>& args, std::ostream& out) {
    const ParsedArgs parsed = parse_args(args, {"--out-dir", "--count", "--seed", "--services"});
    reject_positional(parsed, "generate");
    if (!parsed.has("--out-dir")) throw UsageError("generate requires --out-dir DIR");

    const std::size_t count =
        static_cast<std::size_t>(uint_option(parsed, "--count", 10000, 1, 50'000'000));

    GeneratorConfig config;
    config.seed = uint_option(parsed, "--seed", config.seed, 0, std::numeric_limits<std::uint64_t>::max());
    if (parsed.has("--services")) {
        config.services = split_commas(parsed.options.at("--services"));
        std::set<std::string> seen;
        for (const std::string& name : config.services) {
            if (!is_safe_service_name(name)) {
                throw UsageError("invalid service name '" + name +
                                 "' (use letters, digits, '-', '_' and '.')");
            }
            if (!seen.insert(name).second) throw UsageError("duplicate service name '" + name + "'");
        }
    } else {
        for (const std::string& name : config.services) {
            if (!is_safe_service_name(name)) throw std::logic_error("built-in service name is unsafe: " + name);
        }
    }

    std::unique_ptr<LogGenerator> generator;
    try {
        generator = std::make_unique<LogGenerator>(config);
    } catch (const std::invalid_argument& e) {
        throw UsageError(e.what());
    }

    const fs::path dir = parsed.options.at("--out-dir");
    std::error_code ec;
    fs::create_directories(dir, ec);
    if (ec) throw std::runtime_error("cannot create directory " + dir.string() + ": " + ec.message());

    for (std::size_t i = 0; i < config.services.size(); ++i) {
        const std::vector<LogEntry> entries = generator->generate_service(i, count);
        const fs::path path = dir / (config.services[i] + ".log");
        std::ofstream file(path, std::ios::binary);
        if (!file) throw std::runtime_error("cannot write file: " + path.string());
        {
            LineWriter writer(file);
            for (const LogEntry& entry : entries) writer.write(entry);
        }
        file.flush();
        if (!file) throw std::runtime_error("write failed: " + path.string());
        out << "wrote " << entries.size() << " entries to " << path.string() << "\n";
    }
    return kOk;
}

int cmd_merge(const std::vector<std::string>& args, std::ostream& out, std::ostream& err) {
    const ParsedArgs parsed = parse_args(args, {"--out"});
    if (parsed.positional.empty()) throw UsageError("merge needs at least one FILE");
    const std::vector<std::string> files = expand_inputs(parsed.positional);

    std::size_t malformed = 0;
    std::vector<std::vector<LogEntry>> sources;
    sources.reserve(files.size());
    for (const std::string& path : files) {
        sources.push_back(load_file(path, malformed));
        require_sorted(path, sources.back());
    }

    KWayMerger merger(std::move(sources));
    const std::size_t total = merger.remaining();

    std::ofstream file;
    std::ostream* sink = &out;
    if (parsed.has("--out")) {
        const std::string& path = parsed.options.at("--out");
        file.open(path, std::ios::binary);
        if (!file) throw std::runtime_error("cannot write file: " + path);
        sink = &file;
    }
    {
        LineWriter writer(*sink);
        while (merger.has_next()) writer.write(merger.next());
    }
    sink->flush();
    if (!*sink) throw std::runtime_error("write failed");

    err << "merged " << total << " entries from " << files.size() << " files (" << malformed
        << " malformed skipped)\n";
    return kOk;
}

/// A sketch counts plain strings, so a (service, signature) group is encoded as
/// "<len>:<service><signature>". The length prefix keeps ("ab","c") and ("a","bc") distinct,
/// which a bare concatenation would merge.
std::string sketch_key(const std::string& service, const std::string& signature) {
    std::string key = std::to_string(service.size());
    key += ':';
    key += service;
    key += signature;
    return key;
}

/// Inverse of sketch_key; false when `key` is not one of ours.
bool split_sketch_key(const std::string& key, std::string& service, std::string& signature) {
    const std::size_t colon = key.find(':');
    if (colon == std::string::npos || colon == 0 || colon > 18) return false;
    std::uint64_t length = 0;
    for (std::size_t i = 0; i < colon; ++i) {
        if (key[i] < '0' || key[i] > '9') return false;
        length = length * 10 + static_cast<std::uint64_t>(key[i] - '0');
    }
    if (length > key.size() - colon - 1) return false;
    service = key.substr(colon + 1, static_cast<std::size_t>(length));
    signature = key.substr(colon + 1 + static_cast<std::size_t>(length));
    return true;
}

/// top-errors with a fixed-memory Count-Min Sketch instead of one counter per group.
int top_errors_approx(const std::vector<std::string>& files, std::size_t k, Level min_level, std::size_t width,
                      std::size_t depth, std::ostream& out) {
    SketchTopK sketch(k, width, depth);
    std::size_t malformed = 0;
    for (const std::string& path : files) {
        for (const LogEntry& entry : load_file(path, malformed)) {
            if (entry.level < min_level) continue;
            sketch.add(sketch_key(entry.service, normalize_signature(entry.message)));
        }
    }

    const std::vector<HeavyHitter> top = sketch.top();
    if (top.empty()) {
        out << "no entries at level " << to_string(min_level) << " or above found (" << malformed
            << " malformed lines skipped)\n";
        return kOk;
    }

    std::size_t count_width = 5;
    std::size_t service_width = 7;
    std::vector<std::string> services(top.size()), signatures(top.size());
    for (std::size_t i = 0; i < top.size(); ++i) {
        if (!split_sketch_key(top[i].key, services[i], signatures[i])) {
            throw std::logic_error("sketch returned a key this command did not create");
        }
        count_width = std::max(count_width, std::to_string(top[i].estimate).size() + 1);
        service_width = std::max(service_width, services[i].size());
    }

    out << "Approximate top " << top.size() << " signature groups (level >= " << to_string(min_level) << ", "
        << sketch.total() << " entries, " << malformed << " malformed lines skipped)\n";
    out << "Count-Min Sketch " << sketch.sketch().width() << " x " << sketch.sketch().depth() << " = "
        << sketch.memory_bytes() / 1024 << " KiB total, whatever the number of groups. Counts are estimates: they\n"
        << "never undercount, and each is off by at most " << std::fixed << std::setprecision(1)
        << sketch.sketch().epsilon() * static_cast<double>(sketch.total()) << " (epsilon*N) with probability >= "
        << std::setprecision(3) << 1.0 - sketch.sketch().delta() << ".\n\n"
        << std::defaultfloat;
    out << std::setw(4) << "RANK" << "  " << std::setw(static_cast<int>(count_width)) << "EST" << "  " << std::left
        << std::setw(static_cast<int>(service_width)) << "SERVICE" << std::right << "  SIGNATURE\n";
    for (std::size_t i = 0; i < top.size(); ++i) {
        out << std::setw(4) << i + 1 << "  " << std::setw(static_cast<int>(count_width))
            << ("~" + std::to_string(top[i].estimate)) << "  " << std::left << std::setw(static_cast<int>(service_width))
            << services[i] << std::right << "  " << signatures[i] << "\n";
    }
    return kOk;
}

int cmd_top_errors(const std::vector<std::string>& args, std::ostream& out) {
    const ParsedArgs parsed = parse_args(args, {"--k", "--min-level", "--width", "--depth"}, {}, {"--approx"});
    if (parsed.positional.empty()) throw UsageError("top-errors needs at least one FILE");
    const std::vector<std::string> files = expand_inputs(parsed.positional);

    const std::size_t k = static_cast<std::size_t>(uint_option(parsed, "--k", 10, 1, 1'000'000));
    Level min_level = Level::Error;
    if (parsed.has("--min-level")) {
        const std::optional<Level> level = level_from_string(parsed.options.at("--min-level"));
        if (!level) throw UsageError("--min-level must be one of DEBUG, INFO, WARN, ERROR");
        min_level = *level;
    }

    if (parsed.flag("--approx")) {
        const std::size_t width = static_cast<std::size_t>(uint_option(parsed, "--width", 4096, 16, 10'000'000));
        const std::size_t depth = static_cast<std::size_t>(uint_option(parsed, "--depth", 4, 1, 16));
        return top_errors_approx(files, k, min_level, width, depth, out);
    }
    if (parsed.has("--width") || parsed.has("--depth")) throw UsageError("--width and --depth need --approx");

    TopKErrors counter(min_level);
    std::size_t malformed = 0;
    for (const std::string& path : files) {
        for (const LogEntry& entry : load_file(path, malformed)) counter.add(entry);
    }

    const std::vector<SignatureCount> top = counter.top_k(k);
    if (top.empty()) {
        out << "no entries at level " << to_string(min_level) << " or above found (" << malformed
            << " malformed lines skipped)\n";
        return kOk;
    }

    std::size_t count_width = 5;
    std::size_t service_width = 7;
    for (const SignatureCount& g : top) {
        count_width = std::max(count_width, std::to_string(g.count).size());
        service_width = std::max(service_width, g.service.size());
    }

    out << "Top " << top.size() << " of " << counter.distinct() << " signature groups (level >= "
        << to_string(min_level) << ", " << counter.total() << " entries, " << malformed
        << " malformed lines skipped)\n\n";
    out << std::setw(4) << "RANK" << "  " << std::setw(static_cast<int>(count_width)) << "COUNT" << "  "
        << std::left << std::setw(static_cast<int>(service_width)) << "SERVICE" << std::right << "  SIGNATURE\n";
    std::size_t rank = 1;
    for (const SignatureCount& g : top) {
        out << std::setw(4) << rank++ << "  " << std::setw(static_cast<int>(count_width)) << g.count << "  "
            << std::left << std::setw(static_cast<int>(service_width)) << g.service << std::right << "  "
            << g.signature << "\n";
        out << std::string(4 + 2 + count_width + 2, ' ') << "first " << format_iso8601_utc(g.first_seen_ms)
            << "  last " << format_iso8601_utc(g.last_seen_ms) << "\n";
        out << std::string(4 + 2 + count_width + 2, ' ') << "e.g. " << g.example << "\n";
    }
    return kOk;
}

/// One rule spec per line; blank lines and lines starting with '#' are skipped.
void load_rules_file(const std::string& path, AlertEngine& engine) {
    // Binary mode: in text mode MSVC treats a stray 0x1A byte as end-of-file and would silently
    // drop every rule after it. A trailing '\r' (CRLF files) is stripped below instead.
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("cannot open rules file: " + path);
    std::string line;
    std::size_t line_number = 0;
    while (std::getline(in, line)) {
        ++line_number;
        if (line_number == 1) {
            // Editors and PowerShell's UTF-8 output start the file with a BOM; UTF-16 (what
            // '>' redirection writes in Windows PowerShell 5.1) cannot be read byte-wise.
            if (line.compare(0, 3, "\xEF\xBB\xBF") == 0) {
                line.erase(0, 3);
            } else if (line.compare(0, 2, "\xFF\xFE") == 0 || line.compare(0, 2, "\xFE\xFF") == 0) {
                throw std::runtime_error(path + " is UTF-16 encoded; save the rules file as UTF-8 or ASCII");
            }
        }
        std::size_t begin = 0, end = line.size();
        while (begin < end && (line[begin] == ' ' || line[begin] == '\t')) ++begin;
        while (end > begin && (line[end - 1] == ' ' || line[end - 1] == '\t' || line[end - 1] == '\r')) --end;
        if (begin == end || line[begin] == '#') continue;
        try {
            engine.add_rule(parse_rule_spec(std::string_view(line).substr(begin, end - begin)));
        } catch (const std::invalid_argument& e) {
            throw UsageError(path + ":" + std::to_string(line_number) + ": " + e.what());
        }
    }
}

/// Builds an AlertEngine from the repeatable --rule options and an optional --rules-file.
AlertEngine alert_engine_from(const ParsedArgs& parsed) {
    AlertEngine engine;
    for (const std::string& spec : parsed.all("--rule")) {
        try {
            engine.add_rule(parse_rule_spec(spec));
        } catch (const std::invalid_argument& e) {
            throw UsageError("bad --rule '" + spec + "': " + e.what());
        }
    }
    if (parsed.has("--rules-file")) load_rules_file(parsed.options.at("--rules-file"), engine);
    return engine;
}

/// One alert as a line of output.
void write_alert(std::ostream& out, const Alert& a) {
    out << format_iso8601_utc(a.fired_at_ms) << " ALERT rule=" << a.rule << " service=" << a.service
        << " count=" << a.count << " since=" << format_iso8601_utc(a.first_event_ms)
        << " suppressed=" << a.suppressed << "\n";
}

bool timestamp_less(const LogEntry& a, const LogEntry& b) { return a.timestamp_ms < b.timestamp_ms; }

/// alerts --follow: keeps polling the files and prints each alert the moment it fires.
///
/// Live input has no global order (files grow independently), so each poll's batch is sorted by
/// timestamp and replayed in that order; an entry older than what its window has already seen is
/// counted as late by the engine, not mis-ordered.
int alerts_follow(const std::vector<std::string>& files, AlertEngine& engine, bool from_end, std::uint64_t poll_ms,
                  std::uint64_t max_seconds, std::uint64_t max_alerts, std::ostream& out, std::ostream& err) {
    FollowerOptions follower_options;
    follower_options.from_start = !from_end;
    // Nothing accumulates here, so keep each poll small: its entries are held in memory at once
    // (a log of tiny lines becomes about nine times as many bytes of LogEntry objects).
    follower_options.max_bytes_per_poll = 1 << 20;
    FileFollower follower(files, follower_options);
    // With --from-end the first poll only records where each file ends (it returns nothing).
    // Do it BEFORE announcing that we are following: whatever is appended after the
    // announcement must be seen, never mistaken for content that was already there.
    if (from_end) (void)follower.poll();

    InterruptScope interrupt;  // before the announcement below: see InterruptScope
    err << "following " << files.size() << (files.size() == 1 ? " file" : " files") << " with " << engine.rule_count()
        << (engine.rule_count() == 1 ? " rule" : " rules") << " (press Ctrl+C to stop)" << std::endl;

    using Clock = std::chrono::steady_clock;
    const Clock::time_point started = Clock::now();
    std::uint64_t entries = 0;
    std::uint64_t alerts = 0;
    bool finished = false;
    while (!finished && !shutdown_requested()) {
        do {
            std::vector<LogEntry> batch = follower.poll();
            std::stable_sort(batch.begin(), batch.end(), timestamp_less);
            for (const LogEntry& entry : batch) {
                ++entries;
                for (const Alert& a : engine.process(entry)) {
                    write_alert(out, a);
                    out.flush();  // an alert is only useful if the reader sees it now
                    if (!out) throw std::runtime_error("write failed");
                    ++alerts;
                    if (max_alerts != 0 && alerts >= max_alerts) finished = true;
                }
                if ((entries & 0xFFF) == 0) engine.expire_idle(entry.timestamp_ms);
                if (finished) break;
            }
        } while (!finished && follower.backlog() && !shutdown_requested());
        if (finished) break;
        if (max_seconds != 0 &&
            static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(Clock::now() - started).count()) >=
                max_seconds) {
            break;
        }
        sleep_unless_shutdown(poll_ms);
    }

    const FollowStats& stats = follower.stats();
    err << "processed " << entries << " entries with " << engine.rule_count() << " rules: " << alerts << " alerts ("
        << stats.malformed << " malformed lines skipped, " << engine.late_events() << " late entries ignored, "
        << stats.rotations << " file rotations seen";
    if (engine.unreported_suppressed() != 0) {
        err << ", " << engine.unreported_suppressed() << " suppressed crossings after the last alert";
    }
    err << ")\n";
    return kOk;
}

int cmd_alerts(const std::vector<std::string>& args, std::ostream& out, std::ostream& err) {
    const ParsedArgs parsed = parse_args(args, {"--rules-file", "--poll-ms", "--max-seconds", "--max-alerts"},
                                         {"--rule"}, {"--follow", "--from-end"});
    if (parsed.positional.empty()) throw UsageError("alerts needs at least one FILE");
    const bool follow = parsed.flag("--follow");
    if (!follow && (parsed.flag("--from-end") || parsed.has("--poll-ms") || parsed.has("--max-seconds") ||
                    parsed.has("--max-alerts"))) {
        throw UsageError("--from-end, --poll-ms, --max-seconds and --max-alerts only make sense with --follow");
    }
    const std::vector<std::string> files = expand_inputs(parsed.positional);

    AlertEngine engine = alert_engine_from(parsed);
    if (engine.rule_count() == 0) throw UsageError("alerts needs at least one --rule or --rules-file");

    if (follow) {
        return alerts_follow(files, engine, parsed.flag("--from-end"), uint_option(parsed, "--poll-ms", 250, 10, 60'000),
                             uint_option(parsed, "--max-seconds", 0, 1, 31'536'000),
                             uint_option(parsed, "--max-alerts", 0, 1, 1'000'000'000), out, err);
    }

    std::size_t malformed = 0;
    std::vector<std::vector<LogEntry>> sources;
    sources.reserve(files.size());
    for (const std::string& path : files) {
        sources.push_back(load_file(path, malformed));
        require_sorted(path, sources.back());
    }

    // Rules need one globally time-ordered stream, which is exactly what the merge produces.
    KWayMerger merger(std::move(sources));
    std::uint64_t entries = 0;
    std::uint64_t alerts = 0;
    while (merger.has_next()) {
        const LogEntry entry = merger.next();
        ++entries;
        for (const Alert& a : engine.process(entry)) {
            ++alerts;
            write_alert(out, a);
        }
        // Keep memory proportional to the services active in the last window, not to every
        // service ever seen (the merged stream is time-ordered, as expire_idle requires).
        if ((entries & 0xFFF) == 0) engine.expire_idle(entry.timestamp_ms);
    }
    out.flush();
    if (!out) throw std::runtime_error("write failed");

    err << "processed " << entries << " entries with " << engine.rule_count() << " rules: " << alerts
        << " alerts (" << malformed << " malformed lines skipped";
    // Crossings swallowed by a cooldown after the last alert are in no alert's `suppressed`.
    if (engine.unreported_suppressed() != 0) {
        err << ", " << engine.unreported_suppressed() << " suppressed crossings after the last alert";
    }
    err << ")\n";
    return kOk;
}

/// "--level" style option: a level name, or `fallback` when the option is absent.
Level level_option(const ParsedArgs& args, const std::string& name, Level fallback) {
    if (!args.has(name)) return fallback;
    const std::optional<Level> level = level_from_string(args.options.at(name));
    if (!level) throw UsageError(name + " must be one of DEBUG, INFO, WARN, ERROR");
    return *level;
}

int cmd_grep(const std::vector<std::string>& args, std::ostream& out, std::ostream& err) {
    const ParsedArgs parsed = parse_args(args, {"--level", "--service", "--max"}, {}, {"--ignore-case", "--count"});
    if (parsed.positional.size() < 2) throw UsageError("grep needs a PATTERN and at least one FILE");
    const std::string& pattern = parsed.positional.front();
    if (pattern.empty()) throw UsageError("grep PATTERN must not be empty");
    const std::vector<std::string> files =
        expand_inputs(std::vector<std::string>(parsed.positional.begin() + 1, parsed.positional.end()));

    const Level min_level = level_option(parsed, "--level", Level::Debug);
    const std::string service = parsed.has("--service") ? parsed.options.at("--service") : std::string();
    const std::size_t max_lines = static_cast<std::size_t>(uint_option(parsed, "--max", 0, 1, 1'000'000'000));
    const bool count_only = parsed.flag("--count");
    const KmpMatcher matcher(pattern, parsed.flag("--ignore-case"));

    std::size_t malformed = 0, scanned = 0, matched = 0, printed = 0;
    {
        LineWriter writer(out);
        for (const std::string& path : files) {
            for (const LogEntry& entry : load_file(path, malformed)) {
                ++scanned;
                if (entry.level < min_level) continue;
                if (!service.empty() && entry.service != service) continue;
                if (!matcher.contains(entry.message)) continue;
                ++matched;
                if (!count_only && (max_lines == 0 || printed < max_lines)) {
                    writer.write(entry);
                    ++printed;
                }
            }
        }
    }
    if (count_only) out << matched << "\n";
    out.flush();
    if (!out) throw std::runtime_error("write failed");

    err << "matched " << matched << " of " << scanned << " entries (" << malformed << " malformed skipped)";
    if (!count_only && printed < matched) err << ", showing the first " << printed;
    err << "\n";
    return kOk;
}

int cmd_search(const std::vector<std::string>& args, std::ostream& out, std::ostream& err) {
    const ParsedArgs parsed = parse_args(args, {"--limit"}, {}, {"--count"});
    if (parsed.positional.size() < 2) throw UsageError("search needs a QUERY and at least one FILE");
    const std::string& query = parsed.positional.front();
    const std::vector<std::string> files =
        expand_inputs(std::vector<std::string>(parsed.positional.begin() + 1, parsed.positional.end()));
    const std::size_t limit = static_cast<std::size_t>(uint_option(parsed, "--limit", 50, 1, 1'000'000'000));
    const bool count_only = parsed.flag("--count");

    // Each entry is indexed as "service LEVEL message", so queries can name a service or a
    // level ("payment error timeout") as well as words from the message. DocId = position.
    std::vector<LogEntry> entries;
    InvertedIndex index;
    std::size_t malformed = 0;
    for (const std::string& path : files) {
        for (LogEntry& entry : load_file(path, malformed)) {
            std::string text = entry.service;
            text += ' ';
            text += to_string(entry.level);
            text += ' ';
            text += entry.message;
            index.add(text);
            entries.push_back(std::move(entry));
        }
    }

    const std::vector<DocId> hits = index.search(query);
    std::size_t shown = 0;
    if (count_only) {
        out << hits.size() << "\n";
    } else {
        LineWriter writer(out);
        for (DocId id : hits) {
            if (shown == limit) break;
            writer.write(entries[id]);
            ++shown;
        }
    }
    out.flush();
    if (!out) throw std::runtime_error("write failed");

    err << hits.size() << " matches among " << entries.size() << " entries (" << index.term_count()
        << " distinct terms, " << malformed << " malformed skipped)";
    if (!count_only && shown < hits.size()) err << ", showing the first " << shown;
    err << "\n";
    return kOk;
}

int cmd_complete(const std::vector<std::string>& args, std::ostream& out, std::ostream& err) {
    const ParsedArgs parsed = parse_args(args, {"--prefix", "--field", "--k", "--min-level"});
    if (parsed.positional.empty()) throw UsageError("complete needs at least one FILE");
    const std::vector<std::string> files = expand_inputs(parsed.positional);

    const std::string field = parsed.has("--field") ? parsed.options.at("--field") : std::string("signature");
    if (field != "signature" && field != "service" && field != "word") {
        throw UsageError("--field must be one of signature, service, word");
    }
    const std::size_t k = static_cast<std::size_t>(uint_option(parsed, "--k", 10, 1, 1'000'000));
    const Level min_level = level_option(parsed, "--min-level", Level::Debug);
    std::string prefix = parsed.has("--prefix") ? parsed.options.at("--prefix") : std::string();
    if (field == "word") {  // words are indexed lower-case, so make the prefix case-insensitive
        for (char& c : prefix) {
            if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
        }
    }

    Trie trie;
    std::size_t malformed = 0, entries = 0;
    for (const std::string& path : files) {
        for (const LogEntry& entry : load_file(path, malformed)) {
            if (entry.level < min_level) continue;
            ++entries;
            if (field == "service") {
                trie.insert(entry.service);
            } else if (field == "signature") {
                const std::string signature = normalize_signature(entry.message);
                if (!signature.empty()) trie.insert(signature);
            } else {
                for (const std::string& token : tokenize(entry.message)) trie.insert(token);
            }
        }
    }

    const std::vector<Completion> best = trie.complete(prefix, k);
    if (best.empty()) {
        out << "no " << field << " starts with '" << prefix << "'\n";
    } else {
        std::size_t width = 5;
        for (const Completion& c : best) width = std::max(width, std::to_string(c.weight).size());
        out << "Top " << best.size() << " " << field << " completions of '" << prefix << "' (" << trie.size()
            << " distinct, " << entries << " entries)\n\n";
        out << std::setw(static_cast<int>(width)) << "COUNT" << "  " << field << "\n";
        for (const Completion& c : best) out << std::setw(static_cast<int>(width)) << c.weight << "  " << c.key << "\n";
    }
    out.flush();
    if (!out) throw std::runtime_error("write failed");
    err << entries << " entries read (" << malformed << " malformed skipped)\n";
    return kOk;
}

/// Everything `report` and `serve` need from the input files: the entries, and the alerts the
/// rules fire on them.
struct LoadedLogs {
    std::vector<LogEntry> entries;
    std::vector<Alert> alerts;
    std::size_t malformed = 0;
};

/// Reads the files. With rules, the files must each be time-sorted: they are k-way merged and
/// replayed through the engine, so `entries` comes out time-ordered. Without rules the entries
/// are simply concatenated in file order.
LoadedLogs load_logs(const std::vector<std::string>& files, AlertEngine& engine) {
    LoadedLogs logs;
    std::vector<std::vector<LogEntry>> sources;
    sources.reserve(files.size());
    for (const std::string& path : files) {
        sources.push_back(load_file(path, logs.malformed));
        if (engine.rule_count() != 0) require_sorted(path, sources.back());  // rules need a time-ordered stream
    }

    if (engine.rule_count() != 0) {
        KWayMerger merger(std::move(sources));
        logs.entries.reserve(merger.remaining());
        while (merger.has_next()) {
            logs.entries.push_back(merger.next());
            for (Alert& alert : engine.process(logs.entries.back())) logs.alerts.push_back(std::move(alert));
            if ((logs.entries.size() & 0xFFF) == 0) engine.expire_idle(logs.entries.back().timestamp_ms);
        }
    } else {
        for (std::vector<LogEntry>& source : sources) {
            logs.entries.insert(logs.entries.end(), std::make_move_iterator(source.begin()),
                                std::make_move_iterator(source.end()));
        }
    }
    return logs;
}

int cmd_report(const std::vector<std::string>& args, std::ostream& out, std::ostream& err) {
    const ParsedArgs parsed = parse_args(args, {"--out", "--title", "--top", "--buckets", "--rules-file"}, {"--rule"});
    if (parsed.positional.empty()) throw UsageError("report needs at least one FILE");
    const std::vector<std::string> files = expand_inputs(parsed.positional);

    ReportOptions options;
    if (parsed.has("--title")) options.title = parsed.options.at("--title");
    options.top_k = static_cast<std::size_t>(uint_option(parsed, "--top", options.top_k, 1, 1000));
    options.time_buckets = static_cast<std::size_t>(uint_option(parsed, "--buckets", options.time_buckets, 1, 400));

    AlertEngine engine = alert_engine_from(parsed);
    const LoadedLogs logs = load_logs(files, engine);
    const std::vector<LogEntry>& entries = logs.entries;
    const std::vector<Alert>& alerts = logs.alerts;
    const std::size_t malformed = logs.malformed;

    const std::string html = render_html_report(entries, alerts, options);
    if (parsed.has("--out")) {
        const std::string& path = parsed.options.at("--out");
        std::ofstream file(path, std::ios::binary);
        if (!file) throw std::runtime_error("cannot write file: " + path);
        file.write(html.data(), static_cast<std::streamsize>(html.size()));
        file.flush();
        if (!file) throw std::runtime_error("write failed: " + path);
    } else {
        out.write(html.data(), static_cast<std::streamsize>(html.size()));
        out.flush();
        if (!out) throw std::runtime_error("write failed");
    }
    err << "report: " << entries.size() << " entries, " << alerts.size() << " alerts, " << malformed
        << " malformed lines skipped";
    if (parsed.has("--out")) err << " -> " << parsed.options.at("--out");
    err << "\n";
    return kOk;
}

/// "127.x.y.z": the whole 127.0.0.0/8 block is loopback.
bool is_loopback_address(const std::string& address) { return address.compare(0, 4, "127.") == 0; }

/// serve --follow: a dashboard that keeps up with growing log files.
///
/// DashboardService is an immutable snapshot (its indexes and the rendered page are built once).
/// To stay live, a request that arrives after `refresh` has passed since the last look polls the
/// FileFollower and, if anything new came in, replays it through the alert engine and swaps in a
/// freshly built service before answering. The HttpServer calls the handler from one thread at a
/// time, so no locking is needed; a refresh costs O(entries) and delays only the request that
/// triggered it. Without traffic nothing is read.
class LiveDashboard {
public:
    LiveDashboard(const std::vector<std::string>& files, AlertEngine engine, ServeOptions options,
                  std::chrono::milliseconds refresh)
        : follower_(files), engine_(std::move(engine)), options_(std::move(options)), refresh_(refresh) {
        // Everything already in the files (the static `serve` loads all of it too), then keep
        // following from there.
        ingest(std::numeric_limits<std::size_t>::max());
        rebuild();
        last_check_ = Clock::now();
    }

    HttpResponse handle(const HttpRequest& request) {
        refresh_if_due();
        return service_->handle(request);
    }

    std::size_t entry_count() const { return entries_.size(); }
    std::uint64_t malformed() const { return follower_.stats().malformed; }

private:
    using Clock = std::chrono::steady_clock;

    /// Reads whatever is new, at most `max_rounds` polls' worth (so one huge backlog cannot stall a
    /// request for ever; the rest is picked up by the next refresh). True if any entry arrived.
    bool ingest(std::size_t max_rounds) {
        bool any = false;
        for (std::size_t round = 0; round < max_rounds; ++round) {
            std::vector<LogEntry> batch = follower_.poll();
            std::stable_sort(batch.begin(), batch.end(), timestamp_less);
            for (LogEntry& entry : batch) {
                for (Alert& alert : engine_.process(entry)) alerts_.push_back(std::move(alert));
                entries_.push_back(std::move(entry));
                any = true;
                if ((entries_.size() & 0xFFF) == 0) engine_.expire_idle(entries_.back().timestamp_ms);
            }
            if (!follower_.backlog()) break;
        }
        return any;
    }

    void rebuild() { service_ = std::make_shared<DashboardService>(entries_, alerts_, options_); }

    void refresh_if_due() {
        const Clock::time_point now = Clock::now();
        if (now - last_check_ < refresh_) return;
        last_check_ = now;
        if (ingest(64)) rebuild();  // the old service keeps answering if building the new one throws
    }

    FileFollower follower_;
    AlertEngine engine_;
    ServeOptions options_;
    std::chrono::milliseconds refresh_;
    std::vector<LogEntry> entries_;
    std::vector<Alert> alerts_;
    std::shared_ptr<DashboardService> service_;
    Clock::time_point last_check_;
};

int cmd_serve(const std::vector<std::string>& args, std::ostream& out, std::ostream& err) {
    const ParsedArgs parsed = parse_args(
        args, {"--port", "--bind", "--title", "--top", "--buckets", "--rules-file", "--max-requests", "--refresh-ms"},
        {"--rule", "--allow-host"}, {"--follow"});
    if (parsed.positional.empty()) throw UsageError("serve needs at least one FILE");
    const bool follow = parsed.flag("--follow");
    if (!follow && parsed.has("--refresh-ms")) throw UsageError("--refresh-ms only makes sense with --follow");
    const std::uint64_t refresh_ms = uint_option(parsed, "--refresh-ms", 1000, 50, 3'600'000);
    const std::vector<std::string> files = expand_inputs(parsed.positional);

    ServeOptions options;
    options.title = parsed.has("--title") ? parsed.options.at("--title") : std::string("Log dashboard");
    options.top_k = static_cast<std::size_t>(uint_option(parsed, "--top", options.top_k, 1, 1000));
    options.time_buckets = static_cast<std::size_t>(uint_option(parsed, "--buckets", options.time_buckets, 1, 400));

    HttpServerOptions server_options;
    server_options.bind_address = parsed.has("--bind") ? parsed.options.at("--bind") : std::string("127.0.0.1");
    server_options.port = static_cast<std::uint16_t>(uint_option(parsed, "--port", 8080, 0, 65535));
    const std::uint64_t max_requests = uint_option(parsed, "--max-requests", 0, 1, 1'000'000'000);  // 0 = no limit

    // DNS-rebinding defence: on loopback only the names that reach this machine are answered.
    // On any other address the operator must say which names are expected (--allow-host), or the
    // check stays off, with a warning.
    std::vector<std::string> hosts = parsed.all("--allow-host");
    if (is_loopback_address(server_options.bind_address)) {
        for (const std::string& name : {std::string("localhost"), std::string("127.0.0.1"), server_options.bind_address}) {
            if (std::find(hosts.begin(), hosts.end(), name) == hosts.end()) hosts.push_back(name);
        }
    }
    server_options.allowed_hosts = hosts;

    AlertEngine engine = alert_engine_from(parsed);
    HttpHandler handler;
    std::size_t entry_count = 0;
    std::uint64_t malformed = 0;
    if (follow) {
        auto live = std::make_shared<LiveDashboard>(files, std::move(engine), options,
                                                    std::chrono::milliseconds(static_cast<std::int64_t>(refresh_ms)));
        entry_count = live->entry_count();
        malformed = live->malformed();
        handler = [live](const HttpRequest& request) { return live->handle(request); };
    } else {
        LoadedLogs logs = load_logs(files, engine);
        entry_count = logs.entries.size();
        malformed = logs.malformed;
        // DashboardService is move-only; the handler (a std::function) must be copyable.
        auto service = std::make_shared<DashboardService>(std::move(logs.entries), std::move(logs.alerts), options);
        handler = [service](const HttpRequest& request) { return service->handle(request); };
    }

    std::unique_ptr<HttpServer> server;
    try {
        server = std::make_unique<HttpServer>(server_options);
    } catch (const std::invalid_argument& e) {
        throw UsageError(e.what());
    }
    server->start(std::move(handler));

    InterruptScope interrupt;  // before the announcement below: see InterruptScope
    out << "serving " << entry_count << " entries on http://" << server_options.bind_address << ":" << server->port()
        << "/ (press Ctrl+C to stop)" << std::endl;
    if (follow) {
        err << "following " << files.size() << (files.size() == 1 ? " file" : " files")
            << ", refreshing at most every " << refresh_ms << " ms when requests arrive\n";
    }
    if (server_options.allowed_hosts.empty()) {
        err << "warning: bound to " << server_options.bind_address
            << " without Host header checking; pass --allow-host NAME (repeatable) to answer only the names "
               "you expect\n";
    }
    if (malformed != 0) err << malformed << " malformed lines skipped\n";

    while (server->running() && !shutdown_requested() &&
           (max_requests == 0 || server->requests_served() < max_requests)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    server->stop();
    err << "served " << server->requests_served() << " requests\n";
    return kOk;
}

/// Signed relative error in percent, "+0.04%"; "n/a" when there is nothing to divide by.
std::string percent_error(double estimate, double exact) {
    if (exact <= 0.0) return "n/a";
    std::ostringstream os;
    os << std::showpos << std::fixed << std::setprecision(2) << (estimate - exact) / exact * 100.0 << "%";
    return os.str();
}

int cmd_distinct(const std::vector<std::string>& args, std::ostream& out, std::ostream& err) {
    const ParsedArgs parsed = parse_args(args, {"--field", "--precision", "--min-level"}, {}, {"--exact"});
    if (parsed.positional.empty()) throw UsageError("distinct needs at least one FILE");
    const std::vector<std::string> files = expand_inputs(parsed.positional);

    const std::string field = parsed.has("--field") ? parsed.options.at("--field") : std::string("signature");
    if (field != "service" && field != "signature" && field != "message" && field != "token") {
        throw UsageError("--field must be one of service, signature, message, token");
    }
    const unsigned precision = static_cast<unsigned>(uint_option(parsed, "--precision", 14, 4, 18));
    const Level min_level = level_option(parsed, "--min-level", Level::Debug);
    const bool exact_too = parsed.flag("--exact");

    HyperLogLog hll(precision);
    std::unordered_set<std::string> exact;
    std::size_t entries = 0, malformed = 0;
    auto add = [&](const std::string& value) {
        hll.add(value);
        if (exact_too) exact.insert(value);
    };
    for (const std::string& path : files) {
        for (const LogEntry& entry : load_file(path, malformed)) {
            if (entry.level < min_level) continue;
            ++entries;
            if (field == "service") {
                add(entry.service);
            } else if (field == "message") {
                add(entry.message);
            } else if (field == "signature") {
                add(normalize_signature(entry.message));
            } else {
                for (const std::string& token : tokenize(entry.message)) add(token);
            }
        }
    }

    out << "distinct " << field << " values over " << entries << " entries (level >= " << to_string(min_level)
        << ")\n";
    out << "  estimated: " << hll.count() << "   HyperLogLog p=" << precision << ": " << hll.register_count()
        << " registers = " << hll.memory_bytes() / 1024.0 << " KiB, standard error " << std::fixed
        << std::setprecision(2) << hll.standard_error() * 100.0 << "%\n"
        << std::defaultfloat;
    if (exact_too) {
        out << "  exact:     " << exact.size() << "   error " << percent_error(static_cast<double>(hll.count()),
                                                                           static_cast<double>(exact.size()))
            << " (a hash set had to remember every distinct value)\n";
    }
    out.flush();
    if (!out) throw std::runtime_error("write failed");
    err << entries << " entries read (" << malformed << " malformed skipped)\n";
    return kOk;
}

struct BenchRow {
    std::string stage;
    double millis;
};

int cmd_bench(const std::vector<std::string>& args, std::ostream& out) {
    using Clock = std::chrono::steady_clock;
    const ParsedArgs parsed = parse_args(args, {"--count"});
    reject_positional(parsed, "bench");
    const std::size_t requested =
        static_cast<std::size_t>(uint_option(parsed, "--count", 1'000'000, 1, 20'000'000));

    GeneratorConfig config;
    const std::size_t services = config.services.size();
    const std::size_t per_service = std::max<std::size_t>(1, requested / services);
    const std::size_t total = per_service * services;

    std::vector<BenchRow> rows;
    auto mark = Clock::now();
    auto lap = [&](const char* stage) {
        rows.push_back({stage, std::chrono::duration<double, std::milli>(Clock::now() - mark).count()});
    };

    LogGenerator generator(config);
    std::vector<std::vector<LogEntry>> generated = generator.generate_all(per_service);
    lap("generate");

    mark = Clock::now();
    std::vector<std::string> buffers(services);
    std::size_t errors_generated = 0;
    for (std::size_t s = 0; s < services; ++s) {
        buffers[s].reserve(per_service * 96);
        for (const LogEntry& entry : generated[s]) {
            buffers[s] += format_entry(entry);
            buffers[s] += '\n';
            if (entry.level == Level::Error) ++errors_generated;
        }
    }
    lap("format");
    generated = {};

    mark = Clock::now();
    std::vector<std::vector<LogEntry>> sources(services);
    std::size_t bytes = 0;
    for (std::size_t s = 0; s < services; ++s) {
        const std::string_view text(buffers[s]);
        bytes += text.size();
        sources[s].reserve(per_service);
        std::size_t pos = 0;
        while (pos < text.size()) {
            std::size_t end = text.find('\n', pos);
            if (end == std::string_view::npos) end = text.size();
            std::optional<LogEntry> entry = parse_line(text.substr(pos, end - pos));
            if (!entry) throw std::runtime_error("bench: a freshly formatted line failed to parse");
            sources[s].push_back(std::move(*entry));
            pos = end + 1;
        }
    }
    lap("parse");
    buffers = {};

    mark = Clock::now();
    const std::vector<LogEntry> merged = merge_sorted(std::move(sources));
    lap("merge");

    mark = Clock::now();
    TopKErrors counter;
    for (const LogEntry& entry : merged) counter.add(entry);
    const std::vector<SignatureCount> top = counter.top_k(10);
    lap("top-k");

    // The same question answered in fixed memory: a Count-Min Sketch behind a top-10 tracker, and
    // HyperLogLog for the number of distinct messages.
    mark = Clock::now();
    SketchTopK sketch(10, 8192, 4);
    for (const LogEntry& entry : merged) {
        if (entry.level != Level::Error) continue;
        sketch.add(sketch_key(entry.service, normalize_signature(entry.message)));
    }
    const std::vector<HeavyHitter> heavy = sketch.top();
    lap("sketch");

    mark = Clock::now();
    HyperLogLog hll(14);
    for (const LogEntry& entry : merged) hll.add(entry.message);
    const std::uint64_t hll_estimate = hll.count();
    lap("hll");

    // Cheap self-checks so a benchmark number never comes from broken output.
    if (merged.size() != total) throw std::runtime_error("bench: merge lost entries");
    if (!std::is_sorted(merged.begin(), merged.end(), [](const LogEntry& a, const LogEntry& b) {
            return a.timestamp_ms < b.timestamp_ms;
        })) {
        throw std::runtime_error("bench: merged output is not sorted");
    }
    if (counter.total() != errors_generated) throw std::runtime_error("bench: Top-K miscounted errors");

    out << "benchmark: " << total << " entries (" << per_service << " x " << services << " services, "
        << bytes / (1024 * 1024) << " MiB of log text), single run\n\n";
    out << std::left << std::setw(10) << "stage" << std::right << std::setw(10) << "ms" << std::setw(18)
        << "M entries/sec" << "\n";
    for (const BenchRow& row : rows) {
        const double per_sec = row.millis > 0 ? static_cast<double>(total) / row.millis / 1000.0 : 0.0;
        out << std::left << std::setw(10) << row.stage << std::right << std::setw(10) << std::fixed
            << std::setprecision(1) << row.millis << std::setw(18) << std::setprecision(2) << per_sec << "\n";
    }
    out << "\nTop-K check: " << counter.total() << " errors in " << counter.distinct()
        << " signature groups; most frequent: " << (top.empty() ? "-" : top.front().signature) << " ("
        << (top.empty() ? 0 : top.front().count) << "x)\n";

    // Accuracy of the sketches against the exact answers. A Count-Min estimate may be too high
    // but never too low, so an undercount means a bug and fails the run.
    std::unordered_map<std::string, std::uint64_t> exact_counts;
    std::unordered_set<std::string> exact_top;
    for (const SignatureCount& g : counter.top_k(counter.distinct())) {
        exact_counts[sketch_key(g.service, g.signature)] = g.count;
    }
    for (const SignatureCount& g : top) exact_top.insert(sketch_key(g.service, g.signature));
    std::size_t agreed = 0;
    std::uint64_t max_overcount = 0;
    for (const HeavyHitter& h : heavy) {
        const auto it = exact_counts.find(h.key);
        const std::uint64_t truth = it == exact_counts.end() ? 0 : it->second;
        if (h.estimate < truth) throw std::runtime_error("bench: the sketch undercounted a key");
        max_overcount = std::max(max_overcount, h.estimate - truth);
        if (exact_top.count(h.key) != 0) ++agreed;
    }
    out << "Sketch check: top-10 from " << sketch.memory_bytes() / 1024 << " KiB agrees with the exact top-10 on "
        << agreed << "/" << top.size() << " groups, largest overcount " << max_overcount << " (of "
        << sketch.total() << " errors)\n";

    if (total <= 5'000'000) {  // the exact distinct count needs a set of every message: bound its memory
        std::unordered_set<std::string_view> messages;
        for (const LogEntry& entry : merged) messages.insert(entry.message);
        out << "HyperLogLog check: " << hll_estimate << " distinct messages estimated from "
            << hll.memory_bytes() / 1024 << " KiB, exact " << messages.size() << " (error "
            << percent_error(static_cast<double>(hll_estimate), static_cast<double>(messages.size())) << ")\n";
    } else {
        out << "HyperLogLog check: " << hll_estimate << " distinct messages estimated from "
            << hll.memory_bytes() / 1024 << " KiB (exact comparison skipped above 5,000,000 entries)\n";
    }
    return kOk;
}

}  // namespace

void request_shutdown() noexcept { g_shutdown_requested.store(true); }

const char* version_string() noexcept { return "1.0.0"; }

int run_cli(const std::vector<std::string>& args, std::ostream& out, std::ostream& err) {
    try {
        if (args.empty()) {
            err << kHelpText;
            return kUsageError;
        }
        const std::string& command = args[0];
        if (command == "help" || command == "--help" || command == "-h") {
            out << kHelpText;
            return kOk;
        }
        if (command == "version" || command == "--version" || command == "-V") {
            out << "loganalyzer " << version_string() << "\n";
            return kOk;
        }
        if (command == "generate") return cmd_generate(args, out);
        if (command == "merge") return cmd_merge(args, out, err);
        if (command == "top-errors") return cmd_top_errors(args, out);
        if (command == "alerts") return cmd_alerts(args, out, err);
        if (command == "report") return cmd_report(args, out, err);
        if (command == "serve") return cmd_serve(args, out, err);
        if (command == "grep") return cmd_grep(args, out, err);
        if (command == "search") return cmd_search(args, out, err);
        if (command == "complete") return cmd_complete(args, out, err);
        if (command == "distinct") return cmd_distinct(args, out, err);
        if (command == "bench") return cmd_bench(args, out);
        throw UsageError("unknown command: " + command);
    } catch (const UsageError& e) {
        err << "error: " << e.what() << "\nrun 'loganalyzer help' for usage\n";
        return kUsageError;
    } catch (const std::exception& e) {
        err << "error: " << e.what() << "\n";
        return kRuntimeError;
    }
}

}  // namespace loganalyzer
