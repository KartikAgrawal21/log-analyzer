#include "loganalyzer/cli.hpp"

#include <algorithm>
#include <chrono>
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
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "loganalyzer/alert_engine.hpp"
#include "loganalyzer/error_signature.hpp"
#include "loganalyzer/inverted_index.hpp"
#include "loganalyzer/kmp.hpp"
#include "loganalyzer/level.hpp"
#include "loganalyzer/log_entry.hpp"
#include "loganalyzer/log_generator.hpp"
#include "loganalyzer/log_merger.hpp"
#include "loganalyzer/log_parser.hpp"
#include "loganalyzer/report.hpp"
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
  loganalyzer top-errors FILE... [--k N] [--min-level LEVEL]
      Most frequent error signatures (default: top 10 at level ERROR and above).
  loganalyzer alerts FILE... --rule SPEC [--rule SPEC ...] [--rules-file FILE]
      Replay the merged logs through sliding-window alert rules. SPEC is comma-separated key=value:
        name=NAME,threshold=N,window=60s[,service=S][,level=ERROR][,cooldown=5m][,per-service=true]
      Fires when >= N matching entries fall inside the window; cooldown suppresses repeats.
      A rules file holds one SPEC per line; lines starting with '#' are comments.
  loganalyzer report FILE... [--out report.html] [--title T] [--top N] [--buckets N] [--rule SPEC ...] [--rules-file F]
      One self-contained HTML dashboard (no scripts, no network): summary, levels, services,
      timeline, top error signatures and, with rules, the alerts they fire. Stdout without --out.
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
  loganalyzer help

FILE arguments may contain * and ? in the file name (logs/*.log); matches are sorted by name.

Log line format:
  2026-10-10T12:00:00.123Z ERROR payment-service Timeout calling bank gateway after 3000ms
)";

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

int cmd_top_errors(const std::vector<std::string>& args, std::ostream& out) {
    const ParsedArgs parsed = parse_args(args, {"--k", "--min-level"});
    if (parsed.positional.empty()) throw UsageError("top-errors needs at least one FILE");
    const std::vector<std::string> files = expand_inputs(parsed.positional);

    const std::size_t k = static_cast<std::size_t>(uint_option(parsed, "--k", 10, 1, 1'000'000));
    Level min_level = Level::Error;
    if (parsed.has("--min-level")) {
        const std::optional<Level> level = level_from_string(parsed.options.at("--min-level"));
        if (!level) throw UsageError("--min-level must be one of DEBUG, INFO, WARN, ERROR");
        min_level = *level;
    }

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

int cmd_alerts(const std::vector<std::string>& args, std::ostream& out, std::ostream& err) {
    const ParsedArgs parsed = parse_args(args, {"--rules-file"}, {"--rule"});
    if (parsed.positional.empty()) throw UsageError("alerts needs at least one FILE");
    const std::vector<std::string> files = expand_inputs(parsed.positional);

    AlertEngine engine;
    for (const std::string& spec : parsed.all("--rule")) {
        try {
            engine.add_rule(parse_rule_spec(spec));
        } catch (const std::invalid_argument& e) {
            throw UsageError("bad --rule '" + spec + "': " + e.what());
        }
    }
    if (parsed.has("--rules-file")) load_rules_file(parsed.options.at("--rules-file"), engine);
    if (engine.rule_count() == 0) throw UsageError("alerts needs at least one --rule or --rules-file");

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
            out << format_iso8601_utc(a.fired_at_ms) << " ALERT rule=" << a.rule << " service=" << a.service
                << " count=" << a.count << " since=" << format_iso8601_utc(a.first_event_ms)
                << " suppressed=" << a.suppressed << "\n";
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

int cmd_report(const std::vector<std::string>& args, std::ostream& out, std::ostream& err) {
    const ParsedArgs parsed = parse_args(args, {"--out", "--title", "--top", "--buckets", "--rules-file"}, {"--rule"});
    if (parsed.positional.empty()) throw UsageError("report needs at least one FILE");
    const std::vector<std::string> files = expand_inputs(parsed.positional);

    ReportOptions options;
    if (parsed.has("--title")) options.title = parsed.options.at("--title");
    options.top_k = static_cast<std::size_t>(uint_option(parsed, "--top", options.top_k, 1, 1000));
    options.time_buckets = static_cast<std::size_t>(uint_option(parsed, "--buckets", options.time_buckets, 1, 400));

    AlertEngine engine;
    for (const std::string& spec : parsed.all("--rule")) {
        try {
            engine.add_rule(parse_rule_spec(spec));
        } catch (const std::invalid_argument& e) {
            throw UsageError("bad --rule '" + spec + "': " + e.what());
        }
    }
    if (parsed.has("--rules-file")) load_rules_file(parsed.options.at("--rules-file"), engine);

    std::size_t malformed = 0;
    std::vector<std::vector<LogEntry>> sources;
    sources.reserve(files.size());
    for (const std::string& path : files) {
        sources.push_back(load_file(path, malformed));
        if (engine.rule_count() != 0) require_sorted(path, sources.back());  // rules need a time-ordered stream
    }

    std::vector<LogEntry> entries;
    std::vector<Alert> alerts;
    if (engine.rule_count() != 0) {
        KWayMerger merger(std::move(sources));
        entries.reserve(merger.remaining());
        while (merger.has_next()) {
            entries.push_back(merger.next());
            for (Alert& alert : engine.process(entries.back())) alerts.push_back(std::move(alert));
            if ((entries.size() & 0xFFF) == 0) engine.expire_idle(entries.back().timestamp_ms);
        }
    } else {
        for (std::vector<LogEntry>& source : sources) {
            entries.insert(entries.end(), std::make_move_iterator(source.begin()), std::make_move_iterator(source.end()));
        }
    }

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
    return kOk;
}

}  // namespace

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
        if (command == "generate") return cmd_generate(args, out);
        if (command == "merge") return cmd_merge(args, out, err);
        if (command == "top-errors") return cmd_top_errors(args, out);
        if (command == "alerts") return cmd_alerts(args, out, err);
        if (command == "report") return cmd_report(args, out, err);
        if (command == "grep") return cmd_grep(args, out, err);
        if (command == "search") return cmd_search(args, out, err);
        if (command == "complete") return cmd_complete(args, out, err);
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
