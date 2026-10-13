#include "loganalyzer/serve.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <map>
#include <optional>
#include <stdexcept>
#include <utility>

#include "loganalyzer/error_signature.hpp"
#include "loganalyzer/inverted_index.hpp"
#include "loganalyzer/level.hpp"
#include "loganalyzer/log_parser.hpp"
#include "loganalyzer/report.hpp"
#include "loganalyzer/top_k_errors.hpp"
#include "loganalyzer/trie.hpp"

namespace loganalyzer {
namespace {

constexpr const char* kJsonType = "application/json; charset=utf-8";
constexpr const char* kHtmlType = "text/html; charset=utf-8";
constexpr const char* kTextType = "text/plain; charset=utf-8";

// Response headers of the HTML page only (see "GET /" in serve.hpp).
constexpr const char* kPageCsp =
    "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

constexpr std::uint64_t kMaxRows = 1000;
constexpr std::uint64_t kDefaultTopK = 10;
constexpr std::uint64_t kDefaultSearchLimit = 50;
constexpr std::size_t kLevelCount = 4;

// The resource bounds of serve.hpp (RESOURCE BOUNDS); change them together with that text.
constexpr std::size_t kMaxFieldBytes = 4096;               // STRINGS: one log string in a response
constexpr std::size_t kMaxBodyBytes = std::size_t{4} << 20;  // BODY: the rows of search / top-errors
constexpr std::size_t kMaxKeyBytes = 256;                  // MAX_KEY: the longest completion key
constexpr std::size_t kMaxMemoEntries = 32;                // memoized completion lists
// The tries cache this many best keys per node (Trie's default): a larger k is a scan, see memo.
constexpr std::size_t kTrieCachedK = 10;
// MEMORY: the estimate for a trie is this many bytes per byte of distinct key text, and tries
// are dropped, least recently used first, while the estimates add up to more than the budget.
constexpr std::size_t kTrieBytesPerKeyByte = 40;
constexpr std::size_t kDefaultTrieBudget = std::size_t{256} << 20;
// Per trie, so that the sum over the (at most 12) tries cannot overflow.
constexpr std::size_t kMaxTrieEstimate = std::numeric_limits<std::size_t>::max() / 16;

// ---------------------------------------------------------------------------------------------
// UTF-8 validation and JSON escaping
// ---------------------------------------------------------------------------------------------

struct Utf8Step {
    std::size_t length;  // bytes consumed, >= 1
    bool valid;          // a complete well-formed sequence, or a maximal invalid subpart
};

// Looks at the sequence that starts at p[0] >= 0x80 with `avail` bytes left (avail >= 1). The
// accepted sequences are the rows of the Unicode well-formedness table (see json_escape in the
// header): the lead byte decides the length and the range of the SECOND byte, every later byte
// is 80..BF. On failure `length` is the number of bytes that were still a valid beginning, so
// the caller emits one U+FFFD for them and resumes at the byte that broke the sequence.
Utf8Step scan_utf8(const unsigned char* p, std::size_t avail) noexcept {
    const unsigned char lead = p[0];
    std::size_t length = 0;
    unsigned char lo = 0x80;
    unsigned char hi = 0xBF;
    if (lead >= 0xC2 && lead <= 0xDF) {
        length = 2;
    } else if (lead >= 0xE0 && lead <= 0xEF) {
        length = 3;
        if (lead == 0xE0) lo = 0xA0;       // E0 80..9F: overlong
        else if (lead == 0xED) hi = 0x9F;  // ED A0..BF: a surrogate
    } else if (lead >= 0xF0 && lead <= 0xF4) {
        length = 4;
        if (lead == 0xF0) lo = 0x90;       // F0 80..8F: overlong
        else if (lead == 0xF4) hi = 0x8F;  // F4 90..BF: above U+10FFFF
    } else {
        return {1, false};  // 80..C1 (stray continuation, overlong C0/C1) and F5..FF
    }
    if (avail < 2 || p[1] < lo || p[1] > hi) return {1, false};
    std::size_t used = 2;
    while (used < length && used < avail && p[used] >= 0x80 && p[used] <= 0xBF) ++used;
    return {used, used == length};
}

// Appends the escaped content of `text`. Runs that need no change are copied in one piece.
void append_escaped(std::string& out, std::string_view text) {
    static const char kHex[] = "0123456789abcdef";
    const std::size_t n = text.size();
    if (n == 0) return;
    const auto* bytes = reinterpret_cast<const unsigned char*>(text.data());
    std::size_t run = 0;  // start of the pending verbatim run [run, i)
    std::size_t i = 0;
    while (i < n) {
        const unsigned char c = bytes[i];
        if (c >= 0x80) {
            const Utf8Step step = scan_utf8(bytes + i, n - i);
            if (step.valid) {
                i += step.length;
                continue;
            }
            out.append(text.data() + run, i - run);
            out.append("\xEF\xBF\xBD", 3);
            i += step.length;
            run = i;
            continue;
        }
        if (c >= 0x20 && c != '"' && c != '\\' && c != '<' && c != '>' && c != '&' && c != 0x7F) {
            ++i;
            continue;
        }
        out.append(text.data() + run, i - run);
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                out += "\\u00";
                out += kHex[c >> 4];
                out += kHex[c & 0x0F];
                break;
        }
        ++i;
        run = i;
    }
    out.append(text.data() + run, n - run);
}

// ---------------------------------------------------------------------------------------------
// JSON building blocks. Member names are fixed ASCII literals, so they need no escaping.
// ---------------------------------------------------------------------------------------------

// A string that the CLIENT sent or that this module wrote: escaped in full.
void append_string(std::string& out, std::string_view text) {
    out.push_back('"');
    append_escaped(out, text);
    out.push_back('"');
}

// How many leading bytes of `text` a response keeps: all of them when there are at most `limit`,
// else the longest prefix of at most `limit` bytes that does not end inside a UTF-8 sequence.
// text[limit] is the first dropped byte; if it is a continuation byte, the character it belongs
// to straddles the limit, so back up to that character's lead byte (a sequence has at most 4
// bytes, so at most 3 steps). Invalid UTF-8 is cut anywhere: json_escape repairs it anyway.
std::size_t clipped_length(std::string_view text, std::size_t limit) noexcept {
    if (text.size() <= limit) return text.size();
    std::size_t keep = limit;
    for (int back = 0; back < 3 && keep > 0 && (static_cast<unsigned char>(text[keep]) & 0xC0) == 0x80; ++back) --keep;
    return keep;
}

// A string that comes from the log: at most kMaxFieldBytes of it, then U+2026 if it was cut
// (serve.hpp, STRINGS). Bounds what one row of a response can cost.
void append_log_string(std::string& out, std::string_view text) {
    const std::size_t keep = clipped_length(text, kMaxFieldBytes);
    out.push_back('"');
    append_escaped(out, text.substr(0, keep));
    if (keep < text.size()) out.append("\xE2\x80\xA6", 3);
    out.push_back('"');
}

void append_uint(std::string& out, std::uint64_t value) {
    char digits[20];
    std::size_t count = 0;
    do {
        digits[count++] = static_cast<char>('0' + value % 10);
        value /= 10;
    } while (value != 0);
    while (count != 0) out.push_back(digits[--count]);
}

// The timestamp formatter only emits digits, '-', ':', '.', 'T' and 'Z': nothing to escape.
void append_time(std::string& out, std::int64_t epoch_ms) {
    out.push_back('"');
    out += format_iso8601_utc(epoch_ms);
    out.push_back('"');
}

void append_key(std::string& out, const char* name) {
    out.push_back('"');
    out += name;
    out += "\":";
}

// The rows of a response are appended to `rows` one at a time; `mark` is where row `index`
// started. Once the rows pass kMaxBodyBytes the row that did it is taken back and the caller
// stops (serve.hpp, BODY). The first row always stays.
bool keep_row(std::string& rows, std::size_t index, std::size_t mark) {
    if (index == 0 || rows.size() <= kMaxBodyBytes) return true;
    rows.resize(mark);
    return false;
}

HttpResponse make_response(int status, const char* content_type, std::string body) {
    HttpResponse response;
    response.status = status;
    response.content_type = content_type;
    response.body = std::move(body);
    return response;
}

HttpResponse json_error(int status, std::string_view message) {
    std::string body = "{\"error\":";
    append_string(body, message);
    body.push_back('}');
    return make_response(status, kJsonType, std::move(body));
}

HttpResponse build_failure_response() { return json_error(500, "internal error"); }

// ---------------------------------------------------------------------------------------------
// Parameters
// ---------------------------------------------------------------------------------------------

// "Plain decimal digits only" in [lo, hi]. Stops as soon as the value leaves the range, so the
// accumulator can never overflow (hi is tiny) and a very long digit string costs one pass at
// most.
bool parse_bounded(std::string_view text, std::uint64_t lo, std::uint64_t hi, std::uint64_t& out) {
    if (text.empty()) return false;
    std::uint64_t value = 0;
    for (const char c : text) {
        if (c < '0' || c > '9') return false;
        value = value * 10 + static_cast<std::uint64_t>(c - '0');
        if (value > hi) return false;
    }
    if (value < lo) return false;
    out = value;
    return true;
}

// Reads an optional integer parameter into `out`: the default when it is absent, otherwise the
// value, which must be in [lo, hi]. On failure `error` is a fixed message naming the parameter.
bool read_count(const HttpRequest& request, const char* name, std::uint64_t fallback, std::uint64_t lo,
                std::uint64_t hi, std::uint64_t& out, std::string& error) {
    const std::string* value = request.query_value(name);
    if (value == nullptr) {
        out = fallback;
        return true;
    }
    if (parse_bounded(*value, lo, hi, out)) return true;
    error = std::string(name) + " must be a whole number from " + std::to_string(lo) + " to " + std::to_string(hi);
    return false;
}

bool read_level(const HttpRequest& request, const char* name, Level fallback, Level& out, std::string& error) {
    const std::string* value = request.query_value(name);
    if (value == nullptr) {
        out = fallback;
        return true;
    }
    const std::optional<Level> level = level_from_string(*value);
    if (level) {
        out = *level;
        return true;
    }
    error = std::string(name) + " must be one of DEBUG, INFO, WARN, ERROR";
    return false;
}

enum class Field : std::size_t { Signature = 0, Service = 1, Word = 2 };
constexpr std::size_t kFieldCount = 3;

std::optional<Field> field_from_string(std::string_view text) {
    if (text == "signature") return Field::Signature;
    if (text == "service") return Field::Service;
    if (text == "word") return Field::Word;
    return std::nullopt;
}

// ---------------------------------------------------------------------------------------------
// Bodies that depend only on the data: rendered once by the constructor
// ---------------------------------------------------------------------------------------------

std::string build_summary(const std::vector<LogEntry>& entries, std::size_t alert_count) {
    struct Counts {
        std::uint64_t entries = 0;
        std::uint64_t errors = 0;
    };
    std::array<std::uint64_t, kLevelCount> levels{};
    // Ordered map keyed by views into `entries` (which is not modified while this runs): no hash
    // table, so service names chosen by an attacker cannot make the lookups degrade.
    std::map<std::string_view, Counts> services;
    std::int64_t first = 0;
    std::int64_t last = 0;
    for (std::size_t i = 0; i < entries.size(); ++i) {
        const LogEntry& entry = entries[i];
        if (i == 0 || entry.timestamp_ms < first) first = entry.timestamp_ms;
        if (i == 0 || entry.timestamp_ms > last) last = entry.timestamp_ms;
        const auto level = static_cast<std::size_t>(entry.level);
        if (level < kLevelCount) ++levels[level];
        Counts& counts = services[entry.service];
        ++counts.entries;
        if (entry.level == Level::Error) ++counts.errors;
    }

    // A total order (names are distinct), so the result does not depend on the sort being stable.
    std::vector<std::pair<std::string_view, Counts>> rows(services.begin(), services.end());
    std::sort(rows.begin(), rows.end(), [](const auto& a, const auto& b) {
        if (a.second.entries != b.second.entries) return a.second.entries > b.second.entries;
        return a.first < b.first;
    });

    std::string out = "{";
    append_key(out, "entries");
    append_uint(out, entries.size());
    out += ",\"levels\":{";
    static const char* const kNames[kLevelCount] = {"debug", "info", "warn", "error"};
    for (std::size_t i = 0; i < kLevelCount; ++i) {
        if (i != 0) out.push_back(',');
        append_key(out, kNames[i]);
        append_uint(out, levels[i]);
    }
    out += "},\"services\":[";
    for (std::size_t i = 0; i < rows.size(); ++i) {
        if (i != 0) out.push_back(',');
        out += "{\"name\":";
        append_log_string(out, rows[i].first);
        out += ",\"entries\":";
        append_uint(out, rows[i].second.entries);
        out += ",\"errors\":";
        append_uint(out, rows[i].second.errors);
        out.push_back('}');
    }
    out += "],\"first\":";
    if (entries.empty()) out += "null"; else append_time(out, first);
    out += ",\"last\":";
    if (entries.empty()) out += "null"; else append_time(out, last);
    out += ",\"alerts\":";
    append_uint(out, alert_count);
    out.push_back('}');
    return out;
}

// In the order given: alerts are never sorted here, whatever their timestamps say.
std::string build_alerts(const std::vector<Alert>& alerts) {
    std::string out = "{\"alerts\":[";
    for (std::size_t i = 0; i < alerts.size(); ++i) {
        const Alert& alert = alerts[i];
        if (i != 0) out.push_back(',');
        out += "{\"rule\":";
        append_log_string(out, alert.rule);
        out += ",\"service\":";
        append_log_string(out, alert.service);
        out += ",\"fired_at\":";
        append_time(out, alert.fired_at_ms);
        out += ",\"count\":";
        append_uint(out, alert.count);
        out += ",\"first_event\":";
        append_time(out, alert.first_event_ms);
        out += ",\"suppressed\":";
        append_uint(out, alert.suppressed);
        out.push_back('}');
    }
    out += "]}";
    return out;
}

// True when the earliest timestamp is exactly INT64_MIN and the latest exactly INT64_MAX.
bool spans_the_whole_int64_range(const std::vector<LogEntry>& entries) noexcept {
    bool has_min = false;
    bool has_max = false;
    for (const LogEntry& entry : entries) {
        has_min = has_min || entry.timestamp_ms == std::numeric_limits<std::int64_t>::min();
        has_max = has_max || entry.timestamp_ms == std::numeric_limits<std::int64_t>::max();
    }
    return has_min && has_max;
}

// Inserts `key` into the trie unless it is empty (the trie rejects it) or longer than
// kMaxKeyBytes (not a completion, see serve.hpp MAX_KEY). `key_bytes` grows by the length of
// every DISTINCT key that was inserted: it is what the memory estimate is based on.
void add_key(Trie& trie, std::size_t& key_bytes, std::string_view key) {
    if (key.empty() || key.size() > kMaxKeyBytes) return;
    const std::size_t before = trie.size();
    trie.insert(key);
    if (trie.size() != before) key_bytes += key.size();
}

}  // namespace

std::string json_escape(std::string_view text) {
    std::string out;
    out.reserve(text.size() + text.size() / 8 + 8);
    append_escaped(out, text);
    return out;
}

// ---------------------------------------------------------------------------------------------
// DashboardService
// ---------------------------------------------------------------------------------------------

struct DashboardService::Impl {
    struct TrieSlot {
        std::unique_ptr<Trie> trie;
        std::size_t estimated_bytes = 0;  // what the trie is assumed to cost while it is resident
        std::uint64_t last_used = 0;      // value of `tick` at the last request that used it
    };

    // The top kMaxRows completions of one (field, level, prefix). The data never changes, so an
    // entry stays correct for ever, even when its trie has been dropped and rebuilt.
    struct MemoEntry {
        Field field;
        Level level;
        std::string prefix;  // at most kMaxKeyBytes long
        std::vector<Completion> top;
        std::uint64_t last_used;
    };

    Impl(std::vector<LogEntry> input, const std::vector<Alert>& alerts, const ServeOptions& options)
        : entries(std::move(input)) {
        memo.reserve(kMaxMemoEntries);  // so that adding an entry never reallocates
        std::string text;  // "service LEVEL message", the same text `search` indexes
        for (const LogEntry& entry : entries) {
            text.clear();
            text += entry.service;
            text += ' ';
            text += to_string(entry.level);
            text += ' ';
            text += entry.message;
            index.add(text);
        }
        ReportOptions report;
        report.title = options.title;
        report.top_k = options.top_k;
        report.time_buckets = options.time_buckets;
        // report.cpp (write_timeline) puts the last entry one bucket too far, past the end of its
        // table, when the timestamps span exactly INT64_MIN..INT64_MAX and the bucket count divides
        // 2^64 - 1 (1, 3, 5, 15, 17, ...): the range is 2^64 wide, which its unsigned span cannot
        // hold. No log has such timestamps (the parser stops at year 9999), but this constructor
        // takes any LogEntry, so the report is rendered from a copy whose earliest timestamp is
        // 1 ms later in that one case (the API below keeps the real ones). Redundant once
        // write_timeline clamps its bucket index.
        if (spans_the_whole_int64_range(entries)) {
            std::vector<LogEntry> shifted = entries;
            for (LogEntry& entry : shifted) {
                if (entry.timestamp_ms == std::numeric_limits<std::int64_t>::min()) ++entry.timestamp_ms;
            }
            html = render_html_report(shifted, alerts, report);
        } else {
            html = render_html_report(entries, alerts, report);
        }
        summary_json = build_summary(entries, alerts.size());
        alerts_json = build_alerts(alerts);
    }

    HttpResponse route(const HttpRequest& request) {
        if (request.method != "GET" && request.method != "HEAD") {
            HttpResponse response = json_error(405, "method not allowed");
            response.headers.push_back(HttpHeader{"Allow", "GET, HEAD"});
            return response;
        }
        const std::string& path = request.path;
        if (path == "/") {
            HttpResponse page = make_response(200, kHtmlType, html);
            page.headers.push_back(HttpHeader{"Content-Security-Policy", kPageCsp});
            page.headers.push_back(HttpHeader{"Referrer-Policy", "no-referrer"});
            return page;
        }
        if (path == "/healthz") return make_response(200, kTextType, "ok");
        if (path == "/api/summary") return make_response(200, kJsonType, summary_json);
        if (path == "/api/top-errors") return top_errors_route(request);
        if (path == "/api/search") return search_route(request);
        if (path == "/api/complete") return complete_route(request);
        if (path == "/api/alerts") return make_response(200, kJsonType, alerts_json);
        return json_error(404, "not found");
    }

    HttpResponse top_errors_route(const HttpRequest& request) {
        std::string error;
        std::uint64_t k = 0;
        Level min_level = Level::Error;
        if (!read_count(request, "k", kDefaultTopK, 1, kMaxRows, k, error) ||
            !read_level(request, "min-level", Level::Error, min_level, error)) {
            return json_error(400, error);
        }

        const TopKErrors& counter = top_errors_for(min_level);
        const std::vector<SignatureCount> top = counter.top_k(static_cast<std::size_t>(k));

        std::string rows;
        for (std::size_t i = 0; i < top.size(); ++i) {
            const SignatureCount& group = top[i];
            const std::size_t mark = rows.size();
            if (i != 0) rows.push_back(',');
            rows += "{\"service\":";
            append_log_string(rows, group.service);
            rows += ",\"signature\":";
            append_log_string(rows, group.signature);
            rows += ",\"count\":";
            append_uint(rows, group.count);
            rows += ",\"first_seen\":";
            append_time(rows, group.first_seen_ms);
            rows += ",\"last_seen\":";
            append_time(rows, group.last_seen_ms);
            rows += ",\"example\":";
            append_log_string(rows, group.example);
            rows.push_back('}');
            if (!keep_row(rows, i, mark)) break;
        }

        std::string body = "{\"total\":";
        body.reserve(rows.size() + 64);
        append_uint(body, counter.total());
        body += ",\"distinct\":";
        append_uint(body, counter.distinct());
        body += ",\"results\":[";
        body += rows;
        body += "]}";
        return make_response(200, kJsonType, std::move(body));
    }

    HttpResponse search_route(const HttpRequest& request) {
        const std::string* query = request.query_value("q");
        if (query == nullptr || query->empty()) {
            return json_error(400, "q is required: give a non-empty search query");
        }
        std::string error;
        std::uint64_t limit = 0;
        if (!read_count(request, "limit", kDefaultSearchLimit, 1, kMaxRows, limit, error)) {
            return json_error(400, error);
        }

        const std::vector<DocId> hits = index.search(*query);
        const std::size_t wanted = std::min<std::size_t>(hits.size(), static_cast<std::size_t>(limit));

        // The rows come first because "shown" (before them in the body) is the number that fit.
        std::string rows;
        std::size_t shown = 0;
        for (; shown < wanted; ++shown) {
            const LogEntry& entry = entries.at(hits[shown]);  // DocId = position; at() maps a bug to a 500
            const std::size_t mark = rows.size();
            if (shown != 0) rows.push_back(',');
            rows += "{\"time\":";
            append_time(rows, entry.timestamp_ms);
            rows += ",\"level\":";
            append_string(rows, to_string(entry.level));
            rows += ",\"service\":";
            append_log_string(rows, entry.service);
            rows += ",\"message\":";
            append_log_string(rows, entry.message);
            rows.push_back('}');
            if (!keep_row(rows, shown, mark)) break;
        }

        std::string body = "{\"query\":";
        body.reserve(rows.size() + query->size() + 128);
        append_string(body, *query);
        body += ",\"matches\":";
        append_uint(body, hits.size());
        body += ",\"shown\":";
        append_uint(body, shown);
        body += ",\"results\":[";
        body += rows;
        body += "]}";
        return make_response(200, kJsonType, std::move(body));
    }

    HttpResponse complete_route(const HttpRequest& request) {
        Field field = Field::Signature;
        if (const std::string* value = request.query_value("field")) {
            const std::optional<Field> parsed = field_from_string(*value);
            if (!parsed) return json_error(400, "field must be one of signature, service, word");
            field = *parsed;
        }
        std::string error;
        std::uint64_t k = 0;
        Level min_level = Level::Debug;
        if (!read_count(request, "k", kDefaultTopK, 1, kMaxRows, k, error) ||
            !read_level(request, "min-level", Level::Debug, min_level, error)) {
            return json_error(400, error);
        }
        std::string prefix;
        if (const std::string* value = request.query_value("prefix")) prefix = *value;
        if (field == Field::Word) {  // words are indexed lower-case, so the prefix is case-insensitive
            for (char& c : prefix) {
                if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
            }
        }

        std::vector<Completion> fresh;
        const std::vector<Completion>* rows = &fresh;
        if (prefix.size() <= kMaxKeyBytes) {  // no key is longer, so a longer prefix matches nothing
            if (k <= kTrieCachedK) {
                fresh = trie_for(field, min_level).complete(prefix, static_cast<std::size_t>(k));  // from the node's cache
            } else {
                rows = &memoized_top(field, min_level, prefix);  // the first k of the top kMaxRows
            }
        }
        const std::size_t shown = std::min<std::size_t>(rows->size(), static_cast<std::size_t>(k));

        static const char* const kFieldNames[kFieldCount] = {"signature", "service", "word"};
        std::string body = "{\"field\":";
        append_string(body, kFieldNames[static_cast<std::size_t>(field)]);
        body += ",\"prefix\":";
        append_string(body, prefix);
        body += ",\"results\":[";
        for (std::size_t i = 0; i < shown; ++i) {
            if (i != 0) body.push_back(',');
            body += "{\"key\":";
            append_log_string(body, (*rows)[i].key);  // at most kMaxKeyBytes: never clipped
            body += ",\"count\":";
            append_uint(body, (*rows)[i].weight);
            body.push_back('}');
        }
        body += "]}";
        return make_response(200, kJsonType, std::move(body));
    }

    // ---- caches: lazily built, not thread-safe (serve.hpp, THREADING AND CACHES) ------------

    // A slot is filled only after its object is complete, so a build that throws leaves the
    // cache exactly as it was.
    const TopKErrors& top_errors_for(Level min_level) {
        std::unique_ptr<TopKErrors>& slot = top_errors_cache[static_cast<std::size_t>(min_level)];
        if (!slot) {
            auto counter = std::make_unique<TopKErrors>(min_level);
            for (const LogEntry& entry : entries) counter->add(entry);
            slot = std::move(counter);
            ++top_errors_builds;
        }
        return *slot;
    }

    const Trie& trie_for(Field field, Level min_level) {
        TrieSlot& slot = trie_cache[static_cast<std::size_t>(field)][static_cast<std::size_t>(min_level)];
        if (!slot.trie) {
            auto trie = std::make_unique<Trie>(kTrieCachedK);
            std::size_t key_bytes = 0;
            std::string token;  // scratch for Field::Word: one token at a time, never all of them
            for (const LogEntry& entry : entries) {
                if (entry.level < min_level) continue;
                switch (field) {
                    case Field::Service:
                        add_key(*trie, key_bytes, entry.service);
                        break;
                    case Field::Signature:
                        add_key(*trie, key_bytes, normalize_signature(entry.message));
                        break;
                    case Field::Word: {
                        detail::TokenScanner scanner(entry.message);  // the scanner tokenize() and the index use
                        while (scanner.next(token)) add_key(*trie, key_bytes, token);
                        break;
                    }
                }
            }
            slot.trie = std::move(trie);
            slot.estimated_bytes =
                key_bytes > kMaxTrieEstimate / kTrieBytesPerKeyByte ? kMaxTrieEstimate : key_bytes * kTrieBytesPerKeyByte;
            ++trie_builds;
            drop_tries_over_budget(slot);
        }
        slot.last_used = ++tick;
        return *slot.trie;
    }

    // Drops the least recently used tries (never `keep`) while the estimates exceed the budget.
    void drop_tries_over_budget(const TrieSlot& keep) noexcept {
        for (;;) {
            std::size_t total = 0;
            TrieSlot* victim = nullptr;
            for (auto& row : trie_cache) {
                for (TrieSlot& slot : row) {
                    if (!slot.trie) continue;
                    total += slot.estimated_bytes;
                    if (&slot != &keep && (victim == nullptr || slot.last_used < victim->last_used)) victim = &slot;
                }
            }
            if (total <= trie_budget || victim == nullptr) return;
            victim->trie.reset();
            victim->estimated_bytes = 0;
        }
    }

    // The top kMaxRows completions of `prefix`, from the memo or (and then remembered) from the
    // trie, which a memo hit does not need. The reference is good until the next call.
    const std::vector<Completion>& memoized_top(Field field, Level level, const std::string& prefix) {
        ++tick;
        for (MemoEntry& entry : memo) {
            if (entry.field == field && entry.level == level && entry.prefix == prefix) {
                entry.last_used = tick;
                ++memo_hits;
                return entry.top;
            }
        }
        ++memo_misses;
        MemoEntry fresh{field, level, prefix, trie_for(field, level).complete(prefix, static_cast<std::size_t>(kMaxRows)), tick};
        if (memo.size() < kMaxMemoEntries) {
            memo.push_back(std::move(fresh));  // capacity was reserved: cannot throw
            return memo.back().top;
        }
        MemoEntry& victim = *std::min_element(
            memo.begin(), memo.end(), [](const MemoEntry& a, const MemoEntry& b) { return a.last_used < b.last_used; });
        victim = std::move(fresh);
        return victim.top;
    }

    CacheStats stats() const noexcept {
        CacheStats result;
        result.trie_builds = trie_builds;
        result.top_errors_builds = top_errors_builds;
        for (const auto& row : trie_cache) {
            for (const TrieSlot& slot : row) result.resident_tries += slot.trie ? 1 : 0;
        }
        result.memo_hits = memo_hits;
        result.memo_misses = memo_misses;
        result.resident_memo = memo.size();
        return result;
    }

    std::vector<LogEntry> entries;
    InvertedIndex index;
    std::string html;
    std::string summary_json;
    std::string alerts_json;

    std::array<std::unique_ptr<TopKErrors>, kLevelCount> top_errors_cache;
    std::array<std::array<TrieSlot, kLevelCount>, kFieldCount> trie_cache;
    std::vector<MemoEntry> memo;
    std::size_t trie_budget = kDefaultTrieBudget;
    std::uint64_t tick = 0;  // a clock for "least recently used": one step per use
    std::size_t trie_builds = 0;
    std::size_t top_errors_builds = 0;
    std::size_t memo_hits = 0;
    std::size_t memo_misses = 0;
};

DashboardService::DashboardService(std::vector<LogEntry> entries, std::vector<Alert> alerts, ServeOptions options)
    : impl_(std::make_unique<Impl>(std::move(entries), alerts, options)), failure_response_(build_failure_response()) {}

DashboardService::~DashboardService() = default;
DashboardService::DashboardService(DashboardService&&) noexcept = default;
DashboardService& DashboardService::operator=(DashboardService&&) noexcept = default;

HttpResponse DashboardService::handle(const HttpRequest& request) {
    return handle_with(request, detail::NoServeFault{});
}

std::size_t DashboardService::entry_count() const noexcept { return impl_ ? impl_->entries.size() : 0; }

DashboardService::CacheStats DashboardService::cache_stats() const noexcept { return impl_ ? impl_->stats() : CacheStats{}; }

void DashboardService::set_trie_budget(std::size_t estimated_bytes) noexcept {
    if (impl_) impl_->trie_budget = estimated_bytes;
}

HttpResponse DashboardService::route(const HttpRequest& request) {
    if (!impl_) throw std::logic_error("DashboardService used after being moved from");
    return impl_->route(request);
}

HttpResponse DashboardService::take_failure_response() noexcept {
    // A moved-from service, or one whose last refill failed, has no spare: try to make one now.
    try {
        if (failure_response_.content_type.empty()) failure_response_ = build_failure_response();
    } catch (...) {
    }
    HttpResponse response = std::move(failure_response_);  // noexcept moves: no allocation
    failure_response_.content_type.clear();                // a moved-from string is only "unspecified"
    failure_response_.body.clear();
    failure_response_.headers.clear();
    try {
        failure_response_ = build_failure_response();  // the spare for the NEXT failure; may fail
    } catch (...) {
    }
    return response;
}

}  // namespace loganalyzer
