#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <limits>
#include <map>
#include <memory>
#include <new>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "loganalyzer/alert_engine.hpp"
#include "loganalyzer/error_signature.hpp"
#include "loganalyzer/http_server.hpp"
#include "loganalyzer/inverted_index.hpp"
#include "loganalyzer/level.hpp"
#include "loganalyzer/log_entry.hpp"
#include "loganalyzer/log_generator.hpp"
#include "loganalyzer/log_parser.hpp"
#include "loganalyzer/report.hpp"
#include "loganalyzer/serve.hpp"
#include "loganalyzer/top_k_errors.hpp"
#include "loganalyzer/trie.hpp"
#include "testkit.hpp"

using namespace loganalyzer;
using namespace std::string_literals;

// The friend that lets a test inject a failure into handle(), count what the caches have done and
// look at the prepared 500 (see serve.hpp).
namespace loganalyzer {
struct DashboardServiceTestAccess {
    template <class Fault>
    static HttpResponse handle_with(DashboardService& service, const HttpRequest& request, Fault&& fault) {
        return service.handle_with(request, std::forward<Fault>(fault));
    }
    static auto cache_stats(const DashboardService& service) { return service.cache_stats(); }
    static void set_trie_budget(DashboardService& service, std::size_t estimated_bytes) {
        service.set_trie_budget(estimated_bytes);
    }
    static const HttpResponse& spare(const DashboardService& service) { return service.failure_response_; }
};
}  // namespace loganalyzer

namespace {

const char* const kJsonType = "application/json; charset=utf-8";
const char* const kHtmlType = "text/html; charset=utf-8";
const char* const kTextType = "text/plain; charset=utf-8";
const std::string kReplacement = "\xEF\xBF\xBD";

// The documented resource bounds (serve.hpp, RESOURCE BOUNDS). They are part of the contract, so
// the tests state them as numbers instead of reading them from the implementation.
const std::string kEllipsis = "\xE2\x80\xA6";             // U+2026, ends every clipped string
constexpr std::size_t kFieldLimit = 4096;                 // bytes of one log string echoed in a response
constexpr std::size_t kKeyLimit = 256;                    // longest completion key (and useful prefix)
constexpr std::size_t kBodyLimit = std::size_t{4} << 20;  // the rows of search / top-errors stop here
constexpr std::size_t kTrieBytesPerKeyByte = 40;          // the estimate behind the tries' memory budget
constexpr std::size_t kMemoLimit = 32;                    // memoized completion lists
const char* const kCsp =
    "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

// =============================================================================================
// UTF-8, written a second time and differently from the code under test: Table 3-7 of the
// Unicode standard as DATA, and a repair routine that follows the "maximal subpart" practice.
// =============================================================================================

struct Utf8Row {
    unsigned char lead_lo, lead_hi;
    unsigned char second_lo, second_hi;
    std::size_t length;
};

const Utf8Row kUtf8Rows[] = {
    {0xC2, 0xDF, 0x80, 0xBF, 2}, {0xE0, 0xE0, 0xA0, 0xBF, 3}, {0xE1, 0xEC, 0x80, 0xBF, 3},
    {0xED, 0xED, 0x80, 0x9F, 3}, {0xEE, 0xEF, 0x80, 0xBF, 3}, {0xF0, 0xF0, 0x90, 0xBF, 4},
    {0xF1, 0xF3, 0x80, 0xBF, 4}, {0xF4, 0xF4, 0x80, 0x8F, 4},
};

const Utf8Row* utf8_row_for(unsigned char lead) {
    for (const Utf8Row& row : kUtf8Rows) {
        if (lead >= row.lead_lo && lead <= row.lead_hi) return &row;
    }
    return nullptr;
}

// How many bytes of `s` starting at `i` still follow the table (for a lead byte with a row);
// the sequence is complete when the result equals row.length.
std::size_t utf8_prefix_length(std::string_view s, std::size_t i, const Utf8Row& row) {
    std::size_t taken = 1;
    for (std::size_t k = 1; k < row.length; ++k) {
        if (i + k >= s.size()) break;
        const auto b = static_cast<unsigned char>(s[i + k]);
        const unsigned char lo = k == 1 ? row.second_lo : static_cast<unsigned char>(0x80);
        const unsigned char hi = k == 1 ? row.second_hi : static_cast<unsigned char>(0xBF);
        if (b < lo || b > hi) break;
        ++taken;
    }
    return taken;
}

bool well_formed_utf8(std::string_view s) {
    std::size_t i = 0;
    while (i < s.size()) {
        const auto c = static_cast<unsigned char>(s[i]);
        if (c < 0x80) {
            ++i;
            continue;
        }
        const Utf8Row* row = utf8_row_for(c);
        if (row == nullptr || utf8_prefix_length(s, i, *row) != row->length) return false;
        i += row->length;
    }
    return true;
}

std::string reference_repair(std::string_view in) {
    std::string out;
    std::size_t i = 0;
    while (i < in.size()) {
        const auto c = static_cast<unsigned char>(in[i]);
        if (c < 0x80) {
            out.push_back(in[i]);
            ++i;
            continue;
        }
        const Utf8Row* row = utf8_row_for(c);
        if (row == nullptr) {
            out += kReplacement;
            ++i;
            continue;
        }
        const std::size_t taken = utf8_prefix_length(in, i, *row);
        if (taken == row->length) out.append(in.data() + i, taken);
        else out += kReplacement;
        i += taken;
    }
    return out;
}

// Escapes ASCII only; the input must already be valid UTF-8 (bytes >= 0x80 pass through).
std::string reference_escape(std::string_view valid_utf8) {
    std::string out;
    for (const char ch : valid_utf8) {
        const auto c = static_cast<unsigned char>(ch);
        if (c == '"') out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\b') out += "\\b";
        else if (c == '\f') out += "\\f";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if (c == '\t') out += "\\t";
        else if (c < 0x20 || c == 0x7F || c == '<' || c == '>' || c == '&') {
            char buf[8];
            std::snprintf(buf, sizeof buf, "\\u%04x", static_cast<unsigned>(c));
            out += buf;
        } else {
            out.push_back(ch);
        }
    }
    return out;
}

std::string from_hex(std::string_view hex) {
    std::string out;
    int pending = -1;
    for (const char c : hex) {
        int v;
        if (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        else continue;  // spaces
        if (pending < 0) {
            pending = v;
        } else {
            out.push_back(static_cast<char>(pending * 16 + v));
            pending = -1;
        }
    }
    return out;
}

std::string to_hex(std::string_view bytes) {
    static const char kDigits[] = "0123456789abcdef";
    std::string out;
    for (const char ch : bytes) {
        const auto c = static_cast<unsigned char>(ch);
        if (!out.empty()) out.push_back(' ');
        out.push_back(kDigits[c >> 4]);
        out.push_back(kDigits[c & 15]);
    }
    return out;
}

// json_escape on a buffer of EXACTLY bytes.size() bytes (no terminator, no slack), so that
// AddressSanitizer reports any read past the end.
std::string escape_exact(std::string_view bytes) {
    std::unique_ptr<char[]> buffer(new char[bytes.empty() ? 1 : bytes.size()]);
    if (!bytes.empty()) std::memcpy(buffer.get(), bytes.data(), bytes.size());
    return json_escape(std::string_view(buffer.get(), bytes.size()));
}

// =============================================================================================
// A strict RFC 8259 JSON parser (grammar of section 2 to 7), used on every response body.
// Stricter than the grammar in two places that cannot hurt a conforming producer: a lone
// surrogate escape is rejected, and so is an object with a duplicate key. The whole text must
// also be well-formed UTF-8 (section 8.1).
// =============================================================================================

struct JValue {
    enum class Type { Null, Bool, Number, String, Array, Object };
    Type type = Type::Null;
    bool boolean = false;
    std::string text;  // String: the decoded value; Number: the lexeme
    std::vector<JValue> items;
    std::vector<std::string> keys;
    std::vector<JValue> values;

    const JValue& at(const std::string& key) const {
        if (type != Type::Object) throw testkit::Failure{"not an object while looking for \"" + key + "\""};
        for (std::size_t i = 0; i < keys.size(); ++i) {
            if (keys[i] == key) return values[i];
        }
        throw testkit::Failure{"missing member \"" + key + "\""};
    }
    const JValue& item(std::size_t i) const {
        if (type != Type::Array || i >= items.size()) throw testkit::Failure{"no array item " + std::to_string(i)};
        return items[i];
    }
    const std::string& str() const {
        if (type != Type::String) throw testkit::Failure{"not a string"};
        return text;
    }
    std::uint64_t u64() const {
        if (type != Type::Number || text.empty() || text.size() > 19) throw testkit::Failure{"not a small integer: " + text};
        std::uint64_t v = 0;
        for (const char c : text) {
            if (c < '0' || c > '9') throw testkit::Failure{"not a non-negative integer: " + text};
            v = v * 10 + static_cast<std::uint64_t>(c - '0');
        }
        return v;
    }
    std::size_t size() const {
        if (type == Type::Array) return items.size();
        if (type == Type::Object) return keys.size();
        throw testkit::Failure{"not a container"};
    }
};

class JsonParser {
public:
    explicit JsonParser(std::string_view text) : s_(text) {}

    bool parse(JValue& out, std::string& error) {
        if (!well_formed_utf8(s_)) {
            error = "the text is not well-formed UTF-8";
            return false;
        }
        try {
            skip_ws();
            value(out, 0);
            skip_ws();
            if (pos_ != s_.size()) fail("data after the value");
            return true;
        } catch (const Problem& p) {
            error = p.what + " at offset " + std::to_string(p.at);
            return false;
        }
    }

private:
    struct Problem {
        std::string what;
        std::size_t at;
    };

    [[noreturn]] void fail(const std::string& what) const { throw Problem{what, pos_}; }

    bool at_end() const { return pos_ >= s_.size(); }

    void skip_ws() {
        while (!at_end() && (s_[pos_] == ' ' || s_[pos_] == '\t' || s_[pos_] == '\n' || s_[pos_] == '\r')) ++pos_;
    }

    void expect(char c) {
        if (at_end() || s_[pos_] != c) fail(std::string("expected '") + c + "'");
        ++pos_;
    }

    void literal(const char* word) {
        const std::size_t n = std::strlen(word);
        if (s_.compare(pos_, n, word) != 0) fail(std::string("expected ") + word);
        pos_ += n;
    }

    void value(JValue& out, int depth) {
        out = JValue();
        if (depth > 64) fail("nesting too deep");
        if (at_end()) fail("unexpected end of text");
        const char c = s_[pos_];
        if (c == '{') {
            object(out, depth);
        } else if (c == '[') {
            array(out, depth);
        } else if (c == '"') {
            out.type = JValue::Type::String;
            out.text = string();
        } else if (c == 't') {
            literal("true");
            out.type = JValue::Type::Bool;
            out.boolean = true;
        } else if (c == 'f') {
            literal("false");
            out.type = JValue::Type::Bool;
        } else if (c == 'n') {
            literal("null");
        } else if (c == '-' || (c >= '0' && c <= '9')) {
            number(out);
        } else {
            fail("unexpected character");
        }
    }

    void array(JValue& out, int depth) {
        out.type = JValue::Type::Array;
        expect('[');
        skip_ws();
        if (!at_end() && s_[pos_] == ']') {
            ++pos_;
            return;
        }
        for (;;) {
            out.items.emplace_back();
            value(out.items.back(), depth + 1);
            skip_ws();
            if (!at_end() && s_[pos_] == ',') {
                ++pos_;
                skip_ws();
                continue;
            }
            expect(']');
            return;
        }
    }

    void object(JValue& out, int depth) {
        out.type = JValue::Type::Object;
        expect('{');
        skip_ws();
        if (!at_end() && s_[pos_] == '}') {
            ++pos_;
            return;
        }
        for (;;) {
            if (at_end() || s_[pos_] != '"') fail("expected a member name");
            std::string key = string();
            if (std::find(out.keys.begin(), out.keys.end(), key) != out.keys.end()) fail("duplicate member name");
            skip_ws();
            expect(':');
            skip_ws();
            out.keys.push_back(std::move(key));
            out.values.emplace_back();
            value(out.values.back(), depth + 1);
            skip_ws();
            if (!at_end() && s_[pos_] == ',') {
                ++pos_;
                skip_ws();
                continue;
            }
            expect('}');
            return;
        }
    }

    unsigned hex4() {
        unsigned v = 0;
        for (int i = 0; i < 4; ++i) {
            if (at_end()) fail("truncated \\u escape");
            const char c = s_[pos_++];
            unsigned d = 0;
            if (c >= '0' && c <= '9') d = static_cast<unsigned>(c - '0');
            else if (c >= 'a' && c <= 'f') d = static_cast<unsigned>(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') d = static_cast<unsigned>(c - 'A' + 10);
            else fail("bad hex digit in \\u escape");
            v = v * 16 + d;
        }
        return v;
    }

    static void append_utf8(std::string& out, unsigned cp) {
        if (cp < 0x80) {
            out.push_back(static_cast<char>(cp));
        } else if (cp < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else if (cp < 0x10000) {
            out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
    }

    std::string string() {
        expect('"');
        std::string out;
        for (;;) {
            if (at_end()) fail("unterminated string");
            const auto c = static_cast<unsigned char>(s_[pos_]);
            if (c == '"') {
                ++pos_;
                return out;
            }
            if (c < 0x20) fail("raw control character in a string");
            if (c != '\\') {
                out.push_back(static_cast<char>(c));
                ++pos_;
                continue;
            }
            ++pos_;
            if (at_end()) fail("truncated escape");
            const char e = s_[pos_++];
            switch (e) {
                case '"': out.push_back('"'); break;
                case '\\': out.push_back('\\'); break;
                case '/': out.push_back('/'); break;
                case 'b': out.push_back('\b'); break;
                case 'f': out.push_back('\f'); break;
                case 'n': out.push_back('\n'); break;
                case 'r': out.push_back('\r'); break;
                case 't': out.push_back('\t'); break;
                case 'u': {
                    unsigned cp = hex4();
                    if (cp >= 0xD800 && cp <= 0xDBFF) {
                        if (s_.compare(pos_, 2, "\\u") != 0) fail("high surrogate without a low one");
                        pos_ += 2;
                        const unsigned low = hex4();
                        if (low < 0xDC00 || low > 0xDFFF) fail("high surrogate followed by a non-low surrogate");
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
                    } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                        fail("lone low surrogate");
                    }
                    append_utf8(out, cp);
                    break;
                }
                default: fail("invalid escape");
            }
        }
    }

    static bool digit(char c) { return c >= '0' && c <= '9'; }

    void number(JValue& out) {
        const std::size_t start = pos_;
        if (s_[pos_] == '-') ++pos_;
        if (at_end()) fail("bad number");
        if (s_[pos_] == '0') {
            ++pos_;
        } else if (s_[pos_] >= '1' && s_[pos_] <= '9') {
            while (!at_end() && digit(s_[pos_])) ++pos_;
        } else {
            fail("bad number");
        }
        if (!at_end() && s_[pos_] == '.') {
            ++pos_;
            if (at_end() || !digit(s_[pos_])) fail("digits required after the decimal point");
            while (!at_end() && digit(s_[pos_])) ++pos_;
        }
        if (!at_end() && (s_[pos_] == 'e' || s_[pos_] == 'E')) {
            ++pos_;
            if (!at_end() && (s_[pos_] == '+' || s_[pos_] == '-')) ++pos_;
            if (at_end() || !digit(s_[pos_])) fail("digits required in the exponent");
            while (!at_end() && digit(s_[pos_])) ++pos_;
        }
        out.type = JValue::Type::Number;
        out.text = std::string(s_.substr(start, pos_ - start));
    }

    std::string_view s_;
    std::size_t pos_ = 0;
};

bool json_parses(const std::string& text) {
    JValue v;
    std::string error;
    return JsonParser(text).parse(v, error);
}

std::string clipped(const std::string& text) {
    return text.size() <= 200 ? text : text.substr(0, 200) + "... (" + std::to_string(text.size()) + " bytes)";
}

JValue parse_json(const std::string& text) {
    JValue v;
    std::string error;
    if (!JsonParser(text).parse(v, error)) throw testkit::Failure{"invalid JSON (" + error + "): " + clipped(text)};
    return v;
}

std::string join(const std::vector<std::string>& parts) {
    std::string out;
    for (const std::string& p : parts) {
        if (!out.empty()) out += ",";
        out += p;
    }
    return out;
}

void expect_keys(const JValue& object, std::initializer_list<const char*> names) {
    if (object.type != JValue::Type::Object) throw testkit::Failure{"expected an object"};
    const std::vector<std::string> want(names.begin(), names.end());
    if (object.keys != want) {
        throw testkit::Failure{"member names are [" + join(object.keys) + "], expected [" + join(want) + "]"};
    }
}

// =============================================================================================
// Requests and responses
// =============================================================================================

// Built from a literal request head, so the real URL parsing (decoding, query splitting) runs.
HttpRequest make_request(const std::string& target, const char* method = "GET") {
    HttpServerOptions limits;
    limits.max_target_bytes = std::size_t{1} << 22;
    limits.max_query_params = 1000;
    const std::string head = std::string(method) + " " + target + " HTTP/1.1\r\nHost: localhost";
    HttpRequest request;
    if (parse_request_head(head, limits, request) != ParseStatus::Ok) {
        throw testkit::Failure{"parse_request_head rejected the target " + clipped(target)};
    }
    return request;
}

HttpResponse fetch(DashboardService& service, const std::string& target) {
    return service.handle(make_request(target));
}

JValue json_of(const HttpResponse& response, int status) {
    if (response.status != status) {
        throw testkit::Failure{"status " + std::to_string(response.status) + ", expected " + std::to_string(status) +
                               ": " + clipped(response.body)};
    }
    if (response.content_type != kJsonType) throw testkit::Failure{"content type " + response.content_type};
    if (!response.headers.empty()) throw testkit::Failure{"unexpected extra headers"};
    return parse_json(response.body);
}

JValue fetch_json(DashboardService& service, const std::string& target, int status = 200) {
    return json_of(fetch(service, target), status);
}

bool same_response(const HttpResponse& a, const HttpResponse& b) {
    if (a.status != b.status || a.content_type != b.content_type || a.body != b.body) return false;
    if (a.headers.size() != b.headers.size()) return false;
    for (std::size_t i = 0; i < a.headers.size(); ++i) {
        if (a.headers[i].name != b.headers[i].name || a.headers[i].value != b.headers[i].value) return false;
    }
    return true;
}

std::string url_encode(std::string_view text) {
    static const char kDigits[] = "0123456789ABCDEF";
    std::string out;
    for (const char ch : text) {
        const auto c = static_cast<unsigned char>(ch);
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' ||
            c == '.' || c == '~') {
            out.push_back(ch);
        } else {
            out.push_back('%');
            out.push_back(kDigits[c >> 4]);
            out.push_back(kDigits[c & 15]);
        }
    }
    return out;
}

bool contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

bool contains_ignoring_case(std::string haystack, std::string needle) {
    for (char& c : haystack) c = (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
    for (char& c : needle) c = (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
    return contains(haystack, needle);
}

// =============================================================================================
// Data
// =============================================================================================

LogEntry ev(std::int64_t ts, Level level, std::string service, std::string message) {
    LogEntry e;
    e.timestamp_ms = ts;
    e.level = level;
    e.service = std::move(service);
    e.message = std::move(message);
    return e;
}

std::string index_text(const LogEntry& e) {
    return e.service + " " + std::string(to_string(e.level)) + " " + e.message;
}

const Level kAllLevels[] = {Level::Debug, Level::Info, Level::Warn, Level::Error};

std::string level_arg(Level level) { return std::string(to_string(level)); }

// `n` in base 26 as exactly `width` lower-case letters: distinct for distinct n, increasing with n,
// and free of digits (so normalize_signature leaves it alone).
std::string base26(std::size_t n, std::size_t width) {
    std::string out(width, 'a');
    for (std::size_t i = width; i-- > 0;) {
        out[i] = static_cast<char>('a' + n % 26);
        n /= 26;
    }
    return out;
}

// The "key" members of a /api/complete answer, in order.
std::vector<std::string> complete_keys(const JValue& answer) {
    std::vector<std::string> keys;
    for (const JValue& row : answer.at("results").items) keys.push_back(row.at("key").str());
    return keys;
}

struct Fixture {
    std::vector<LogEntry> entries;  // service after service, so NOT in time order overall
    std::vector<Alert> alerts;
    ServeOptions options;
    InvertedIndex index;  // the oracle for /api/search
    std::unique_ptr<DashboardService> service;
};

Fixture make_fixture() {
    Fixture f;
    LogGenerator generator;  // seed 42, five services
    for (std::vector<LogEntry>& stream : generator.generate_all(500)) {
        for (LogEntry& e : stream) f.entries.push_back(std::move(e));
    }
    const std::int64_t start = generator.config().start_ms;
    f.entries.push_back(ev(start + 5, Level::Warn, "auth-service", ""));
    f.entries.push_back(ev(start + 6, Level::Error, "Edge-Service", "  Timeout   TIMEOUT after 5ms  "));

    std::vector<LogEntry> ordered = f.entries;
    std::stable_sort(ordered.begin(), ordered.end(),
                     [](const LogEntry& a, const LogEntry& b) { return a.timestamp_ms < b.timestamp_ms; });
    AlertEngine engine;
    engine.add_rule(parse_rule_spec("name=burst,threshold=4,window=2s,cooldown=3s"));
    engine.add_rule(parse_rule_spec("name=payment-errors,service=payment-service,threshold=2,window=1s,per-service=true"));
    for (const LogEntry& e : ordered) {
        for (Alert& a : engine.process(e)) f.alerts.push_back(std::move(a));
    }
    if (f.alerts.size() < 3) throw testkit::Failure{"the fixture is expected to fire a few alerts"};

    f.options.title = "Fixture dashboard";
    f.options.top_k = 7;
    f.options.time_buckets = 20;
    for (const LogEntry& e : f.entries) f.index.add(index_text(e));
    f.service = std::make_unique<DashboardService>(f.entries, f.alerts, f.options);
    return f;
}

Fixture& fixture() {
    static Fixture f = make_fixture();
    return f;
}

// The expected completions, computed twice: from a Trie fed the way `loganalyzer complete` feeds
// it, and from std::map frequencies plus a sort (independent of the Trie). Built once per
// (field, min-level) and then asked about many prefixes.
class CompleteOracle {
public:
    CompleteOracle(const std::vector<LogEntry>& entries, std::string field, Level min_level) : field_(std::move(field)) {
        for (const LogEntry& e : entries) {
            if (e.level < min_level) continue;
            if (field_ == "service") {
                if (e.service.empty()) continue;  // the trie rejects empty keys; the service skips them
                trie_.insert(e.service);
                ++counts_[e.service];
            } else if (field_ == "signature") {
                const std::string signature = normalize_signature(e.message);
                if (signature.empty()) continue;
                trie_.insert(signature);
                ++counts_[signature];
            } else {
                for (const std::string& token : tokenize(e.message)) {
                    trie_.insert(token);
                    ++counts_[token];
                }
            }
        }
    }

    std::vector<Completion> from_trie(const std::string& prefix, std::size_t k) const {
        return trie_.complete(effective(prefix), k);
    }

    std::vector<std::pair<std::string, std::uint64_t>> from_model(const std::string& requested, std::size_t k) const {
        const std::string prefix = effective(requested);
        std::vector<std::pair<std::string, std::uint64_t>> rows;
        for (const auto& kv : counts_) {
            if (kv.first.compare(0, prefix.size(), prefix) == 0) rows.push_back(kv);
        }
        std::sort(rows.begin(), rows.end(), [](const auto& a, const auto& b) {
            if (a.second != b.second) return a.second > b.second;
            return a.first < b.first;
        });
        if (rows.size() > k) rows.resize(k);
        return rows;
    }

    // Total length of the distinct keys: what the service bases its memory estimate on.
    std::size_t distinct_key_bytes() const {
        std::size_t bytes = 0;
        for (const auto& kv : counts_) bytes += kv.first.size();
        return bytes;
    }

    // The prefix as it is matched: words are indexed in lower case.
    std::string effective(std::string prefix) const {
        if (field_ == "word") {
            for (char& c : prefix) {
                if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
            }
        }
        return prefix;
    }

private:
    std::string field_;
    Trie trie_;
    std::map<std::string, std::uint64_t> counts_;
};

}  // namespace

// =============================================================================================
// The test's own JSON parser has to be right before anything is trusted to it
// =============================================================================================

TEST(ServeJsonParser, AcceptsValidDocuments) {
    const std::vector<std::string> valid = {
        "0", "-0", "1", "-12.5e+3", "1E2", "0.5", "true", "false", "null", "\"\"", "[]", " [ ] ", "{}", " { } ",
        "\t\r\n 1 \n", "[1,2.5e-3,-0,true,false,null]", "{\"a\":[1,2,{\"b\":null}],\"c\":\"d\"}",
        "\"a\\u00e9\\ud83d\\ude00\\n\\/\\\\\\\"\"", "\"\\u0000\\u001f\"", "[[],[[]],{}]",
    };
    for (const std::string& text : valid) CHECK(json_parses(text));
}

TEST(ServeJsonParser, RejectsInvalidDocuments) {
    const std::vector<std::string> invalid = {
        "", " ", "[1,]", "[,1]", "{\"a\":1,}", "{\"a\" 1}", "{a:1}", "{\"a\":}", "{,}", "[01]", "[1.]", "[.5]", "[+1]",
        "[1e]", "[1e+]", "[-]", "[0x10]", "[NaN]", "[Infinity]", "[-Infinity]", "\"abc", "\"\\x\"", "\"\\u12\"",
        "\"\\u12G4\"", "\"\\ud800\"", "\"\\udc00\"", "\"\\ud800\\u0041\"", "\"\\ud800x\"", "\"a\tb\"", "\"a\nb\"",
        "\"\x01\"", "\"\x7F\"x", "[1] x", "[1][2]", "tru", "nul", "truee", "[true false]", "{\"a\":1,\"a\":2}", "'a'",
        "{1:2}", "\"\xFF\"", "\"\xC3\"", "\"\xED\xA0\x80\"", "\"\xC0\xAF\"", "[1 2]", "[", "]", "{", "}", "\"\\",
        "[\"a\" \"b\"]", "{\"a\":1 \"b\":2}", std::string(100, '[') + std::string(100, ']'), "\xEF\xBB\xBF[]",
        "[1]\x01", "{\"a\"\n:\n1,\n}",
    };
    for (const std::string& text : invalid) {
        if (json_parses(text)) throw testkit::Failure{"the parser accepted " + clipped(text)};
    }
}

TEST(ServeJsonParser, DecodesEscapesAndSurrogatePairs) {
    const JValue v = parse_json("[\"a\\u00e9\\ud83d\\ude00\\n\\/\\\\\\\"\", \"\\u0000x\", 12, -3.5e2, {\"k\":[true,null]}]");
    CHECK_EQ(v.size(), std::size_t{5});
    CHECK_EQ(v.item(0).str(), "a\xC3\xA9\xF0\x9F\x98\x80\n/\\\""s);
    CHECK_EQ(v.item(1).str(), std::string("\0x", 2));
    CHECK_EQ(v.item(2).u64(), std::uint64_t{12});
    CHECK_EQ(v.item(3).text, "-3.5e2"s);
    CHECK(v.item(4).at("k").item(0).boolean);
    CHECK(v.item(4).at("k").item(1).type == JValue::Type::Null);
}

// =============================================================================================
// json_escape
// =============================================================================================

TEST(ServeEscape, PlainTextAndTheSpecialCharacters) {
    CHECK_EQ(json_escape(""), ""s);
    CHECK_EQ(json_escape("plain text 123 ~!#$%'()*+,-./:;=?@[]^_`{|}"), "plain text 123 ~!#$%'()*+,-./:;=?@[]^_`{|}"s);
    CHECK_EQ(json_escape("say \"hi\""), "say \\\"hi\\\""s);
    CHECK_EQ(json_escape("a\\b"), "a\\\\b"s);
    CHECK_EQ(json_escape("\\\""), "\\\\\\\""s);
    CHECK_EQ(json_escape("<script>alert(1)</script>"), "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e"s);
    CHECK_EQ(json_escape("a&b"), "a\\u0026b"s);
    CHECK_EQ(json_escape("</"), "\\u003c/"s);  // '/' itself is left alone
    CHECK_EQ(json_escape("\x7F"), "\\u007f"s);
    CHECK_EQ(json_escape("\x08\x0c\n\r\t"), "\\b\\f\\n\\r\\t"s);
    CHECK_EQ(json_escape(std::string("a\0b", 3)), "a\\u0000b"s);
    CHECK_EQ(json_escape("\x01\x1b\x1f"), "\\u0001\\u001b\\u001f"s);
}

TEST(ServeEscape, ValidUtf8PassesThroughUnchanged) {
    const char* const samples[] = {
        "caf\xC3\xA9",           "\xC2\x80",         "\xDF\xBF",         "\xE0\xA0\x80",        "\xED\x9F\xBF",
        "\xEE\x80\x80",          "\xEF\xBF\xBD",     "\xEF\xBF\xBE",     "\xEF\xBF\xBF",        "\xF0\x90\x80\x80",
        "\xF4\x8F\xBF\xBF",      "\xE2\x82\xAC",     "\xF0\x9F\x98\x80", "\xE2\x80\xA8\xE2\x80\xA9",  // U+2028, U+2029
        "x\xC3\xA9y\xE2\x82\xACz\xF0\x9F\x98\x80w",
    };
    for (const char* sample : samples) CHECK_EQ(json_escape(sample), std::string(sample));
}

TEST(ServeEscape, InvalidSequencesBecomeOneReplacementPerMaximalSubpart) {
    // {input, expected}; the expectations are what Python's bytes.decode("utf-8", "replace") gives
    // (the Unicode "maximal subpart" practice), checked independently of this implementation.
    struct Case {
        const char* input;
        const char* expected;
    };
    const Case cases[] = {
        {"C3", "ef bf bd"},                      // truncated 2-byte sequence at the end
        {"E2 82", "ef bf bd"},                   // truncated 3-byte sequence: ONE replacement
        {"E2", "ef bf bd"},
        {"F0 9F 98", "ef bf bd"},                // truncated 4-byte sequence
        {"F0 9F", "ef bf bd"},
        {"F0", "ef bf bd"},
        {"61 E2 82", "61 ef bf bd"},             // truncated at the end after text
        {"E2 82 41", "ef bf bd 41"},             // the byte that broke it is not swallowed
        {"F0 9F 41", "ef bf bd 41"},
        {"E2 E2 82 AC", "ef bf bd e2 82 ac"},    // ... and may begin a valid sequence itself
        {"80", "ef bf bd"},                      // stray continuation bytes: one each
        {"80 80", "ef bf bd ef bf bd"},
        {"41 80 42", "41 ef bf bd 42"},
        {"C0 AF", "ef bf bd ef bf bd"},          // overlong 2-byte forms
        {"C1 BF", "ef bf bd ef bf bd"},
        {"E0 80 80", "ef bf bd ef bf bd ef bf bd"},  // overlong 3-byte form
        {"E0 9F BF", "ef bf bd ef bf bd ef bf bd"},
        {"ED A0 80", "ef bf bd ef bf bd ef bf bd"},  // UTF-16 surrogates U+D800 and U+DFFF
        {"ED BF BF", "ef bf bd ef bf bd ef bf bd"},
        {"F0 80 80 80", "ef bf bd ef bf bd ef bf bd ef bf bd"},  // overlong 4-byte form
        {"F0 8F BF BF", "ef bf bd ef bf bd ef bf bd ef bf bd"},
        {"F4 90 80 80", "ef bf bd ef bf bd ef bf bd ef bf bd"},  // above U+10FFFF
        {"F5 80 80 80", "ef bf bd ef bf bd ef bf bd ef bf bd"},
        {"FF", "ef bf bd"},
        {"FE FF", "ef bf bd ef bf bd"},
        {"F8 88 80 80 80", "ef bf bd ef bf bd ef bf bd ef bf bd ef bf bd"},
        {"E0 A0", "ef bf bd"},                   // a valid beginning cut off by the end
        {"ED 9F", "ef bf bd"},
        {"F4 8F BF", "ef bf bd"},
        {"E2 82 AC E2 82", "e2 82 ac ef bf bd"},
        {"F0 9F 98 80 F0 9F 98", "f0 9f 98 80 ef bf bd"},
        {"C2 80", "c2 80"},                      // the valid boundary cases stay untouched
        {"DF BF", "df bf"},
        {"E0 A0 80", "e0 a0 80"},
        {"ED 9F BF", "ed 9f bf"},
        {"EE 80 80", "ee 80 80"},
        {"EF BF BF", "ef bf bf"},
        {"F0 90 80 80", "f0 90 80 80"},
        {"F4 8F BF BF", "f4 8f bf bf"},
    };
    for (const Case& c : cases) {
        const std::string input = from_hex(c.input);
        const std::string got = to_hex(escape_exact(input));
        if (got != c.expected) {
            throw testkit::Failure{std::string("input ") + c.input + ": got " + got + ", expected " + c.expected};
        }
        CHECK(escape_exact(input) == reference_repair(input));  // (none of these has an ASCII special)
    }
}

TEST(ServeEscape, EverySingleByteValue) {
    for (int b = 0; b < 256; ++b) {
        std::string expected;
        switch (b) {
            case '"': expected = "\\\""; break;
            case '\\': expected = "\\\\"; break;
            case 0x08: expected = "\\b"; break;
            case 0x0C: expected = "\\f"; break;
            case 0x0A: expected = "\\n"; break;
            case 0x0D: expected = "\\r"; break;
            case 0x09: expected = "\\t"; break;
            case '<': expected = "\\u003c"; break;
            case '>': expected = "\\u003e"; break;
            case '&': expected = "\\u0026"; break;
            case 0x7F: expected = "\\u007f"; break;
            default:
                if (b < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof buf, "\\u%04x", static_cast<unsigned>(b));
                    expected = buf;
                } else if (b < 0x80) {
                    expected = std::string(1, static_cast<char>(b));
                } else {
                    expected = kReplacement;  // a lone byte >= 0x80 is never valid UTF-8
                }
        }
        const std::string alone(1, static_cast<char>(b));
        if (escape_exact(alone) != expected) throw testkit::Failure{"byte " + std::to_string(b) + " alone"};
        // Surrounded by text, and doubled: neighbours are never swallowed or corrupted.
        const std::string around = "a" + alone + "b";
        if (escape_exact(around) != "a" + expected + "b") throw testkit::Failure{"byte " + std::to_string(b) + " inside text"};
        const std::string twice = alone + alone;
        if (escape_exact(twice) != expected + expected) throw testkit::Failure{"byte " + std::to_string(b) + " twice"};
    }
}

TEST(ServeEscape, EveryBoundaryCombinationAgreesWithTheReference) {
    const unsigned char b3[] = {0x00, 0x22, 0x41, 0x5C, 0x7F, 0x80, 0x8F, 0x90, 0x9F, 0xA0, 0xBF, 0xC0,
                                0xC2, 0xDF, 0xE0, 0xE1, 0xEC, 0xED, 0xEE, 0xEF, 0xF0, 0xF1, 0xF3, 0xF4, 0xF5, 0xFF};
    const unsigned char b4[] = {0x41, 0x80, 0x8F, 0x90, 0xBF, 0xC2, 0xE0, 0xED, 0xF0, 0xF4, 0xF5, 0xFF};
    std::size_t checked = 0;
    auto check = [&checked](const std::string& input) {
        const std::string got = escape_exact(input);
        const std::string repaired = reference_repair(input);
        if (got != reference_escape(repaired)) throw testkit::Failure{"mismatch for bytes " + to_hex(input)};
        if (!well_formed_utf8(got)) throw testkit::Failure{"output is not UTF-8 for bytes " + to_hex(input)};
        for (const char c : got) {
            if (static_cast<unsigned char>(c) < 0x20 || c == 0x7F || c == '<' || c == '>' || c == '&') {
                throw testkit::Failure{"a raw special byte survived for bytes " + to_hex(input)};
            }
        }
        ++checked;
    };
    for (const unsigned char x : b3) {
        check(std::string(1, static_cast<char>(x)));
        for (const unsigned char y : b3) {
            check(std::string{static_cast<char>(x), static_cast<char>(y)});
            for (const unsigned char z : b3) check(std::string{static_cast<char>(x), static_cast<char>(y), static_cast<char>(z)});
        }
    }
    for (const unsigned char w : b4) {
        for (const unsigned char x : b4) {
            for (const unsigned char y : b4) {
                for (const unsigned char z : b4) {
                    check(std::string{static_cast<char>(w), static_cast<char>(x), static_cast<char>(y), static_cast<char>(z)});
                }
            }
        }
    }
    CHECK(checked > 20000);
}

TEST(ServeEscape, RandomBytesAgreeWithTheReferenceAndParseBack) {
    Xoshiro256 rng(7);
    for (int round = 0; round < 6000; ++round) {
        std::string input;
        const std::uint32_t length = rng.below(25);
        for (std::uint32_t i = 0; i < length; ++i) {
            const std::uint32_t kind = rng.below(100);
            if (kind < 35) input.push_back(static_cast<char>(rng.below(128)));
            else if (kind < 65) input.push_back(static_cast<char>(0x80 + rng.below(64)));
            else input.push_back(static_cast<char>(0xC0 + rng.below(64)));
        }
        const std::string got = escape_exact(input);
        const std::string repaired = reference_repair(input);
        if (got != reference_escape(repaired)) throw testkit::Failure{"mismatch for bytes " + to_hex(input)};
        // Wrapped in quotes it is a JSON string that decodes to exactly the repaired text.
        const JValue parsed = parse_json("\"" + got + "\"");
        if (parsed.str() != repaired) throw testkit::Failure{"does not parse back, bytes " + to_hex(input)};
    }
}

TEST(ServeEscape, RandomValidTextWithoutSpecialsIsUnchanged) {
    Xoshiro256 rng(11);
    for (int round = 0; round < 3000; ++round) {
        std::string input;
        const std::uint32_t count = 1 + rng.below(12);
        for (std::uint32_t i = 0; i < count; ++i) {
            const std::uint32_t range = rng.below(4);
            std::uint32_t cp = 0;
            if (range == 0) {
                do cp = 0x20 + rng.below(0x5F); while (cp == '"' || cp == '\\' || cp == '<' || cp == '>' || cp == '&');
            } else if (range == 1) {
                cp = 0x80 + rng.below(0x780);
            } else if (range == 2) {
                cp = 0x800 + rng.below(0xD800 - 0x800);
            } else {
                cp = 0xE000 + rng.below(0x110000 - 0xE000);
            }
            if (cp < 0x80) {
                input.push_back(static_cast<char>(cp));
            } else if (cp < 0x800) {
                input.push_back(static_cast<char>(0xC0 | (cp >> 6)));
                input.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
            } else if (cp < 0x10000) {
                input.push_back(static_cast<char>(0xE0 | (cp >> 12)));
                input.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
                input.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
            } else {
                input.push_back(static_cast<char>(0xF0 | (cp >> 18)));
                input.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
                input.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
                input.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
            }
        }
        if (!well_formed_utf8(input)) throw testkit::Failure{"the generator produced invalid UTF-8"};
        // 0x7F is the only ASCII byte in this range that is still escaped; it cannot occur
        // because the ASCII range stops at 0x7E.
        if (escape_exact(input) != input) throw testkit::Failure{"valid text was altered: " + to_hex(input)};
    }
}

TEST(ServeEscape, TruncatedSequencesNeverReadPastTheEnd) {
    // Every proper prefix of every valid multi-byte sequence, in a buffer of exactly that size
    // (AddressSanitizer reports a read one byte too far).
    const char* const sequences[] = {"\xC2\x80", "\xDF\xBF", "\xE0\xA0\x80", "\xED\x9F\xBF", "\xEF\xBF\xBF",
                                     "\xF0\x90\x80\x80", "\xF1\x80\x80\x80", "\xF4\x8F\xBF\xBF"};
    for (const char* sequence : sequences) {
        const std::string full(sequence);
        CHECK_EQ(escape_exact(full), full);
        for (std::size_t cut = 1; cut < full.size(); ++cut) {
            const std::string prefix = full.substr(0, cut);
            CHECK_EQ(escape_exact(prefix), kReplacement);
            CHECK_EQ(escape_exact("ab" + prefix), "ab" + kReplacement);
            CHECK_EQ(escape_exact(prefix + "\"") , kReplacement + "\\\"");
        }
    }
}

TEST(ServeEscape, LargeInputsAreHandledInOnePass) {
    const std::string quotes(100000, '"');
    const std::string escaped = json_escape(quotes);
    CHECK_EQ(escaped.size(), std::size_t{200000});
    CHECK(escaped.compare(0, 4, "\\\"\\\"") == 0);

    std::string mixed;
    while (mixed.size() < 1000000) mixed += "ab\"c\\d<e>f&g\nh\xC3\xA9 \xFF\xE2\x82 tail ";
    const std::string expected = reference_escape(reference_repair(mixed));
    CHECK(json_escape(mixed) == expected);
}

// =============================================================================================
// Routes, happy paths (every answer is compared with the library pieces computed in the test)
// =============================================================================================

TEST(ServeRoutes, HealthzAndTheReport) {
    Fixture& f = fixture();
    const HttpResponse health = fetch(*f.service, "/healthz");
    CHECK_EQ(health.status, 200);
    CHECK_EQ(health.content_type, std::string(kTextType));
    CHECK_EQ(health.body, "ok"s);
    CHECK(health.headers.empty());

    const HttpResponse page = fetch(*f.service, "/");
    CHECK_EQ(page.status, 200);
    CHECK_EQ(page.content_type, std::string(kHtmlType));
    // Defence in depth for the page (see serve.hpp): the report is inline CSS and SVG only.
    CHECK_EQ(page.headers.size(), std::size_t{2});
    CHECK_EQ(page.headers[0].name, "Content-Security-Policy"s);
    CHECK_EQ(page.headers[0].value, std::string(kCsp));
    CHECK_EQ(page.headers[1].name, "Referrer-Policy"s);
    CHECK_EQ(page.headers[1].value, "no-referrer"s);
    ReportOptions report;
    report.title = f.options.title;
    report.top_k = f.options.top_k;
    report.time_buckets = f.options.time_buckets;
    CHECK(page.body == render_html_report(f.entries, f.alerts, report));
    CHECK(contains(page.body, "Fixture dashboard"));
    CHECK(fetch(*f.service, "/").body == page.body);  // rendered once, the same bytes every time
}

TEST(ServeRoutes, SummaryMatchesTheData) {
    Fixture& f = fixture();
    const JValue j = fetch_json(*f.service, "/api/summary");
    expect_keys(j, {"entries", "levels", "services", "first", "last", "alerts"});
    CHECK_EQ(j.at("entries").u64(), static_cast<std::uint64_t>(f.entries.size()));
    CHECK_EQ(j.at("alerts").u64(), static_cast<std::uint64_t>(f.alerts.size()));

    expect_keys(j.at("levels"), {"debug", "info", "warn", "error"});
    const char* const names[] = {"debug", "info", "warn", "error"};
    std::uint64_t total = 0;
    for (std::size_t i = 0; i < 4; ++i) {
        const auto want = static_cast<std::uint64_t>(
            std::count_if(f.entries.begin(), f.entries.end(), [&](const LogEntry& e) { return e.level == kAllLevels[i]; }));
        CHECK_EQ(j.at("levels").at(names[i]).u64(), want);
        total += want;
    }
    CHECK_EQ(total, static_cast<std::uint64_t>(f.entries.size()));

    std::map<std::string, std::pair<std::uint64_t, std::uint64_t>> by_service;
    for (const LogEntry& e : f.entries) {
        ++by_service[e.service].first;
        if (e.level == Level::Error) ++by_service[e.service].second;
    }
    struct Row {
        std::string name;
        std::uint64_t entries, errors;
    };
    std::vector<Row> rows;
    for (const auto& kv : by_service) rows.push_back({kv.first, kv.second.first, kv.second.second});
    std::sort(rows.begin(), rows.end(), [](const Row& a, const Row& b) {
        if (a.entries != b.entries) return a.entries > b.entries;
        return a.name < b.name;
    });
    const JValue& services = j.at("services");
    CHECK_EQ(services.size(), rows.size());
    CHECK(rows.size() >= 6);  // five generated services plus "Edge-Service"
    for (std::size_t i = 0; i < rows.size(); ++i) {
        expect_keys(services.item(i), {"name", "entries", "errors"});
        CHECK_EQ(services.item(i).at("name").str(), rows[i].name);
        CHECK_EQ(services.item(i).at("entries").u64(), rows[i].entries);
        CHECK_EQ(services.item(i).at("errors").u64(), rows[i].errors);
    }

    const auto minmax = std::minmax_element(f.entries.begin(), f.entries.end(), [](const LogEntry& a, const LogEntry& b) {
        return a.timestamp_ms < b.timestamp_ms;
    });
    CHECK_EQ(j.at("first").str(), format_iso8601_utc(minmax.first->timestamp_ms));
    CHECK_EQ(j.at("last").str(), format_iso8601_utc(minmax.second->timestamp_ms));
}

TEST(ServeRoutes, SummaryTieBreakHoldsWithManyServicesAndMixedCounts) {
    // 100+ services with 1 to 4 entries each, in shuffled order: far more services than an
    // unstable sort would leave in order by accident, and many ties at every count.
    Xoshiro256 rng(2024);
    std::map<std::string, std::uint64_t> counts;
    std::vector<LogEntry> entries;
    for (int i = 0; i < 110; ++i) {
        const std::string name = "svc-" + base26(rng.below(1000000), 5);
        const std::uint32_t repeats = 1 + rng.below(4);
        for (std::uint32_t r = 0; r < repeats; ++r) {
            entries.push_back(ev(static_cast<std::int64_t>(entries.size()), Level::Info, name, "m"));
        }
        counts[name] += repeats;
    }
    for (std::size_t i = entries.size(); i > 1; --i) std::swap(entries[i - 1], entries[rng.below(static_cast<std::uint32_t>(i))]);
    DashboardService service(std::move(entries), {});

    std::vector<std::pair<std::string, std::uint64_t>> expected(counts.begin(), counts.end());
    std::sort(expected.begin(), expected.end(), [](const auto& a, const auto& b) {
        if (a.second != b.second) return a.second > b.second;
        return a.first < b.first;
    });
    const JValue services = fetch_json(service, "/api/summary").at("services");
    CHECK(expected.size() > 100);
    CHECK_EQ(services.size(), expected.size());
    for (std::size_t i = 0; i < expected.size(); ++i) {
        if (services.item(i).at("name").str() != expected[i].first || services.item(i).at("entries").u64() != expected[i].second) {
            throw testkit::Failure{"service row " + std::to_string(i) + " is not " + expected[i].first};
        }
    }
}

TEST(ServeRoutes, AlertsKeepTheOrderTheyWereGivenEvenWhenNotChronological) {
    std::vector<Alert> alerts;
    for (int i = 0; i < 30; ++i) {
        Alert a;
        a.rule = std::string(1, static_cast<char>('z' - i % 26)) + std::to_string(i);  // z0, y1, x2 ...: not sorted ascending
        a.service = i % 3 == 0 ? "*" : "svc" + std::to_string(i % 5);
        a.fired_at_ms = 100000 - 1000 * i;  // descending in time
        a.first_event_ms = a.fired_at_ms - 500;
        a.count = static_cast<std::uint64_t>(30 - i);
        a.suppressed = static_cast<std::uint64_t>(i);
        alerts.push_back(a);
    }
    DashboardService service({ev(5, Level::Error, "svc0", "x")}, alerts);
    const JValue rows = fetch_json(service, "/api/alerts").at("alerts");
    CHECK_EQ(rows.size(), alerts.size());
    for (std::size_t i = 0; i < alerts.size(); ++i) {
        CHECK_EQ(rows.item(i).at("rule").str(), alerts[i].rule);
        CHECK_EQ(rows.item(i).at("fired_at").str(), format_iso8601_utc(alerts[i].fired_at_ms));
        CHECK_EQ(rows.item(i).at("count").u64(), alerts[i].count);
    }
}

TEST(ServeRoutes, SummaryOrdersServicesByCountThenName) {
    std::vector<LogEntry> entries;
    for (int i = 0; i < 3; ++i) entries.push_back(ev(100 + i, Level::Info, "b", "m"));
    for (int i = 0; i < 3; ++i) entries.push_back(ev(200 + i, Level::Error, "a", "m"));
    entries.push_back(ev(5, Level::Warn, "z", "m"));
    for (int i = 0; i < 5; ++i) entries.push_back(ev(300 + i, Level::Debug, "m", "m"));
    DashboardService service(std::move(entries), {});
    const JValue j = fetch_json(service, "/api/summary");
    const JValue& services = j.at("services");
    CHECK_EQ(services.size(), std::size_t{4});
    CHECK_EQ(services.item(0).at("name").str(), "m"s);
    CHECK_EQ(services.item(1).at("name").str(), "a"s);  // 3 entries, ties by name
    CHECK_EQ(services.item(2).at("name").str(), "b"s);
    CHECK_EQ(services.item(3).at("name").str(), "z"s);
    CHECK_EQ(services.item(1).at("errors").u64(), std::uint64_t{3});
    CHECK_EQ(j.at("first").str(), format_iso8601_utc(5));
    CHECK_EQ(j.at("last").str(), format_iso8601_utc(304));
}

namespace {

void check_top_errors(DashboardService& service, const std::vector<LogEntry>& entries, const std::string& target,
                      Level level, std::size_t k) {
    TopKErrors oracle(level);
    for (const LogEntry& e : entries) oracle.add(e);
    const std::vector<SignatureCount> want = oracle.top_k(k);
    const JValue j = fetch_json(service, target);
    expect_keys(j, {"total", "distinct", "results"});
    CHECK_EQ(j.at("total").u64(), oracle.total());
    CHECK_EQ(j.at("distinct").u64(), static_cast<std::uint64_t>(oracle.distinct()));
    const auto counted = static_cast<std::uint64_t>(
        std::count_if(entries.begin(), entries.end(), [level](const LogEntry& e) { return e.level >= level; }));
    CHECK_EQ(j.at("total").u64(), counted);
    const JValue& rows = j.at("results");
    CHECK_EQ(rows.size(), want.size());
    CHECK_EQ(want.size(), std::min(k, oracle.distinct()));
    for (std::size_t i = 0; i < want.size(); ++i) {
        const JValue& row = rows.item(i);
        expect_keys(row, {"service", "signature", "count", "first_seen", "last_seen", "example"});
        CHECK_EQ(row.at("service").str(), want[i].service);
        CHECK_EQ(row.at("signature").str(), want[i].signature);
        CHECK_EQ(row.at("count").u64(), want[i].count);
        CHECK_EQ(row.at("first_seen").str(), format_iso8601_utc(want[i].first_seen_ms));
        CHECK_EQ(row.at("last_seen").str(), format_iso8601_utc(want[i].last_seen_ms));
        CHECK_EQ(row.at("example").str(), want[i].example);
    }
}

}  // namespace

TEST(ServeRoutes, TopErrorsMatchesTopKErrors) {
    Fixture& f = fixture();
    check_top_errors(*f.service, f.entries, "/api/top-errors", Level::Error, 10);  // the defaults
    for (const Level level : kAllLevels) {
        for (const std::size_t k : {std::size_t{1}, std::size_t{3}, std::size_t{10}, std::size_t{1000}}) {
            check_top_errors(*f.service, f.entries,
                             "/api/top-errors?k=" + std::to_string(k) + "&min-level=" + level_arg(level), level, k);
        }
    }
    // The level name is matched in any letter case; the sum of all groups is the total.
    check_top_errors(*f.service, f.entries, "/api/top-errors?min-level=warn&k=1000", Level::Warn, 1000);
    check_top_errors(*f.service, f.entries, "/api/top-errors?min-level=wArN", Level::Warn, 10);
    const JValue everything = fetch_json(*f.service, "/api/top-errors?k=1000");
    std::uint64_t sum = 0;
    for (const JValue& row : everything.at("results").items) sum += row.at("count").u64();
    CHECK_EQ(sum, everything.at("total").u64());
    CHECK(everything.at("distinct").u64() >= 20);  // 10 error templates x 5 services, give or take
}

TEST(ServeRoutes, SearchMatchesTheInvertedIndex) {
    Fixture& f = fixture();
    const std::vector<std::string> queries = {
        "timeout",      "error timeout", "payment-service error", "timeout|refused", "error -timeout", "-debug",
        "ERROR Timeout", "zzzznotthere", "payment error timeout|refused -retry", "auth-service", "info", "|", "-",
        "  spaced   out  ", "Edge-Service", "timeout 5ms",
    };
    bool saw_more_than_a_page = false;
    bool saw_none = false;
    bool saw_some = false;
    for (const std::string& q : queries) {
        for (const std::size_t limit : {std::size_t{0}, std::size_t{1}, std::size_t{7}, std::size_t{1000}}) {
            const std::string target =
                "/api/search?q=" + url_encode(q) + (limit == 0 ? "" : "&limit=" + std::to_string(limit));
            const std::vector<DocId> hits = f.index.search(q);
            const std::size_t effective = limit == 0 ? 50 : limit;
            const std::size_t shown = std::min(hits.size(), effective);
            const JValue j = fetch_json(*f.service, target);
            expect_keys(j, {"query", "matches", "shown", "results"});
            CHECK_EQ(j.at("query").str(), q);
            CHECK_EQ(j.at("matches").u64(), static_cast<std::uint64_t>(hits.size()));
            CHECK_EQ(j.at("shown").u64(), static_cast<std::uint64_t>(shown));
            const JValue& rows = j.at("results");
            CHECK_EQ(rows.size(), shown);
            for (std::size_t i = 0; i < shown; ++i) {
                const LogEntry& e = f.entries[hits[i]];
                expect_keys(rows.item(i), {"time", "level", "service", "message"});
                CHECK_EQ(rows.item(i).at("time").str(), format_iso8601_utc(e.timestamp_ms));
                CHECK_EQ(rows.item(i).at("level").str(), std::string(to_string(e.level)));
                CHECK_EQ(rows.item(i).at("service").str(), e.service);
                CHECK_EQ(rows.item(i).at("message").str(), e.message);
            }
            saw_more_than_a_page |= hits.size() > effective;
            saw_none |= hits.empty();
            saw_some |= !hits.empty();
        }
    }
    CHECK(saw_more_than_a_page);
    CHECK(saw_none);
    CHECK(saw_some);
}

TEST(ServeRoutes, SearchCountsAgreeWithBruteForceAndKeepDocumentOrder) {
    Fixture& f = fixture();
    // matches = the number of entries whose "service LEVEL message" contains the token.
    for (const char* word : {"timeout", "error", "payment", "info", "5ms"}) {
        const auto want = static_cast<std::uint64_t>(std::count_if(f.entries.begin(), f.entries.end(), [&](const LogEntry& e) {
            const std::vector<std::string> tokens = tokenize(index_text(e));
            return std::find(tokens.begin(), tokens.end(), word) != tokens.end();
        }));
        const JValue j = fetch_json(*f.service, "/api/search?limit=1&q=" + url_encode(word));
        CHECK_EQ(j.at("matches").u64(), want);
    }
    // Results come in vector order, not in time order: the fixture is service after service.
    const JValue j = fetch_json(*f.service, "/api/search?q=info&limit=1000");
    const JValue& rows = j.at("results");
    CHECK_EQ(rows.size(), std::size_t{1000});
    std::vector<std::string> times;
    for (const JValue& row : rows.items) times.push_back(row.at("time").str());
    CHECK(!std::is_sorted(times.begin(), times.end()));
    CHECK_EQ(rows.item(0).at("service").str(), "auth-service"s);
}

TEST(ServeRoutes, CompleteMatchesTheTrieAndAnIndependentModel) {
    Fixture& f = fixture();
    struct Probe {
        const char* field;
        std::vector<std::string> prefixes;
    };
    const std::vector<Probe> probes = {
        {"signature", {"", "Payment", "Timeout", "Failed to", "zzz", "payment"}},
        {"service", {"", "pay", "auth", "Edge", "x"}},
        {"word", {"", "TIME", "time", "pay", "qq", "Fail"}},
    };
    bool saw_a_result = false;
    for (const Probe& probe : probes) {
        for (const char* level_name : {static_cast<const char*>(nullptr), "error", "WARN", "info"}) {
            const Level level = level_name == nullptr ? Level::Debug : *level_from_string(level_name);
            const CompleteOracle oracle(f.entries, probe.field, level);
            for (const std::string& prefix : probe.prefixes) {
                // 11 and above cannot come from the trie's per-node caches: they are answered from
                // the memo (first request computes it, the second one reads it), so each is asked twice.
                for (const std::size_t k : {std::size_t{1}, std::size_t{3}, std::size_t{10}, std::size_t{11}, std::size_t{25},
                                            std::size_t{999}, std::size_t{1000}}) {
                    std::string target = std::string("/api/complete?field=") + probe.field + "&prefix=" +
                                         url_encode(prefix) + "&k=" + std::to_string(k);
                    if (level_name != nullptr) target += std::string("&min-level=") + level_name;

                    const std::vector<Completion> trie = oracle.from_trie(prefix, k);
                    const auto model = oracle.from_model(prefix, k);
                    CHECK_EQ(trie.size(), model.size());
                    const JValue j = fetch_json(*f.service, target);
                    CHECK(fetch(*f.service, target).body == fetch(*f.service, target).body);  // cold or memoized: the same
                    expect_keys(j, {"field", "prefix", "results"});
                    CHECK_EQ(j.at("field").str(), std::string(probe.field));
                    // For the word field the prefix is reported as it was matched: lower-cased.
                    CHECK_EQ(j.at("prefix").str(), oracle.effective(prefix));
                    const JValue& rows = j.at("results");
                    CHECK_EQ(rows.size(), trie.size());
                    for (std::size_t i = 0; i < trie.size(); ++i) {
                        expect_keys(rows.item(i), {"key", "count"});
                        CHECK_EQ(rows.item(i).at("key").str(), trie[i].key);
                        CHECK_EQ(rows.item(i).at("count").u64(), trie[i].weight);
                        CHECK_EQ(trie[i].key, model[i].first);
                        CHECK_EQ(trie[i].weight, model[i].second);
                    }
                    saw_a_result |= !trie.empty();
                }
            }
        }
    }
    CHECK(saw_a_result);
}

TEST(ServeRoutes, CompleteDefaultsAndTheWordPrefixCase) {
    Fixture& f = fixture();
    // No parameters: field=signature, prefix "", k=10, min-level DEBUG.
    const JValue defaults = fetch_json(*f.service, "/api/complete");
    CHECK_EQ(defaults.at("field").str(), "signature"s);
    CHECK_EQ(defaults.at("prefix").str(), ""s);
    const auto model = CompleteOracle(f.entries, "signature", Level::Debug).from_model("", 10);
    CHECK_EQ(defaults.at("results").size(), model.size());
    CHECK_EQ(defaults.at("results").size(), std::size_t{10});

    const JValue upper = fetch_json(*f.service, "/api/complete?field=word&prefix=TIMEOUT");
    const JValue lower = fetch_json(*f.service, "/api/complete?field=word&prefix=timeout");
    CHECK_EQ(upper.at("prefix").str(), "timeout"s);
    CHECK(upper.at("results").size() >= 1);
    CHECK(upper.at("results").size() == lower.at("results").size());
    // Signatures and services are case-sensitive.
    CHECK_EQ(fetch_json(*f.service, "/api/complete?field=service&prefix=AUTH").at("results").size(), std::size_t{0});
    CHECK_EQ(fetch_json(*f.service, "/api/complete?field=service&prefix=auth").at("results").size(), std::size_t{1});
    CHECK_EQ(fetch_json(*f.service, "/api/complete?field=service&prefix=AUTH").at("prefix").str(), "AUTH"s);
}

TEST(ServeRoutes, AlertsAreListedInOrder) {
    Fixture& f = fixture();
    const JValue j = fetch_json(*f.service, "/api/alerts");
    expect_keys(j, {"alerts"});
    const JValue& rows = j.at("alerts");
    CHECK_EQ(rows.size(), f.alerts.size());
    for (std::size_t i = 0; i < f.alerts.size(); ++i) {
        const Alert& a = f.alerts[i];
        const JValue& row = rows.item(i);
        expect_keys(row, {"rule", "service", "fired_at", "count", "first_event", "suppressed"});
        CHECK_EQ(row.at("rule").str(), a.rule);
        CHECK_EQ(row.at("service").str(), a.service);
        CHECK_EQ(row.at("fired_at").str(), format_iso8601_utc(a.fired_at_ms));
        CHECK_EQ(row.at("count").u64(), a.count);
        CHECK_EQ(row.at("first_event").str(), format_iso8601_utc(a.first_event_ms));
        CHECK_EQ(row.at("suppressed").u64(), a.suppressed);
    }
}

TEST(ServeRoutes, ServeOptionsReachTheReport) {
    std::vector<LogEntry> entries = {ev(1000, Level::Error, "svc", "Timeout after 5ms"),
                                     ev(2000, Level::Error, "svc", "Timeout after 9ms"),
                                     ev(3000, Level::Info, "svc", "hello")};
    ServeOptions options;
    options.title = "Ops & <Co>";
    options.top_k = 3;
    options.time_buckets = 5;
    DashboardService custom(entries, {}, options);
    ReportOptions report;
    report.title = options.title;
    report.top_k = 3;
    report.time_buckets = 5;
    CHECK(fetch(custom, "/").body == render_html_report(entries, {}, report));
    CHECK(contains(fetch(custom, "/").body, "Ops &amp; &lt;Co&gt;"));

    DashboardService plain(entries, {});  // the defaults of ServeOptions
    ReportOptions defaults;
    defaults.title = "Log dashboard";
    defaults.top_k = 10;
    defaults.time_buckets = 60;
    CHECK(fetch(plain, "/").body == render_html_report(entries, {}, defaults));
    CHECK(fetch(plain, "/").body != fetch(custom, "/").body);
    CHECK_EQ(plain.entry_count(), std::size_t{3});
    // ServeOptions::top_k is about the report only: the API default stays 10.
    CHECK_EQ(fetch_json(custom, "/api/top-errors").at("results").size(), std::size_t{1});
}

// =============================================================================================
// Parameters: semantics and the 400 cases
// =============================================================================================

TEST(ServeParams, LastValueWinsAndUnknownParametersAreIgnored) {
    Fixture& f = fixture();
    CHECK_EQ(fetch_json(*f.service, "/api/top-errors?k=1&k=2").at("results").size(), std::size_t{2});
    CHECK_EQ(fetch_json(*f.service, "/api/top-errors?k=2&k=1").at("results").size(), std::size_t{1});
    CHECK_EQ(fetch_json(*f.service, "/api/top-errors?k=bad&k=2").at("results").size(), std::size_t{2});  // the first is not looked at
    fetch_json(*f.service, "/api/top-errors?k=2&k=bad", 400);
    CHECK(fetch(*f.service, "/api/top-errors?foo=bar&k=3&zzz").body == fetch(*f.service, "/api/top-errors?k=3").body);
    CHECK(fetch(*f.service, "/api/search?q=error&nope=1&limit=2").body == fetch(*f.service, "/api/search?q=error&limit=2").body);
    CHECK(fetch(*f.service, "/api/search?q=nothing&q=error").body == fetch(*f.service, "/api/search?q=error").body);
    // Routes without parameters do not look at the query at all.
    CHECK_EQ(fetch(*f.service, "/healthz?k=banana").body, "ok"s);
    CHECK_EQ(fetch(*f.service, "/api/summary?k=banana&limit=0").status, 200);
    CHECK_EQ(fetch(*f.service, "/api/alerts?q=").status, 200);
    // '+' and %20 are both a space in the query, so these are the same AND query.
    CHECK(fetch(*f.service, "/api/search?q=payment+error").body == fetch(*f.service, "/api/search?q=payment%20error").body);
    CHECK(fetch_json(*f.service, "/api/search?q=payment+error").at("matches").u64() > 0);
    CHECK_EQ(fetch_json(*f.service, "/api/search?q=payment+error").at("query").str(), "payment error"s);
    CHECK_EQ(fetch_json(*f.service, "/api/search?q=a%2Bb").at("query").str(), "a+b"s);  // %2B is a literal plus
    // Leading zeros are digits, so they are fine.
    CHECK_EQ(fetch_json(*f.service, "/api/top-errors?k=0003").at("results").size(), std::size_t{3});
    CHECK_EQ(fetch_json(*f.service, "/api/top-errors?k=1000").at("results").size() <= 1000, true);
}

TEST(ServeParams, TheLastValueWinsForEveryParameter) {
    Fixture& f = fixture();
    auto same = [&f](const std::string& twice, const std::string& once) {
        const HttpResponse a = fetch(*f.service, twice);
        const HttpResponse b = fetch(*f.service, once);
        if (!same_response(a, b)) throw testkit::Failure{twice + " is not the same as " + once};
    };
    auto differs = [&f](const std::string& first, const std::string& second) {
        if (same_response(fetch(*f.service, first), fetch(*f.service, second))) {
            throw testkit::Failure{first + " and " + second + " must differ for the test to mean anything"};
        }
    };
    // field, prefix, k, min-level of /api/complete: a first-value-wins reader would answer the
    // other request, and the pairs are chosen so that the two requests have different answers.
    same("/api/complete?field=signature&field=word&prefix=ti", "/api/complete?field=word&prefix=ti");
    differs("/api/complete?field=signature&prefix=ti", "/api/complete?field=word&prefix=ti");
    same("/api/complete?field=word&prefix=zzz&prefix=pay", "/api/complete?field=word&prefix=pay");
    differs("/api/complete?field=word&prefix=zzz", "/api/complete?field=word&prefix=pay");
    same("/api/complete?k=1&k=3&field=service", "/api/complete?k=3&field=service");
    differs("/api/complete?k=1&field=service", "/api/complete?k=3&field=service");
    same("/api/complete?min-level=error&min-level=debug", "/api/complete?min-level=debug");
    differs("/api/complete?min-level=error", "/api/complete?min-level=debug");
    same("/api/complete?field=bogus&field=service", "/api/complete?field=service");  // a bad first value is not looked at
    CHECK_EQ(fetch(*f.service, "/api/complete?field=service&field=bogus").status, 400);
    CHECK_EQ(fetch(*f.service, "/api/complete?min-level=nope&min-level=info").status, 200);
    CHECK_EQ(fetch(*f.service, "/api/complete?min-level=info&min-level=nope").status, 400);
    // min-level of /api/top-errors, limit and q of /api/search.
    same("/api/top-errors?min-level=error&min-level=debug&k=1000", "/api/top-errors?min-level=debug&k=1000");
    differs("/api/top-errors?min-level=error&k=1000", "/api/top-errors?min-level=debug&k=1000");
    same("/api/search?q=error&limit=1&limit=3", "/api/search?q=error&limit=3");
    differs("/api/search?q=error&limit=1", "/api/search?q=error&limit=3");
    same("/api/search?q=timeout&q=error", "/api/search?q=error");
    differs("/api/search?q=timeout", "/api/search?q=error");
}

namespace {

void expect_bad_request(DashboardService& service, const std::string& target, const std::string& param) {
    const HttpResponse response = fetch(service, target);
    const JValue j = json_of(response, 400);
    expect_keys(j, {"error"});
    const std::string& message = j.at("error").str();
    if (!contains(message, param)) throw testkit::Failure{target + ": the message \"" + message + "\" does not name " + param};
    if (message.size() > 100) throw testkit::Failure{target + ": the message is not short"};
}

}  // namespace

TEST(ServeParams, BadParametersAre400AndNameTheParameter) {
    Fixture& f = fixture();
    struct Bad {
        const char* target;
        const char* param;
    };
    const Bad cases[] = {
        {"/api/top-errors?k=0", "k"},
        {"/api/top-errors?k=1001", "k"},
        {"/api/top-errors?k=abc", "k"},
        {"/api/top-errors?k=-1", "k"},
        {"/api/top-errors?k=%2B5", "k"},
        {"/api/top-errors?k=%205", "k"},
        {"/api/top-errors?k=5%20", "k"},
        {"/api/top-errors?k=5.0", "k"},
        {"/api/top-errors?k=1e3", "k"},
        {"/api/top-errors?k=0x10", "k"},
        {"/api/top-errors?k=", "k"},
        {"/api/top-errors?k", "k"},
        {"/api/top-errors?k=99999999999999999999", "k"},
        {"/api/top-errors?k=18446744073709551616", "k"},
        {"/api/top-errors?k=18446744073709551615", "k"},
        {"/api/top-errors?k=4294967296", "k"},
        {"/api/top-errors?k=%EF%BC%95", "k"},
        {"/api/top-errors?min-level=fatal", "min-level"},
        {"/api/top-errors?min-level=", "min-level"},
        {"/api/top-errors?min-level=ERRORS", "min-level"},
        {"/api/top-errors?min-level=%20error", "min-level"},
        {"/api/top-errors?min-level=0", "min-level"},
        {"/api/top-errors?k=5&min-level=nope", "min-level"},
        {"/api/search", "q"},
        {"/api/search?q=", "q"},
        {"/api/search?q", "q"},
        {"/api/search?limit=5", "q"},
        {"/api/search?q=error&q=", "q"},  // the LAST value is the empty one
        {"/api/search?q=x&limit=0", "limit"},
        {"/api/search?q=x&limit=1001", "limit"},
        {"/api/search?q=x&limit=abc", "limit"},
        {"/api/search?q=x&limit=-1", "limit"},
        {"/api/search?q=x&limit=", "limit"},
        {"/api/search?q=x&limit=99999999999999999999", "limit"},
        {"/api/search?q=x&limit=1.5", "limit"},
        {"/api/complete?field=bogus", "field"},
        {"/api/complete?field=Signature", "field"},
        {"/api/complete?field=WORD", "field"},
        {"/api/complete?field=", "field"},
        {"/api/complete?field=signature%20", "field"},
        {"/api/complete?k=0", "k"},
        {"/api/complete?k=1001", "k"},
        {"/api/complete?k=x", "k"},
        {"/api/complete?k=99999999999999999999", "k"},
        {"/api/complete?min-level=x", "min-level"},
        {"/api/complete?min-level=", "min-level"},
    };
    for (const Bad& c : cases) expect_bad_request(*f.service, c.target, c.param);

    // When several parameters are bad, the first one in the documented order is named.
    expect_bad_request(*f.service, "/api/top-errors?min-level=bad&k=bad", "k");
    expect_bad_request(*f.service, "/api/search?limit=bad", "q");
    expect_bad_request(*f.service, "/api/search?q=&limit=bad", "q");
    expect_bad_request(*f.service, "/api/complete?min-level=bad&k=bad&field=bad", "field");
    expect_bad_request(*f.service, "/api/complete?min-level=bad&k=bad", "k");

    // The offending value is never echoed back.
    const JValue j = fetch_json(*f.service, "/api/top-errors?k=SENTINEL-VALUE-123", 400);
    CHECK(!contains(j.at("error").str(), "SENTINEL"));
    const JValue level = fetch_json(*f.service, "/api/top-errors?min-level=SENTINEL-VALUE-123", 400);
    CHECK(!contains(level.at("error").str(), "SENTINEL"));
}

TEST(ServeParams, TheBoundariesAreAccepted) {
    Fixture& f = fixture();
    CHECK_EQ(fetch(*f.service, "/api/top-errors?k=1").status, 200);
    CHECK_EQ(fetch(*f.service, "/api/top-errors?k=1000").status, 200);
    CHECK_EQ(fetch(*f.service, "/api/search?q=x&limit=1").status, 200);
    CHECK_EQ(fetch(*f.service, "/api/search?q=x&limit=1000").status, 200);
    CHECK_EQ(fetch(*f.service, "/api/complete?k=1").status, 200);
    CHECK_EQ(fetch(*f.service, "/api/complete?k=1000").status, 200);
    CHECK_EQ(fetch(*f.service, "/api/complete?prefix=").status, 200);  // an empty prefix is allowed
    CHECK_EQ(fetch(*f.service, "/api/complete?prefix").status, 200);
    // q is non-empty after decoding even when it is only blanks or operators; it just finds nothing.
    for (const char* q : {"%20", "%7C", "-", "---", "%09"}) {
        const JValue j = fetch_json(*f.service, std::string("/api/search?q=") + q);
        CHECK_EQ(j.at("matches").u64(), std::uint64_t{0});
        CHECK_EQ(j.at("shown").u64(), std::uint64_t{0});
        CHECK_EQ(j.at("results").size(), std::size_t{0});
    }
}

// =============================================================================================
// 404, methods, HEAD
// =============================================================================================

TEST(ServeRoutes, UnknownPathsAre404) {
    Fixture& f = fixture();
    const char* const targets[] = {
        "/nope", "/api/summary/", "/API/summary", "/api/Summary", "/healthz/", "/HEALTHZ", "/index.html", "//", "/api",
        "/api/", "/api/search/", "/api/top-errors/", "/api/complete/", "/api/alerts/", "/api/Alerts", "/%20", "/..",
        "/api/../healthz", "/api/summary%2F", "/api/summary%20", "/api//summary", "/api/summaryx", "/healthz.txt",
        "/nope?k=bad", "/api/search/x?q=y", "/favicon.ico", "/Api/summary", "/ap%69/summary/",
    };
    for (const char* target : targets) {
        const JValue j = fetch_json(*f.service, target, 404);
        expect_keys(j, {"error"});
        CHECK_EQ(j.at("error").str(), "not found"s);
    }
    CHECK_EQ(fetch(*f.service, "/nope").body, "{\"error\":\"not found\"}"s);
}

TEST(ServeRoutes, RoutesUseThePercentDecodedPath) {
    Fixture& f = fixture();
    CHECK(fetch(*f.service, "/%61pi/summary").body == fetch(*f.service, "/api/summary").body);
    CHECK_EQ(fetch(*f.service, "/%61pi/summary").status, 200);
    CHECK_EQ(fetch(*f.service, "/health%7a").body, "ok"s);
}

TEST(ServeRoutes, OtherMethodsAreRefusedByTheGuard) {
    Fixture& f = fixture();
    for (const char* method : {"POST", "PUT", "DELETE", "OPTIONS", "get", ""}) {
        HttpRequest request = make_request("/healthz");
        request.method = method;
        const HttpResponse response = f.service->handle(request);
        CHECK_EQ(response.status, 405);
        CHECK_EQ(response.content_type, std::string(kJsonType));
        CHECK_EQ(response.body, "{\"error\":\"method not allowed\"}"s);
        CHECK_EQ(response.headers.size(), std::size_t{1});
        CHECK_EQ(response.headers[0].name, "Allow"s);
        CHECK_EQ(response.headers[0].value, "GET, HEAD"s);
    }
}

TEST(ServeRoutes, HeadIsExactlyGet) {
    Fixture& f = fixture();
    const std::vector<std::string> targets = {
        "/", "/healthz", "/api/summary", "/api/top-errors", "/api/top-errors?k=3&min-level=warn", "/api/search?q=error",
        "/api/search?q=timeout&limit=2", "/api/complete", "/api/complete?field=word&prefix=ti", "/api/alerts",
        "/nope", "/api/top-errors?k=0", "/api/search", "/api/complete?field=x",
    };
    for (const std::string& target : targets) {
        const HttpResponse via_get = f.service->handle(make_request(target, "GET"));
        const HttpResponse via_head = f.service->handle(make_request(target, "HEAD"));
        if (!same_response(via_get, via_head)) throw testkit::Failure{"HEAD differs from GET for " + target};
        CHECK(!via_get.body.empty());
    }
}

// =============================================================================================
// Caches, determinism, resource bounds
// =============================================================================================

TEST(ServeCaches, WarmAnswersEqualColdAnswersInAnyOrder) {
    Fixture& f = fixture();
    const std::vector<std::string> targets = {
        "/api/top-errors?min-level=info", "/api/complete?field=word&min-level=error&prefix=t",
        "/api/top-errors", "/api/complete?field=signature&min-level=warn", "/api/top-errors?min-level=debug&k=5",
        "/api/complete?field=service", "/api/complete?field=word&min-level=error&prefix=t&k=1000",
        "/api/complete?field=signature&min-level=warn&k=3", "/api/search?q=error", "/api/top-errors?min-level=info&k=2",
    };
    // A fresh service per request is "cold"; the shared one answers each of them for the first
    // and second time, with other levels and fields built in between.
    for (int pass = 0; pass < 2; ++pass) {
        for (const std::string& target : targets) {
            DashboardService cold(f.entries, f.alerts, f.options);
            if (!same_response(fetch(cold, target), fetch(*f.service, target))) {
                throw testkit::Failure{"warm and cold answers differ for " + target};
            }
        }
    }
}

TEST(ServeCaches, TwoServicesOverTheSameDataAgreeByteForByte) {
    Fixture& f = fixture();
    DashboardService a(f.entries, f.alerts, f.options);
    DashboardService b(f.entries, f.alerts, f.options);
    for (const char* target : {"/", "/api/summary", "/api/alerts", "/api/top-errors?min-level=info",
                               "/api/search?q=error+-timeout&limit=100", "/api/complete?field=word&prefix=a"}) {
        CHECK(same_response(fetch(a, target), fetch(b, target)));
    }
}

TEST(ServeCaches, EachCacheIsBuiltOnceAndThenReused) {
    Fixture& f = fixture();
    DashboardService service(f.entries, f.alerts, f.options);
    auto stats = [&service] { return DashboardServiceTestAccess::cache_stats(service); };
    CHECK_EQ(stats().trie_builds, std::size_t{0});
    CHECK_EQ(stats().top_errors_builds, std::size_t{0});

    // Routes that need no cache build none (the report, summary and alerts exist since the constructor).
    for (const char* target : {"/", "/healthz", "/api/summary", "/api/alerts", "/api/search?q=error", "/nope", "/api/search?q="}) {
        fetch(service, target);
    }
    CHECK_EQ(stats().trie_builds, std::size_t{0});
    CHECK_EQ(stats().top_errors_builds, std::size_t{0});

    // Three tries (two fields, one more min-level) and two TopKErrors tables, each asked many times.
    for (int round = 0; round < 3; ++round) {
        fetch(service, "/api/complete?field=signature");
        fetch(service, "/api/complete?field=word&prefix=ti&k=3");
        fetch(service, "/api/complete?field=signature&min-level=error&k=1000");
        fetch(service, "/api/complete?field=signature&prefix=Pay&k=11");
        fetch(service, "/api/top-errors");
        fetch(service, "/api/top-errors?min-level=info&k=5");
        fetch(service, "/api/top-errors?k=1000");
        CHECK_EQ(stats().trie_builds, std::size_t{3});
        CHECK_EQ(stats().top_errors_builds, std::size_t{2});
        CHECK_EQ(stats().resident_tries, std::size_t{3});
    }
    // A bad request builds nothing, and a prefix that no key can have needs no trie at all.
    fetch(service, "/api/complete?field=service&k=0");
    fetch(service, "/api/top-errors?min-level=debug&k=x");
    fetch(service, "/api/complete?field=service&prefix=" + std::string(kKeyLimit + 1, 's'));
    CHECK_EQ(stats().trie_builds, std::size_t{3});
    CHECK_EQ(stats().top_errors_builds, std::size_t{2});
    // The first request that does need another one builds exactly that one.
    fetch(service, "/api/complete?field=service");
    CHECK_EQ(stats().trie_builds, std::size_t{4});
}

TEST(ServeCaches, TriesAreDroppedLeastRecentlyUsedFirstWhenTheEstimateIsOverBudget) {
    Fixture& f = fixture();
    const std::size_t service_bytes = CompleteOracle(f.entries, "service", Level::Debug).distinct_key_bytes() * kTrieBytesPerKeyByte;
    const std::size_t signature_bytes = CompleteOracle(f.entries, "signature", Level::Debug).distinct_key_bytes() * kTrieBytesPerKeyByte;
    const std::size_t word_bytes = CompleteOracle(f.entries, "word", Level::Debug).distinct_key_bytes() * kTrieBytesPerKeyByte;
    CHECK(service_bytes > 0 && signature_bytes > 0 && word_bytes > 0);

    // The service names are by far the fewest keys: the test relies on that to know what is dropped.
    CHECK(service_bytes <= signature_bytes && service_bytes <= word_bytes);

    const std::string by_service = "/api/complete?field=service&k=10";
    const std::string by_signature = "/api/complete?field=signature&k=10";
    const std::string by_word = "/api/complete?field=word&k=10";
    const std::string expected_service = fetch(*f.service, by_service).body;
    const std::string expected_signature = fetch(*f.service, by_signature).body;
    const std::string expected_word = fetch(*f.service, by_word).body;

    DashboardService service(f.entries, f.alerts, f.options);
    auto stats = [&service] { return DashboardServiceTestAccess::cache_stats(service); };
    // Under the default budget everything stays: service is the least recently used of the two.
    CHECK_EQ(fetch(service, by_service).body, expected_service);
    CHECK_EQ(fetch(service, by_signature).body, expected_signature);
    CHECK_EQ(stats().trie_builds, std::size_t{2});
    // Room for signature + word only. Building the word trie pushes the estimates over the budget,
    // so the least recently used one (service) goes, and not one more: signature + word fit.
    DashboardServiceTestAccess::set_trie_budget(service, signature_bytes + word_bytes);
    CHECK_EQ(fetch(service, by_word).body, expected_word);
    CHECK_EQ(stats().trie_builds, std::size_t{3});
    CHECK_EQ(stats().resident_tries, std::size_t{2});
    CHECK_EQ(fetch(service, by_signature).body, expected_signature);  // both still resident: no build
    CHECK_EQ(fetch(service, by_word).body, expected_word);            // (word is now the most recently used)
    CHECK_EQ(stats().trie_builds, std::size_t{3});
    // The dropped trie is built again and answers the same; that drops the least recently used of
    // the others (signature), and service + word fit.
    CHECK_EQ(fetch(service, by_service).body, expected_service);
    CHECK_EQ(stats().trie_builds, std::size_t{4});
    CHECK_EQ(stats().resident_tries, std::size_t{2});
    CHECK_EQ(fetch(service, by_word).body, expected_word);  // word survived, service is there too
    CHECK_EQ(fetch(service, by_service).body, expected_service);
    CHECK_EQ(stats().trie_builds, std::size_t{4});
    CHECK_EQ(fetch(service, by_signature).body, expected_signature);  // signature was the one dropped
    CHECK_EQ(stats().trie_builds, std::size_t{5});

    // A budget that nothing fits in still serves every request (the trie just built is never
    // dropped) and keeps exactly one trie, whatever the order.
    DashboardService tiny(f.entries, f.alerts, f.options);
    DashboardServiceTestAccess::set_trie_budget(tiny, 1);
    for (int round = 0; round < 2; ++round) {
        for (const std::string* target : {&by_signature, &by_service, &by_word}) {
            const std::string& expected = target == &by_signature ? expected_signature : target == &by_service ? expected_service : expected_word;
            CHECK_EQ(fetch(tiny, *target).body, expected);
            CHECK_EQ(DashboardServiceTestAccess::cache_stats(tiny).resident_tries, std::size_t{1});
        }
    }
    CHECK_EQ(DashboardServiceTestAccess::cache_stats(tiny).trie_builds, std::size_t{6});  // each request built its trie again
    // The answers that were memoized before their trie went away stay valid.
    const std::string big_k = "/api/complete?field=word&k=50";
    const std::string memoized = fetch(tiny, big_k).body;  // word trie (built), then the memo
    fetch(tiny, by_service);                                // drops the word trie
    CHECK_EQ(DashboardServiceTestAccess::cache_stats(tiny).resident_tries, std::size_t{1});
    const std::size_t builds = DashboardServiceTestAccess::cache_stats(tiny).trie_builds;
    CHECK_EQ(fetch(tiny, big_k).body, memoized);  // a memo hit does not even need the trie
    CHECK_EQ(DashboardServiceTestAccess::cache_stats(tiny).trie_builds, builds);
    CHECK_EQ(fetch(tiny, big_k).body, fetch(*f.service, big_k).body);
}

TEST(ServeCaches, CompletionsWithLargeKAreMemoizedInABoundedMemo) {
    Fixture& f = fixture();
    DashboardService service(f.entries, f.alerts, f.options);
    auto stats = [&service] { return DashboardServiceTestAccess::cache_stats(service); };
    const CompleteOracle oracle(f.entries, "word", Level::Debug);
    auto rows_of = [&](const std::string& target) { return fetch_json(service, target).at("results").size(); };

    // k up to 10 comes from the trie's per-node caches and never touches the memo.
    fetch(service, "/api/complete?field=word&k=10");
    fetch(service, "/api/complete?field=word&prefix=t&k=3");
    CHECK_EQ(stats().memo_hits + stats().memo_misses, std::size_t{0});

    // The first k above 10 computes the top 1000 of the prefix; any other k above 10 reads it.
    const std::string first = fetch(service, "/api/complete?field=word&k=11").body;
    CHECK_EQ(stats().memo_misses, std::size_t{1});
    CHECK_EQ(stats().memo_hits, std::size_t{0});
    for (const std::size_t k : {std::size_t{11}, std::size_t{12}, std::size_t{50}, std::size_t{1000}}) {
        const std::string target = "/api/complete?field=word&k=" + std::to_string(k);
        const HttpResponse response = fetch(service, target);
        const auto model = oracle.from_model("", k);
        const JValue j = json_of(response, 200);
        CHECK_EQ(j.at("results").size(), model.size());
        for (std::size_t i = 0; i < model.size(); ++i) {
            CHECK_EQ(j.at("results").item(i).at("key").str(), model[i].first);
            CHECK_EQ(j.at("results").item(i).at("count").u64(), model[i].second);
        }
    }
    CHECK_EQ(fetch(service, "/api/complete?field=word&k=11").body, first);
    CHECK_EQ(stats().memo_misses, std::size_t{1});  // nothing was computed again
    CHECK_EQ(stats().memo_hits, std::size_t{5});

    // A different prefix, field or min-level is a different entry; the case of a word prefix is not.
    fetch(service, "/api/complete?field=word&k=11&prefix=t");
    fetch(service, "/api/complete?field=word&k=11&prefix=T");  // lower-cased before the lookup
    fetch(service, "/api/complete?field=signature&k=11");
    fetch(service, "/api/complete?field=word&k=11&min-level=error");
    CHECK_EQ(stats().memo_misses, std::size_t{4});
    CHECK_EQ(stats().memo_hits, std::size_t{6});

    // The memo never holds more than kMemoLimit entries, and drops the least recently used.
    const std::size_t baseline = stats().memo_misses;
    for (std::size_t i = 0; i < 100; ++i) fetch(service, "/api/complete?field=word&k=11&prefix=q" + base26(i, 3));
    CHECK_EQ(stats().resident_memo, kMemoLimit);
    CHECK_EQ(stats().memo_misses, baseline + 100);
    const std::size_t hits = stats().memo_hits;
    fetch(service, "/api/complete?field=word&k=11&prefix=q" + base26(99, 3));  // among the 32 latest
    CHECK_EQ(stats().memo_hits, hits + 1);
    fetch(service, "/api/complete?field=word&k=11&prefix=q" + base26(0, 3));   // long gone
    CHECK_EQ(stats().memo_hits, hits + 1);
    CHECK_EQ(stats().memo_misses, baseline + 101);
    CHECK_EQ(stats().resident_memo, kMemoLimit);
    // What was recomputed after the eviction is the same answer.
    CHECK_EQ(rows_of("/api/complete?field=word&k=11"), std::size_t{11});
}

TEST(ServeBounds, RowCountsAreCappedAt1000) {
    Fixture& f = fixture();
    const JValue search = fetch_json(*f.service, "/api/search?q=info&limit=1000");
    CHECK(search.at("matches").u64() > 1000);  // more hits than the cap: the count stays exact
    CHECK_EQ(search.at("shown").u64(), std::uint64_t{1000});
    CHECK_EQ(search.at("results").size(), std::size_t{1000});
    CHECK_EQ(search.at("matches").u64(), static_cast<std::uint64_t>(f.index.search("info").size()));

    const JValue top = fetch_json(*f.service, "/api/top-errors?k=1000&min-level=debug");
    CHECK(top.at("results").size() <= 1000);
    CHECK_EQ(top.at("results").size(), static_cast<std::size_t>(top.at("distinct").u64()));

    const JValue complete = fetch_json(*f.service, "/api/complete?field=word&k=1000");
    CHECK(complete.at("results").size() <= 1000);
    CHECK(complete.at("results").size() > 10);
}

TEST(ServeBounds, HugeQueryStringsOnlyCostParsing) {
    Fixture& f = fixture();
    // The same word named 6000 times: the index evaluates it once.
    std::string many;
    for (int i = 0; i < 6000; ++i) many += "timeout|";
    many += "timeout";
    const JValue repeated = fetch_json(*f.service, "/api/search?limit=1&q=" + url_encode(many));
    const JValue once = fetch_json(*f.service, "/api/search?limit=1&q=timeout");
    CHECK_EQ(repeated.at("matches").u64(), once.at("matches").u64());
    CHECK_EQ(repeated.at("query").str(), many);

    // One 200,000-byte word that matches nothing, and a 200,000-byte prefix for every field.
    const std::string huge(200000, 'a');
    const JValue none = fetch_json(*f.service, "/api/search?q=" + huge);
    CHECK_EQ(none.at("matches").u64(), std::uint64_t{0});
    CHECK_EQ(none.at("query").str().size(), huge.size());
    for (const char* field : {"signature", "service", "word"}) {
        const JValue j = fetch_json(*f.service, std::string("/api/complete?field=") + field + "&prefix=" + huge);
        CHECK_EQ(j.at("results").size(), std::size_t{0});
        CHECK_EQ(j.at("prefix").str().size(), huge.size());
    }
    // A query of a hundred thousand escapes-worth of hostile characters is echoed escaped.
    const std::string noisy = std::string(50000, '"') + std::string(50000, '<');
    const JValue echoed = fetch_json(*f.service, "/api/search?q=" + url_encode(noisy));
    CHECK(echoed.at("query").str() == noisy);
}

TEST(ServeBounds, CompletionKeysLongerThan256BytesAreNotOffered) {
    // 256 bytes is the longest key; one more and the string is not a completion in any field.
    // (Signatures, services and words are inserted into tries, whose tie-breaking costs the length
    // of the common prefix: unbounded keys would make the first request quadratic.)
    const std::string s256(kKeyLimit, 's'), s257(kKeyLimit + 1, 's');
    const std::string m256(kKeyLimit, 'm'), n257(kKeyLimit + 1, 'n');
    DashboardService service({ev(1, Level::Error, s256, m256), ev(2, Level::Error, s257, n257),
                              ev(3, Level::Error, "ok", "short words only")},
                             {});
    const std::vector<std::string> signatures = complete_keys(fetch_json(service, "/api/complete?field=signature&k=1000"));
    CHECK(std::find(signatures.begin(), signatures.end(), m256) != signatures.end());
    CHECK(std::find(signatures.begin(), signatures.end(), n257) == signatures.end());
    CHECK_EQ(signatures.size(), std::size_t{2});  // m256 and "short words only"
    const std::vector<std::string> services = complete_keys(fetch_json(service, "/api/complete?field=service&k=1000"));
    CHECK(std::find(services.begin(), services.end(), s256) != services.end());
    CHECK(std::find(services.begin(), services.end(), s257) == services.end());
    CHECK_EQ(services.size(), std::size_t{2});  // s256 and "ok"
    const std::vector<std::string> words = complete_keys(fetch_json(service, "/api/complete?field=word&k=1000"));
    CHECK(std::find(words.begin(), words.end(), m256) != words.end());
    CHECK(std::find(words.begin(), words.end(), n257) == words.end());
    CHECK_EQ(words.size(), std::size_t{4});  // m256, short, words, only

    // A prefix longer than any key matches nothing (and is still echoed), the longest key is found.
    const JValue none = fetch_json(service, "/api/complete?field=signature&prefix=" + std::string(kKeyLimit + 1, 'm'));
    CHECK_EQ(none.at("results").size(), std::size_t{0});
    CHECK_EQ(none.at("prefix").str().size(), kKeyLimit + 1);
    const JValue exact = fetch_json(service, "/api/complete?field=signature&prefix=" + m256);
    CHECK_EQ(exact.at("results").size(), std::size_t{1});
    CHECK_EQ(exact.at("results").item(0).at("key").str(), m256);

    // The other routes still see the long strings (the limit is about completions only).
    CHECK_EQ(fetch_json(service, "/api/search?q=" + n257).at("matches").u64(), std::uint64_t{1});
    CHECK_EQ(fetch_json(service, "/api/top-errors?k=1000").at("distinct").u64(), std::uint64_t{3});
}

TEST(ServeBounds, TheFirstCompletionOverNearIdenticalHugeKeysIsNotQuadratic) {
    // Twelve 100,000-byte messages that differ only in a short tail, and twelve 100,000-byte service
    // names that do the same. A trie breaks weight ties by comparing keys, so inserting such keys
    // took seconds per (field, min-level) cache and froze the serving thread. They are skipped now.
    std::vector<LogEntry> entries;
    std::string repeated;
    for (int i = 0; i < 9090; ++i) repeated += "abcdefghij ";
    for (std::size_t i = 0; i < 12; ++i) {
        entries.push_back(ev(10 + static_cast<std::int64_t>(i), Level::Error, "svc", repeated + "tail" + base26(i, 3)));
        entries.push_back(ev(100 + static_cast<std::int64_t>(i), Level::Error, std::string(100000, 'q') + base26(i, 3), "x"));
    }
    DashboardService service(std::move(entries), {});

    CHECK_EQ(fetch_json(service, "/api/complete?field=signature&k=1000").at("results").size(), std::size_t{1});  // just "x"
    const std::vector<std::string> services = complete_keys(fetch_json(service, "/api/complete?field=service&k=1000"));
    CHECK_EQ(services.size(), std::size_t{1});
    CHECK_EQ(services[0], "svc"s);
    const JValue words = fetch_json(service, "/api/complete?field=word&k=1000");
    CHECK_EQ(words.at("results").size(), std::size_t{14});  // abcdefghij, 12 tails, x
    CHECK_EQ(words.at("results").item(0).at("key").str(), "abcdefghij"s);
    CHECK_EQ(words.at("results").item(0).at("count").u64(), std::uint64_t{12 * 9090});
    // Every other (field, min-level) combination as well.
    for (const char* field : {"signature", "service", "word"}) {
        for (const char* level : {"debug", "info", "warn", "error"}) {
            fetch_json(service, std::string("/api/complete?k=5&field=") + field + "&min-level=" + level);
        }
    }
}

namespace {

// Search for every entry (all of them mention a word that is not -zzzznotpresent) and return the
// messages of the rows, in order.
std::vector<std::string> all_messages(DashboardService& service, std::size_t expected_rows) {
    const JValue j = fetch_json(service, "/api/search?q=-zzzznotpresent&limit=1000");
    if (j.at("results").size() != expected_rows) throw testkit::Failure{"unexpected number of rows"};
    std::vector<std::string> messages;
    for (const JValue& row : j.at("results").items) messages.push_back(row.at("message").str());
    return messages;
}

}  // namespace

TEST(ServeBounds, LongLogStringsAreClippedOnACharacterBoundary) {
    const std::string euro = "\xE2\x82\xAC";           // 3 bytes
    const std::string emoji = "\xF0\x9F\x98\x80";      // 4 bytes
    const std::string eacute = "\xC3\xA9";             // 2 bytes
    struct Case {
        std::size_t pad;
        std::string sequence;
        std::string tail;
        std::size_t kept;  // bytes of the message that survive (the rest is replaced by the ellipsis)
        bool clipped;
    };
    const std::vector<Case> cases = {
        {4092, "", "tail", 4096, false},          // exactly kFieldLimit bytes: untouched
        {4093, "", "tail", 4096, true},           // one byte too many
        {5000, "", "", 4096, true},
        {4093, euro, "tail", 4096, true},         // the sequence ends exactly at the limit: kept whole
        {4094, euro, "tail", 4094, true},         // cut after its 1st byte: the whole sequence goes
        {4095, euro, "tail", 4095, true},         // cut after its 2nd byte
        {4092, emoji, "tail", 4096, true},        // 4-byte sequence ends exactly at the limit
        {4093, emoji, "tail", 4093, true},
        {4094, emoji, "tail", 4094, true},
        {4095, emoji, "tail", 4095, true},
        {4094, eacute, "tail", 4096, true},
        {4095, eacute, "tail", 4095, true},
        {4090, eacute, "", 4092, false},          // short and valid: untouched
    };
    std::vector<LogEntry> entries;
    std::vector<std::string> expected;
    for (std::size_t i = 0; i < cases.size(); ++i) {
        const Case& c = cases[i];
        const std::string message = std::string(c.pad, 'a') + c.sequence + c.tail;
        entries.push_back(ev(static_cast<std::int64_t>(i), Level::Error, "svc" + std::to_string(i), message));
        if (c.clipped) {
            expected.push_back(message.substr(0, c.kept) + kEllipsis);
        } else {
            CHECK_EQ(message.size(), c.kept);
            expected.push_back(message);
        }
    }
    DashboardService service(entries, {});
    const std::vector<std::string> messages = all_messages(service, cases.size());
    for (std::size_t i = 0; i < cases.size(); ++i) {
        if (messages[i] != expected[i]) {
            throw testkit::Failure{"case " + std::to_string(i) + ": " + std::to_string(messages[i].size()) + " bytes, expected " +
                                   std::to_string(expected[i].size())};
        }
        if (!well_formed_utf8(messages[i])) throw testkit::Failure{"case " + std::to_string(i) + " is not UTF-8"};
    }

    // Invalid UTF-8 is repaired, and clipped like anything else (one U+FFFD per stray byte).
    DashboardService stray({ev(1, Level::Error, "svc", std::string(5000, '\x80'))}, {});
    const std::string repaired = all_messages(stray, 1)[0];
    CHECK(repaired.size() >= 4090 * 3);
    CHECK(repaired.size() <= kFieldLimit * 3 + 3);
    CHECK_EQ(repaired.compare(repaired.size() - 3, 3, kEllipsis), 0);
    CHECK(well_formed_utf8(repaired));
}

TEST(ServeBounds, EveryLogStringInEveryRouteIsClipped) {
    const std::string long_name(5000, 'x');
    const std::string long_text(5000, 'a');
    Alert alert;
    alert.rule = std::string(5000, 'r');
    alert.service = std::string(5000, 'q');
    alert.fired_at_ms = 9;
    alert.first_event_ms = 1;
    alert.count = 2;
    DashboardService service({ev(1, Level::Error, long_name, long_text)}, {alert});
    const std::string clipped_name = long_name.substr(0, kFieldLimit) + kEllipsis;
    const std::string clipped_text = long_text.substr(0, kFieldLimit) + kEllipsis;

    const JValue summary = fetch_json(service, "/api/summary");
    CHECK_EQ(summary.at("services").item(0).at("name").str(), clipped_name);
    CHECK_EQ(summary.at("services").item(0).at("entries").u64(), std::uint64_t{1});

    const JValue top = fetch_json(service, "/api/top-errors");
    CHECK_EQ(top.at("results").item(0).at("service").str(), clipped_name);
    CHECK_EQ(top.at("results").item(0).at("signature").str(), clipped_text);
    CHECK_EQ(top.at("results").item(0).at("example").str(), clipped_text);

    const JValue search = fetch_json(service, "/api/search?q=" + long_text);
    CHECK_EQ(search.at("matches").u64(), std::uint64_t{1});
    CHECK_EQ(search.at("results").item(0).at("service").str(), clipped_name);
    CHECK_EQ(search.at("results").item(0).at("message").str(), clipped_text);
    CHECK_EQ(search.at("query").str(), long_text);  // what the CLIENT sent is echoed as it is

    const JValue alerts = fetch_json(service, "/api/alerts");
    CHECK_EQ(alerts.at("alerts").item(0).at("rule").str(), alert.rule.substr(0, kFieldLimit) + kEllipsis);
    CHECK_EQ(alerts.at("alerts").item(0).at("service").str(), alert.service.substr(0, kFieldLimit) + kEllipsis);
}

TEST(ServeBounds, SearchAndTopErrorsStopAddingRowsAtFourMebibytes) {
    // 800 entries whose message is 4096 '<' (24,576 bytes once escaped) in a service of its own:
    // a row is about 25 KB in search and 50 KB in top-errors, so a limit of 1000 used to build
    // 20 MB and 40 MB bodies. (With longer messages, hundreds of MB: rows were capped, bytes not.)
    constexpr std::size_t kEntries = 800;
    std::vector<LogEntry> entries;
    for (std::size_t i = 0; i < kEntries; ++i) {
        entries.push_back(ev(static_cast<std::int64_t>(1000 + i), Level::Error, "svc-" + base26(i, 4),
                             std::string(kFieldLimit, '<') + base26(i, 4)));
    }
    DashboardService service(std::move(entries), {});

    const HttpResponse search = fetch(service, "/api/search?q=error&limit=1000");
    CHECK_EQ(search.status, 200);
    CHECK(search.body.size() <= kBodyLimit + 1024);
    const JValue j = parse_json(search.body);
    CHECK_EQ(j.at("matches").u64(), std::uint64_t{kEntries});  // the count stays exact
    const std::size_t shown = j.at("results").size();
    CHECK_EQ(j.at("shown").u64(), static_cast<std::uint64_t>(shown));  // `shown` is what was returned
    CHECK(shown >= 100 && shown < kEntries);
    for (std::size_t i = 0; i < shown; ++i) {  // a prefix of the hits, in document order
        CHECK_EQ(j.at("results").item(i).at("service").str(), "svc-" + base26(i, 4));
    }

    const HttpResponse top = fetch(service, "/api/top-errors?k=1000");
    CHECK_EQ(top.status, 200);
    CHECK(top.body.size() <= kBodyLimit + 1024);
    const JValue t = parse_json(top.body);
    CHECK_EQ(t.at("total").u64(), std::uint64_t{kEntries});
    CHECK_EQ(t.at("distinct").u64(), std::uint64_t{kEntries});
    const std::size_t rows = t.at("results").size();
    CHECK(rows >= 50 && rows < kEntries);
    for (std::size_t i = 0; i < rows; ++i) {  // best first: equal counts, so by signature, i.e. by tail
        CHECK_EQ(t.at("results").item(i).at("service").str(), "svc-" + base26(i, 4));
    }

    // Under the limit nothing is dropped, whatever k asks for.
    const JValue few = fetch_json(service, "/api/search?q=error&limit=40");
    CHECK_EQ(few.at("shown").u64(), std::uint64_t{40});
    CHECK_EQ(few.at("results").size(), std::size_t{40});
    CHECK_EQ(fetch_json(service, "/api/top-errors?k=40").at("results").size(), std::size_t{40});
}

// =============================================================================================
// Hostile log text
// =============================================================================================

namespace {

std::vector<LogEntry> hostile_entries() {
    std::vector<LogEntry> v;
    v.push_back(ev(1000, Level::Error, "svc-a", "He said \"hi\" and \\ left"));
    v.push_back(ev(2000, Level::Error, "svc-a", "line1\nline2\r\n\tTabbed"));
    v.push_back(ev(3000, Level::Error, "svc-a", std::string("before\0after", 12)));
    v.push_back(ev(4000, Level::Error, "svc-b", "<script>alert(1)</script>"));
    v.push_back(ev(5000, Level::Error, "svc-b", "&amp; <img src=x onerror=alert(2)> ]]> </title> <!--"));
    v.push_back(ev(6000, Level::Error, "svc-c",
                   "bad " "\xFF\xFE" " and " "\xC3" " trunc " "\xE2\x82" " overlong " "\xC0\xAF" " surrogate "
                   "\xED\xA0\x80" " big " "\xF4\x90\x80\x80" " end " "\xF0\x9F"));
    v.push_back(ev(7000, Level::Warn, "svc\"q\\<b>&", "service with quote, backslash and angle brackets"));
    v.push_back(ev(8000, Level::Info, "svc-\xFF-bad", "service with an invalid byte"));
    v.push_back(ev(9000, Level::Error, "svc-a", "ctrl " "\x01\x02\x1f" " del " "\x7f" " end"));
    v.push_back(ev(10000, Level::Error, "svc-d", "caf\xC3\xA9 \xE2\x82\xAC \xF0\x9F\x98\x80 done"));
    v.push_back(ev(11000, Level::Debug, "svc-a", ""));
    v.push_back(ev(12000, Level::Error, "svc-e", "</script><script>alert(3)</script>"));
    return v;
}

std::vector<Alert> hostile_alerts() {
    Alert a;
    a.rule = "bad\"rule</script>";
    a.service = "svc\\\n\x01<&>";
    a.fired_at_ms = 5000;
    a.count = 3;
    a.first_event_ms = 1000;
    a.suppressed = 7;
    Alert b = a;
    b.rule = "bytes " "\xFF" " \xC3";
    b.service = "*";
    return {a, b};
}

void check_json_body_is_inert(const std::string& body, const std::string& what) {
    for (const char c : body) {
        const auto u = static_cast<unsigned char>(c);
        if (u < 0x20 || u == 0x7F) throw testkit::Failure{what + ": a raw control byte in the body"};
        if (c == '<' || c == '>' || c == '&') throw testkit::Failure{what + ": a raw <, > or & in the body"};
    }
    if (!well_formed_utf8(body)) throw testkit::Failure{what + ": the body is not valid UTF-8"};
    parse_json(body);
}

}  // namespace

TEST(ServeHostile, EveryJsonRouteStaysValidAndInert) {
    ServeOptions options;
    options.title = "</title><script>boom()</script>";
    options.top_k = 100;
    const std::vector<LogEntry> entries = hostile_entries();
    DashboardService service(entries, hostile_alerts(), options);

    for (const std::string& target : std::vector<std::string>{
             "/api/summary", "/api/alerts", "/api/top-errors?min-level=debug&k=1000", "/api/top-errors",
             "/api/search?q=-zzzznotpresent&limit=1000", "/api/search?q=script", "/api/search?q=svc",
             "/api/complete?k=1000", "/api/complete?field=service&k=1000", "/api/complete?field=word&k=1000",
             "/api/complete?field=signature&prefix=%3Cscript", "/nope?x=%3Cscript%3E"}) {
        const HttpResponse response = service.handle(make_request(target));
        if (response.content_type != kJsonType) throw testkit::Failure{target + ": content type"};
        check_json_body_is_inert(response.body, target);
    }
    // The hostile prefix and query come back escaped and decode to what was sent.
    const JValue prefixed = fetch_json(service, "/api/complete?prefix=%3Cscript%22%5C");
    CHECK_EQ(prefixed.at("prefix").str(), "<script\"\\"s);
    const JValue queried = fetch_json(service, "/api/search?q=%3C%2Fscript%3E%26%22");
    CHECK_EQ(queried.at("query").str(), "</script>&\""s);
    CHECK(!contains(fetch(service, "/api/search?q=%3C%2Fscript%3E%26%22").body, "<"));
}

TEST(ServeHostile, SearchReturnsEveryEntryRepairedAndInOrder) {
    const std::vector<LogEntry> entries = hostile_entries();
    DashboardService service(entries, {});
    const JValue j = fetch_json(service, "/api/search?q=-zzzznotpresent&limit=1000");  // every entry
    CHECK_EQ(j.at("matches").u64(), static_cast<std::uint64_t>(entries.size()));
    const JValue& rows = j.at("results");
    CHECK_EQ(rows.size(), entries.size());
    for (std::size_t i = 0; i < entries.size(); ++i) {
        const JValue& row = rows.item(i);
        CHECK_EQ(row.at("time").str(), format_iso8601_utc(entries[i].timestamp_ms));
        CHECK_EQ(row.at("level").str(), std::string(to_string(entries[i].level)));
        if (row.at("service").str() != reference_repair(entries[i].service)) throw testkit::Failure{"service of entry " + std::to_string(i)};
        if (row.at("message").str() != reference_repair(entries[i].message)) throw testkit::Failure{"message of entry " + std::to_string(i)};
    }
    // The NUL is a real U+0000 after decoding, and the valid UTF-8 entry is untouched.
    CHECK_EQ(rows.item(2).at("message").str(), std::string("before\0after", 12));
    CHECK_EQ(rows.item(9).at("message").str(), "caf\xC3\xA9 \xE2\x82\xAC \xF0\x9F\x98\x80 done"s);
    CHECK(contains(rows.item(5).at("message").str(), kReplacement));
    // The dangerous characters are escaped in the raw text of the response.
    const std::string raw = fetch(service, "/api/search?q=script&limit=1000").body;
    CHECK(contains(raw, "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e"));
    CHECK(!contains(raw, "<script"));
    // Finding entries by words that sit next to the hostile text still works.
    CHECK_EQ(fetch_json(service, "/api/search?q=before+after").at("matches").u64(), std::uint64_t{1});
    CHECK_EQ(fetch_json(service, "/api/search?q=script").at("matches").u64(), std::uint64_t{2});
    CHECK_EQ(fetch_json(service, "/api/search?q=onerror").at("matches").u64(), std::uint64_t{1});
}

TEST(ServeHostile, TopErrorsAndCompleteKeepHostileKeysDistinctAndEscaped) {
    const std::vector<LogEntry> entries = hostile_entries();
    DashboardService service(entries, {});

    TopKErrors oracle(Level::Error);
    for (const LogEntry& e : entries) oracle.add(e);
    const JValue top = fetch_json(service, "/api/top-errors?k=1000");
    CHECK_EQ(top.at("total").u64(), oracle.total());
    const std::vector<SignatureCount> want = oracle.top_k(1000);
    CHECK_EQ(top.at("results").size(), want.size());
    for (std::size_t i = 0; i < want.size(); ++i) {
        const JValue& row = top.at("results").item(i);
        if (row.at("service").str() != reference_repair(want[i].service)) throw testkit::Failure{"service of group " + std::to_string(i)};
        if (row.at("signature").str() != reference_repair(want[i].signature)) throw testkit::Failure{"signature of group " + std::to_string(i)};
        if (row.at("example").str() != reference_repair(want[i].example)) throw testkit::Failure{"example of group " + std::to_string(i)};
    }

    // Completion keys: compare as sorted (repaired key, count) lists, because two different raw
    // keys may repair to the same text.
    for (const char* field : {"signature", "service", "word"}) {
        const auto model = CompleteOracle(entries, field, Level::Debug).from_model("", 1000);
        std::vector<std::pair<std::string, std::uint64_t>> expected;
        for (const auto& kv : model) expected.emplace_back(reference_repair(kv.first), kv.second);
        std::vector<std::pair<std::string, std::uint64_t>> got;
        const JValue j = fetch_json(service, std::string("/api/complete?k=1000&field=") + field);
        for (const JValue& row : j.at("results").items) got.emplace_back(row.at("key").str(), row.at("count").u64());
        std::sort(expected.begin(), expected.end());
        std::sort(got.begin(), got.end());
        if (expected != got) throw testkit::Failure{std::string("completions differ for field ") + field};
    }
}

TEST(ServeHostile, TheReportAndTheTitleNeverCarryARawScriptTag) {
    ServeOptions options;
    options.title = "</title><script>boom()</script>";
    options.top_k = 100;
    DashboardService service(hostile_entries(), hostile_alerts(), options);
    const HttpResponse page = fetch(service, "/");
    CHECK_EQ(page.status, 200);
    CHECK_EQ(page.content_type, std::string(kHtmlType));
    CHECK(!contains_ignoring_case(page.body, "<script"));
    CHECK(!contains_ignoring_case(page.body, "</script"));
    CHECK(!contains(page.body, "onerror=alert(2)>"));   // the angle bracket that would close the tag is escaped
    CHECK(!contains(page.body, "<img"));
    CHECK(contains(page.body, "&lt;script&gt;alert(1)&lt;/script&gt;"));  // the message is there, as text
    CHECK(contains(page.body, "&lt;/title&gt;&lt;script&gt;boom()&lt;/script&gt;"));
}

TEST(ServeHostile, AHundredThousandByteMessageSurvivesEveryRoute) {
    std::string big;
    while (big.size() < 100000) big += "ab\"c\\d<e>f&g\nh ";
    big.resize(99990);
    big += " zzneedle";  // 9 more bytes, a unique token at the very end
    CHECK_EQ(big.size(), std::size_t{99999});
    big += '!';
    CHECK_EQ(big.size(), std::size_t{100000});

    std::vector<LogEntry> entries = {ev(1, Level::Info, "small", "hello"), ev(2, Level::Error, "big", big),
                                     ev(3, Level::Error, "big", "short and sweet")};
    DashboardService service(entries, {});

    // The index sees the whole message (the needle is its last word), but the response carries at
    // most kFieldLimit bytes of it, cut at a character boundary and marked with an ellipsis.
    const std::string clipped_big = big.substr(0, kFieldLimit) + kEllipsis;
    const HttpResponse search = fetch(service, "/api/search?q=zzneedle");
    check_json_body_is_inert(search.body, "search");
    const JValue j = parse_json(search.body);
    CHECK_EQ(j.at("matches").u64(), std::uint64_t{1});
    CHECK(j.at("results").item(0).at("message").str() == clipped_big);
    CHECK(search.body.size() > kFieldLimit);
    CHECK(search.body.size() < 2 * 6 * kFieldLimit);  // far below the 100,000 bytes (600,000 escaped) of the log text

    for (const char* target : {"/api/top-errors", "/api/top-errors?min-level=debug", "/api/summary",
                               "/api/complete", "/api/complete?field=word&prefix=zz", "/api/complete?field=signature&prefix=ab"}) {
        const HttpResponse response = fetch(service, target);
        check_json_body_is_inert(response.body, target);
        CHECK(response.body.size() < 4 * 6 * kFieldLimit);
    }
    const JValue top = fetch_json(service, "/api/top-errors");
    bool found = false;
    for (const JValue& row : top.at("results").items) found |= row.at("example").str() == clipped_big;
    CHECK(found);
    CHECK(!contains_ignoring_case(fetch(service, "/").body, "<script"));
}

// =============================================================================================
// Empty data
// =============================================================================================

TEST(ServeEmpty, EveryRouteWorksWithoutEntries) {
    DashboardService service({}, {});
    CHECK_EQ(service.entry_count(), std::size_t{0});

    const JValue summary = fetch_json(service, "/api/summary");
    expect_keys(summary, {"entries", "levels", "services", "first", "last", "alerts"});
    CHECK_EQ(summary.at("entries").u64(), std::uint64_t{0});
    for (const char* level : {"debug", "info", "warn", "error"}) CHECK_EQ(summary.at("levels").at(level).u64(), std::uint64_t{0});
    CHECK_EQ(summary.at("services").size(), std::size_t{0});
    CHECK(summary.at("first").type == JValue::Type::Null);
    CHECK(summary.at("last").type == JValue::Type::Null);
    CHECK_EQ(summary.at("alerts").u64(), std::uint64_t{0});
    CHECK_EQ(fetch(service, "/api/summary").body,
             "{\"entries\":0,\"levels\":{\"debug\":0,\"info\":0,\"warn\":0,\"error\":0},\"services\":[],"
             "\"first\":null,\"last\":null,\"alerts\":0}"s);

    const JValue top = fetch_json(service, "/api/top-errors?min-level=debug");
    CHECK_EQ(top.at("total").u64(), std::uint64_t{0});
    CHECK_EQ(top.at("distinct").u64(), std::uint64_t{0});
    CHECK_EQ(top.at("results").size(), std::size_t{0});

    const JValue search = fetch_json(service, "/api/search?q=anything");
    CHECK_EQ(search.at("matches").u64(), std::uint64_t{0});
    CHECK_EQ(search.at("shown").u64(), std::uint64_t{0});
    CHECK_EQ(search.at("results").size(), std::size_t{0});
    CHECK_EQ(fetch_json(service, "/api/search?q=-x").at("matches").u64(), std::uint64_t{0});

    for (const char* field : {"signature", "service", "word"}) {
        const JValue complete = fetch_json(service, std::string("/api/complete?field=") + field);
        CHECK_EQ(complete.at("results").size(), std::size_t{0});
    }
    CHECK_EQ(fetch(service, "/api/alerts").body, "{\"alerts\":[]}"s);
    CHECK_EQ(fetch(service, "/healthz").body, "ok"s);
    const HttpResponse page = fetch(service, "/");
    CHECK_EQ(page.status, 200);
    CHECK_EQ(page.content_type, std::string(kHtmlType));
    CHECK(page.body == render_html_report({}, {}, ReportOptions{"Log dashboard", 10, 60}));
    CHECK_EQ(fetch(service, "/nope").status, 404);
}

TEST(ServeEmpty, AlertsWithoutEntriesAndEntriesWithoutAlerts) {
    Alert a;
    a.rule = "r";
    a.service = "*";
    a.fired_at_ms = 1000;
    a.count = 2;
    a.first_event_ms = 500;
    a.suppressed = 1;
    DashboardService alerts_only({}, {a});
    CHECK_EQ(fetch_json(alerts_only, "/api/alerts").at("alerts").size(), std::size_t{1});
    CHECK_EQ(fetch_json(alerts_only, "/api/summary").at("alerts").u64(), std::uint64_t{1});
    CHECK(fetch_json(alerts_only, "/api/summary").at("first").type == JValue::Type::Null);

    DashboardService entries_only({ev(7, Level::Error, "s", "boom 1")}, {});
    CHECK_EQ(fetch(entries_only, "/api/alerts").body, "{\"alerts\":[]}"s);
    CHECK_EQ(fetch_json(entries_only, "/api/summary").at("first").str(), format_iso8601_utc(7));
    CHECK_EQ(fetch_json(entries_only, "/api/summary").at("last").str(), format_iso8601_utc(7));
    // Entries without a service name or message do not break the caches.
    DashboardService odd({ev(1, Level::Error, "", ""), ev(2, Level::Error, "x", "")}, {});
    CHECK_EQ(fetch_json(odd, "/api/complete?field=service").at("results").size(), std::size_t{1});
    CHECK_EQ(fetch_json(odd, "/api/complete?field=signature").at("results").size(), std::size_t{0});
    CHECK_EQ(fetch_json(odd, "/api/complete?field=word").at("results").size(), std::size_t{0});
    CHECK_EQ(fetch_json(odd, "/api/top-errors").at("total").u64(), std::uint64_t{2});
    CHECK_EQ(fetch_json(odd, "/api/summary").at("services").size(), std::size_t{2});
    CHECK_EQ(fetch_json(odd, "/api/summary").at("services").item(0).at("name").str(), ""s);  // ties by name
    CHECK_EQ(fetch_json(odd, "/api/summary").at("services").item(1).at("name").str(), "x"s);
}

TEST(ServeEmpty, EntriesSpanningTheWholeInt64RangeStillRender) {
    // report.cpp used to index its timeline out of range for exactly this input when the bucket
    // count divides 2^64 - 1 (AddressSanitizer: heap-buffer-overflow for 1, 3, 5, 15, 17 ...). The
    // service renders the report without the overflow, and the API still has the real timestamps.
    const std::int64_t lo = std::numeric_limits<std::int64_t>::min();
    const std::int64_t hi = std::numeric_limits<std::int64_t>::max();
    for (const std::size_t buckets : {std::size_t{1}, std::size_t{2}, std::size_t{3}, std::size_t{5}, std::size_t{15},
                                      std::size_t{17}, std::size_t{51}, std::size_t{60}, std::size_t{255}, std::size_t{400}}) {
        ServeOptions options;
        options.time_buckets = buckets;
        DashboardService service({ev(lo, Level::Error, "a", "x"), ev(0, Level::Warn, "b", "y"), ev(hi, Level::Info, "c", "z")}, {},
                                 options);
        const HttpResponse page = fetch(service, "/");
        CHECK_EQ(page.status, 200);
        CHECK(contains(page.body, "Log dashboard"));
        const JValue summary = fetch_json(service, "/api/summary");
        CHECK_EQ(summary.at("entries").u64(), std::uint64_t{3});
        CHECK_EQ(summary.at("first").str(), format_iso8601_utc(lo));
        CHECK_EQ(summary.at("last").str(), format_iso8601_utc(hi));
    }
    // Only INT64_MIN and INT64_MAX together are special; each alone is an ordinary range.
    DashboardService low_only({ev(lo, Level::Error, "a", "x"), ev(5, Level::Error, "a", "y")}, {}, ServeOptions{"t", 3, 1});
    CHECK_EQ(fetch(low_only, "/").status, 200);
    DashboardService high_only({ev(hi, Level::Error, "a", "x"), ev(5, Level::Error, "a", "y")}, {}, ServeOptions{"t", 3, 1});
    CHECK_EQ(fetch(high_only, "/").status, 200);
}

TEST(ServeEmpty, EntriesMayComeInAnyOrder) {
    std::vector<LogEntry> entries = {ev(300, Level::Error, "late", "x 1"), ev(100, Level::Error, "early", "x 2"),
                                     ev(200, Level::Warn, "mid", "x 3")};
    DashboardService service(entries, {});
    const JValue summary = fetch_json(service, "/api/summary");
    CHECK_EQ(summary.at("first").str(), format_iso8601_utc(100));
    CHECK_EQ(summary.at("last").str(), format_iso8601_utc(300));
    const JValue search = fetch_json(service, "/api/search?q=x");
    CHECK_EQ(search.at("results").item(0).at("service").str(), "late"s);  // vector order, not time order
    CHECK_EQ(search.at("results").item(1).at("service").str(), "early"s);
    CHECK_EQ(search.at("results").item(2).at("service").str(), "mid"s);
    const JValue top = fetch_json(service, "/api/top-errors");
    CHECK_EQ(top.at("results").size(), std::size_t{2});
    CHECK_EQ(top.at("results").item(0).at("count").u64(), std::uint64_t{1});
}

// =============================================================================================
// Failures
// =============================================================================================

namespace {
struct Secret {};
}  // namespace

TEST(ServeFailure, AnyExceptionBecomesTheSameGenericFiveHundred) {
    Fixture& f = fixture();
    const HttpRequest request = make_request("/api/summary");
    const std::string expected = "{\"error\":\"internal error\"}";

    auto check_failure = [&](const HttpResponse& response) {
        CHECK_EQ(response.status, 500);
        CHECK_EQ(response.content_type, std::string(kJsonType));
        CHECK_EQ(response.body, expected);
        CHECK(response.headers.empty());
        parse_json(response.body);
    };
    check_failure(DashboardServiceTestAccess::handle_with(*f.service, request, [](const HttpRequest&) { throw std::bad_alloc(); }));
    check_failure(DashboardServiceTestAccess::handle_with(
        *f.service, request, [](const HttpRequest&) { throw std::runtime_error("secret internals: /etc/passwd"); }));
    check_failure(DashboardServiceTestAccess::handle_with(
        *f.service, request, [](const HttpRequest&) { throw std::out_of_range("vector::at"); }));
    check_failure(DashboardServiceTestAccess::handle_with(*f.service, request, [](const HttpRequest&) { throw 42; }));
    check_failure(DashboardServiceTestAccess::handle_with(*f.service, request, [](const HttpRequest&) { throw Secret(); }));

    // Nothing about the exception leaks, and the service keeps working afterwards.
    const HttpResponse leaky = DashboardServiceTestAccess::handle_with(
        *f.service, request, [](const HttpRequest&) { throw std::runtime_error("secret internals: /etc/passwd"); });
    CHECK(!contains(leaky.body, "secret"));
    CHECK(!contains(leaky.body, "passwd"));
    const HttpResponse fine = f.service->handle(request);
    CHECK_EQ(fine.status, 200);
    CHECK(fine.body == fetch(*f.service, "/api/summary").body);

    // The hook sees the request that is being handled, and a hook that does not throw changes nothing.
    int seen = 0;
    const HttpResponse passthrough = DashboardServiceTestAccess::handle_with(
        *f.service, request, [&seen](const HttpRequest& r) { seen += r.path == "/api/summary" ? 1 : 0; });
    CHECK_EQ(seen, 1);
    CHECK(same_response(passthrough, fine));
}

TEST(ServeFailure, EveryFailureLeavesAFreshPreparedResponseForTheNextOne) {
    // The spare is rebuilt right after it was used, while memory is there: a second failure in
    // a row (typically the same out-of-memory condition) must not have to allocate to answer.
    DashboardService service({ev(1, Level::Error, "s", "m 1")}, {});
    const std::string generic = "{\"error\":\"internal error\"}";
    auto check_spare = [&service, &generic] {
        const HttpResponse& spare = DashboardServiceTestAccess::spare(service);
        CHECK_EQ(spare.status, 500);
        CHECK_EQ(spare.content_type, std::string(kJsonType));
        CHECK_EQ(spare.body, generic);
        CHECK(spare.headers.empty());
    };
    check_spare();  // ready from the start
    const HttpRequest request = make_request("/healthz");
    for (int failure = 0; failure < 4; ++failure) {
        const HttpResponse response = DashboardServiceTestAccess::handle_with(
            service, request, [](const HttpRequest&) { throw std::bad_alloc(); });
        CHECK_EQ(response.status, 500);
        CHECK_EQ(response.content_type, std::string(kJsonType));
        CHECK_EQ(response.body, generic);
        check_spare();  // and again, right after it was handed out
    }
    CHECK_EQ(fetch(service, "/healthz").body, "ok"s);
    check_spare();  // a request that succeeds leaves it alone
}

TEST(ServeRoutes, TheReportAsksForNothingTheContentSecurityPolicyForbids) {
    // "/" carries default-src 'none' with inline styles allowed: no script, image, font, frame,
    // form, stylesheet link or @import may ever appear in the page, or the browser would drop it
    // silently. (Log text is escaped, so the entries below cannot add any either.)
    Fixture& f = fixture();
    const std::string page = fetch(*f.service, "/").body;
    CHECK(page.size() > 1000);
    for (const char* forbidden : {"<script", "<img", "<link", "<iframe", "<object", "<embed", "<form", "<base", "<audio",
                                  "<video", "<source", "<meta http-equiv", "@import", "@font-face", "src=", "url(",
                                  "javascript:", "http://", "https://", "xlink:href", "href="}) {
        if (contains_ignoring_case(page, forbidden)) throw testkit::Failure{std::string("the page contains ") + forbidden};
    }
    // With hostile log text (escaped, so it may mention "src=" as TEXT) no tag of any kind can appear.
    DashboardService hostile(hostile_entries(), hostile_alerts(), f.options);
    const std::string hostile_page = fetch(hostile, "/").body;
    for (const char* tag : {"<script", "<img", "<link", "<iframe", "<object", "<embed", "<form", "<base", "<audio", "<video",
                            "<source", "<meta http-equiv", "<a "}) {
        if (contains_ignoring_case(hostile_page, tag)) throw testkit::Failure{std::string("the hostile page contains ") + tag};
    }
}

TEST(ServeFailure, AMovedFromServiceAnswersWithAGenericFiveHundred) {
    std::vector<LogEntry> entries = {ev(1, Level::Error, "s", "m 1")};
    DashboardService original(entries, {});
    DashboardService moved(std::move(original));
    CHECK_EQ(moved.entry_count(), std::size_t{1});
    CHECK_EQ(original.entry_count(), std::size_t{0});
    CHECK_EQ(fetch_json(moved, "/api/summary").at("entries").u64(), std::uint64_t{1});

    const HttpResponse response = fetch(original, "/healthz");
    CHECK_EQ(response.status, 500);
    CHECK_EQ(response.content_type, std::string(kJsonType));
    CHECK_EQ(response.body, "{\"error\":\"internal error\"}"s);
    CHECK_EQ(fetch(original, "/healthz").body, "{\"error\":\"internal error\"}"s);  // and again

    DashboardService assigned({}, {});
    assigned = std::move(moved);
    CHECK_EQ(assigned.entry_count(), std::size_t{1});
    CHECK_EQ(fetch(assigned, "/healthz").body, "ok"s);
    CHECK_EQ(fetch(moved, "/healthz").status, 500);
}

TEST(ServeFailure, EntryCountReportsWhatWasGiven) {
    CHECK_EQ(fixture().service->entry_count(), fixture().entries.size());
    CHECK_EQ(DashboardService({}, {}).entry_count(), std::size_t{0});
    CHECK_EQ(DashboardService({ev(1, Level::Info, "s", "m"), ev(2, Level::Info, "s", "m")}, {}).entry_count(), std::size_t{2});
}
