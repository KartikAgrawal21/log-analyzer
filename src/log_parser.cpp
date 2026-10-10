#include "loganalyzer/log_parser.hpp"

#include <initializer_list>
#include <istream>
#include <utility>

namespace loganalyzer {
namespace {

constexpr std::int64_t kMsPerDay = 86'400'000;
constexpr std::int64_t kMinFormattableMs = days_from_civil(0, 1, 1) * kMsPerDay;
constexpr std::int64_t kMaxFormattableMs = days_from_civil(9999, 12, 31) * kMsPerDay + (kMsPerDay - 1);

constexpr bool is_digit(char c) noexcept { return c >= '0' && c <= '9'; }

// Callers have already checked the characters, so no per-digit validation here.
constexpr unsigned digits_to_uint(const char* p, std::size_t n) noexcept {
    unsigned v = 0;
    for (std::size_t i = 0; i < n; ++i) v = v * 10 + static_cast<unsigned>(p[i] - '0');
    return v;
}

bool all_digits(std::string_view t, std::size_t pos, std::size_t n) noexcept {
    for (std::size_t i = 0; i < n; ++i) {
        if (!is_digit(t[pos + i])) return false;
    }
    return true;
}

bool has_whitespace(std::string_view s) noexcept {
    for (char c : s) {
        if (c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r') return true;
    }
    return false;
}

bool is_blank(std::string_view s) noexcept {
    for (char c : s) {
        if (c != ' ' && c != '\t' && c != '\r') return false;
    }
    return true;
}

// ASCII-only case-insensitive match against the upper-case wire names. level.hpp's
// level_from_string goes through std::toupper, which depends on the C locale (in a Turkish
// locale 'i' does not upper-case to 'I'); a log parser must not.
std::optional<Level> parse_level(std::string_view text) noexcept {
    for (Level level : {Level::Debug, Level::Info, Level::Warn, Level::Error}) {
        const std::string_view name = to_string(level);
        if (text.size() != name.size()) continue;
        bool match = true;
        for (std::size_t i = 0; i < name.size() && match; ++i) {
            const char c = text[i];
            match = c == name[i] || c == static_cast<char>(name[i] | 0x20);  // names are A-Z only
        }
        if (match) return level;
    }
    return std::nullopt;
}

void write_digits(char* out, std::uint64_t value, int width) noexcept {
    for (int i = width - 1; i >= 0; --i) {
        out[i] = static_cast<char>('0' + value % 10);
        value /= 10;
    }
}

// Writes exactly 24 characters: "YYYY-MM-DDTHH:MM:SS.mmmZ".
void write_iso8601(char* out, std::int64_t epoch_ms) noexcept {
    if (epoch_ms < kMinFormattableMs) epoch_ms = kMinFormattableMs;
    if (epoch_ms > kMaxFormattableMs) epoch_ms = kMaxFormattableMs;

    // Floor division: "-1 ms" is 23:59:59.999 of the previous day, not 00:00:00.000 + 1.
    std::int64_t days = epoch_ms / kMsPerDay;
    std::int64_t ms_of_day = epoch_ms % kMsPerDay;
    if (ms_of_day < 0) {
        ms_of_day += kMsPerDay;
        --days;
    }
    const CivilDate date = civil_from_days(days);
    const std::uint64_t second_of_day = static_cast<std::uint64_t>(ms_of_day / 1000);
    const std::uint64_t millis = static_cast<std::uint64_t>(ms_of_day % 1000);

    write_digits(out + 0, static_cast<std::uint64_t>(date.year), 4);
    out[4] = '-';
    write_digits(out + 5, date.month, 2);
    out[7] = '-';
    write_digits(out + 8, date.day, 2);
    out[10] = 'T';
    write_digits(out + 11, second_of_day / 3600, 2);
    out[13] = ':';
    write_digits(out + 14, second_of_day / 60 % 60, 2);
    out[16] = ':';
    write_digits(out + 17, second_of_day % 60, 2);
    out[19] = '.';
    write_digits(out + 20, millis, 3);
    out[23] = 'Z';
}

constexpr std::size_t kTimestampWidth = 24;

}  // namespace

std::optional<std::int64_t> parse_iso8601_utc(std::string_view t) {
    constexpr std::size_t kShortest = 20;               // "YYYY-MM-DDTHH:MM:SSZ"
    constexpr std::size_t kLongest = kShortest + 1 + 9;  // ... plus ".fffffffff"
    if (t.size() < kShortest || t.size() > kLongest) return std::nullopt;
    if (t[4] != '-' || t[7] != '-' || t[10] != 'T' || t[13] != ':' || t[16] != ':' ||
        t.back() != 'Z') {
        return std::nullopt;
    }
    if (!all_digits(t, 0, 4) || !all_digits(t, 5, 2) || !all_digits(t, 8, 2) ||
        !all_digits(t, 11, 2) || !all_digits(t, 14, 2) || !all_digits(t, 17, 2)) {
        return std::nullopt;
    }

    unsigned millis = 0;
    if (t.size() > kShortest) {
        // t[19] == '.', digits in [20, size-1), then the final 'Z'.
        const std::size_t fraction_digits = t.size() - 21;
        if (t[19] != '.' || fraction_digits < 1 || fraction_digits > 9) return std::nullopt;
        if (!all_digits(t, 20, fraction_digits)) return std::nullopt;
        // Truncate (not round) to milliseconds: take the first three digits, zero padded.
        for (std::size_t i = 0; i < 3; ++i) {
            millis = millis * 10 + (i < fraction_digits ? static_cast<unsigned>(t[20 + i] - '0') : 0u);
        }
    }

    const unsigned year = digits_to_uint(t.data(), 4);
    const unsigned month = digits_to_uint(t.data() + 5, 2);
    const unsigned day = digits_to_uint(t.data() + 8, 2);
    const unsigned hour = digits_to_uint(t.data() + 11, 2);
    const unsigned minute = digits_to_uint(t.data() + 14, 2);
    const unsigned second = digits_to_uint(t.data() + 17, 2);

    if (year < 1970) return std::nullopt;  // 9999 is the ceiling of a 4-digit year
    if (month < 1 || month > 12) return std::nullopt;
    if (day < 1 || day > days_in_month(year, month)) return std::nullopt;
    if (hour > 23 || minute > 59 || second > 59) return std::nullopt;

    const std::int64_t days = days_from_civil(year, month, day);
    const std::int64_t seconds =
        days * 86400 + static_cast<std::int64_t>(hour) * 3600 + static_cast<std::int64_t>(minute) * 60 + second;
    return seconds * 1000 + millis;
}

std::string format_iso8601_utc(std::int64_t epoch_ms) {
    char buffer[kTimestampWidth];
    write_iso8601(buffer, epoch_ms);
    return std::string(buffer, kTimestampWidth);
}

std::optional<LogEntry> parse_line(std::string_view line) {
    if (!line.empty() && line.back() == '\r') line.remove_suffix(1);

    // Field boundaries are located with three finds; nothing is copied until the whole line
    // has been validated, so a malformed line costs no allocation.
    const std::size_t first_space = line.find(' ');
    if (first_space == std::string_view::npos) return std::nullopt;
    const std::optional<std::int64_t> timestamp = parse_iso8601_utc(line.substr(0, first_space));
    if (!timestamp) return std::nullopt;

    const std::size_t second_space = line.find(' ', first_space + 1);
    if (second_space == std::string_view::npos) return std::nullopt;
    const std::optional<Level> level =
        parse_level(line.substr(first_space + 1, second_space - first_space - 1));
    if (!level) return std::nullopt;

    const std::size_t third_space = line.find(' ', second_space + 1);
    const bool has_message_separator = third_space != std::string_view::npos;
    const std::string_view service =
        has_message_separator ? line.substr(second_space + 1, third_space - second_space - 1)
                              : line.substr(second_space + 1);
    if (service.empty() || has_whitespace(service)) return std::nullopt;
    const std::string_view message =
        has_message_separator ? line.substr(third_space + 1) : std::string_view();

    std::optional<LogEntry> result(std::in_place);
    result->timestamp_ms = *timestamp;
    result->level = *level;
    result->service.assign(service.data(), service.size());
    result->message.assign(message.data(), message.size());
    return result;
}

std::string format_entry(const LogEntry& entry) {
    const std::string_view level = to_string(entry.level);
    std::string out;
    out.reserve(kTimestampWidth + 1 + level.size() + 1 + entry.service.size() + 1 +
                entry.message.size());
    char timestamp[kTimestampWidth];
    write_iso8601(timestamp, entry.timestamp_ms);
    out.append(timestamp, kTimestampWidth);
    out.push_back(' ');
    out.append(level.data(), level.size());
    out.push_back(' ');
    out.append(entry.service);
    out.push_back(' ');
    out.append(entry.message);
    return out;
}

std::vector<LogEntry> parse_stream(std::istream& in, std::size_t* malformed_count) {
    std::vector<LogEntry> entries;
    std::size_t malformed = 0;

    auto handle_line = [&](std::string_view line) {
        if (is_blank(line)) return;
        std::optional<LogEntry> entry = parse_line(line);
        if (entry) {
            entries.push_back(std::move(*entry));
        } else {
            ++malformed;
        }
    };

    // std::getline is a character-at-a-time loop on some standard libraries. Reading
    // 64 KiB blocks and splitting with find('\n') is several times faster on a 1M-line file;
    // only a line that straddles two blocks is copied (into `carry`).
    constexpr std::size_t kBlock = 64 * 1024;
    std::vector<char> block(kBlock);
    std::string carry;
    while (true) {
        in.read(block.data(), static_cast<std::streamsize>(block.size()));
        const std::streamsize got = in.gcount();
        if (got <= 0) break;

        std::string_view rest(block.data(), static_cast<std::size_t>(got));
        while (!rest.empty()) {
            const std::size_t newline = rest.find('\n');
            if (newline == std::string_view::npos) {
                carry.append(rest.data(), rest.size());
                break;
            }
            if (carry.empty()) {
                handle_line(rest.substr(0, newline));
            } else {
                carry.append(rest.data(), newline);
                handle_line(carry);
                carry.clear();
            }
            rest.remove_prefix(newline + 1);
        }
        if (!in) break;  // short read: end of input
    }
    if (!carry.empty()) handle_line(carry);  // last line without a trailing '\n'

    if (malformed_count != nullptr) *malformed_count = malformed;
    return entries;
}

}  // namespace loganalyzer
