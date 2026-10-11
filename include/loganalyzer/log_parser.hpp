#pragma once

#include <cstddef>
#include <cstdint>
#include <iosfwd>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "loganalyzer/log_entry.hpp"

namespace loganalyzer {

// ---------------------------------------------------------------------------
// Calendar arithmetic (Howard Hinnant's days-from-civil / civil-from-days).
//
// Proleptic Gregorian calendar, no time zones, no locale, no <ctime>: the C library
// conversions (mktime / timegm / gmtime / get_time) are either non-portable or depend
// on the process time zone. Both directions are O(1) and branch-light.
// ---------------------------------------------------------------------------

struct CivilDate {
    std::int64_t year;
    unsigned month;  ///< 1..12
    unsigned day;    ///< 1..31
};

constexpr bool is_leap_year(std::int64_t year) noexcept {
    return (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;  // 1900 is not leap, 2000 is
}

/// Number of days in `month` (1..12) of `year`; 0 for an invalid month.
constexpr unsigned days_in_month(std::int64_t year, unsigned month) noexcept {
    constexpr unsigned kDays[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    if (month < 1 || month > 12) return 0;
    return month == 2 && is_leap_year(year) ? 29u : kDays[month - 1];
}

/// Days since 1970-01-01 (negative before it). Precondition: a real calendar date.
/// The year is shifted so that it starts on 1 March: the leap day then ends the "year" and
/// the length of each 400-year era (146097 days) is a constant.
constexpr std::int64_t days_from_civil(std::int64_t year, unsigned month, unsigned day) noexcept {
    if (month <= 2) --year;
    const std::int64_t era = (year >= 0 ? year : year - 399) / 400;
    const unsigned yoe = static_cast<unsigned>(year - era * 400);                        // [0, 399]
    const unsigned doy = (153 * (month > 2 ? month - 3 : month + 9) + 2) / 5 + day - 1;  // [0, 365]
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;                          // [0, 146096]
    return era * 146097 + static_cast<std::int64_t>(doe) - 719468;
}

/// Inverse of days_from_civil, valid for any int64 day count that stays in range.
constexpr CivilDate civil_from_days(std::int64_t days) noexcept {
    days += 719468;
    const std::int64_t era = (days >= 0 ? days : days - 146096) / 146097;
    const unsigned doe = static_cast<unsigned>(days - era * 146097);                       // [0, 146096]
    const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;            // [0, 399]
    const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);                          // [0, 365]
    const unsigned mp = (5 * doy + 2) / 153;                                               // [0, 11]
    const unsigned day = doy - (153 * mp + 2) / 5 + 1;                                     // [1, 31]
    const unsigned month = mp < 10 ? mp + 3 : mp - 9;                                      // [1, 12]
    const std::int64_t year = static_cast<std::int64_t>(yoe) + era * 400 + (month <= 2 ? 1 : 0);
    return CivilDate{year, month, day};
}

// ---------------------------------------------------------------------------
// ISO-8601 UTC timestamps
// ---------------------------------------------------------------------------

/// Parses "YYYY-MM-DDTHH:MM:SS[.f{1,9}]Z" into milliseconds since the Unix epoch.
///
/// Strict: every digit group has its exact width, 'T' and 'Z' are mandatory and upper-case,
/// and nothing may precede or follow the text (no offsets such as "+05:30", no spaces).
/// Range checks: year 1970..9999, month 1-12, day valid for that month (leap years
/// handled: 1900 is not leap, 2000 is), hour < 24, minute < 60, second < 60 (so a leap
/// second ":60" is rejected). The fraction may have 1 to 9 digits and is truncated, not
/// rounded, to milliseconds. Returns std::nullopt for anything else; never throws.
std::optional<std::int64_t> parse_iso8601_utc(std::string_view text);

/// Always "YYYY-MM-DDTHH:MM:SS.mmmZ" (24 characters). Total function: instants before year
/// 0000 or after year 9999 are clamped to 0000-01-01T00:00:00.000Z / 9999-12-31T23:59:59.999Z,
/// and instants before 1970 are printed correctly (floor semantics) but will not parse back.
std::string format_iso8601_utc(std::int64_t epoch_ms);

// ---------------------------------------------------------------------------
// Log lines
// ---------------------------------------------------------------------------

/// Parses one line: "{timestamp} {LEVEL} {service} {message}".
///
///  * Exactly one space separates the timestamp, level, service and message. The message is
///    everything after that single space, verbatim: leading, internal and trailing spaces
///    are kept, and it may be empty. (A line that ends right after the service, with no
///    separator space, is read as an empty message, so editors that trim trailing
///    whitespace do not turn valid entries into malformed ones.)
///  * One trailing '\r' is stripped first (CRLF files). A second one belongs to the message.
///  * The level is matched case-insensitively (ASCII only, independent of the C locale).
///  * The service is non-empty and contains no whitespace.
///  * Anything else gives std::nullopt. Never throws and never reads out of bounds.
std::optional<LogEntry> parse_line(std::string_view line);

/// "{timestamp} {LEVEL} {service} {message}" with no trailing newline; an empty message
/// still gets its separating space. parse_line(format_entry(e)) == e for every entry whose
/// timestamp is in [0, 9999-12-31T23:59:59.999Z], whose service is non-empty without
/// whitespace, and whose message contains no '\n' and does not end in '\r' (the parser
/// would strip that '\r' as a CRLF line ending). Violating the preconditions does not throw.
std::string format_entry(const LogEntry& entry);

/// Reads `in` to the end and returns the parsed entries in input order.
///
/// Lines are split on '\n'. Blank lines (empty, or only spaces / tabs / '\r') are skipped
/// silently; every other line that fails parse_line is skipped and counted. If
/// `malformed_count` is non-null it is overwritten (not added to) with that count.
/// Input is consumed in large blocks and sliced with string_view, so there is no per-line
/// std::string copy before parsing.
///
/// A UTF-8 byte-order mark at the very start of the input (what Windows editors and
/// PowerShell write) is skipped; one anywhere else stays part of its line.
///
/// Stream state: reading to the end of the input is how this function stops, so on return
/// failbit is clear (unless the stream was already failed when it was passed in, in which case
/// nothing is read and it stays failed) and eofbit is set. The caller's exceptions() mask is
/// honoured for real I/O errors (badbit) only; it is suspended while reading and restored on
/// return, so a mask containing failbit or eofbit no longer makes the end of input throw
/// away every entry that was parsed. If the mask contains eofbit, eofbit is cleared on return
/// too, since leaving it set would throw while restoring the mask.
std::vector<LogEntry> parse_stream(std::istream& in, std::size_t* malformed_count = nullptr);

}  // namespace loganalyzer
