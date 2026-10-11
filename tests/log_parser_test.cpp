#include <cstddef>
#include <cstdint>
#include <optional>
#include <random>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "loganalyzer/log_parser.hpp"
#include "testkit.hpp"

using namespace loganalyzer;

namespace {

constexpr std::int64_t kMaxMs = 253402300799999;  // 9999-12-31T23:59:59.999Z

// --- Reference implementations: deliberately naive and structured differently from the
// --- library (cursor-based grammar reader, year-by-year day counting).

bool ref_leap(int y) { return y % 4 == 0 && (y % 100 != 0 || y % 400 == 0); }

int ref_days_in_month(int y, int m) {
    static const int d[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    return (m == 2 && ref_leap(y)) ? 29 : d[m - 1];
}

// days_before_year[y] = days from 1970-01-01 to y-01-01, built by walking year by year.
const std::vector<std::int64_t>& days_before_year() {
    static const std::vector<std::int64_t> table = [] {
        std::vector<std::int64_t> t(10000, 0);
        std::int64_t days = 0;
        for (int y = 1970; y <= 9999; ++y) {
            t[static_cast<std::size_t>(y)] = days;
            days += ref_leap(y) ? 366 : 365;
        }
        return t;
    }();
    return table;
}

std::int64_t ref_epoch_ms(int y, int mo, int d, int h, int mi, int s, int ms) {
    std::int64_t days = days_before_year()[static_cast<std::size_t>(y)];
    for (int m = 1; m < mo; ++m) days += ref_days_in_month(y, m);
    days += d - 1;
    return (((days * 24 + h) * 60 + mi) * 60 + s) * 1000 + ms;
}

struct Cursor {
    std::string_view text;
    std::size_t pos = 0;
    bool ok = true;

    int digits(std::size_t count) {
        int v = 0;
        for (std::size_t i = 0; i < count; ++i) {
            if (pos >= text.size() || text[pos] < '0' || text[pos] > '9') {
                ok = false;
                return 0;
            }
            v = v * 10 + (text[pos] - '0');
            ++pos;
        }
        return v;
    }
    void expect(char c) {
        if (pos >= text.size() || text[pos] != c) {
            ok = false;
            return;
        }
        ++pos;
    }
};

std::optional<std::int64_t> ref_parse_iso(std::string_view text) {
    Cursor c{text};
    const int y = c.digits(4);
    c.expect('-');
    const int mo = c.digits(2);
    c.expect('-');
    const int d = c.digits(2);
    c.expect('T');
    const int h = c.digits(2);
    c.expect(':');
    const int mi = c.digits(2);
    c.expect(':');
    const int s = c.digits(2);
    int ms = 0;
    if (c.ok && c.pos < text.size() && text[c.pos] == '.') {
        ++c.pos;
        std::size_t n = 0;
        while (c.pos < text.size() && text[c.pos] >= '0' && text[c.pos] <= '9') {
            if (n < 3) ms = ms * 10 + (text[c.pos] - '0');
            ++n;
            ++c.pos;
        }
        if (n < 1 || n > 9) return std::nullopt;
        for (std::size_t i = n; i < 3; ++i) ms *= 10;
    }
    c.expect('Z');
    if (!c.ok || c.pos != text.size()) return std::nullopt;
    if (y < 1970 || mo < 1 || mo > 12) return std::nullopt;
    if (d < 1 || d > ref_days_in_month(y, mo)) return std::nullopt;
    if (h > 23 || mi > 59 || s > 59) return std::nullopt;
    return ref_epoch_ms(y, mo, d, h, mi, s, ms);
}

std::optional<LogEntry> ref_parse_line(std::string line) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    // positions of the first three single spaces
    std::size_t sp[3];
    std::size_t found = 0;
    for (std::size_t i = 0; i < line.size() && found < 3; ++i) {
        if (line[i] == ' ') sp[found++] = i;
    }
    if (found < 2) return std::nullopt;
    const auto ts = ref_parse_iso(line.substr(0, sp[0]));
    if (!ts) return std::nullopt;
    std::string level_text = line.substr(sp[0] + 1, sp[1] - sp[0] - 1);
    for (char& ch : level_text) {
        if (ch >= 'a' && ch <= 'z') ch = static_cast<char>(ch - 'a' + 'A');
    }
    Level level;
    if (level_text == "DEBUG") level = Level::Debug;
    else if (level_text == "INFO") level = Level::Info;
    else if (level_text == "WARN") level = Level::Warn;
    else if (level_text == "ERROR") level = Level::Error;
    else return std::nullopt;

    std::string service;
    std::string message;
    if (found == 3) {
        service = line.substr(sp[1] + 1, sp[2] - sp[1] - 1);
        message = line.substr(sp[2] + 1);
    } else {
        service = line.substr(sp[1] + 1);
    }
    if (service.empty()) return std::nullopt;
    for (char ch : service) {
        if (ch == '\t' || ch == '\n' || ch == '\v' || ch == '\f' || ch == '\r') return std::nullopt;
    }
    LogEntry e;
    e.timestamp_ms = *ts;
    e.level = level;
    e.service = service;
    e.message = message;
    return e;
}

[[noreturn]] void fail_at_day(const char* what, std::int64_t day) {
    throw testkit::Failure{std::string(what) + " at day number " + std::to_string(day)};
}

std::string random_text(std::mt19937_64& rng, std::size_t max_len, const std::string& alphabet) {
    const std::size_t n = static_cast<std::size_t>(rng() % (max_len + 1));
    std::string s;
    for (std::size_t i = 0; i < n; ++i) s.push_back(alphabet[rng() % alphabet.size()]);
    return s;
}

LogEntry random_entry(std::mt19937_64& rng) {
    static const std::string service_chars = "abcdefghijklmnopqrstuvwxyz0123456789-_.:/";
    // Messages: spaces (leading, internal, trailing), tabs, punctuation, UTF-8 bytes, NUL.
    static const std::string message_chars =
        std::string("abcXYZ019 ,.;:!?-_/\\\"'()[]{}=+*&%$#@\t   ") + "\xC3\xA9\xE2\x82\xAC" + std::string(1, '\0');
    LogEntry e;
    e.timestamp_ms = static_cast<std::int64_t>(rng() % static_cast<std::uint64_t>(kMaxMs + 1));
    e.level = static_cast<Level>(rng() % 4);
    e.service = random_text(rng, 20, service_chars);
    if (e.service.empty()) e.service = "s";
    e.message = random_text(rng, 80, message_chars);
    return e;
}

}  // namespace

// ---------------------------------------------------------------------------
// Calendar arithmetic
// ---------------------------------------------------------------------------

static_assert(days_from_civil(1970, 1, 1) == 0, "epoch");
static_assert(days_from_civil(2026, 10, 10) == 20736, "2026-10-10");
static_assert(civil_from_days(0).year == 1970 && civil_from_days(0).month == 1 && civil_from_days(0).day == 1,
              "epoch inverse");
static_assert(is_leap_year(2000) && !is_leap_year(1900) && is_leap_year(2024) && !is_leap_year(2100),
              "leap rule");

TEST(LogParser, CivilKnownDayNumbers) {
    CHECK_EQ(days_from_civil(1969, 12, 31), std::int64_t{-1});
    CHECK_EQ(days_from_civil(2000, 3, 1), std::int64_t{11017});
    CHECK_EQ(days_from_civil(1900, 3, 1), std::int64_t{-25508});
    CHECK_EQ(days_from_civil(1, 1, 1), std::int64_t{-719162});
    CHECK_EQ(days_from_civil(1, 3, 1), std::int64_t{-719103});
    CHECK_EQ(days_from_civil(400, 2, 29), std::int64_t{-573372});
    CHECK_EQ(days_from_civil(9999, 12, 31), std::int64_t{2932896});
    CHECK_EQ(days_from_civil(2000, 3, 1) - days_from_civil(2000, 2, 28), std::int64_t{2});  // leap year
    CHECK_EQ(days_from_civil(1900, 3, 1) - days_from_civil(1900, 2, 28), std::int64_t{1});  // not leap
}

TEST(LogParser, CivilLeapYearRule) {
    for (int y : {1600, 2000, 2004, 2024, 2400}) CHECK(is_leap_year(y));
    for (int y : {1700, 1800, 1900, 2001, 2023, 2100, 2200, 2300}) CHECK(!is_leap_year(y));
    CHECK_EQ(days_in_month(2000, 2), 29u);
    CHECK_EQ(days_in_month(1900, 2), 28u);
    CHECK_EQ(days_in_month(2026, 4), 30u);
    CHECK_EQ(days_in_month(2026, 12), 31u);
    CHECK_EQ(days_in_month(2026, 0), 0u);
    CHECK_EQ(days_in_month(2026, 13), 0u);
}

// Walks every calendar day from year 0 to year 9999 one at a time (naive increment with
// month lengths) and checks both conversion directions against that walk.
TEST(LogParser, CivilMatchesDayByDayWalk) {
    std::int64_t year = 1970;
    unsigned month = 1;
    unsigned day = 1;
    for (std::int64_t n = 0; year <= 9999; ++n) {
        const CivilDate c = civil_from_days(n);
        if (c.year != year || c.month != month || c.day != day) fail_at_day("civil_from_days mismatch", n);
        if (days_from_civil(year, month, day) != n) fail_at_day("days_from_civil mismatch", n);
        if (++day > days_in_month(year, month)) {
            day = 1;
            if (++month > 12) {
                month = 1;
                ++year;
            }
        }
    }
    // and backwards from 1969-12-31 down to 0000-01-01
    year = 1969;
    month = 12;
    day = 31;
    for (std::int64_t n = -1; year >= 0; --n) {
        const CivilDate c = civil_from_days(n);
        if (c.year != year || c.month != month || c.day != day) fail_at_day("civil_from_days mismatch", n);
        if (days_from_civil(year, month, day) != n) fail_at_day("days_from_civil mismatch", n);
        if (--day < 1) {
            if (--month < 1) {
                month = 12;
                --year;
            }
            day = days_in_month(year, month);
        }
    }
}

// ---------------------------------------------------------------------------
// parse_iso8601_utc / format_iso8601_utc
// ---------------------------------------------------------------------------

TEST(LogParser, Iso8601KnownEpochValues) {
    // Expected values computed independently with Python's datetime.
    struct Known {
        const char* text;
        std::int64_t ms;
    };
    const Known known[] = {
        {"1970-01-01T00:00:00Z", 0},
        {"1970-01-01T00:00:00.000Z", 0},
        {"1970-01-01T00:00:00.001Z", 1},
        {"1970-01-01T00:00:01Z", 1000},
        {"1972-02-29T00:00:00Z", 68169600000},
        {"1999-12-31T23:59:59Z", 946684799000},
        {"1999-12-31T23:59:59.999Z", 946684799999},
        {"2000-02-29T12:34:56Z", 951827696000},
        {"2000-03-01T00:00:00Z", 951868800000},
        {"2001-09-09T01:46:40Z", 1000000000000},
        {"2024-02-29T00:00:00Z", 1709164800000},
        {"2026-10-10T00:00:00Z", 1791590400000},
        {"2026-10-10T12:00:00.123Z", 1791633600123},
        {"2038-01-19T03:14:07Z", 2147483647000},
        {"2100-03-01T00:00:00Z", 4107542400000},
        {"2262-04-11T23:47:16Z", 9223372036000},
        {"3000-01-01T00:00:00Z", 32503680000000},
        {"9999-12-31T23:59:59.999Z", kMaxMs},
    };
    for (const Known& k : known) {
        const auto parsed = parse_iso8601_utc(k.text);
        CHECK(parsed.has_value());
        CHECK_EQ(*parsed, k.ms);
    }
}

TEST(LogParser, Iso8601FractionIsTruncatedToMilliseconds) {
    const std::int64_t base = 1791590400000;  // 2026-10-10T00:00:00Z
    struct Case {
        const char* fraction;
        int ms;
    };
    const Case cases[] = {{"0", 0},          {"5", 500},       {"05", 50},          {"005", 5},
                          {"0005", 0},       {"12", 120},      {"123", 123},        {"1239", 123},
                          {"9999", 999},     {"0019", 1},      {"123456", 123},     {"1234567", 123},
                          {"12345678", 123}, {"123456789", 123}, {"999999999", 999}, {"000000001", 0}};
    for (const Case& c : cases) {
        const std::string text = std::string("2026-10-10T00:00:00.") + c.fraction + "Z";
        const auto parsed = parse_iso8601_utc(text);
        CHECK(parsed.has_value());
        CHECK_EQ(*parsed, base + c.ms);
    }
}

TEST(LogParser, Iso8601RejectsMalformedText) {
    const char* bad[] = {
        "",
        "Z",
        "2026-10-10",
        "2026-10-10T00:00:00",       // no Z
        "2026-10-10T00:00Z",         // no seconds
        "2026-10-10T00:00:00z",      // lower-case z
        "2026-10-10t00:00:00Z",      // lower-case t
        "2026-10-10 00:00:00Z",      // space instead of T
        "2026-10-10T00:00:00+00:00", // offsets are not accepted, even zero
        "2026-10-10T00:00:00+05:30",
        "2026-10-10T05:30:00+05:30",
        "2026-10-10T00:00:00-08:00",
        "2026-10-10T00:00:00ZZ",     // trailing garbage
        "2026-10-10T00:00:00Z ",
        " 2026-10-10T00:00:00Z",
        "2026-10-10T00:00:00Z\n",
        "2026-10-10T00:00:00.Z",     // dot without digits
        "2026-10-10T00:00:00.1234567890Z",  // ten fraction digits
        "2026-10-10T00:00:00.12a4Z",
        "2026-10-10T00:00:00,123Z",  // comma decimal separator
        "2026/10/10T00:00:00Z",
        "2026-10-10T00-00-00Z",
        "26-10-10T00:00:00Z",        // two-digit year
        "02026-10-10T00:00:00Z",
        "2026-1-10T00:00:00Z",       // unpadded fields
        "2026-10-1T00:00:00Z",
        "2026-10-10T0:00:00Z",
        "2026-10-10T00:00:0Z",
        "2026-1a-10T00:00:00Z",
        "+026-10-10T00:00:00Z",
        "2026-10-10T00:00:00.123",
        "2026-10-10T24:00:00Z",      // hour 24
        "2026-10-10T00:60:00Z",      // minute 60
        "2026-10-10T00:00:60Z",      // second 60 (leap second) is rejected
        "2026-10-10T00:00:99Z",
        "2026-00-10T00:00:00Z",      // month 0
        "2026-13-10T00:00:00Z",      // month 13
        "2026-10-00T00:00:00Z",      // day 0
        "2026-10-32T00:00:00Z",
        "2026-04-31T00:00:00Z",      // April has 30 days
        "2026-02-29T00:00:00Z",      // 2026 is not a leap year
        "2023-02-29T00:00:00Z",
        "1900-02-29T00:00:00Z",      // divisible by 100, not by 400
        "2100-02-29T00:00:00Z",
        "2026-02-30T00:00:00Z",
        "1969-12-31T23:59:59Z",      // before the epoch
        "1000-01-01T00:00:00Z",
        "0000-01-01T00:00:00Z",
    };
    for (const char* text : bad) CHECK(!parse_iso8601_utc(text).has_value());

    const std::string with_nul("2026-10-10T00:00:00Z\0", 21);
    CHECK(!parse_iso8601_utc(with_nul).has_value());
    const std::string nul_inside("2026-10-10T00:00\0" "00Z", 20);
    CHECK(!parse_iso8601_utc(nul_inside).has_value());
}

TEST(LogParser, Iso8601AcceptsBoundaryDates) {
    for (const char* text : {
             "2000-02-29T00:00:00Z",  // divisible by 400: leap
             "2024-02-29T23:59:59.999Z", "2026-12-31T23:59:59Z", "2026-01-31T00:00:00Z",
             "2026-04-30T00:00:00Z", "2026-02-28T00:00:00Z", "1970-01-01T00:00:00Z",
             "9999-12-31T23:59:59Z", "2026-10-10T23:00:59.5Z", "2026-10-10T00:59:00Z"}) {
        CHECK(parse_iso8601_utc(text).has_value());
    }
    // 1970 itself is valid, one second earlier is not
    CHECK(parse_iso8601_utc("1970-01-01T00:00:00Z").has_value());
    CHECK(!parse_iso8601_utc("1969-12-31T23:59:59.999Z").has_value());
}

TEST(LogParser, Iso8601FormatKnownValues) {
    CHECK_EQ(format_iso8601_utc(0), std::string("1970-01-01T00:00:00.000Z"));
    CHECK_EQ(format_iso8601_utc(1), std::string("1970-01-01T00:00:00.001Z"));
    CHECK_EQ(format_iso8601_utc(1791590400000), std::string("2026-10-10T00:00:00.000Z"));
    CHECK_EQ(format_iso8601_utc(1791633600123), std::string("2026-10-10T12:00:00.123Z"));
    CHECK_EQ(format_iso8601_utc(951827696000), std::string("2000-02-29T12:34:56.000Z"));
    CHECK_EQ(format_iso8601_utc(2147483647999), std::string("2038-01-19T03:14:07.999Z"));
    CHECK_EQ(format_iso8601_utc(kMaxMs), std::string("9999-12-31T23:59:59.999Z"));
}

TEST(LogParser, Iso8601FormatIsAlways24Characters) {
    std::mt19937_64 rng(7);
    for (int i = 0; i < 2000; ++i) {
        const std::int64_t ms = static_cast<std::int64_t>(rng() % static_cast<std::uint64_t>(kMaxMs + 1));
        const std::string s = format_iso8601_utc(ms);
        CHECK_EQ(s.size(), std::size_t{24});
        CHECK(s[4] == '-' && s[7] == '-' && s[10] == 'T' && s[13] == ':' && s[16] == ':' &&
              s[19] == '.' && s[23] == 'Z');
    }
}

TEST(LogParser, Iso8601FormatBeforeEpochUsesFloorSemantics) {
    CHECK_EQ(format_iso8601_utc(-1), std::string("1969-12-31T23:59:59.999Z"));
    CHECK_EQ(format_iso8601_utc(-1000), std::string("1969-12-31T23:59:59.000Z"));
    CHECK_EQ(format_iso8601_utc(-86400000), std::string("1969-12-31T00:00:00.000Z"));
    CHECK_EQ(format_iso8601_utc(-86400001), std::string("1969-12-30T23:59:59.999Z"));
    // Printed correctly, but the parser only accepts 1970 and later.
    CHECK(!parse_iso8601_utc(format_iso8601_utc(-1)).has_value());
}

TEST(LogParser, Iso8601FormatClampsOutOfRangeInstants) {
    CHECK_EQ(format_iso8601_utc(kMaxMs + 1), std::string("9999-12-31T23:59:59.999Z"));
    CHECK_EQ(format_iso8601_utc(INT64_MAX), std::string("9999-12-31T23:59:59.999Z"));
    CHECK_EQ(format_iso8601_utc(INT64_MIN), std::string("0000-01-01T00:00:00.000Z"));
    CHECK_EQ(format_iso8601_utc(-62167219200000), std::string("0000-01-01T00:00:00.000Z"));
    CHECK_EQ(format_iso8601_utc(-62167219200001), std::string("0000-01-01T00:00:00.000Z"));
}

TEST(LogParser, Iso8601RoundTripsRandomInstants) {
    std::mt19937_64 rng(2026);
    for (int i = 0; i < 100000; ++i) {
        // Mix of whole range and "recent" instants; plus exact day boundaries.
        std::int64_t ms = (i % 3 == 0) ? static_cast<std::int64_t>(rng() % static_cast<std::uint64_t>(kMaxMs + 1))
                                       : 1700000000000 + static_cast<std::int64_t>(rng() % 200000000000ULL);
        if (i % 7 == 0) ms -= ms % 86400000;
        const std::string text = format_iso8601_utc(ms);
        const auto back = parse_iso8601_utc(text);
        CHECK(back.has_value());
        CHECK_EQ(*back, ms);
    }
    for (std::int64_t day = 0; day < 40000; ++day) {  // every midnight and last millisecond, 1970..2079
        for (std::int64_t ms : {day * 86400000, day * 86400000 + 86399999}) {
            const auto back = parse_iso8601_utc(format_iso8601_utc(ms));
            CHECK(back.has_value());
            CHECK_EQ(*back, ms);
        }
    }
}

TEST(LogParser, Iso8601MatchesNaiveReferenceOnRandomFields) {
    std::mt19937_64 rng(99);
    auto pad = [](std::uint64_t v, int width) {
        std::string s = std::to_string(v);
        while (static_cast<int>(s.size()) < width) s.insert(s.begin(), '0');
        return s;
    };
    for (int i = 0; i < 60000; ++i) {
        // Fields drawn from a range slightly wider than valid, so invalid dates are common.
        const int year = 1965 + static_cast<int>(rng() % 8100);
        const int month = static_cast<int>(rng() % 14);
        const int day = static_cast<int>(rng() % 33);
        const int hour = static_cast<int>(rng() % 26);
        const int minute = static_cast<int>(rng() % 62);
        const int second = static_cast<int>(rng() % 62);
        std::string text = pad(static_cast<std::uint64_t>(year), 4) + "-" + pad(static_cast<std::uint64_t>(month), 2) + "-" +
                           pad(static_cast<std::uint64_t>(day), 2) + "T" + pad(static_cast<std::uint64_t>(hour), 2) + ":" +
                           pad(static_cast<std::uint64_t>(minute), 2) + ":" + pad(static_cast<std::uint64_t>(second), 2);
        if (rng() % 2 == 0) {
            text += ".";
            const std::size_t digits = static_cast<std::size_t>(rng() % 12);  // 0 and >9 digits are invalid
            for (std::size_t k = 0; k < digits; ++k) text.push_back(static_cast<char>('0' + rng() % 10));
        }
        text += "Z";
        const auto expected = ref_parse_iso(text);
        const auto actual = parse_iso8601_utc(text);
        CHECK(expected == actual);
    }
}

TEST(LogParser, Iso8601MutatedTextMatchesReference) {
    std::mt19937_64 rng(1234);
    static const std::string alphabet = "0123456789-:TZtz.+ \n,/";
    const std::string seeds[] = {"2026-10-10T12:34:56Z", "2026-10-10T12:34:56.789Z", "2000-02-29T00:00:00.1Z",
                                 "9999-12-31T23:59:59.999999999Z"};
    int accepted = 0;
    for (int i = 0; i < 80000; ++i) {
        std::string s = seeds[rng() % 4];
        const int edits = 1 + static_cast<int>(rng() % 3);
        for (int e = 0; e < edits; ++e) {
            switch (rng() % 4) {
                case 0: s[rng() % s.size()] = alphabet[rng() % alphabet.size()]; break;
                case 1: if (s.size() > 1) s.erase(rng() % s.size(), 1); break;
                case 2: s.insert(rng() % (s.size() + 1), 1, alphabet[rng() % alphabet.size()]); break;
                default: s.resize(rng() % (s.size() + 1)); break;
            }
            if (s.empty()) s = "Z";
        }
        const auto expected = ref_parse_iso(s);
        const auto actual = parse_iso8601_utc(s);
        CHECK(expected == actual);
        if (actual) ++accepted;
    }
    CHECK(accepted > 1000);  // the mutation mix really exercises the accepting path too
}

// ---------------------------------------------------------------------------
// parse_line
// ---------------------------------------------------------------------------

TEST(LogParser, ParseLineReadmeExample) {
    const auto e = parse_line("2026-10-10T12:00:00.123Z ERROR payment-service Timeout calling bank gateway after 3000ms");
    CHECK(e.has_value());
    CHECK_EQ(e->timestamp_ms, std::int64_t{1791633600123});
    CHECK(e->level == Level::Error);
    CHECK_EQ(e->service, std::string("payment-service"));
    CHECK_EQ(e->message, std::string("Timeout calling bank gateway after 3000ms"));
}

TEST(LogParser, ParseLineLevelsAreCaseInsensitive) {
    struct Case {
        const char* level;
        Level expected;
    };
    const Case cases[] = {{"DEBUG", Level::Debug}, {"debug", Level::Debug}, {"Debug", Level::Debug},
                          {"INFO", Level::Info},   {"info", Level::Info},   {"iNfO", Level::Info},
                          {"WARN", Level::Warn},   {"warn", Level::Warn},   {"Warn", Level::Warn},
                          {"ERROR", Level::Error}, {"error", Level::Error}, {"eRRoR", Level::Error}};
    for (const Case& c : cases) {
        const auto e = parse_line(std::string("2026-10-10T00:00:00Z ") + c.level + " svc hello");
        CHECK(e.has_value());
        CHECK(e->level == c.expected);
    }
}

TEST(LogParser, ParseLineRejectsUnknownLevels) {
    for (const char* level : {"TRACE", "FATAL", "WARNING", "ERR", "INF", "INFOO", "DEBU", "", "0", "ERROR1",
                              "\xC3\x89RROR", "INF\xC3\x98"}) {
        const auto e = parse_line(std::string("2026-10-10T00:00:00Z ") + level + " svc hello");
        CHECK(!e.has_value());
    }
}

TEST(LogParser, ParseLineKeepsMessageVerbatim) {
    const std::string prefix = "2026-10-10T00:00:00Z INFO svc ";
    const std::string messages[] = {
        "plain",
        "two  spaces   inside",
        " leading space",
        "  two leading spaces",
        "trailing space ",
        "trailing spaces   ",
        "tab\tinside\t",
        "looks like a line 2026-10-10T00:00:00Z ERROR other-service boom",
        "key=value other=\"quoted text\" {json: [1,2,3]}",
        "unicode \xC3\xA9\xE2\x82\xAC\xF0\x9F\x98\x80 bytes",
        "carriage\rreturn inside",
        "x",
    };
    for (const std::string& m : messages) {
        const auto e = parse_line(prefix + m);
        CHECK(e.has_value());
        CHECK_EQ(e->message, m);
        CHECK_EQ(e->service, std::string("svc"));
    }
    // embedded NUL survives
    const std::string with_nul = std::string("a\0b", 3);
    const auto e = parse_line(prefix + with_nul);
    CHECK(e.has_value());
    CHECK_EQ(e->message, with_nul);
}

TEST(LogParser, ParseLineEmptyMessage) {
    // With the separating space (what format_entry writes) ...
    const auto with_space = parse_line("2026-10-10T00:00:00Z INFO svc ");
    CHECK(with_space.has_value());
    CHECK_EQ(with_space->message, std::string());
    // ... and with trailing whitespace trimmed away by an editor.
    const auto trimmed = parse_line("2026-10-10T00:00:00Z INFO svc");
    CHECK(trimmed.has_value());
    CHECK_EQ(trimmed->message, std::string());
    CHECK_EQ(trimmed->service, std::string("svc"));
    // Two spaces: the message is a single space.
    const auto one_space = parse_line("2026-10-10T00:00:00Z INFO svc  ");
    CHECK(one_space.has_value());
    CHECK_EQ(one_space->message, std::string(" "));
}

TEST(LogParser, ParseLineStripsExactlyOneTrailingCarriageReturn) {
    const auto crlf = parse_line("2026-10-10T00:00:00Z WARN svc disk almost full\r");
    CHECK(crlf.has_value());
    CHECK_EQ(crlf->message, std::string("disk almost full"));

    const auto two = parse_line("2026-10-10T00:00:00Z WARN svc disk\r\r");
    CHECK(two.has_value());
    CHECK_EQ(two->message, std::string("disk\r"));

    const auto empty_crlf = parse_line("2026-10-10T00:00:00Z WARN svc \r");
    CHECK(empty_crlf.has_value());
    CHECK_EQ(empty_crlf->message, std::string());

    const auto trimmed_crlf = parse_line("2026-10-10T00:00:00Z WARN svc\r");
    CHECK(trimmed_crlf.has_value());
    CHECK_EQ(trimmed_crlf->service, std::string("svc"));

    CHECK(!parse_line("\r").has_value());
    CHECK(!parse_line("2026-10-10T00:00:00Z WARN\r").has_value());
}

TEST(LogParser, ParseLineRejectsMalformedLines) {
    const char* bad[] = {
        "",
        " ",
        "\r",
        "garbage",
        "2026-10-10T00:00:00Z",
        "2026-10-10T00:00:00Z ",
        "2026-10-10T00:00:00Z INFO",
        "2026-10-10T00:00:00Z INFO ",
        "2026-10-10T00:00:00Z  INFO svc msg",      // two spaces: empty level field
        "2026-10-10T00:00:00Z INFO  svc msg",      // two spaces: empty service field
        "2026-10-10T00:00:00Z INFO  ",
        " 2026-10-10T00:00:00Z INFO svc msg",      // leading space
        "2026-10-10T00:00:00Z\tINFO svc msg",      // tab separator
        "2026-10-10T00:00:00Z INFO\tsvc msg",
        "2026-10-10T00:00:00Z INFO svc\tmsg",      // service would contain a tab
        "2026-10-10T00:00:00Z INFO sv\tc msg",
        "2026-10-10T00:00:00Z INFO svc\fmsg",
        "2026-10-10T00:00:00 INFO svc msg",        // timestamp without Z
        "2026-10-10T00:00:00+01:00 INFO svc msg",
        "2026-10-10 00:00:00Z INFO svc msg",       // space inside the timestamp
        "2026-13-10T00:00:00Z INFO svc msg",
    };
    for (const char* line : bad) CHECK(!parse_line(line).has_value());
}

TEST(LogParser, ParseLineNeverReadsOutOfBoundsOnTruncatedInput) {
    const std::string line = "2026-10-10T12:00:00.123Z ERROR payment-service Timeout calling bank";
    const std::size_t level_end = line.find(' ', line.find(' ') + 1);
    const std::size_t service_start = level_end + 1;
    const std::size_t service_end = line.find(' ', service_start);
    const std::size_t message_start = service_end + 1;
    for (std::size_t len = 0; len <= line.size(); ++len) {
        // Hand each prefix over as an exact-size heap copy so ASan sees any overread.
        const std::string prefix = line.substr(0, len);
        const auto e = parse_line(std::string_view(prefix.data(), prefix.size()));
        if (len <= service_start) {
            CHECK(!e.has_value());  // timestamp, level or the first service character is missing
        } else {
            CHECK(e.has_value());
            const std::size_t service_len = (len < service_end ? len : service_end) - service_start;
            CHECK_EQ(e->service, line.substr(service_start, service_len));
            CHECK_EQ(e->message, len <= message_start ? std::string() : line.substr(message_start, len - message_start));
        }
    }
}

TEST(LogParser, ParseLineMatchesReferenceOnMutatedLines) {
    std::mt19937_64 rng(31337);
    static const std::string alphabet = "ABCabc019 -:.TZ\t\r\n";
    int accepted = 0;
    int rejected = 0;
    for (int i = 0; i < 60000; ++i) {
        std::string s = format_entry(random_entry(rng));
        const int edits = static_cast<int>(rng() % 4);  // 0 edits keeps some lines valid
        for (int e = 0; e < edits; ++e) {
            switch (rng() % 4) {
                case 0: s[rng() % s.size()] = alphabet[rng() % alphabet.size()]; break;
                case 1: if (s.size() > 1) s.erase(rng() % s.size(), 1); break;
                case 2: s.insert(rng() % (s.size() + 1), 1, alphabet[rng() % alphabet.size()]); break;
                default: s.resize(rng() % (s.size() + 1)); break;
            }
            if (s.empty()) s = " ";
        }
        const auto expected = ref_parse_line(s);
        const auto actual = parse_line(s);
        CHECK(expected == actual);
        if (actual) {
            ++accepted;
        } else {
            ++rejected;
        }
    }
    CHECK(accepted > 5000);
    CHECK(rejected > 5000);
}

// ---------------------------------------------------------------------------
// format_entry
// ---------------------------------------------------------------------------

TEST(LogParser, FormatEntryProducesWireFormat) {
    LogEntry e;
    e.timestamp_ms = 1791633600123;
    e.level = Level::Error;
    e.service = "payment-service";
    e.message = "Timeout calling bank gateway after 3000ms";
    CHECK_EQ(format_entry(e),
             std::string("2026-10-10T12:00:00.123Z ERROR payment-service Timeout calling bank gateway after 3000ms"));

    e.message.clear();
    CHECK_EQ(format_entry(e), std::string("2026-10-10T12:00:00.123Z ERROR payment-service "));
    e.level = Level::Debug;
    e.message = " padded  message ";
    CHECK_EQ(format_entry(e), std::string("2026-10-10T12:00:00.123Z DEBUG payment-service  padded  message "));
}

TEST(LogParser, FormatEntryAndParseLineRoundTripOnRandomEntries) {
    std::mt19937_64 rng(555);
    for (int i = 0; i < 50000; ++i) {
        const LogEntry e = random_entry(rng);
        const std::string line = format_entry(e);
        CHECK(line.find('\n') == std::string::npos);
        const auto back = parse_line(line);
        CHECK(back.has_value());
        CHECK(*back == e);
        CHECK_EQ(format_entry(*back), line);  // and the text is a fixed point as well
    }
}

TEST(LogParser, FormatEntryRoundTripEdgeCases) {
    const std::string messages[] = {"", " ", "  ", "a", " a", "a ", "\t", std::string(1000, 'x'),
                                    std::string(300, ' '), "\xE2\x82\xAC"};
    for (std::int64_t ts : {std::int64_t{0}, std::int64_t{1}, std::int64_t{999}, std::int64_t{86399999}, kMaxMs}) {
        for (Level level : {Level::Debug, Level::Info, Level::Warn, Level::Error}) {
            for (const std::string& m : messages) {
                LogEntry e;
                e.timestamp_ms = ts;
                e.level = level;
                e.service = "s";
                e.message = m;
                const auto back = parse_line(format_entry(e));
                CHECK(back.has_value());
                CHECK(*back == e);
            }
        }
    }
}

TEST(LogParser, FormatEntryDocumentedLimitationTrailingCarriageReturn) {
    // A message that ends in '\r' cannot round-trip: the parser strips it as a CRLF ending.
    LogEntry e;
    e.timestamp_ms = 0;
    e.level = Level::Info;
    e.service = "svc";
    e.message = "abc\r";
    const auto back = parse_line(format_entry(e));
    CHECK(back.has_value());
    CHECK_EQ(back->message, std::string("abc"));
}

// ---------------------------------------------------------------------------
// parse_stream
// ---------------------------------------------------------------------------

TEST(LogParser, ParseStreamSkipsAndCountsMalformedLines) {
    std::istringstream in(
        "2026-10-10T00:00:01.000Z INFO a one\n"
        "this is not a log line\n"
        "2026-10-10T00:00:02.000Z error b two words\n"
        "\n"
        "2026-13-10T00:00:00.000Z INFO a bad month\n"
        "   \n"
        "2026-10-10T00:00:03.000Z WARN c \n"
        "2026-10-10T00:00:04.000Z TRACE d bad level\n"
        "2026-10-10T00:00:05.000Z DEBUG e last without newline");
    std::size_t malformed = 12345;
    const std::vector<LogEntry> entries = parse_stream(in, &malformed);
    CHECK_EQ(malformed, std::size_t{3});
    CHECK_EQ(entries.size(), std::size_t{4});
    CHECK_EQ(entries[0].message, std::string("one"));
    CHECK_EQ(entries[1].service, std::string("b"));
    CHECK(entries[1].level == Level::Error);
    CHECK_EQ(entries[2].message, std::string());
    CHECK(entries[3].level == Level::Debug);
    CHECK_EQ(entries[3].message, std::string("last without newline"));
}

TEST(LogParser, ParseStreamBlankLinesAreNotMalformed) {
    std::istringstream in("\n\n   \n\t\n\r\n \r\n");
    std::size_t malformed = 99;
    CHECK(parse_stream(in, &malformed).empty());
    CHECK_EQ(malformed, std::size_t{0});
}

TEST(LogParser, ParseStreamEmptyAndNullCounter) {
    std::istringstream empty("");
    std::size_t malformed = 7;
    CHECK(parse_stream(empty, &malformed).empty());
    CHECK_EQ(malformed, std::size_t{0});  // overwritten, not accumulated

    std::istringstream one("junk\n2026-10-10T00:00:00Z INFO s ok\n");
    const auto entries = parse_stream(one);  // counter is optional
    CHECK_EQ(entries.size(), std::size_t{1});

    std::istringstream bad_state("2026-10-10T00:00:00Z INFO s ok\n");
    bad_state.setstate(std::ios::failbit);
    CHECK(parse_stream(bad_state).empty());
}

TEST(LogParser, ParseStreamHandlesCrlfFiles) {
    std::istringstream in(
        "2026-10-10T00:00:01Z INFO a first\r\n"
        "2026-10-10T00:00:02Z WARN b second \r\n"
        "\r\n"
        "2026-10-10T00:00:03Z ERROR c third\r\n");
    std::size_t malformed = 1;
    const auto entries = parse_stream(in, &malformed);
    CHECK_EQ(malformed, std::size_t{0});
    CHECK_EQ(entries.size(), std::size_t{3});
    CHECK_EQ(entries[0].message, std::string("first"));
    CHECK_EQ(entries[1].message, std::string("second "));  // trailing space kept, only the CR is gone
    CHECK_EQ(entries[2].message, std::string("third"));
}

TEST(LogParser, ParseStreamPreservesInputOrderEvenIfTimestampsDescend) {
    std::istringstream in(
        "2026-10-10T00:00:03Z INFO s c\n"
        "2026-10-10T00:00:01Z INFO s a\n"
        "2026-10-10T00:00:02Z INFO s b\n");
    const auto entries = parse_stream(in);
    CHECK_EQ(entries.size(), std::size_t{3});
    CHECK_EQ(entries[0].message, std::string("c"));
    CHECK_EQ(entries[1].message, std::string("a"));
    CHECK_EQ(entries[2].message, std::string("b"));
}

namespace {

// Reference: std::getline + parse_line, the obvious way.
std::vector<LogEntry> reference_stream(const std::string& text, std::size_t* malformed) {
    std::istringstream in(text);
    std::vector<LogEntry> out;
    *malformed = 0;
    std::string line;
    while (std::getline(in, line)) {
        bool blank = true;
        for (char c : line) {
            if (c != ' ' && c != '\t' && c != '\r') blank = false;
        }
        if (blank) continue;
        auto e = parse_line(line);
        if (e) {
            out.push_back(std::move(*e));
        } else {
            ++*malformed;
        }
    }
    return out;
}

void check_stream_matches_reference(const std::string& text) {
    std::size_t expected_malformed = 0;
    const std::vector<LogEntry> expected = reference_stream(text, &expected_malformed);
    std::istringstream in(text);
    std::size_t malformed = 0;
    const std::vector<LogEntry> actual = parse_stream(in, &malformed);
    CHECK_EQ(malformed, expected_malformed);
    CHECK_EQ(actual.size(), expected.size());
    for (std::size_t i = 0; i < expected.size(); ++i) CHECK(actual[i] == expected[i]);
}

}  // namespace

TEST(LogParser, ParseStreamMatchesGetlineOnLargeRandomInput) {
    // ~3 MB: many 64 KiB block boundaries fall in the middle of lines.
    std::mt19937_64 rng(4242);
    std::string text;
    for (int i = 0; i < 30000; ++i) {
        std::string line;
        switch (rng() % 10) {
            case 0: line = "not a log line " + std::to_string(i); break;
            case 1: line = ""; break;
            case 2: line = "   "; break;
            default: line = format_entry(random_entry(rng)); break;
        }
        // random_entry may contain NUL and tabs but never '\n'
        text += line;
        text += (rng() % 5 == 0) ? "\r\n" : "\n";
    }
    text += format_entry(random_entry(rng));  // last line has no newline
    CHECK(text.size() > 1000000);
    check_stream_matches_reference(text);
}

TEST(LogParser, ParseStreamLinesLongerThanTheReadBlock) {
    LogEntry big;
    big.timestamp_ms = 1791590400000;
    big.level = Level::Info;
    big.service = "svc";
    big.message.assign(300000, 'm');
    big.message[150000] = ' ';
    const std::string text = format_entry(big) + "\n2026-10-10T00:00:00Z INFO tail ok\n" + format_entry(big);
    std::istringstream in(text);
    std::size_t malformed = 5;
    const auto entries = parse_stream(in, &malformed);
    CHECK_EQ(malformed, std::size_t{0});
    CHECK_EQ(entries.size(), std::size_t{3});
    CHECK(entries[0] == big);
    CHECK_EQ(entries[1].service, std::string("tail"));
    CHECK(entries[2] == big);
}

TEST(LogParser, ParseStreamNewlineExactlyAtBlockBoundaries) {
    // Whatever the internal block size, line terminators at offsets around common sizes
    // (including a CR as the last byte of a block and its LF as the first of the next)
    // must not lose, duplicate or merge lines.
    const std::string prefix = "2026-10-10T00:00:00Z INFO svc ";
    for (std::size_t block : {std::size_t{4096}, std::size_t{8192}, std::size_t{65536}, std::size_t{131072}}) {
        for (const char* terminator : {"\n", "\r\n"}) {
            const std::size_t term_len = std::string(terminator).size();
            for (long long delta = -2; delta <= 2; ++delta) {
                const std::size_t first_total = static_cast<std::size_t>(static_cast<long long>(block) + delta);
                const std::size_t body = first_total - prefix.size() - term_len;
                const std::string text = prefix + std::string(body, 'a') + terminator +
                                         "2026-10-10T00:00:01Z WARN svc second\n"
                                         "2026-10-10T00:00:02Z ERROR svc third";
                check_stream_matches_reference(text);
                std::istringstream in(text);
                const auto entries = parse_stream(in);
                CHECK_EQ(entries.size(), std::size_t{3});
                CHECK_EQ(entries[0].message.size(), body);
                CHECK_EQ(entries[1].message, std::string("second"));
                CHECK_EQ(entries[2].message, std::string("third"));
            }
        }
    }
}

TEST(LogParser, ParseStreamIsConsistentWithFormatEntry) {
    std::mt19937_64 rng(808);
    std::vector<LogEntry> originals;
    std::string text;
    for (int i = 0; i < 5000; ++i) {
        LogEntry e = random_entry(rng);
        if (!e.message.empty() && e.message.back() == '\r') e.message.pop_back();
        text += format_entry(e);
        text += '\n';
        originals.push_back(std::move(e));
    }
    std::istringstream in(text);
    std::size_t malformed = 0;
    const auto parsed = parse_stream(in, &malformed);
    CHECK_EQ(malformed, std::size_t{0});
    CHECK_EQ(parsed.size(), originals.size());
    for (std::size_t i = 0; i < originals.size(); ++i) {
        // Blank-looking lines are never produced: every line starts with a timestamp.
        CHECK(parsed[i] == originals[i]);
    }
}

// ---- added after review: BOM and exceptions() mask handling ------------------------------

TEST(LogParser, ParseStreamSkipsALeadingUtf8Bom) {
    std::istringstream in(
        "\xEF\xBB\xBF"
        "2026-10-10T00:00:01Z INFO a first\n"
        "2026-10-10T00:00:02Z INFO a second\n");
    std::size_t malformed = 9;
    const auto entries = parse_stream(in, &malformed);
    CHECK_EQ(malformed, std::size_t{0});
    CHECK_EQ(entries.size(), std::size_t{2});
    CHECK_EQ(entries[0].message, std::string("first"));
}

TEST(LogParser, ParseStreamBomAloneOrBeforeBlankLinesIsEmptyInput) {
    for (const char* text : {"\xEF\xBB\xBF", "\xEF\xBB\xBF\n", "\xEF\xBB\xBF\n\r\n  \n"}) {
        std::istringstream in(text);
        std::size_t malformed = 9;
        CHECK(parse_stream(in, &malformed).empty());
        CHECK_EQ(malformed, std::size_t{0});
    }
}

TEST(LogParser, ParseStreamOnlyTheLeadingBomIsSkipped) {
    // A BOM in the middle of the input belongs to its line, which is then malformed.
    std::istringstream in(
        "2026-10-10T00:00:01Z INFO a ok\n"
        "\xEF\xBB\xBF"
        "2026-10-10T00:00:02Z INFO a mid-stream\n");
    std::size_t malformed = 0;
    const auto entries = parse_stream(in, &malformed);
    CHECK_EQ(entries.size(), std::size_t{1});
    CHECK_EQ(malformed, std::size_t{1});

    // Two bytes of a BOM are just junk.
    std::istringstream partial("\xEF\xBB\n2026-10-10T00:00:01Z INFO a ok\n");
    CHECK_EQ(parse_stream(partial, &malformed).size(), std::size_t{1});
    CHECK_EQ(malformed, std::size_t{1});
}

TEST(LogParser, ParseStreamSurvivesAnExceptionsMaskAndRestoresIt) {
    std::string text;
    for (int i = 0; i < 3000; ++i) {  // > 64 KiB, so several block reads
        text += "2026-10-10T00:00:" + std::string(i % 60 < 10 ? "0" : "") + std::to_string(i % 60) + "Z INFO svc line " +
                std::to_string(i) + "\n";
    }
    const std::vector<std::ios_base::iostate> masks = {
        std::ios_base::failbit, std::ios_base::eofbit, std::ios_base::failbit | std::ios_base::eofbit,
        std::ios_base::badbit | std::ios_base::failbit, std::ios_base::badbit | std::ios_base::failbit | std::ios_base::eofbit};
    for (std::ios_base::iostate mask : masks) {
        std::istringstream in(text);
        in.exceptions(mask);
        std::size_t malformed = 99;
        std::vector<LogEntry> entries;
        bool threw = false;
        try {
            entries = parse_stream(in, &malformed);
        } catch (const std::ios_base::failure&) {
            threw = true;  // used to happen at the end of the input and discard every entry
        }
        CHECK(!threw);
        CHECK_EQ(entries.size(), std::size_t{3000});
        CHECK_EQ(malformed, std::size_t{0});
        CHECK(in.exceptions() == mask);                    // the caller's mask is back in place
        CHECK(!in.fail());                                 // reaching the end is not a failure
        CHECK((in.rdstate() & mask) == std::ios_base::goodbit);  // nothing left set that the mask would throw on
    }
}

TEST(LogParser, ParseStreamLeavesAnAlreadyFailedStreamFailed) {
    std::istringstream bad("2026-10-10T00:00:00Z INFO s ok\n");
    bad.setstate(std::ios::failbit);
    CHECK(parse_stream(bad).empty());
    CHECK(bad.fail());  // the caller's failure is not silently cleared
}
