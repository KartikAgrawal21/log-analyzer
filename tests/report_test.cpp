#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

#include "loganalyzer/alert_engine.hpp"
#include "loganalyzer/log_entry.hpp"
#include "loganalyzer/report.hpp"
#include "testkit.hpp"

using namespace loganalyzer;

namespace {

LogEntry ev(std::int64_t ts, Level level, std::string service, std::string message) {
    LogEntry e;
    e.timestamp_ms = ts;
    e.level = level;
    e.service = std::move(service);
    e.message = std::move(message);
    return e;
}

std::size_t count_of(const std::string& haystack, const std::string& needle) {
    std::size_t n = 0;
    for (std::size_t pos = haystack.find(needle); pos != std::string::npos; pos = haystack.find(needle, pos + needle.size())) ++n;
    return n;
}

bool has(const std::string& haystack, const std::string& needle) { return haystack.find(needle) != std::string::npos; }

std::vector<LogEntry> sample() {
    return {
        ev(1'000, Level::Info, "auth", "User 1 logged in"),
        ev(2'000, Level::Error, "payment", "Timeout after 100ms"),
        ev(3'000, Level::Error, "payment", "Timeout after 250ms"),
        ev(4'000, Level::Warn, "payment", "Slow query"),
        ev(5'000, Level::Error, "auth", "Token invalid"),
        ev(6'000, Level::Debug, "auth", "cache hit"),
    };
}

}  // namespace

TEST(HtmlEscape, EscapesTheFiveSpecialCharacters) {
    CHECK_EQ(html_escape("a&b<c>d\"e'f"), std::string("a&amp;b&lt;c&gt;d&quot;e&#39;f"));
    CHECK_EQ(html_escape(""), std::string());
    CHECK_EQ(html_escape("plain text 123"), std::string("plain text 123"));
    CHECK_EQ(html_escape("&amp;"), std::string("&amp;amp;"));  // already-escaped text is escaped again, not trusted
    CHECK_EQ(html_escape("caf\xC3\xA9"), std::string("caf\xC3\xA9"));  // bytes >= 128 pass through untouched
    CHECK_EQ(html_escape(std::string("a\0b", 3)), std::string("a\0b", 3));
}

TEST(FormatDuration, ReadsNaturally) {
    CHECK_EQ(format_duration_ms(0), std::string("0 ms"));
    CHECK_EQ(format_duration_ms(850), std::string("850 ms"));
    CHECK_EQ(format_duration_ms(999), std::string("999 ms"));
    CHECK_EQ(format_duration_ms(1000), std::string("1.000 s"));
    CHECK_EQ(format_duration_ms(12'345), std::string("12.345 s"));
    CHECK_EQ(format_duration_ms(59'999), std::string("59.999 s"));
    CHECK_EQ(format_duration_ms(60'000), std::string("1m 00s"));
    CHECK_EQ(format_duration_ms(187'000), std::string("3m 07s"));
    CHECK_EQ(format_duration_ms(3'723'000), std::string("1h 02m 03s"));
    CHECK_EQ(format_duration_ms(86'400'000ULL + 4ULL * 3'600'000), std::string("1d 04h 00m"));
}

TEST(Report, EmptyInputSaysSoAndStaysWellFormed) {
    const std::string html = render_html_report({}, {});
    CHECK(has(html, "<!doctype html>"));
    CHECK(has(html, "No entries to report"));
    CHECK(!has(html, "<svg"));
    CHECK(html.size() > 100 && html.substr(html.size() - 8) == "</html>\n");
}

TEST(Report, SummaryTilesCountEntriesLevelsServicesAlerts) {
    Alert alert;
    alert.rule = "r";
    alert.service = "*";
    const std::string html = render_html_report(sample(), {alert});
    CHECK(has(html, "<b>6</b><span>entries</span>"));
    CHECK(has(html, "<b>3</b><span>errors</span>"));
    CHECK(has(html, "<b>1</b><span>warnings</span>"));
    CHECK(has(html, "<b>2</b><span>services</span>"));
    CHECK(has(html, "<b>1</b><span>alerts fired</span>"));
    CHECK(has(html, "<b>5.000 s</b><span>time covered</span>"));
    CHECK(has(html, "1970-01-01T00:00:01.000Z to 1970-01-01T00:00:06.000Z"));
}

TEST(Report, LevelTableAndServiceTableAreCorrectAndOrdered) {
    const std::string html = render_html_report(sample(), {});
    // Level rows run from most to least severe: ERROR 3 (50%), WARN 1 (16%), INFO 1, DEBUG 1.
    CHECK(has(html, "<tr><td>ERROR</td><td class=\"n\">3</td><td class=\"n\">50%</td></tr>"));
    CHECK(has(html, "<tr><td>WARN</td><td class=\"n\">1</td><td class=\"n\">16%</td></tr>"));
    CHECK(html.find("<td>ERROR</td>") < html.find("<td>WARN</td>"));
    CHECK(html.find("<td>WARN</td>") < html.find("<td>INFO</td>"));
    CHECK(html.find("<td>INFO</td>") < html.find("<td>DEBUG</td>"));

    // auth and payment both have 3 entries: the tie stays alphabetical.
    CHECK(html.find(">auth</td>") < html.find(">payment</td>"));

    std::vector<LogEntry> skewed = sample();
    for (int i = 0; i < 10; ++i) skewed.push_back(ev(7'000 + i, Level::Info, "zeta", "busy"));
    const std::string busy = render_html_report(skewed, {});
    CHECK(busy.find(">zeta</td>") < busy.find(">auth</td>"));  // busiest first
}

TEST(Report, TimelineBucketCountFollowsTheDocumentedRule) {
    const std::vector<LogEntry> one = {ev(500, Level::Info, "s", "m")};
    CHECK_EQ(count_of(render_html_report(one, {}), "<g class=\"bucket\">"), std::size_t{1});

    std::vector<LogEntry> eleven;  // range of exactly 11 ms
    eleven.push_back(ev(100, Level::Info, "s", "m"));
    eleven.push_back(ev(110, Level::Info, "s", "m"));
    CHECK_EQ(count_of(render_html_report(eleven, {}), "<g class=\"bucket\">"), std::size_t{11});  // min(60, 11)

    std::vector<LogEntry> wide = {ev(0, Level::Info, "s", "m"), ev(999, Level::Info, "s", "m")};
    ReportOptions ten;
    ten.time_buckets = 10;
    CHECK_EQ(count_of(render_html_report(wide, {}, ten), "<g class=\"bucket\">"), std::size_t{10});

    ReportOptions zero;
    zero.time_buckets = 0;  // clamped to 1
    CHECK_EQ(count_of(render_html_report(wide, {}, zero), "<g class=\"bucket\">"), std::size_t{1});

    std::vector<LogEntry> long_span = {ev(0, Level::Info, "s", "m"), ev(1'000'000'000, Level::Info, "s", "m")};
    ReportOptions huge;
    huge.time_buckets = 100'000;  // clamped to 400
    CHECK_EQ(count_of(render_html_report(long_span, {}, huge), "<g class=\"bucket\">"), std::size_t{400});
}

TEST(Report, TimelineTooltipsAccountForEveryEntry) {
    std::vector<LogEntry> entries;
    for (int i = 0; i < 500; ++i) {
        entries.push_back(ev(i * 37, static_cast<Level>(i % 4), "s" + std::to_string(i % 3), "m"));
    }
    const std::string html = render_html_report(entries, {});
    std::uint64_t sum = 0;
    for (std::size_t pos = html.find(" entries ("); pos != std::string::npos; pos = html.find(" entries (", pos + 1)) {
        std::size_t start = pos;
        while (start > 0 && html[start - 1] >= '0' && html[start - 1] <= '9') --start;
        sum += std::stoull(html.substr(start, pos - start));
    }
    CHECK_EQ(sum, std::uint64_t{500});
}

TEST(Report, TopErrorSignaturesGroupVariantsAndEscapeThePlaceholders) {
    const std::string html = render_html_report(sample(), {});
    // "Timeout after 100ms" and "Timeout after 250ms" are the same signature: one row, count 2.
    CHECK(has(html, "<td class=\"n\">2</td><td class=\"mono\">payment</td><td><code>Timeout after &lt;N&gt;ms</code>"));
    CHECK(has(html, "<code>Token invalid</code>"));
    CHECK(has(html, "2 of 2 signature groups, 3 error entries"));
    CHECK(!has(html, "<N>"));  // the raw placeholder would be parsed as a tag

    ReportOptions one;
    one.top_k = 1;
    const std::string limited = render_html_report(sample(), {}, one);
    CHECK(has(limited, "1 of 2 signature groups"));
    CHECK(!has(limited, "<code>Token invalid</code>"));
}

TEST(Report, NoErrorsMeansNoSignatureTable) {
    const std::vector<LogEntry> quiet = {ev(1, Level::Info, "s", "fine")};
    const std::string html = render_html_report(quiet, {});
    CHECK(has(html, "No ERROR entries."));
}

TEST(Report, AlertsAreListedWithAllTheirFields) {
    Alert a;
    a.rule = "burst";
    a.service = "payment";
    a.fired_at_ms = 3000;
    a.count = 7;
    a.first_event_ms = 1000;
    a.suppressed = 4;
    const std::string with = render_html_report(sample(), {a});
    // One whole row, so each field is checked in its own column and in the documented order.
    CHECK(has(with,
              "<tr><td class=\"mono ts\">1970-01-01T00:00:03.000Z</td><td>burst</td><td class=\"mono\">payment</td>"
              "<td class=\"n\">7</td><td class=\"mono ts\">1970-01-01T00:00:01.000Z</td><td class=\"n\">4</td></tr>"));
    CHECK(has(render_html_report(sample(), {}), "No alerts fired."));
}

TEST(Report, LogTextCannotInjectMarkup) {
    std::vector<LogEntry> hostile = {
        ev(1, Level::Error, "\"><img src=x onerror=alert(1)>", "<script>alert(1)</script> & more"),
        ev(2, Level::Error, "svc", "'; DROP TABLE logs; --"),
    };
    Alert alert;
    alert.rule = "<b>rule</b>";
    alert.service = "<i>x</i>";
    ReportOptions options;
    options.title = "</title><script>alert('t')</script>";
    const std::string html = render_html_report(hostile, {alert}, options);
    CHECK(!has(html, "<script"));
    CHECK(!has(html, "<img"));
    CHECK(!has(html, "<b>rule"));
    CHECK(!has(html, "<i>x"));
    CHECK(!has(html, "onerror=alert(1)>"));
    CHECK(has(html, "&lt;script&gt;alert(1)&lt;/script&gt; &amp; more"));
    CHECK(has(html, "&quot;&gt;&lt;img src=x onerror=alert(1)&gt;"));
    CHECK(has(html, "<title>&lt;/title&gt;&lt;script&gt;"));
}

TEST(Report, MarkupIsBalanced) {
    Alert a;
    a.rule = "r";
    a.service = "s";
    const std::string html = render_html_report(sample(), {a});
    for (const char* tag : {"table", "svg", "g", "tr", "section", "div", "main", "body", "html", "head", "style", "title", "h1", "h2"}) {
        const std::string open = std::string("<") + tag;
        std::size_t opens = 0;
        for (std::size_t pos = html.find(open); pos != std::string::npos; pos = html.find(open, pos + 1)) {
            const char next = html[pos + open.size()];
            if (next == '>' || next == ' ') ++opens;  // not a longer tag name such as <title vs <t
        }
        CHECK_EQ(opens, count_of(html, std::string("</") + tag + ">"));
    }
}

TEST(Report, SameInputRendersTheSameBytesWhateverTheInputOrder) {
    std::vector<LogEntry> a = sample();
    // Examples come from the first entry added per signature, so use identical messages per group
    // to make the output independent of the order.
    for (LogEntry& e : a) {
        if (e.level == Level::Error && e.service == "payment") e.message = "Timeout after 100ms";
    }
    std::vector<LogEntry> b(a.rbegin(), a.rend());
    CHECK_EQ(render_html_report(a, {}), render_html_report(a, {}));
    CHECK_EQ(render_html_report(a, {}), render_html_report(b, {}));
}

TEST(Report, ExtremeTimestampsDoNotBreakIt) {
    const std::int64_t lo = std::numeric_limits<std::int64_t>::min();
    const std::int64_t hi = std::numeric_limits<std::int64_t>::max();
    const std::vector<LogEntry> entries = {ev(lo, Level::Error, "s", "boom"), ev(hi, Level::Warn, "s", "hmm"),
                                           ev(0, Level::Info, "s", "ok")};
    const std::string html = render_html_report(entries, {});
    CHECK(has(html, "<svg"));
    CHECK_EQ(count_of(html, "<g class=\"bucket\">"), std::size_t{60});
    CHECK(has(html, "<b>3</b><span>entries</span>"));
}
