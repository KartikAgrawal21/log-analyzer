#include "loganalyzer/report.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <map>
#include <sstream>
#include <utility>

#include "loganalyzer/level.hpp"
#include "loganalyzer/log_parser.hpp"
#include "loganalyzer/top_k_errors.hpp"

namespace loganalyzer {
namespace {

constexpr std::size_t kLevelCount = 4;
constexpr std::array<Level, kLevelCount> kLevels = {Level::Debug, Level::Info, Level::Warn, Level::Error};

std::size_t level_index(Level level) { return static_cast<std::size_t>(level); }

const char* level_css(Level level) {
    switch (level) {
        case Level::Debug: return "debug";
        case Level::Info: return "info";
        case Level::Warn: return "warn";
        case Level::Error: return "error";
    }
    return "info";
}

struct ServiceStats {
    std::string name;
    std::array<std::uint64_t, kLevelCount> by_level{};
    std::uint64_t total = 0;
};

std::string number(std::uint64_t n) { return std::to_string(n); }

/// Whole-number percentage of part in whole, rounded down (0 when whole is 0). The counts are
/// sizes of an in-memory vector (far below 2^50), so part * 100 cannot overflow 64 bits.
std::uint64_t percent(std::uint64_t part, std::uint64_t whole) {
    if (whole == 0) return 0;
    return part * 100 / whole;
}

const char* const kCss = R"(
:root{color-scheme:light dark;--bg:#f6f7f9;--card:#fff;--ink:#1c2128;--muted:#5b6573;--line:#dde1e6;
--debug:#8b949e;--info:#2f6fdb;--warn:#d98b0a;--error:#d63a3a;--accent:#2f6fdb}
@media (prefers-color-scheme:dark){:root{--bg:#0f1318;--card:#171c23;--ink:#e6e9ee;--muted:#98a2b0;--line:#2a313b;
--debug:#8b949e;--info:#5b9bff;--warn:#f0a93a;--error:#ff6b6b;--accent:#5b9bff}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1080px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:1.5rem;margin:0 0 4px}h2{font-size:1.05rem;margin:28px 0 10px}
.sub{color:var(--muted);margin:0 0 20px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.tile,.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.tile b{display:block;font-size:1.5rem;line-height:1.2}.tile span{color:var(--muted);font-size:.85rem}
.card{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:.92rem}
th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:.8rem;text-transform:uppercase;letter-spacing:.03em}
td.n,th.n{text-align:right;font-variant-numeric:tabular-nums}
.ts{white-space:nowrap}code,.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:.85rem;word-break:break-word}
.legend{display:flex;flex-wrap:wrap;gap:14px;margin:8px 0 0;color:var(--muted);font-size:.85rem}
.legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:6px}
.debug{background:var(--debug);fill:var(--debug)}.info{background:var(--info);fill:var(--info)}
.warn{background:var(--warn);fill:var(--warn)}.error{background:var(--error);fill:var(--error)}
.bar{display:flex;height:16px;border-radius:8px;overflow:hidden;background:var(--line)}
.bar span{display:block;height:100%}
.share{display:inline-block;height:8px;border-radius:4px;background:var(--accent);vertical-align:middle}
svg{display:block;width:100%;height:auto}svg text{fill:var(--muted);font-size:11px}
.grid{stroke:var(--line);stroke-width:1}
.empty{color:var(--muted);font-style:italic}
footer{margin-top:32px;color:var(--muted);font-size:.8rem}
)";

void write_legend(std::ostringstream& out) {
    out << "<div class=\"legend\">";
    for (Level level : kLevels) {
        out << "<span><i class=\"" << level_css(level) << "\"></i>" << to_string(level) << "</span>";
    }
    out << "</div>\n";
}

void write_tiles(std::ostringstream& out, std::uint64_t total, const std::array<std::uint64_t, kLevelCount>& by_level,
                 std::size_t services, std::size_t alerts, const std::string& covered) {
    auto tile = [&](const std::string& value, const char* label) {
        out << "<div class=\"tile\"><b>" << html_escape(value) << "</b><span>" << label << "</span></div>";
    };
    out << "<section class=\"tiles\" aria-label=\"summary\">";
    tile(number(total), "entries");
    tile(number(by_level[level_index(Level::Error)]), "errors");
    tile(number(by_level[level_index(Level::Warn)]), "warnings");
    tile(number(services), "services");
    tile(number(alerts), "alerts fired");
    tile(covered, "time covered");
    out << "</section>\n";
}

void write_level_bar(std::ostringstream& out, std::uint64_t total, const std::array<std::uint64_t, kLevelCount>& by_level) {
    out << "<h2>Levels</h2><div class=\"card\"><div class=\"bar\" role=\"img\" aria-label=\"share of entries by level\">";
    for (Level level : kLevels) {
        const std::uint64_t n = by_level[level_index(level)];
        if (n == 0) continue;
        // Width in tenths of a percent so small slices stay visible; the last slice may be a
        // hair off because of rounding, which the flex layout absorbs.
        const std::uint64_t tenths = std::max<std::uint64_t>(1, n * 1000 / total);
        out << "<span class=\"" << level_css(level) << "\" style=\"width:" << tenths / 10 << '.' << tenths % 10
            << "%\" title=\"" << to_string(level) << ": " << n << "\"></span>";
    }
    out << "</div>";
    write_legend(out);
    out << "<table style=\"margin-top:10px\"><tr><th>Level</th><th class=\"n\">Entries</th><th class=\"n\">Share</th></tr>";
    for (auto it = kLevels.rbegin(); it != kLevels.rend(); ++it) {
        const std::uint64_t n = by_level[level_index(*it)];
        out << "<tr><td>" << to_string(*it) << "</td><td class=\"n\">" << n << "</td><td class=\"n\">" << percent(n, total)
            << "%</td></tr>";
    }
    out << "</table></div>\n";
}

void write_services(std::ostringstream& out, const std::vector<ServiceStats>& services, std::uint64_t total) {
    out << "<h2>Services</h2><div class=\"card\"><table><tr><th>Service</th><th class=\"n\">Entries</th>"
           "<th class=\"n\">Errors</th><th class=\"n\">Warnings</th><th>Share</th></tr>";
    for (const ServiceStats& s : services) {
        const std::uint64_t pct = percent(s.total, total);
        out << "<tr><td class=\"mono\">" << html_escape(s.name) << "</td><td class=\"n\">" << s.total
            << "</td><td class=\"n\">" << s.by_level[level_index(Level::Error)] << "</td><td class=\"n\">"
            << s.by_level[level_index(Level::Warn)] << "</td><td><span class=\"share\" style=\"width:" << std::max<std::uint64_t>(pct, 1) * 2
            << "px\"></span> " << pct << "%</td></tr>";
    }
    out << "</table></div>\n";
}

void write_timeline(std::ostringstream& out, const std::vector<LogEntry>& entries, std::int64_t first_ms,
                    std::int64_t last_ms, std::uint64_t span, std::size_t requested_buckets) {
    const std::uint64_t bucket_count = std::min<std::uint64_t>(std::clamp<std::size_t>(requested_buckets, 1, 400), span);
    const std::uint64_t width = span / bucket_count + (span % bucket_count != 0 ? 1 : 0);

    std::vector<std::array<std::uint64_t, kLevelCount>> buckets(static_cast<std::size_t>(bucket_count));
    for (const LogEntry& e : entries) {
        const std::uint64_t offset = static_cast<std::uint64_t>(e.timestamp_ms) - static_cast<std::uint64_t>(first_ms);
        // When the entries span all of int64, span saturates at UINT64_MAX (the true count of
        // milliseconds, 2^64, does not fit), so width * bucket_count can fall one short of the
        // range and the very last entry would land one past the end: clamp it into the last bucket.
        const std::uint64_t index = std::min<std::uint64_t>(offset / width, bucket_count - 1);
        ++buckets[static_cast<std::size_t>(index)][level_index(e.level)];
    }
    std::uint64_t tallest = 1;
    for (const auto& b : buckets) tallest = std::max(tallest, b[0] + b[1] + b[2] + b[3]);

    constexpr int kWidth = 720, kHeight = 220, kLeft = 44, kRight = 8, kTop = 10, kBottom = 26;
    const int plot_w = kWidth - kLeft - kRight, plot_h = kHeight - kTop - kBottom;
    const double slot = static_cast<double>(plot_w) / static_cast<double>(bucket_count);

    out << "<h2>Timeline</h2><div class=\"card\"><svg viewBox=\"0 0 " << kWidth << ' ' << kHeight
        << "\" role=\"img\" aria-label=\"entries over time, stacked by level\">";
    for (int g = 0; g <= 2; ++g) {  // gridlines at 0, 50% and 100% of the tallest bar
        const int y = kTop + plot_h - plot_h * g / 2;
        out << "<line class=\"grid\" x1=\"" << kLeft << "\" x2=\"" << kWidth - kRight << "\" y1=\"" << y << "\" y2=\"" << y
            << "\"/><text x=\"" << kLeft - 6 << "\" y=\"" << y + 4 << "\" text-anchor=\"end\">" << tallest * static_cast<std::uint64_t>(g) / 2
            << "</text>";
    }
    for (std::size_t i = 0; i < buckets.size(); ++i) {
        const auto& b = buckets[i];
        const std::uint64_t total = b[0] + b[1] + b[2] + b[3];
        // Unsigned addition (wraps, never overflows); the result is a valid timestamp because
        // bucket i starts at or before the last entry.
        const std::int64_t start = static_cast<std::int64_t>(static_cast<std::uint64_t>(first_ms) + width * i);
        const double x = kLeft + slot * static_cast<double>(i);
        // Gap of ~1px between bars when there is room for it.
        const double bar_w = std::max(1.0, slot - (slot > 4.0 ? 1.0 : 0.0));
        out << "<g class=\"bucket\"><title>" << format_iso8601_utc(start) << " - " << total << " entries ("
            << b[level_index(Level::Error)] << " errors, " << b[level_index(Level::Warn)] << " warnings)</title>";
        int y = kTop + plot_h;
        for (Level level : kLevels) {  // Debug at the bottom, Error on top
            const std::uint64_t n = b[level_index(level)];
            if (n == 0) continue;
            const int h = std::max(1, static_cast<int>(n * static_cast<std::uint64_t>(plot_h) / tallest));
            y -= h;
            out << "<rect class=\"" << level_css(level) << "\" x=\"" << static_cast<int>(x * 10) / 10 << '.' << static_cast<int>(x * 10) % 10
                << "\" y=\"" << y << "\" width=\"" << static_cast<int>(bar_w * 10) / 10 << '.' << static_cast<int>(bar_w * 10) % 10
                << "\" height=\"" << h << "\"/>";
        }
        out << "</g>";
    }
    out << "<text x=\"" << kLeft << "\" y=\"" << kHeight - 6 << "\">" << format_iso8601_utc(first_ms) << "</text>"
        << "<text x=\"" << kWidth - kRight << "\" y=\"" << kHeight - 6 << "\" text-anchor=\"end\">"
        << format_iso8601_utc(last_ms) << "</text></svg>";
    write_legend(out);
    out << "<p class=\"sub\" style=\"margin:6px 0 0\">" << bucket_count << " buckets of " << html_escape(format_duration_ms(width))
        << "; tallest bar: " << tallest << " entries.</p></div>\n";
}

void write_top_errors(std::ostringstream& out, const std::vector<LogEntry>& entries, std::size_t top_k) {
    TopKErrors counter(Level::Error);
    for (const LogEntry& e : entries) counter.add(e);
    const std::vector<SignatureCount> top = counter.top_k(std::clamp<std::size_t>(top_k, 1, 1000));
    out << "<h2>Top error signatures</h2><div class=\"card\">";
    if (top.empty()) {
        out << "<p class=\"empty\">No ERROR entries.</p></div>\n";
        return;
    }
    out << "<table><tr><th class=\"n\">#</th><th class=\"n\">Count</th><th>Service</th><th>Signature</th>"
           "<th>First seen</th><th>Last seen</th></tr>";
    std::size_t rank = 1;
    for (const SignatureCount& g : top) {
        out << "<tr><td class=\"n\">" << rank++ << "</td><td class=\"n\">" << g.count << "</td><td class=\"mono\">"
            << html_escape(g.service) << "</td><td><code>" << html_escape(g.signature) << "</code><br><span class=\"sub\">e.g. "
            << html_escape(g.example) << "</span></td><td class=\"mono ts\">" << format_iso8601_utc(g.first_seen_ms)
            << "</td><td class=\"mono ts\">" << format_iso8601_utc(g.last_seen_ms) << "</td></tr>";
    }
    out << "</table><p class=\"sub\" style=\"margin:8px 0 0\">" << top.size() << " of " << counter.distinct()
        << " signature groups, " << counter.total() << " error entries.</p></div>\n";
}

void write_alerts(std::ostringstream& out, const std::vector<Alert>& alerts) {
    out << "<h2>Alerts</h2><div class=\"card\">";
    if (alerts.empty()) {
        out << "<p class=\"empty\">No alerts fired.</p></div>\n";
        return;
    }
    out << "<table><tr><th>Fired at</th><th>Rule</th><th>Service</th><th class=\"n\">Count</th><th>Since</th>"
           "<th class=\"n\">Suppressed</th></tr>";
    for (const Alert& a : alerts) {
        out << "<tr><td class=\"mono ts\">" << format_iso8601_utc(a.fired_at_ms) << "</td><td>" << html_escape(a.rule)
            << "</td><td class=\"mono\">" << html_escape(a.service) << "</td><td class=\"n\">" << a.count
            << "</td><td class=\"mono ts\">" << format_iso8601_utc(a.first_event_ms) << "</td><td class=\"n\">" << a.suppressed
            << "</td></tr>";
    }
    out << "</table></div>\n";
}

}  // namespace

std::string html_escape(std::string_view text) {
    std::string out;
    out.reserve(text.size() + text.size() / 8);
    for (char c : text) {
        switch (c) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"': out += "&quot;"; break;
            case '\'': out += "&#39;"; break;
            default: out += c;
        }
    }
    return out;
}

std::string format_duration_ms(unsigned long long ms) {
    if (ms < 1000) return std::to_string(ms) + " ms";
    const unsigned long long seconds = ms / 1000;
    if (seconds < 60) {
        std::string frac = std::to_string(ms % 1000);
        frac.insert(0, 3 - frac.size(), '0');
        return std::to_string(seconds) + "." + frac + " s";
    }
    auto two = [](unsigned long long v) { return (v < 10 ? "0" : "") + std::to_string(v); };
    const unsigned long long minutes = seconds / 60, hours = minutes / 60, days = hours / 24;
    if (hours == 0) return std::to_string(minutes) + "m " + two(seconds % 60) + "s";
    if (days == 0) return std::to_string(hours) + "h " + two(minutes % 60) + "m " + two(seconds % 60) + "s";
    return std::to_string(days) + "d " + two(hours % 24) + "h " + two(minutes % 60) + "m";
}

std::string render_html_report(const std::vector<LogEntry>& entries, const std::vector<Alert>& alerts,
                               const ReportOptions& options) {
    std::ostringstream out;
    out << "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
           "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>"
        << html_escape(options.title) << "</title><style>" << kCss << "</style></head><body><main>\n<h1>"
        << html_escape(options.title) << "</h1>\n";

    if (entries.empty()) {
        out << "<p class=\"sub\">Generated by loganalyzer</p>\n<p class=\"empty\">No entries to report.</p>\n";
        write_alerts(out, alerts);
        out << "<footer>loganalyzer</footer></main></body></html>\n";
        return out.str();
    }

    std::array<std::uint64_t, kLevelCount> by_level{};
    std::map<std::string, ServiceStats> by_service;
    std::int64_t first_ms = entries.front().timestamp_ms, last_ms = first_ms;
    for (const LogEntry& e : entries) {
        ++by_level[level_index(e.level)];
        ServiceStats& s = by_service[e.service];
        s.name = e.service;
        ++s.by_level[level_index(e.level)];
        ++s.total;
        first_ms = std::min(first_ms, e.timestamp_ms);
        last_ms = std::max(last_ms, e.timestamp_ms);
    }
    std::vector<ServiceStats> services;
    services.reserve(by_service.size());
    for (auto& kv : by_service) services.push_back(std::move(kv.second));
    std::stable_sort(services.begin(), services.end(),
                     [](const ServiceStats& a, const ServiceStats& b) { return a.total > b.total; });  // ties stay by name

    const std::uint64_t total = entries.size();
    // range = last - first + 1 in unsigned arithmetic (exact even across the int64 extremes,
    // saturating at 2^64-1 for the full int64 range).
    std::uint64_t span = static_cast<std::uint64_t>(last_ms) - static_cast<std::uint64_t>(first_ms);
    span = span == UINT64_MAX ? span : span + 1;
    const std::string covered = format_duration_ms(span - 1);

    out << "<p class=\"sub\">" << html_escape(format_iso8601_utc(first_ms)) << " to " << html_escape(format_iso8601_utc(last_ms))
        << " &middot; generated by loganalyzer</p>\n";
    write_tiles(out, total, by_level, services.size(), alerts.size(), covered);
    write_level_bar(out, total, by_level);
    write_services(out, services, total);
    write_timeline(out, entries, first_ms, last_ms, span, options.time_buckets);
    write_top_errors(out, entries, options.top_k);
    write_alerts(out, alerts);
    out << "<footer>Self-contained report: no scripts, no external resources.</footer></main></body></html>\n";
    return out.str();
}

}  // namespace loganalyzer
