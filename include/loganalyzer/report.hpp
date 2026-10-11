#pragma once

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

#include "loganalyzer/alert_engine.hpp"
#include "loganalyzer/log_entry.hpp"

namespace loganalyzer {

struct ReportOptions {
    std::string title = "Log report";
    std::size_t top_k = 10;         ///< rows in the top error signatures table (clamped to [1, 1000])
    std::size_t time_buckets = 60;  ///< bars in the timeline chart (clamped to [1, 400])
};

/// Escapes the five characters that matter in HTML text and attribute values:
/// & < > " ' become &amp; &lt; &gt; &quot; &#39;. Every piece of log text that reaches the
/// report goes through it, so a log line cannot inject markup or script.
std::string html_escape(std::string_view text);

/// Milliseconds as a short human duration: "0 ms", "850 ms", "12.345 s", "3m 07s",
/// "1h 02m 03s", "2d 04h 00m".
std::string format_duration_ms(unsigned long long milliseconds);

/// Renders one self-contained HTML page (inline CSS and SVG, no JavaScript, no external
/// resources, light and dark theme via prefers-color-scheme) summarizing `entries`:
///  - summary tiles: entries, errors, warnings, services, alerts fired, time covered;
///  - a stacked bar showing the share of each level;
///  - a per-service table (entries, errors, warnings, share), busiest service first;
///  - a timeline: `time_buckets` equal-width time slices, each bar stacked by level, with the
///    exact counts in a hover tooltip;
///  - the top error signatures (ERROR entries grouped by normalize_signature, per service)
///    with first/last seen and an example message;
///  - the `alerts` (as produced by AlertEngine), if any.
///
/// The entries may come in any order. The output depends only on the arguments (no clock, no
/// randomness), so the same input always renders the same bytes. Empty input renders a page
/// that says so. Timeline bucket i covers [first + i*w, first + (i+1)*w) where first is the
/// earliest timestamp and w = ceil(range / buckets), range = latest - first + 1, and the
/// number of buckets is min(time_buckets, range).
std::string render_html_report(const std::vector<LogEntry>& entries, const std::vector<Alert>& alerts,
                               const ReportOptions& options = {});

}  // namespace loganalyzer
