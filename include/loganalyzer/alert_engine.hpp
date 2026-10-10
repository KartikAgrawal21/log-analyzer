#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "loganalyzer/level.hpp"
#include "loganalyzer/log_entry.hpp"
#include "loganalyzer/ring_buffer.hpp"

namespace loganalyzer {

/// "Fire when at least `threshold` matching entries fall inside a sliding time window."
///
/// Window: an entry at time t counts for entries up to (but excluding) `window_ms` later, i.e.
/// the window at time t is the half-open interval (t - window_ms, t]. An entry exactly
/// `window_ms` older than the newest one has already left the window.
///
/// "More than N errors in 60 seconds" is therefore threshold = N + 1, window_ms = 60000.
struct AlertRule {
    std::string name;                ///< unique; letters, digits, '-', '_' and '.' only
    std::string service;             ///< only entries of this service match; empty = every service
    Level min_level = Level::Error;  ///< entries below this level never match
    std::uint32_t threshold = 1;     ///< >= 1
    std::int64_t window_ms = 60'000; ///< >= 1
    std::int64_t cooldown_ms = 0;    ///< >= 0: minimum event-time gap between two alerts of one window
    /// false: one window shared by every matching service ("5 errors anywhere in 1 minute").
    /// true: a separate window and cooldown per service ("5 errors in the SAME service").
    bool per_service = false;
};

/// One firing of a rule.
struct Alert {
    std::string rule;
    std::string service;               ///< the service whose window fired; "*" for a shared window over all services
    std::int64_t fired_at_ms = 0;      ///< timestamp of the entry that pushed the window over the threshold
    std::uint64_t count = 0;           ///< matching entries inside the window when it fired (>= threshold)
    std::int64_t first_event_ms = 0;   ///< timestamp of the oldest of them
    std::uint64_t suppressed = 0;      ///< threshold crossings swallowed by the cooldown since the previous alert
};

/// Parses "250ms", "30s", "5m", "2h" or "1d" (a number followed by a mandatory unit) into
/// milliseconds. Throws std::invalid_argument on anything else, on zero, and on overflow.
std::int64_t parse_duration_ms(std::string_view text);

/// Parses a comma-separated key=value rule description, e.g.
///   name=payment-errors,service=payment-service,level=ERROR,threshold=50,window=60s,cooldown=5m,per-service=true
/// Required: name, threshold, window. Optional: service, level (default ERROR), cooldown
/// (default 0ms), per-service (true|false, default false). Throws std::invalid_argument with
/// a message naming the problem; the result is already validated like add_rule would.
AlertRule parse_rule_spec(std::string_view spec);

/// Streaming rule evaluation over a time-ordered log stream.
///
/// Each (rule, window) keeps a RingBuffer of the timestamps currently inside its window:
/// an entry evicts everything that has left the window from the front, appends itself, and
/// the rule fires when the buffer holds >= threshold timestamps. Every entry is processed in
/// amortized O(1) per interested rule, because each timestamp is appended once and evicted
/// once. Rules are indexed by service in a hash map, so an entry only visits the rules that
/// name its service plus the rules that match every service.
///
/// Cooldown: after a window fires at time f, further threshold crossings are suppressed until
/// an entry arrives at t with t - f >= cooldown_ms; the next alert reports how many were
/// suppressed. cooldown_ms = 0 means a window that stays over the threshold fires on every entry.
///
/// Ordering: entries must arrive in non-decreasing timestamp order per window (as a k-way
/// merge produces). An entry older than the newest one a window has already accepted is "late":
/// it is ignored by that window and counted in late_events().
///
/// Alerts from one process() call come out in rule insertion order.
class AlertEngine {
public:
    /// Throws std::invalid_argument on an empty/duplicate/invalid name, threshold == 0,
    /// window_ms < 1 or cooldown_ms < 0.
    void add_rule(AlertRule rule);

    /// Alerts fired by this entry (usually none).
    std::vector<Alert> process(const LogEntry& entry);

    std::size_t rule_count() const noexcept { return rules_.size(); }
    const AlertRule& rule(std::size_t index) const { return rules_.at(index).rule; }

    /// (entry, window) pairs skipped because the entry was older than the window's newest entry.
    std::uint64_t late_events() const noexcept { return late_events_; }

private:
    struct Window {
        RingBuffer<std::int64_t> times;  // timestamps currently inside the window, oldest first
        std::int64_t newest = 0;         // newest timestamp this window accepted
        bool has_newest = false;
        std::int64_t last_fired = 0;
        bool has_fired = false;
        std::uint64_t suppressed = 0;
    };

    struct RuleState {
        AlertRule rule;
        Window shared;                                    // used when !rule.per_service
        std::unordered_map<std::string, Window> by_service;  // used when rule.per_service
    };

    void evaluate(RuleState& state, const LogEntry& entry, std::vector<Alert>& out);

    std::vector<RuleState> rules_;
    std::unordered_set<std::string> names_;
    std::unordered_map<std::string, std::vector<std::size_t>> rules_by_service_;  // rule indices, ascending
    std::vector<std::size_t> wildcard_rules_;                                     // rule indices, ascending
    std::uint64_t late_events_ = 0;
};

}  // namespace loganalyzer
