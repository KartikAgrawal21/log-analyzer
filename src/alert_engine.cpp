#include "loganalyzer/alert_engine.hpp"

#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

namespace loganalyzer {
namespace {

bool is_digit(char c) { return c >= '0' && c <= '9'; }

bool is_space(char c) { return c == ' ' || c == '\t'; }

std::string_view trim(std::string_view s) {
    while (!s.empty() && is_space(s.front())) s.remove_prefix(1);
    while (!s.empty() && is_space(s.back())) s.remove_suffix(1);
    return s;
}

bool is_safe_word(std::string_view s) {
    if (s.empty()) return false;
    for (char c : s) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || is_digit(c) || c == '-' ||
                        c == '_' || c == '.';
        if (!ok) return false;
    }
    return true;
}

/// Non-negative integer in [min_value, max_value]; throws naming `what`.
std::uint64_t parse_integer(std::string_view text, std::string_view what, std::uint64_t min_value,
                            std::uint64_t max_value) {
    if (text.empty()) throw std::invalid_argument(std::string(what) + " needs a number");
    std::uint64_t value = 0;
    for (char c : text) {
        if (!is_digit(c)) {
            throw std::invalid_argument(std::string(what) + " must be a non-negative integer, got '" +
                                        std::string(text) + "'");
        }
        const std::uint64_t digit = static_cast<std::uint64_t>(c - '0');
        if (value > (std::numeric_limits<std::uint64_t>::max() - digit) / 10) {
            throw std::invalid_argument(std::string(what) + " is too large: " + std::string(text));
        }
        value = value * 10 + digit;
    }
    if (value < min_value || value > max_value) {
        throw std::invalid_argument(std::string(what) + " must be between " + std::to_string(min_value) +
                                    " and " + std::to_string(max_value) + ", got " + std::string(text));
    }
    return value;
}

void validate_rule(const AlertRule& rule) {
    if (!is_safe_word(rule.name)) {
        throw std::invalid_argument("rule name '" + rule.name +
                                    "' must be non-empty and use only letters, digits, '-', '_' and '.'");
    }
    for (char c : rule.service) {
        if (is_space(c) || c == '\n' || c == '\r') {
            throw std::invalid_argument("rule '" + rule.name + "': service must not contain whitespace");
        }
    }
    if (rule.threshold == 0) throw std::invalid_argument("rule '" + rule.name + "': threshold must be >= 1");
    if (rule.window_ms < 1) throw std::invalid_argument("rule '" + rule.name + "': window must be >= 1ms");
    if (rule.cooldown_ms < 0) throw std::invalid_argument("rule '" + rule.name + "': cooldown must be >= 0");
}

/// later - earlier as an unsigned number; exact for any int64 pair with later >= earlier
/// (the signed subtraction could overflow near the type's limits).
std::uint64_t elapsed(std::int64_t earlier, std::int64_t later) {
    return static_cast<std::uint64_t>(later) - static_cast<std::uint64_t>(earlier);
}

}  // namespace

namespace {

/// Shared by parse_duration_ms (zero rejected) and the cooldown field (zero allowed).
std::int64_t parse_duration_impl(std::string_view text, bool allow_zero) {
    std::size_t i = 0;
    while (i < text.size() && is_digit(text[i])) ++i;
    if (i == 0) {
        throw std::invalid_argument("duration '" + std::string(text) + "' must start with a number (e.g. 30s)");
    }
    const std::string_view unit = text.substr(i);
    std::uint64_t multiplier = 0;
    if (unit == "ms") multiplier = 1;
    else if (unit == "s") multiplier = 1000;
    else if (unit == "m") multiplier = 60ull * 1000;
    else if (unit == "h") multiplier = 3600ull * 1000;
    else if (unit == "d") multiplier = 86400ull * 1000;
    else {
        throw std::invalid_argument("duration '" + std::string(text) + "' needs a unit: ms, s, m, h or d");
    }
    // Parse the number on its own first so the range errors can speak about the whole duration
    // (the bound in milliseconds would be meaningless next to a value written in minutes).
    const std::uint64_t value = parse_integer(text.substr(0, i), "duration", 0, std::numeric_limits<std::uint64_t>::max());
    const std::uint64_t limit = static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
    if (value == 0 && !allow_zero) {
        throw std::invalid_argument("duration '" + std::string(text) + "' must be greater than zero");
    }
    if (value > limit / multiplier) {
        throw std::invalid_argument("duration '" + std::string(text) + "' is too large");
    }
    return static_cast<std::int64_t>(value * multiplier);
}

bool all_zeros(std::string_view s) {
    if (s.empty()) return false;
    for (char c : s) {
        if (c != '0') return false;
    }
    return true;
}

}  // namespace

std::int64_t parse_duration_ms(std::string_view text) { return parse_duration_impl(text, false); }

AlertRule parse_rule_spec(std::string_view spec) {
    AlertRule rule;
    bool have_name = false, have_threshold = false, have_window = false;
    std::unordered_set<std::string> seen;

    std::size_t start = 0;
    while (true) {
        const std::size_t comma = spec.find(',', start);
        const std::string_view part =
            trim(spec.substr(start, comma == std::string_view::npos ? std::string_view::npos : comma - start));
        const std::size_t eq = part.find('=');
        if (eq == std::string_view::npos) {
            throw std::invalid_argument("rule field '" + std::string(part) + "' must look like key=value");
        }
        const std::string key(trim(part.substr(0, eq)));
        const std::string_view value = trim(part.substr(eq + 1));
        if (!seen.insert(key).second) throw std::invalid_argument("rule field '" + key + "' given twice");

        if (key == "name") {
            rule.name = std::string(value);
            have_name = true;
        } else if (key == "service") {
            // An empty value would silently widen the rule to every service (a templated spec
            // whose variable expanded to nothing); omitting the key is how to say "all".
            if (value.empty()) {
                throw std::invalid_argument("service must not be empty (omit it to match every service)");
            }
            rule.service = std::string(value);
        } else if (key == "level") {
            const std::optional<Level> level = level_from_string(value);
            if (!level) throw std::invalid_argument("level must be one of DEBUG, INFO, WARN, ERROR");
            rule.min_level = *level;
        } else if (key == "threshold") {
            rule.threshold = static_cast<std::uint32_t>(
                parse_integer(value, "threshold", 1, std::numeric_limits<std::uint32_t>::max()));
            have_threshold = true;
        } else if (key == "window") {
            rule.window_ms = parse_duration_ms(value);
            have_window = true;
        } else if (key == "cooldown") {
            // A bare zero ("0", "00") means no cooldown; anything else needs a unit ("0ms", "5m").
            rule.cooldown_ms = all_zeros(value) ? 0 : parse_duration_impl(value, true);
        } else if (key == "per-service") {
            if (value == "true") rule.per_service = true;
            else if (value == "false") rule.per_service = false;
            else throw std::invalid_argument("per-service must be true or false");
        } else {
            throw std::invalid_argument("unknown rule field '" + key + "'");
        }

        if (comma == std::string_view::npos) break;
        start = comma + 1;
    }

    if (!have_name) throw std::invalid_argument("rule is missing name=...");
    if (!have_threshold) throw std::invalid_argument("rule is missing threshold=...");
    if (!have_window) throw std::invalid_argument("rule is missing window=... (e.g. window=60s)");
    validate_rule(rule);
    return rule;
}

void AlertEngine::add_rule(AlertRule rule) {
    validate_rule(rule);
    if (names_.count(rule.name) != 0) throw std::invalid_argument("duplicate rule name '" + rule.name + "'");

    // Strong exception guarantee: everything that can throw (allocation) happens before the
    // first visible change. names_.insert is the last throwing step; the two push_backs after
    // it run on capacity that was reserved up front, so they cannot throw.
    const std::size_t index = rules_.size();
    const std::string name = rule.name;
    const std::string service = rule.service;
    auto state = std::make_unique<RuleState>();
    state->rule = std::move(rule);

    // (An empty index list left behind in rules_by_service_ by a later failure is harmless:
    // process() treats it exactly like a missing entry.)
    std::vector<std::size_t>& list = service.empty() ? wildcard_rules_ : rules_by_service_[service];
    auto ensure_room = [](auto& vec) {
        if (vec.size() == vec.capacity()) vec.reserve(vec.empty() ? 4 : vec.size() * 2);
    };
    ensure_room(rules_);
    ensure_room(list);

    names_.insert(name);
    rules_.push_back(std::move(state));
    list.push_back(index);
}

std::size_t AlertEngine::tracked_service_windows() const noexcept {
    std::size_t total = 0;
    for (const std::unique_ptr<RuleState>& state : rules_) total += state->by_service.size();
    return total;
}

std::size_t AlertEngine::expire_idle(std::int64_t now_ms) {
    std::size_t freed = 0;
    for (const std::unique_ptr<RuleState>& state : rules_) {
        if (!state->rule.per_service) continue;
        const std::uint64_t window = static_cast<std::uint64_t>(state->rule.window_ms);
        const std::uint64_t cooldown = static_cast<std::uint64_t>(state->rule.cooldown_ms);
        for (auto it = state->by_service.begin(); it != state->by_service.end();) {
            const Window& w = it->second;
            // `now_ms` behind the window's own clock means we cannot tell: keep it.
            const bool idle = w.has_newest && now_ms >= w.newest && elapsed(w.newest, now_ms) >= window &&
                              (!w.has_fired || elapsed(w.last_fired, now_ms) >= cooldown) && w.suppressed == 0;
            if (idle) {
                it = state->by_service.erase(it);
                ++freed;
            } else {
                ++it;
            }
        }
    }
    return freed;
}

std::uint64_t AlertEngine::unreported_suppressed() const noexcept {
    std::uint64_t total = 0;
    for (const std::unique_ptr<RuleState>& state : rules_) {
        total += state->shared.suppressed;
        for (const auto& entry : state->by_service) total += entry.second.suppressed;
    }
    return total;
}

std::vector<Alert> AlertEngine::process(const LogEntry& entry) {
    std::vector<Alert> alerts;
    static const std::vector<std::size_t> kNone;
    const auto it = rules_by_service_.find(entry.service);
    const std::vector<std::size_t>& specific = it == rules_by_service_.end() ? kNone : it->second;
    const std::vector<std::size_t>& wild = wildcard_rules_;

    // Both index lists are ascending; walk them as a merge so alerts come out in rule order.
    std::size_t a = 0, b = 0;
    while (a < specific.size() || b < wild.size()) {
        std::size_t index;
        if (b >= wild.size() || (a < specific.size() && specific[a] < wild[b])) {
            index = specific[a++];
        } else {
            index = wild[b++];
        }
        evaluate(*rules_[index], entry, alerts);
    }
    return alerts;
}

void AlertEngine::evaluate(RuleState& state, const LogEntry& entry, std::vector<Alert>& out) {
    const AlertRule& rule = state.rule;
    if (entry.level < rule.min_level) return;

    Window& window = rule.per_service ? state.by_service[entry.service] : state.shared;
    const std::int64_t t = entry.timestamp_ms;
    if (window.has_newest && t < window.newest) {
        ++late_events_;
        return;
    }
    window.newest = t;
    window.has_newest = true;

    // Evict what left the window, then admit this entry.
    const std::uint64_t span = static_cast<std::uint64_t>(rule.window_ms);
    while (!window.times.empty() && elapsed(window.times.front(), t) >= span) window.times.pop_front();
    window.times.push_back(t);

    if (window.times.size() < rule.threshold) return;

    if (window.has_fired && elapsed(window.last_fired, t) < static_cast<std::uint64_t>(rule.cooldown_ms)) {
        ++window.suppressed;
        return;
    }

    Alert alert;
    alert.rule = rule.name;
    alert.service = rule.per_service ? entry.service : (rule.service.empty() ? "*" : rule.service);
    alert.fired_at_ms = t;
    alert.count = window.times.size();
    alert.first_event_ms = window.times.front();
    alert.suppressed = window.suppressed;
    out.push_back(std::move(alert));

    window.last_fired = t;
    window.has_fired = true;
    window.suppressed = 0;
}

}  // namespace loganalyzer
