#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <random>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "loganalyzer/alert_engine.hpp"
#include "loganalyzer/level.hpp"
#include "loganalyzer/log_entry.hpp"
#include "testkit.hpp"

using namespace loganalyzer;

namespace {

LogEntry ev(std::int64_t ts, Level level = Level::Error, std::string service = "svc") {
    LogEntry e;
    e.timestamp_ms = ts;
    e.level = level;
    e.service = std::move(service);
    e.message = "m";
    return e;
}

AlertRule rule(std::string name, std::uint32_t threshold, std::int64_t window_ms, std::int64_t cooldown_ms = 0) {
    AlertRule r;
    r.name = std::move(name);
    r.threshold = threshold;
    r.window_ms = window_ms;
    r.cooldown_ms = cooldown_ms;
    return r;
}

std::vector<Alert> feed(AlertEngine& engine, const std::vector<LogEntry>& entries) {
    std::vector<Alert> all;
    for (const LogEntry& e : entries) {
        for (Alert& a : engine.process(e)) all.push_back(std::move(a));
    }
    return all;
}

bool same(const Alert& a, const Alert& b) {
    return a.rule == b.rule && a.service == b.service && a.fired_at_ms == b.fired_at_ms &&
           a.count == b.count && a.first_event_ms == b.first_event_ms && a.suppressed == b.suppressed;
}

}  // namespace

TEST(AlertEngine, FiresWhenThresholdIsReachedInsideTheWindow) {
    AlertEngine engine;
    engine.add_rule(rule("r", 3, 1000));
    std::vector<Alert> alerts = feed(engine, {ev(0), ev(100), ev(200)});
    CHECK_EQ(alerts.size(), std::size_t{1});
    CHECK_EQ(alerts[0].rule, std::string("r"));
    CHECK_EQ(alerts[0].fired_at_ms, std::int64_t{200});
    CHECK_EQ(alerts[0].count, std::uint64_t{3});
    CHECK_EQ(alerts[0].first_event_ms, std::int64_t{0});
    CHECK_EQ(alerts[0].suppressed, std::uint64_t{0});
    CHECK_EQ(alerts[0].service, std::string("*"));
}

TEST(AlertEngine, DoesNotFireBelowThreshold) {
    AlertEngine engine;
    engine.add_rule(rule("r", 3, 1000));
    CHECK(feed(engine, {ev(0), ev(100)}).empty());
}

TEST(AlertEngine, WindowIsHalfOpenAtTheOldEnd) {
    AlertEngine engine;
    engine.add_rule(rule("r", 2, 1000));
    // Exactly window_ms apart: the older entry has already left the window.
    CHECK(feed(engine, {ev(0), ev(1000)}).empty());

    AlertEngine inside;
    inside.add_rule(rule("r", 2, 1000));
    CHECK_EQ(feed(inside, {ev(0), ev(999)}).size(), std::size_t{1});
}

TEST(AlertEngine, OldEntriesSlideOutAndTheCountDrops) {
    AlertEngine engine;
    engine.add_rule(rule("r", 3, 100));
    // 0,10,20 fire; by 150 everything old is gone, so two more entries do not fire again.
    std::vector<Alert> alerts = feed(engine, {ev(0), ev(10), ev(20), ev(150), ev(160)});
    CHECK_EQ(alerts.size(), std::size_t{1});
    CHECK_EQ(alerts[0].fired_at_ms, std::int64_t{20});
}

TEST(AlertEngine, CooldownSuppressesAndReportsHowManyWereSwallowed) {
    AlertEngine engine;
    engine.add_rule(rule("r", 1, 10'000, 500));
    std::vector<Alert> alerts = feed(engine, {ev(0), ev(100), ev(200), ev(499), ev(500), ev(600)});
    CHECK_EQ(alerts.size(), std::size_t{2});
    CHECK_EQ(alerts[0].fired_at_ms, std::int64_t{0});
    CHECK_EQ(alerts[0].suppressed, std::uint64_t{0});
    CHECK_EQ(alerts[1].fired_at_ms, std::int64_t{500});  // cooldown is inclusive: t - fired >= cooldown
    CHECK_EQ(alerts[1].suppressed, std::uint64_t{3});    // 100, 200, 499
    CHECK_EQ(alerts[1].count, std::uint64_t{5});
}

TEST(AlertEngine, ZeroCooldownFiresOnEveryEntryWhileOverThreshold) {
    AlertEngine engine;
    engine.add_rule(rule("r", 2, 1000, 0));
    std::vector<Alert> alerts = feed(engine, {ev(0), ev(1), ev(2), ev(3)});
    CHECK_EQ(alerts.size(), std::size_t{3});  // at 1, 2 and 3
}

TEST(AlertEngine, LevelFilterIgnoresLessSevereEntries) {
    AlertEngine engine;
    AlertRule r = rule("warns", 2, 1000);
    r.min_level = Level::Warn;
    engine.add_rule(r);
    CHECK(feed(engine, {ev(0, Level::Info), ev(1, Level::Debug), ev(2, Level::Info)}).empty());
    CHECK_EQ(feed(engine, {ev(3, Level::Warn), ev(4, Level::Error)}).size(), std::size_t{1});
}

TEST(AlertEngine, ServiceFilterOnlyCountsThatService) {
    AlertEngine engine;
    AlertRule r = rule("pay", 2, 1000);
    r.service = "payment";
    engine.add_rule(r);
    CHECK(feed(engine, {ev(0, Level::Error, "auth"), ev(1, Level::Error, "payment"), ev(2, Level::Error, "auth")}).empty());
    std::vector<Alert> alerts = feed(engine, {ev(3, Level::Error, "payment")});
    CHECK_EQ(alerts.size(), std::size_t{1});
    CHECK_EQ(alerts[0].service, std::string("payment"));
}

TEST(AlertEngine, SharedWindowMixesServicesPerServiceWindowsDoNot) {
    AlertEngine shared;
    shared.add_rule(rule("r", 2, 1000));
    std::vector<Alert> a = feed(shared, {ev(0, Level::Error, "a"), ev(1, Level::Error, "b")});
    CHECK_EQ(a.size(), std::size_t{1});
    CHECK_EQ(a[0].service, std::string("*"));

    AlertEngine per;
    AlertRule r = rule("r", 2, 1000);
    r.per_service = true;
    per.add_rule(r);
    CHECK(feed(per, {ev(0, Level::Error, "a"), ev(1, Level::Error, "b")}).empty());
    std::vector<Alert> b = feed(per, {ev(2, Level::Error, "a")});
    CHECK_EQ(b.size(), std::size_t{1});
    CHECK_EQ(b[0].service, std::string("a"));
    CHECK_EQ(b[0].count, std::uint64_t{2});
}

TEST(AlertEngine, PerServiceCooldownsAreIndependent) {
    AlertEngine engine;
    AlertRule r = rule("r", 1, 1000, 10'000);
    r.per_service = true;
    engine.add_rule(r);
    std::vector<Alert> alerts = feed(engine, {ev(0, Level::Error, "a"), ev(1, Level::Error, "b"),
                                              ev(2, Level::Error, "a"), ev(3, Level::Error, "b")});
    CHECK_EQ(alerts.size(), std::size_t{2});  // one per service, repeats suppressed
    CHECK_EQ(alerts[0].service, std::string("a"));
    CHECK_EQ(alerts[1].service, std::string("b"));
}

TEST(AlertEngine, AlertsComeOutInRuleInsertionOrder) {
    AlertEngine engine;
    AlertRule specific = rule("second", 1, 1000);
    specific.service = "x";
    engine.add_rule(rule("first", 1, 1000));
    engine.add_rule(specific);
    engine.add_rule(rule("third", 1, 1000));

    std::vector<Alert> for_x = engine.process(ev(0, Level::Error, "x"));
    CHECK_EQ(for_x.size(), std::size_t{3});
    CHECK_EQ(for_x[0].rule, std::string("first"));
    CHECK_EQ(for_x[1].rule, std::string("second"));
    CHECK_EQ(for_x[2].rule, std::string("third"));

    std::vector<Alert> for_y = engine.process(ev(1, Level::Error, "y"));
    CHECK_EQ(for_y.size(), std::size_t{2});
    CHECK_EQ(for_y[0].rule, std::string("first"));
    CHECK_EQ(for_y[1].rule, std::string("third"));
}

TEST(AlertEngine, RejectsInvalidRules) {
    AlertEngine engine;
    CHECK_THROWS(engine.add_rule(rule("", 1, 1000)), std::invalid_argument);
    CHECK_THROWS(engine.add_rule(rule("has space", 1, 1000)), std::invalid_argument);
    CHECK_THROWS(engine.add_rule(rule("a,b", 1, 1000)), std::invalid_argument);
    CHECK_THROWS(engine.add_rule(rule("r", 0, 1000)), std::invalid_argument);
    CHECK_THROWS(engine.add_rule(rule("r", 1, 0)), std::invalid_argument);
    CHECK_THROWS(engine.add_rule(rule("r", 1, -5)), std::invalid_argument);
    CHECK_THROWS(engine.add_rule(rule("r", 1, 1000, -1)), std::invalid_argument);
    AlertRule bad_service = rule("r", 1, 1000);
    bad_service.service = "a b";
    CHECK_THROWS(engine.add_rule(bad_service), std::invalid_argument);
    CHECK_EQ(engine.rule_count(), std::size_t{0});

    engine.add_rule(rule("dup", 1, 1000));
    CHECK_THROWS(engine.add_rule(rule("dup", 2, 2000)), std::invalid_argument);
    CHECK_EQ(engine.rule_count(), std::size_t{1});
}

TEST(AlertEngine, LateEntriesAreIgnoredAndCounted) {
    AlertEngine engine;
    engine.add_rule(rule("r", 2, 1000));
    CHECK(feed(engine, {ev(100)}).empty());
    CHECK(feed(engine, {ev(50)}).empty());  // late: older than the newest accepted (100)
    CHECK_EQ(engine.late_events(), std::uint64_t{1});
    std::vector<Alert> alerts = feed(engine, {ev(100)});  // equal timestamp is NOT late
    CHECK_EQ(alerts.size(), std::size_t{1});
    CHECK_EQ(alerts[0].count, std::uint64_t{2});
    CHECK_EQ(engine.late_events(), std::uint64_t{1});
}

TEST(AlertEngine, BurstOfEqualTimestamps) {
    AlertEngine engine;
    engine.add_rule(rule("r", 5, 1000));
    std::vector<LogEntry> burst;
    for (int i = 0; i < 5; ++i) burst.push_back(ev(100));
    std::vector<Alert> alerts = feed(engine, burst);
    CHECK_EQ(alerts.size(), std::size_t{1});
    CHECK_EQ(alerts[0].count, std::uint64_t{5});
}

TEST(AlertEngine, ExtremeTimestampsDoNotOverflow) {
    const std::int64_t lo = std::numeric_limits<std::int64_t>::min();
    const std::int64_t hi = std::numeric_limits<std::int64_t>::max();

    AlertEngine far_apart;
    far_apart.add_rule(rule("r", 2, 1000));
    CHECK(feed(far_apart, {ev(lo), ev(hi)}).empty());  // 2^64-1 ms apart: far outside the window

    AlertEngine close_together;
    close_together.add_rule(rule("r", 2, 1000));
    CHECK_EQ(feed(close_together, {ev(hi - 5), ev(hi)}).size(), std::size_t{1});

    AlertEngine whole_range;
    whole_range.add_rule(rule("r", 2, hi));
    CHECK_EQ(feed(whole_range, {ev(0), ev(hi - 1)}).size(), std::size_t{1});

    AlertEngine cooldown;
    cooldown.add_rule(rule("r", 1, 1000, hi));
    CHECK_EQ(feed(cooldown, {ev(lo), ev(hi)}).size(), std::size_t{2});  // gap is 2^64-1 >= cooldown
}

TEST(AlertEngine, MatchesABruteForceOracleOnRandomStreams) {
    struct Oracle {
        std::vector<std::int64_t> times;
        std::int64_t last_fired = 0;
        bool has_fired = false;
        std::uint64_t suppressed = 0;
    };

    std::vector<AlertRule> rules;
    {
        AlertRule r = rule("all-errors", 3, 100);
        rules.push_back(r);
        r = rule("per-warn", 4, 200, 150);
        r.min_level = Level::Warn;
        r.per_service = true;
        rules.push_back(r);
        r = rule("svc1-info", 5, 50, 30);
        r.service = "svc-1";
        r.min_level = Level::Info;
        rules.push_back(r);
        r = rule("per-debug", 20, 400, 1000);
        r.min_level = Level::Debug;
        r.per_service = true;
        rules.push_back(r);
        r = rule("svc2-one", 1, 10, 25);
        r.service = "svc-2";
        rules.push_back(r);
    }

    for (std::uint32_t seed = 1; seed <= 10; ++seed) {
        std::mt19937 rng(seed);
        std::vector<LogEntry> entries;
        std::int64_t t = 1000;
        for (int i = 0; i < 3000; ++i) {
            t += rng() % 21;  // gaps 0..20, so ties and bursts happen
            entries.push_back(ev(t, static_cast<Level>(rng() % 4), "svc-" + std::to_string(rng() % 3)));
        }

        AlertEngine engine;
        for (const AlertRule& r : rules) engine.add_rule(r);
        const std::vector<Alert> actual = feed(engine, entries);

        std::vector<Alert> expected;
        std::map<std::pair<std::size_t, std::string>, Oracle> windows;
        for (const LogEntry& e : entries) {
            for (std::size_t r = 0; r < rules.size(); ++r) {
                const AlertRule& rl = rules[r];
                if (!rl.service.empty() && rl.service != e.service) continue;
                if (e.level < rl.min_level) continue;
                Oracle& w = windows[{r, rl.per_service ? e.service : std::string()}];
                w.times.push_back(e.timestamp_ms);
                std::vector<std::int64_t> inside;
                for (std::int64_t x : w.times) {
                    if (e.timestamp_ms - x < rl.window_ms) inside.push_back(x);
                }
                if (inside.size() < rl.threshold) continue;
                if (w.has_fired && e.timestamp_ms - w.last_fired < rl.cooldown_ms) {
                    ++w.suppressed;
                    continue;
                }
                Alert a;
                a.rule = rl.name;
                a.service = rl.per_service ? e.service : (rl.service.empty() ? "*" : rl.service);
                a.fired_at_ms = e.timestamp_ms;
                a.count = inside.size();
                a.first_event_ms = inside.front();
                a.suppressed = w.suppressed;
                expected.push_back(a);
                w.last_fired = e.timestamp_ms;
                w.has_fired = true;
                w.suppressed = 0;
            }
        }

        CHECK_EQ(actual.size(), expected.size());
        CHECK(!expected.empty());  // the scenario really exercises firing
        for (std::size_t i = 0; i < expected.size(); ++i) CHECK(same(actual[i], expected[i]));
        CHECK_EQ(engine.late_events(), std::uint64_t{0});
    }
}

TEST(ParseDuration, AcceptsAllUnits) {
    CHECK_EQ(parse_duration_ms("250ms"), std::int64_t{250});
    CHECK_EQ(parse_duration_ms("30s"), std::int64_t{30'000});
    CHECK_EQ(parse_duration_ms("5m"), std::int64_t{300'000});
    CHECK_EQ(parse_duration_ms("2h"), std::int64_t{7'200'000});
    CHECK_EQ(parse_duration_ms("1d"), std::int64_t{86'400'000});
    CHECK_EQ(parse_duration_ms("007s"), std::int64_t{7000});
}

TEST(ParseDuration, RejectsMalformedInput) {
    for (const char* bad : {"", "10", "s", "5x", "0s", "0ms", "-5s", "5 s", " 5s", "5s ", "1.5s", "5S", "5mm",
                            "99999999999999999999s", "9223372036854775807s", "106751991167301d"}) {
        bool threw = false;
        try {
            parse_duration_ms(bad);
        } catch (const std::invalid_argument&) {
            threw = true;
        }
        if (!threw) throw testkit::Failure{std::string("expected invalid_argument for '") + bad + "'"};
    }
}

TEST(ParseRuleSpec, ParsesEveryField) {
    AlertRule r = parse_rule_spec(
        "name=payment-errors,service=payment-service,level=warn,threshold=50,window=60s,cooldown=5m,per-service=true");
    CHECK_EQ(r.name, std::string("payment-errors"));
    CHECK_EQ(r.service, std::string("payment-service"));
    CHECK(r.min_level == Level::Warn);
    CHECK_EQ(r.threshold, std::uint32_t{50});
    CHECK_EQ(r.window_ms, std::int64_t{60'000});
    CHECK_EQ(r.cooldown_ms, std::int64_t{300'000});
    CHECK(r.per_service);
}

TEST(ParseRuleSpec, AppliesDefaultsAndToleratesSpaces) {
    AlertRule r = parse_rule_spec(" name = spike , threshold = 10 , window = 1m ");
    CHECK_EQ(r.name, std::string("spike"));
    CHECK(r.service.empty());
    CHECK(r.min_level == Level::Error);
    CHECK_EQ(r.cooldown_ms, std::int64_t{0});
    CHECK(!r.per_service);
}

TEST(ParseRuleSpec, CooldownMayBeZeroInAnySpelling) {
    // Keep the rules in locals: CHECK_EQ binds references, and a member of a temporary would dangle.
    const AlertRule bare = parse_rule_spec("name=a,threshold=1,window=1s,cooldown=0");
    const AlertRule with_unit = parse_rule_spec("name=a,threshold=1,window=1s,cooldown=0ms");
    CHECK_EQ(bare.cooldown_ms, std::int64_t{0});
    CHECK_EQ(with_unit.cooldown_ms, std::int64_t{0});
    CHECK_THROWS(parse_rule_spec("name=a,threshold=1,window=0s"), std::invalid_argument);
}

TEST(ParseRuleSpec, RejectsBadSpecs) {
    for (const char* bad : {"", "name=a", "name=a,threshold=1", "threshold=1,window=1s", "name=a,window=1s",
                            "name=a,threshold=1,window=1s,bogus=1", "name=a,name=b,threshold=1,window=1s",
                            "name=a,threshold=0,window=1s", "name=a,threshold=x,window=1s",
                            "name=a,threshold=1,window=1s,level=FATAL", "name=a,threshold=1,window=1s,per-service=yes",
                            "name=a,threshold=1,window=1s,cooldown=-1s", "name=a,threshold=1,window=1s,extra",
                            "name=a b,threshold=1,window=1s", "name=a,threshold=4294967296,window=1s",
                            "name=a,,threshold=1,window=1s"}) {
        bool threw = false;
        try {
            parse_rule_spec(bad);
        } catch (const std::invalid_argument&) {
            threw = true;
        }
        if (!threw) throw testkit::Failure{std::string("expected invalid_argument for '") + bad + "'"};
    }
}

// ---- added after review -----------------------------------------------------------------

TEST(AlertEngine, ServiceFilterCombinesWithPerServiceWindows) {
    AlertEngine engine;
    AlertRule r = rule("r", 2, 1000);
    r.service = "a";
    r.per_service = true;
    engine.add_rule(r);
    std::vector<Alert> alerts = feed(engine, {ev(0, Level::Error, "a"), ev(1, Level::Error, "b"),
                                              ev(2, Level::Error, "b"), ev(3, Level::Error, "a")});
    CHECK_EQ(alerts.size(), std::size_t{1});
    CHECK_EQ(alerts[0].service, std::string("a"));
    CHECK_EQ(alerts[0].count, std::uint64_t{2});
}

TEST(AlertEngine, PerServiceWithZeroCooldownFiresOnEveryEntryOverThreshold) {
    AlertEngine engine;
    AlertRule r = rule("r", 1, 1000, 0);
    r.per_service = true;
    engine.add_rule(r);
    CHECK_EQ(feed(engine, {ev(0, Level::Error, "a"), ev(0, Level::Error, "a"), ev(1, Level::Error, "b")}).size(),
             std::size_t{3});
}

TEST(AlertEngine, SuppressedCountRestartsAfterEveryAlert) {
    AlertEngine engine;
    engine.add_rule(rule("r", 1, 1'000'000, 100));
    std::vector<Alert> alerts = feed(engine, {ev(0), ev(10), ev(20), ev(100), ev(110), ev(200)});
    CHECK_EQ(alerts.size(), std::size_t{3});
    CHECK_EQ(alerts[0].suppressed, std::uint64_t{0});
    CHECK_EQ(alerts[1].suppressed, std::uint64_t{2});  // 10, 20
    CHECK_EQ(alerts[2].suppressed, std::uint64_t{1});  // 110 only: the counter was reset at 100
}

TEST(AlertEngine, UnreportedSuppressedCoversTheTailAfterTheLastAlert) {
    AlertEngine engine;
    engine.add_rule(rule("r", 1, 1'000'000, 100));
    CHECK_EQ(engine.unreported_suppressed(), std::uint64_t{0});
    feed(engine, {ev(0), ev(1), ev(2)});
    CHECK_EQ(engine.unreported_suppressed(), std::uint64_t{2});
    std::vector<Alert> alerts = feed(engine, {ev(100)});
    CHECK_EQ(alerts.size(), std::size_t{1});
    CHECK_EQ(alerts[0].suppressed, std::uint64_t{2});
    CHECK_EQ(engine.unreported_suppressed(), std::uint64_t{0});

    // Summed over rules and over per-service windows.
    AlertEngine many;
    AlertRule per = rule("per", 1, 1'000'000, 100);
    per.per_service = true;
    many.add_rule(per);
    many.add_rule(rule("shared", 1, 1'000'000, 100));
    feed(many, {ev(0, Level::Error, "a"), ev(1, Level::Error, "a"), ev(2, Level::Error, "b"), ev(3, Level::Error, "b")});
    CHECK_EQ(many.unreported_suppressed(), std::uint64_t{1 + 1 + 3});  // per:a 1, per:b 1, shared 3
}

TEST(AlertEngine, LateEntriesAreTrackedPerWindow) {
    AlertEngine engine;
    AlertRule r = rule("r", 100, 1000);
    r.per_service = true;
    engine.add_rule(r);
    feed(engine, {ev(100, Level::Error, "a"), ev(50, Level::Error, "b")});  // b has its own window: not late
    CHECK_EQ(engine.late_events(), std::uint64_t{0});
    feed(engine, {ev(60, Level::Error, "a")});  // older than a's newest (100)
    CHECK_EQ(engine.late_events(), std::uint64_t{1});
}

TEST(AlertEngine, RuleReferencesStayValidWhenMoreRulesAreAdded) {
    AlertEngine engine;
    engine.add_rule(rule("first", 1, 1000));
    const AlertRule* first = &engine.rule(0);
    for (int i = 0; i < 200; ++i) engine.add_rule(rule("r" + std::to_string(i), 1, 1000));
    CHECK(first == &engine.rule(0));
    CHECK_EQ(first->name, std::string("first"));
    CHECK_EQ(engine.rule_count(), std::size_t{201});
    CHECK_EQ(engine.process(ev(0)).size(), std::size_t{201});
    CHECK_THROWS(engine.rule(201), std::out_of_range);
}

TEST(AlertEngine, RejectedRulesLeaveNoTraceInTheEngine) {
    AlertEngine engine;
    engine.add_rule(rule("r1", 1, 1000));
    CHECK_THROWS(engine.add_rule(rule("r1", 5, 5000)), std::invalid_argument);  // duplicate
    AlertRule bad = rule("bad", 0, 1000);
    bad.service = "x";
    CHECK_THROWS(engine.add_rule(bad), std::invalid_argument);                  // threshold 0
    AlertRule r2 = rule("r2", 1, 1000);
    r2.service = "x";
    engine.add_rule(r2);
    CHECK_EQ(engine.rule_count(), std::size_t{2});
    std::vector<Alert> alerts = engine.process(ev(0, Level::Error, "x"));
    CHECK_EQ(alerts.size(), std::size_t{2});
    CHECK_EQ(alerts[0].rule, std::string("r1"));
    CHECK_EQ(alerts[1].rule, std::string("r2"));
}

TEST(AlertEngine, RuleNamesUseASafeCharacterSet) {
    AlertEngine engine;
    engine.add_rule(rule("a.b_c-1", 1, 1000));
    for (const char* bad : {"a=b", "a/b", "a\\b", "a:b", "caf\xC3\xA9", "tab\there", "a;b"}) {
        CHECK_THROWS(engine.add_rule(rule(bad, 1, 1000)), std::invalid_argument);
    }
    CHECK_EQ(engine.rule_count(), std::size_t{1});
}

TEST(ParseRuleSpec, RejectsAnEmptyServiceValue) {
    CHECK_THROWS(parse_rule_spec("name=a,threshold=1,window=1s,service="), std::invalid_argument);
    CHECK_THROWS(parse_rule_spec("name=a,threshold=1,window=1s,service=  "), std::invalid_argument);
}

TEST(ParseRuleSpec, CooldownZeroInEveryBareSpelling) {
    for (const char* zero : {"0", "00", "000"}) {
        const AlertRule r = parse_rule_spec(std::string("name=a,threshold=1,window=1s,cooldown=") + zero);
        CHECK_EQ(r.cooldown_ms, std::int64_t{0});
    }
    CHECK_THROWS(parse_rule_spec("name=a,threshold=1,window=1s,cooldown="), std::invalid_argument);
    CHECK_THROWS(parse_rule_spec("name=a,threshold=1,window=1s,cooldown=5"), std::invalid_argument);  // unit needed
}

TEST(ParseRuleSpec, ThresholdAndDurationBoundaries) {
    const AlertRule big = parse_rule_spec("name=a,threshold=4294967295,window=1ms");
    CHECK_EQ(big.threshold, std::uint32_t{4294967295u});
    CHECK_THROWS(parse_rule_spec("name=a,threshold=4294967296,window=1ms"), std::invalid_argument);

    // 106751991167 days (about 292 million years) is the largest whole number of days whose
    // length in milliseconds still fits in an int64; one more day overflows.
    CHECK_EQ(parse_duration_ms("106751991167d"), std::int64_t{106751991167LL} * 86'400'000);
    try {
        parse_duration_ms("106751991168d");
        throw testkit::Failure{"expected an overflow error"};
    } catch (const std::invalid_argument& e) {
        CHECK(std::string(e.what()).find("too large") != std::string::npos);
    }
    try {
        parse_duration_ms("0s");
        throw testkit::Failure{"expected a zero error"};
    } catch (const std::invalid_argument& e) {
        CHECK(std::string(e.what()).find("greater than zero") != std::string::npos);
    }
}

// ---- expire_idle: bounded memory without changing any result ----------------------------

TEST(AlertEngineExpiry, FreesExactlyTheWindowsThatWentQuiet) {
    AlertEngine engine;
    AlertRule r = rule("r", 100, 1000);  // threshold never reached: only the bookkeeping matters
    r.per_service = true;
    engine.add_rule(r);
    for (int i = 0; i < 500; ++i) engine.process(ev(i, Level::Error, "svc" + std::to_string(i)));
    CHECK_EQ(engine.tracked_service_windows(), std::size_t{500});

    CHECK_EQ(engine.expire_idle(499), std::size_t{0});    // the oldest entry is only 499 ms old: still inside its window
    CHECK_EQ(engine.expire_idle(999), std::size_t{0});
    CHECK_EQ(engine.expire_idle(1000), std::size_t{1});   // svc0 (t = 0) is exactly one window old: gone
    CHECK_EQ(engine.tracked_service_windows(), std::size_t{499});
    CHECK_EQ(engine.expire_idle(1249), std::size_t{249}); // svc1..svc249 (t <= 249)
    CHECK_EQ(engine.expire_idle(5000), std::size_t{250});  // svc250..svc499
    CHECK_EQ(engine.tracked_service_windows(), std::size_t{0});
    CHECK_EQ(engine.expire_idle(9999), std::size_t{0});
}

TEST(AlertEngineExpiry, NeverFreesWhatStillMatters) {
    // 1. A cooldown still running keeps the window (and with it the "already fired" memory).
    AlertEngine cool;
    AlertRule c = rule("c", 1, 100, 1000);
    c.per_service = true;
    cool.add_rule(c);
    CHECK_EQ(cool.process(ev(0, Level::Error, "a")).size(), std::size_t{1});
    CHECK_EQ(cool.expire_idle(500), std::size_t{0});     // window is empty by now, but the cooldown runs to t = 1000
    CHECK_EQ(cool.expire_idle(1000), std::size_t{1});
    CHECK_EQ(cool.process(ev(1000, Level::Error, "a")).size(), std::size_t{1});  // same as if nothing was freed

    // 2. Suppressed crossings waiting to be reported keep the window alive until the next alert.
    AlertEngine pending;
    AlertRule p = rule("p", 1, 50, 100);
    p.per_service = true;
    pending.add_rule(p);
    CHECK_EQ(pending.process(ev(0, Level::Error, "a")).size(), std::size_t{1});
    CHECK_EQ(pending.process(ev(10, Level::Error, "a")).size(), std::size_t{0});  // suppressed
    CHECK_EQ(pending.expire_idle(10'000), std::size_t{0});
    const std::vector<Alert> later = pending.process(ev(10'000, Level::Error, "a"));
    CHECK_EQ(later.size(), std::size_t{1});
    CHECK_EQ(later[0].suppressed, std::uint64_t{1});
    CHECK_EQ(pending.expire_idle(20'000), std::size_t{1});  // nothing pending any more

    // 3. A clock that is behind the window's own newest timestamp frees nothing.
    AlertEngine behind;
    AlertRule b = rule("b", 100, 10);
    b.per_service = true;
    behind.add_rule(b);
    behind.process(ev(1000, Level::Error, "a"));
    CHECK_EQ(behind.expire_idle(500), std::size_t{0});
    CHECK_EQ(behind.expire_idle(std::numeric_limits<std::int64_t>::min()), std::size_t{0});

    // 4. Shared windows and engines without rules are untouched.
    AlertEngine shared;
    shared.add_rule(rule("s", 100, 10));
    shared.process(ev(0));
    CHECK_EQ(shared.expire_idle(1'000'000), std::size_t{0});
    CHECK_EQ(shared.tracked_service_windows(), std::size_t{0});
    CHECK_EQ(AlertEngine().expire_idle(5), std::size_t{0});
}

TEST(AlertEngineExpiry, ExpiringNeverChangesAnyAlertOnRandomDriftingStreams) {
    for (std::uint32_t seed = 1; seed <= 12; ++seed) {
        std::mt19937 rng(seed);
        AlertEngine plain;
        AlertEngine pruned;
        for (AlertEngine* engine : {&plain, &pruned}) {
            AlertRule a = rule("errors", 3, 100, 25);
            a.per_service = true;
            engine->add_rule(a);
            AlertRule w = rule("warns", 2, 30, 0);
            w.per_service = true;
            w.min_level = Level::Warn;
            engine->add_rule(w);
            AlertRule shared = rule("shared", 5, 20, 10);
            shared.min_level = Level::Info;
            engine->add_rule(shared);
        }

        std::vector<Alert> from_plain, from_pruned;
        std::int64_t t = 0;
        std::size_t freed = 0;
        for (int i = 0; i < 4000; ++i) {
            t += rng() % 6;  // 0..5 ms: ties and bursts happen
            // The set of active services drifts: 4 live ones at a time, so old windows go quiet.
            const std::string service = "svc" + std::to_string(static_cast<unsigned>(i / 100) * 4 + rng() % 4);
            const LogEntry entry = ev(t, static_cast<Level>(rng() % 4), service);
            for (Alert& alert : plain.process(entry)) from_plain.push_back(std::move(alert));
            for (Alert& alert : pruned.process(entry)) from_pruned.push_back(std::move(alert));
            if (i % 17 == 0) freed += pruned.expire_idle(t);
        }
        CHECK_EQ(from_plain.size(), from_pruned.size());
        CHECK(!from_plain.empty());
        for (std::size_t i = 0; i < from_plain.size(); ++i) CHECK(same(from_plain[i], from_pruned[i]));
        CHECK_EQ(plain.late_events(), pruned.late_events());
        CHECK_EQ(plain.unreported_suppressed(), pruned.unreported_suppressed());
        CHECK(freed > 0);
        CHECK(pruned.tracked_service_windows() < plain.tracked_service_windows());
    }
}
