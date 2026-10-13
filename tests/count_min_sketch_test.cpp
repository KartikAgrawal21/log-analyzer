#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "loganalyzer/count_min_sketch.hpp"
#include "loganalyzer/hash.hpp"
#include "testkit.hpp"

using loganalyzer::CountMinSketch;
using loganalyzer::hash64;
using loganalyzer::mix64;

namespace {

constexpr std::uint64_t kMax = std::numeric_limits<std::uint64_t>::max();
constexpr double kE = 2.718281828459045;

// Everything below is integer arithmetic on mix64, so every stream and every pinned or
// thresholded number in this file is identical on every platform and compiler.
class Rng {
public:
    explicit Rng(std::uint64_t seed) : state_(seed) {}
    std::uint64_t next() { return mix64(state_++); }
    std::uint64_t below(std::uint64_t n) { return next() % n; }  // bias <= n / 2^64: irrelevant

private:
    std::uint64_t state_;
};

// Zipf(s = 1) over `n` ranks with integer weights floor(2^40 / (rank + 1)) and an
// inverse-CDF lookup by binary search: no floating point, no <random> distributions.
class Zipf {
public:
    explicit Zipf(std::size_t n) {
        std::uint64_t sum = 0;
        cumulative_.reserve(n);
        for (std::size_t i = 0; i < n; ++i) {
            sum += (std::uint64_t{1} << 40) / (static_cast<std::uint64_t>(i) + 1);
            cumulative_.push_back(sum);
        }
    }
    std::size_t draw(Rng& rng) const {
        const std::uint64_t x = rng.below(cumulative_.back());
        return static_cast<std::size_t>(std::upper_bound(cumulative_.begin(), cumulative_.end(), x) -
                                        cumulative_.begin());
    }

private:
    std::vector<std::uint64_t> cumulative_;
};

struct Workload {
    std::vector<std::string> keys;       // keys[rank]; every rank is a key of the universe
    std::vector<std::uint32_t> events;   // rank of each event
    std::vector<std::uint64_t> counts;   // count of each event
    std::vector<std::uint64_t> truth;    // exact total count per rank
    std::uint64_t total = 0;
    std::size_t distinct_seen() const {
        return static_cast<std::size_t>(std::count_if(truth.begin(), truth.end(), [](std::uint64_t t) { return t > 0; }));
    }
};

Workload make_workload(std::size_t universe, std::size_t events, std::uint64_t seed, std::uint64_t max_count = 1) {
    Workload w;
    Rng rng(seed);
    const Zipf zipf(universe);
    for (std::size_t r = 0; r < universe; ++r) w.keys.push_back("key-" + std::to_string(r));
    w.truth.assign(universe, 0);
    for (std::size_t i = 0; i < events; ++i) {
        const std::size_t rank = zipf.draw(rng);
        const std::uint64_t count = 1 + rng.below(max_count);
        w.events.push_back(static_cast<std::uint32_t>(rank));
        w.counts.push_back(count);
        w.truth[rank] += count;
        w.total += count;
    }
    return w;
}

enum class Mode { Standard, Conservative, Mixed };

void feed(CountMinSketch& s, const Workload& w, Mode mode, std::size_t begin = 0, std::size_t end = SIZE_MAX) {
    end = std::min(end, w.events.size());
    for (std::size_t i = begin; i < end; ++i) {
        const std::string& key = w.keys[w.events[i]];
        const bool conservative = mode == Mode::Conservative || (mode == Mode::Mixed && (mix64(i) & 1) != 0);
        if (conservative) {
            s.add_conservative(key, w.counts[i]);
        } else {
            s.add(key, w.counts[i]);
        }
    }
}

// The column the documented scheme assigns to `key` in `row`, written out independently of
// the class: h1 = hash64(key, seed), h2 = mix64(h1) | 1, column = (h1 + row * h2) mod 2^64 mod width.
std::size_t expected_column(const std::string& key, std::uint64_t seed, std::size_t width, std::size_t row) {
    const std::uint64_t h1 = hash64(key, seed);
    const std::uint64_t h2 = mix64(h1) | 1;
    return static_cast<std::size_t>((h1 + static_cast<std::uint64_t>(row) * h2) % width);
}

std::uint64_t fingerprint(const std::vector<std::uint64_t>& values) {
    std::uint64_t f = 0;
    for (std::uint64_t v : values) f = mix64(f ^ v);
    return f;
}

}  // namespace

// ---------------------------------------------------------------------------------------
// Construction and dimensions
// ---------------------------------------------------------------------------------------

TEST(CountMinSketch, ConstructorRejectsUnusableDimensions) {
    CHECK_THROWS(CountMinSketch(0, 1), std::invalid_argument);
    CHECK_THROWS(CountMinSketch(1, 0), std::invalid_argument);
    CHECK_THROWS(CountMinSketch(0, 0), std::invalid_argument);
    // Over the 2^31-cell cap (rejected before anything is allocated).
    CHECK_THROWS(CountMinSketch(65537, 32768), std::invalid_argument);  // 2^31 + 2^15
    if (sizeof(std::size_t) >= 8) {
        const std::size_t cap = static_cast<std::size_t>(CountMinSketch::kMaxCells);
        CHECK_THROWS(CountMinSketch(cap + 1, 1), std::invalid_argument);
        CHECK_THROWS(CountMinSketch(1, cap + 1), std::invalid_argument);
        CHECK_THROWS(CountMinSketch(cap / 2 + 1, 2), std::invalid_argument);
        CHECK_THROWS(CountMinSketch(2, cap / 2 + 1), std::invalid_argument);
        // A product that overflows size_t must not wrap around to a "small" table.
        const std::size_t huge = std::numeric_limits<std::size_t>::max();
        CHECK_THROWS(CountMinSketch(huge, 2), std::invalid_argument);
        CHECK_THROWS(CountMinSketch(2, huge), std::invalid_argument);
        CHECK_THROWS(CountMinSketch(huge, huge), std::invalid_argument);
        CHECK_THROWS(CountMinSketch(std::size_t{1} << 32, std::size_t{1} << 32), std::invalid_argument);
    }
}

TEST(CountMinSketch, AccessorsReportWhatWasAskedFor) {
    CountMinSketch s(100, 4, 7);
    CHECK_EQ(s.width(), 100u);
    CHECK_EQ(s.depth(), 4u);
    CHECK_EQ(s.seed(), 7ULL);
    CHECK_EQ(s.total(), 0ULL);
    CHECK_EQ(s.memory_bytes(), std::size_t{100 * 4 * 8});
    CHECK(std::abs(s.epsilon() - kE / 100.0) < 1e-15);
    CHECK(std::abs(s.delta() - std::exp(-4.0)) < 1e-15);
    CHECK_EQ(CountMinSketch(5, 5).seed(), 0ULL);  // default seed
    CHECK_EQ(CountMinSketch(1, 1).memory_bytes(), std::size_t{8});
    CountMinSketch large(1 << 16, 16);  // 8 MiB: a valid, fairly big table
    CHECK_EQ(large.memory_bytes(), std::size_t{(1u << 16) * 16u * 8u});
    CHECK_EQ(large.estimate("anything"), 0ULL);
}

TEST(CountMinSketch, CopyIsIndependentAndMoveLeavesTheSourceUsable) {
    CountMinSketch a(64, 3, 1);
    a.add("x", 5);
    CountMinSketch copy = a;
    copy.add("x", 2);
    CHECK_EQ(a.estimate("x"), 5ULL);
    CHECK_EQ(copy.estimate("x"), 7ULL);
    CHECK(a != copy);

    // There is no cheap valid empty state, so "move" is a documented copy.
    CountMinSketch moved(std::move(a));
    CHECK(moved.width() == 64 && moved.depth() == 3 && moved.seed() == 1);
    CHECK_EQ(moved.estimate("x"), 5ULL);
    CHECK_EQ(a.estimate("x"), 5ULL);  // NOLINT(bugprone-use-after-move): deliberate, see header
    a.add("y");
    CHECK_EQ(a.estimate("y"), 1ULL);

    CountMinSketch assigned(2, 2, 9);
    assigned = copy;
    CHECK(assigned == copy);
    assigned = std::move(copy);
    CHECK_EQ(copy.estimate("x"), 7ULL);  // NOLINT(bugprone-use-after-move)
}

TEST(CountMinSketch, WithErrorComputesTheDocumentedDimensions) {
    // width = ceil(e / epsilon), depth = ceil(ln(1 / delta)).
    struct Case {
        double epsilon, delta;
        std::size_t width, depth;
    };
    const Case cases[] = {
        {0.01, 0.01, 272, 5},     // 271.83 -> 272, 4.605 -> 5
        {0.001, 0.001, 2719, 7},  // 2718.28 -> 2719, 6.908 -> 7
        {0.1, 0.1, 28, 3},        // 27.18 -> 28, 2.303 -> 3
        {0.5, 0.5, 6, 1},         // 5.44 -> 6, 0.693 -> 1
        {0.999999, 0.999999, 3, 1},  // epsilon and delta just below 1: smallest useful tables
        {0.25, 0.3, 11, 2},       // 10.87 -> 11, 1.204 -> 2
    };
    for (const Case& c : cases) {
        const CountMinSketch s = CountMinSketch::with_error(c.epsilon, c.delta);
        if (s.width() != c.width || s.depth() != c.depth) {
            throw testkit::Failure{"with_error(" + std::to_string(c.epsilon) + ", " + std::to_string(c.delta) +
                                   ") gave " + std::to_string(s.width()) + " x " + std::to_string(s.depth()) +
                                   ", expected " + std::to_string(c.width) + " x " + std::to_string(c.depth)};
        }
        // The table is at least as good as asked for (a hair of slack for the rounding of e/width).
        CHECK(s.epsilon() <= c.epsilon * (1.0 + 1e-12));
        CHECK(s.delta() <= c.delta * (1.0 + 1e-9));
    }
    CHECK_EQ(CountMinSketch::with_error(0.1, 0.1, 99).seed(), 99ULL);
}

TEST(CountMinSketch, WithErrorWidthBoundaries) {
    // e / (e / 4) is exactly 4 in IEEE arithmetic (e / 4 is exact), so the width is exactly 4,
    // not 5; a hair smaller epsilon needs the next width.
    CHECK_EQ(CountMinSketch::with_error(kE / 4.0, 0.5).width(), 4u);
    CHECK_EQ(CountMinSketch::with_error(kE / 4.0 * (1.0 + 1e-9), 0.5).width(), 4u);
    CHECK_EQ(CountMinSketch::with_error(kE / 4.0 * (1.0 - 1e-9), 0.5).width(), 5u);
    // Monotone: tighter epsilon never shrinks the table.
    std::size_t previous = 0;
    for (double epsilon = 0.9; epsilon > 1e-4; epsilon *= 0.93) {
        const std::size_t width = CountMinSketch::with_error(epsilon, 0.5).width();
        CHECK(width >= previous);
        CHECK(static_cast<double>(width) >= kE / epsilon);
        CHECK(static_cast<double>(width) < kE / epsilon + 1.0);
        previous = width;
    }
}

TEST(CountMinSketch, WithErrorDepthBoundaries) {
    // ceil(ln(1 / delta)) is d exactly when delta is in [e^-d, e^-(d-1)): probe a hair on each
    // side of every e^-d, and the middle of every interval.
    for (int d = 1; d <= 60; ++d) {
        const double boundary = std::exp(-static_cast<double>(d));
        const double middle = std::exp(-(static_cast<double>(d) - 0.5));
        const std::size_t expected = static_cast<std::size_t>(d);
        CHECK_EQ(CountMinSketch::with_error(0.5, middle).depth(), expected);
        CHECK_EQ(CountMinSketch::with_error(0.5, boundary * (1.0 + 1e-6)).depth(), expected);      // ln just under d
        CHECK_EQ(CountMinSketch::with_error(0.5, boundary * (1.0 - 1e-6)).depth(), expected + 1);  // ln just over d
    }
    // The extremes of the range terminate and are about ln(1 / delta).
    CHECK_EQ(CountMinSketch::with_error(0.5, 1e-300).depth(), 691u);  // ln(1e300) = 690.78
    const std::size_t denormal_depth = CountMinSketch::with_error(0.5, 5e-324).depth();  // ln = 744.44
    CHECK(denormal_depth >= 744 && denormal_depth <= 746);
    CHECK_EQ(CountMinSketch::with_error(0.5, std::nextafter(1.0, 0.0)).depth(), 1u);
}

TEST(CountMinSketch, WithErrorRejectsArgumentsOutsideTheOpenUnitInterval) {
    const double nan = std::numeric_limits<double>::quiet_NaN();
    const double inf = std::numeric_limits<double>::infinity();
    for (double bad : {0.0, -0.0, 1.0, -0.1, 1.5, nan, inf, -inf}) {
        CHECK_THROWS(CountMinSketch::with_error(bad, 0.5), std::invalid_argument);
        CHECK_THROWS(CountMinSketch::with_error(0.5, bad), std::invalid_argument);
    }
    // Valid arguments that ask for a table that cannot exist.
    CHECK_THROWS(CountMinSketch::with_error(1e-12, 0.5), std::invalid_argument);   // width 2.7e12
    CHECK_THROWS(CountMinSketch::with_error(5e-324, 0.5), std::invalid_argument);  // e / epsilon = infinity
    CHECK_THROWS(CountMinSketch::with_error(1e-8, 1e-6), std::invalid_argument);   // 271828183 x 14 > 2^31
}

// ---------------------------------------------------------------------------------------
// Counting, hashing
// ---------------------------------------------------------------------------------------

TEST(CountMinSketch, EmptySketchEstimatesZero) {
    CountMinSketch s(32, 4, 3);
    CHECK_EQ(s.total(), 0ULL);
    CHECK_EQ(s.estimate(""), 0ULL);
    CHECK_EQ(s.estimate("anything"), 0ULL);
}

TEST(CountMinSketch, WideTableCountsExactlyAndAddsCounts) {
    // 2^16 columns for ~20 keys: a collision in every row is essentially impossible for this seed,
    // so the estimates are exact (they never undercount, and nothing inflates them).
    CountMinSketch s(1 << 16, 4, 11);
    s.add("alpha");
    s.add("alpha");
    s.add("alpha", 40);
    s.add("beta", 7);
    s.add("", 3);                      // the empty key is an ordinary key
    s.add(std::string("a\0b", 3), 5);  // embedded NUL: not the same key as "a"
    s.add("a", 2);
    s.add("A", 9);                     // case matters
    s.add(std::string(1000, 'x'), 6);  // long key
    CHECK_EQ(s.estimate("alpha"), 42ULL);
    CHECK_EQ(s.estimate("beta"), 7ULL);
    CHECK_EQ(s.estimate(""), 3ULL);
    CHECK_EQ(s.estimate(std::string("a\0b", 3)), 5ULL);
    CHECK_EQ(s.estimate("a"), 2ULL);
    CHECK_EQ(s.estimate("A"), 9ULL);
    CHECK_EQ(s.estimate(std::string(1000, 'x')), 6ULL);
    CHECK_EQ(s.estimate("gamma"), 0ULL);
    CHECK_EQ(s.total(), 42ULL + 7 + 3 + 5 + 2 + 9 + 6);
}

TEST(CountMinSketch, AddingZeroDoesNothing) {
    CountMinSketch s(16, 3, 5);
    const CountMinSketch fresh = s;
    s.add("x", 0);
    s.add_conservative("x", 0);
    CHECK_EQ(s.update_conservative("x", 0), 0ULL);
    CHECK(s == fresh);
    CHECK_EQ(s.total(), 0ULL);
    s.add("x", 4);
    const CountMinSketch before = s;
    s.add("x", 0);
    s.add_conservative("y", 0);
    CHECK(s == before);
    CHECK_EQ(s.update_conservative("x", 0), 4ULL);  // reports the current estimate
}

TEST(CountMinSketch, ColumnsFollowTheDocumentedDoubleHashing) {
    // A sketch holding one key x with count 11: estimate(y) is 11 exactly when y lands in x's
    // column in EVERY row (the minimum over rows is then x's counter), and 0 otherwise. The
    // expectation below is computed with the documented formula, independently of the class.
    for (std::size_t width : {std::size_t{5}, std::size_t{8}, std::size_t{13}}) {
        const std::uint64_t seed = 0x1234;
        const std::size_t depth = 3;
        CountMinSketch s(width, depth, seed);
        const std::string target = "target";
        s.add(target, 11);
        int full_collisions = 0;
        for (int i = 0; i < 4000; ++i) {
            const std::string key = "probe-" + std::to_string(i);
            bool collides_everywhere = true;
            for (std::size_t row = 0; row < depth; ++row) {
                if (expected_column(key, seed, width, row) != expected_column(target, seed, width, row)) {
                    collides_everywhere = false;
                }
            }
            full_collisions += collides_everywhere ? 1 : 0;
            if (s.estimate(key) != (collides_everywhere ? 11ULL : 0ULL)) {
                throw testkit::Failure{"width " + std::to_string(width) + ": " + key +
                                       " does not follow the documented column formula"};
            }
        }
        CHECK(full_collisions > 0);  // the check above was not vacuous
    }
}

// ---------------------------------------------------------------------------------------
// The guarantees
// ---------------------------------------------------------------------------------------

TEST(CountMinSketch, NeverUnderestimatesStandardConservativeAndMixedUpdates) {
    // Narrow tables put many keys in every counter: the hard case for "never too low".
    const std::size_t widths[] = {1, 5, 64, 300};
    int checked = 0;
    for (std::uint64_t seed = 1; seed <= 32; ++seed) {
        const Workload w = make_workload(300, 2500, 100 + seed, 5);
        const std::size_t width = widths[seed % 4];
        const std::size_t depth = 1 + static_cast<std::size_t>(seed % 5);
        for (Mode mode : {Mode::Standard, Mode::Conservative, Mode::Mixed}) {
            CountMinSketch s(width, depth, seed);
            feed(s, w, mode);
            CHECK_EQ(s.total(), w.total);
            for (std::size_t r = 0; r < w.keys.size(); ++r) {
                const std::uint64_t estimate = s.estimate(w.keys[r]);
                if (estimate < w.truth[r] || estimate > w.total) {
                    throw testkit::Failure{"seed " + std::to_string(seed) + " width " + std::to_string(width) +
                                           " depth " + std::to_string(depth) + ": " + w.keys[r] + " true " +
                                           std::to_string(w.truth[r]) + " estimate " + std::to_string(estimate) +
                                           " total " + std::to_string(w.total)};
                }
                ++checked;
            }
            for (int i = 0; i < 20; ++i) CHECK(s.estimate("never-added-" + std::to_string(i)) <= w.total);
        }
    }
    CHECK(checked == 32 * 3 * 300);
}

TEST(CountMinSketch, EstimatesOnlyGrowAsUpdatesArrive) {
    const Workload w = make_workload(100, 3000, 5, 3);
    CountMinSketch standard(20, 3, 4), conservative(20, 3, 4);
    std::vector<std::uint64_t> last_s(100, 0), last_c(100, 0);
    for (std::size_t i = 0; i < w.events.size(); ++i) {
        standard.add(w.keys[w.events[i]], w.counts[i]);
        conservative.add_conservative(w.keys[w.events[i]], w.counts[i]);
        if (i % 50 == 0) {
            for (std::size_t r = 0; r < 100; ++r) {
                const std::uint64_t es = standard.estimate(w.keys[r]);
                const std::uint64_t ec = conservative.estimate(w.keys[r]);
                CHECK(es >= last_s[r] && ec >= last_c[r]);
                last_s[r] = es;
                last_c[r] = ec;
            }
        }
    }
}

TEST(CountMinSketch, ConservativeUpdateReturnsTheNewEstimate) {
    const Workload w = make_workload(80, 2000, 9, 4);
    CountMinSketch s(16, 3, 2);
    for (std::size_t i = 0; i < w.events.size(); ++i) {
        const std::string& key = w.keys[w.events[i]];
        const std::uint64_t before = s.estimate(key);
        const std::uint64_t returned = s.update_conservative(key, w.counts[i]);
        CHECK_EQ(returned, s.estimate(key));
        CHECK_EQ(returned, before + w.counts[i]);  // the key's estimate rises by exactly the count
    }
}

TEST(CountMinSketch, ConservativeNeverExceedsStandardOnAnyKey) {
    std::uint64_t standard_error = 0, conservative_error = 0, mixed_error = 0;
    for (std::uint64_t seed = 1; seed <= 20; ++seed) {
        const Workload w = make_workload(400, 5000, 300 + seed, 3);
        CountMinSketch standard(64, 3, seed), conservative(64, 3, seed), mixed(64, 3, seed);
        feed(standard, w, Mode::Standard);
        feed(conservative, w, Mode::Conservative);
        feed(mixed, w, Mode::Mixed);
        for (std::size_t r = 0; r < w.keys.size(); ++r) {
            const std::uint64_t s = standard.estimate(w.keys[r]);
            const std::uint64_t c = conservative.estimate(w.keys[r]);
            const std::uint64_t m = mixed.estimate(w.keys[r]);
            if (c > s || m > s) {
                throw testkit::Failure{"seed " + std::to_string(seed) + " " + w.keys[r] + ": standard " +
                                       std::to_string(s) + " conservative " + std::to_string(c) + " mixed " +
                                       std::to_string(m)};
            }
            standard_error += s - w.truth[r];
            conservative_error += c - w.truth[r];
            mixed_error += m - w.truth[r];
        }
    }
    // Not just "never worse": on a table this crowded conservative update visibly helps.
    CHECK(conservative_error < standard_error);
    CHECK(mixed_error < standard_error);
    CHECK(conservative_error * 10 < standard_error * 9);  // at least 10% less total overestimate
}

TEST(CountMinSketch, ConservativeEqualsStandardWhereThereIsNothingToSave) {
    // depth 1: the single counter is the minimum, so "raise to min + count" is "add count".
    // width 1: every row holds the same number, same argument.
    for (auto dims : {std::pair<std::size_t, std::size_t>{50, 1}, std::pair<std::size_t, std::size_t>{1, 4},
                      std::pair<std::size_t, std::size_t>{1, 1}}) {
        const Workload w = make_workload(60, 1500, 21, 3);
        CountMinSketch standard(dims.first, dims.second, 6), conservative(dims.first, dims.second, 6);
        feed(standard, w, Mode::Standard);
        feed(conservative, w, Mode::Conservative);
        CHECK(standard == conservative);
    }
}

TEST(CountMinSketch, ErrorBoundHoldsStatisticallyAndTypicalErrorIsFarBelowIt) {
    // epsilon = delta = 0.01 -> a 272 x 5 table. Stream: 100,000 Zipf events over a universe of
    // 20,000 keys (about 10,000 distinct keys actually occur), N = 100,000, so epsilon * N = 1000.
    //
    // The claim is per key: Pr[error > epsilon * N] <= delta, so over the D ~ 10,000 distinct keys
    // of one stream the EXPECTED fraction exceeding the bound is at most delta = 1%. (Were the
    // failures independent with p = delta exactly, the fraction would have sd
    // sqrt(0.01 * 0.99 / 10000) ~ 0.001 and "fraction <= delta" would fail half of the time, so
    // this test is meaningful only because the true failure rate is far below delta; keys are not
    // independent either, so no binomial tail is claimed.) Measured on these fixed streams: the
    // worst fraction over the 6 seeds is 7.6e-5 (130x below delta) and the mean 1.3e-5. The margin
    // is the looseness of the proof (Markov allows 1/e per row, reality is several times smaller
    // per row, and the rows compound). We assert fraction <= delta on every seed and, with a
    // margin of 13x, worst and mean <= delta / 10. Streams and hashes are integer-exact, so these
    // numbers are identical on every platform: the margin protects against a code change that
    // weakens the sketch, not against chance.
    constexpr double epsilon = 0.01, delta = 0.01;
    constexpr int seeds = 6;
    double worst_fraction = 0, mean_fraction = 0;
    double standard_mean_error = 0, conservative_mean_error = 0, shallow_mean_fraction = 0;
    for (int seed = 1; seed <= seeds; ++seed) {
        const Workload w = make_workload(20000, 100000, 5000 + static_cast<std::uint64_t>(seed));
        const double bound = epsilon * static_cast<double>(w.total);
        CountMinSketch standard = CountMinSketch::with_error(epsilon, delta, static_cast<std::uint64_t>(seed));
        CountMinSketch conservative = CountMinSketch::with_error(epsilon, delta, static_cast<std::uint64_t>(seed));
        // Control: the same width but depth 1 must NOT meet the bound, or this test proves nothing.
        CountMinSketch shallow(standard.width(), 1, static_cast<std::uint64_t>(seed));
        feed(standard, w, Mode::Standard);
        feed(conservative, w, Mode::Conservative);
        feed(shallow, w, Mode::Standard);

        std::size_t exceeding = 0, shallow_exceeding = 0;
        double error_sum = 0, conservative_error_sum = 0;
        for (std::size_t r = 0; r < w.keys.size(); ++r) {
            if (w.truth[r] == 0) continue;
            const double e_std = static_cast<double>(standard.estimate(w.keys[r]) - w.truth[r]);
            const double e_con = static_cast<double>(conservative.estimate(w.keys[r]) - w.truth[r]);
            const double e_shallow = static_cast<double>(shallow.estimate(w.keys[r]) - w.truth[r]);
            if (e_std > bound) ++exceeding;
            if (e_shallow > bound) ++shallow_exceeding;
            error_sum += e_std;
            conservative_error_sum += e_con;
        }
        const double distinct = static_cast<double>(w.distinct_seen());
        const double fraction = static_cast<double>(exceeding) / distinct;
        CHECK(fraction <= delta);
        worst_fraction = std::max(worst_fraction, fraction);
        mean_fraction += fraction / seeds;
        shallow_mean_fraction += static_cast<double>(shallow_exceeding) / distinct / seeds;
        standard_mean_error += error_sum / distinct / bound / seeds;
        conservative_mean_error += conservative_error_sum / distinct / bound / seeds;
    }
    CHECK(worst_fraction <= delta / 10.0);
    CHECK(mean_fraction <= delta / 10.0);
    // Measured: depth 1 exceeds the bound for ~4.7% of the keys (> delta); depth 5 for ~0.001%.
    CHECK(shallow_mean_fraction > delta);
    // Typical error: measured 0.138 * epsilon * N for standard and 0.077 for conservative.
    CHECK(standard_mean_error <= 0.25);
    CHECK(conservative_mean_error <= 0.125);
    CHECK(conservative_mean_error < standard_mean_error);
}

// ---------------------------------------------------------------------------------------
// Merging
// ---------------------------------------------------------------------------------------

TEST(CountMinSketch, MergeOfStandardSketchesIsCellForCellTheSketchOfTheConcatenation) {
    const Workload w = make_workload(500, 6000, 31, 4);
    const std::size_t cut1 = 1000, cut2 = 4100;  // deliberately uneven parts
    CountMinSketch whole(100, 4, 8), a(100, 4, 8), b(100, 4, 8), c(100, 4, 8);
    feed(whole, w, Mode::Standard);
    feed(a, w, Mode::Standard, 0, cut1);
    feed(b, w, Mode::Standard, cut1, cut2);
    feed(c, w, Mode::Standard, cut2);

    CountMinSketch left = a;  // (a + b) + c
    left.merge(b);
    left.merge(c);
    CHECK(left == whole);  // every counter, the total, the dimensions and the seed

    CountMinSketch right = c;  // c + (b + a): merge is commutative and associative
    CountMinSketch ba = b;
    ba.merge(a);
    right.merge(ba);
    CHECK(right == whole);

    for (std::size_t r = 0; r < w.keys.size(); ++r) {
        CHECK_EQ(left.estimate(w.keys[r]), whole.estimate(w.keys[r]));
    }
    CHECK_EQ(left.total(), w.total);

    CountMinSketch empty(100, 4, 8);
    CountMinSketch with_empty = whole;
    with_empty.merge(empty);
    CHECK(with_empty == whole);
    empty.merge(whole);
    CHECK(empty == whole);
}

TEST(CountMinSketch, MergeWithItselfDoublesEveryCounter) {
    const Workload w = make_workload(100, 1500, 41, 3);
    CountMinSketch s(40, 3, 2), twice(40, 3, 2);
    feed(s, w, Mode::Standard);
    feed(twice, w, Mode::Standard);
    feed(twice, w, Mode::Standard);  // the stream followed by itself
    s.merge(s);
    CHECK(s == twice);
}

TEST(CountMinSketch, MergeRejectsMismatchedDimensionsOrSeedAndChangesNothing) {
    CountMinSketch base(32, 3, 7);
    base.add("k", 5);
    const CountMinSketch snapshot = base;
    const CountMinSketch wrong_width(33, 3, 7), wrong_depth(32, 4, 7), wrong_seed(32, 3, 8);
    CHECK_THROWS(base.merge(wrong_width), std::invalid_argument);
    CHECK_THROWS(base.merge(wrong_depth), std::invalid_argument);
    CHECK_THROWS(base.merge(wrong_seed), std::invalid_argument);
    CHECK(base == snapshot);
    // Same cell count but a different shape is still a mismatch (2 x 6 vs 3 x 4 vs 4 x 3).
    CountMinSketch shape_a(6, 2, 1);
    const CountMinSketch shape_b(4, 3, 1), shape_c(3, 4, 1);
    CHECK_THROWS(shape_a.merge(shape_b), std::invalid_argument);
    CHECK_THROWS(shape_a.merge(shape_c), std::invalid_argument);
}

TEST(CountMinSketch, MergeAfterConservativeUpdatesStaysAnUpperBound) {
    // A conservative counter is not a sum of counts, so merged != conservative(concatenation) in
    // general, but every key's counters are >= its count in each half, so the sum is >= the total.
    for (std::uint64_t seed = 1; seed <= 12; ++seed) {
        const Workload w = make_workload(300, 4000, 700 + seed, 3);
        const std::size_t cut = 1700;
        CountMinSketch a(48, 3, seed), b(48, 3, seed), standard_whole(48, 3, seed), conservative_whole(48, 3, seed);
        feed(a, w, Mode::Conservative, 0, cut);
        feed(b, w, Mode::Mixed, cut);
        feed(standard_whole, w, Mode::Standard);
        feed(conservative_whole, w, Mode::Conservative);
        a.merge(b);
        CHECK_EQ(a.total(), w.total);
        for (std::size_t r = 0; r < w.keys.size(); ++r) {
            const std::uint64_t merged = a.estimate(w.keys[r]);
            if (merged < w.truth[r]) {
                throw testkit::Failure{"seed " + std::to_string(seed) + ": merged conservative sketch underestimates " +
                                       w.keys[r]};
            }
            // Still bounded by the standard sketch of the concatenation (so the epsilon/delta bound holds).
            CHECK(merged <= standard_whole.estimate(w.keys[r]));
            CHECK(conservative_whole.estimate(w.keys[r]) >= w.truth[r]);
        }
    }
}

// ---------------------------------------------------------------------------------------
// Saturation
// ---------------------------------------------------------------------------------------

TEST(CountMinSketch, CountersAndTotalSaturateInsteadOfWrapping) {
    CountMinSketch s(16, 3, 1);
    s.add("a", kMax);
    CHECK_EQ(s.estimate("a"), kMax);
    CHECK_EQ(s.total(), kMax);
    s.add("a", 1);  // would wrap to 0
    CHECK_EQ(s.estimate("a"), kMax);
    CHECK_EQ(s.total(), kMax);
    s.add("a", kMax);
    CHECK_EQ(s.estimate("a"), kMax);
    s.add("b", 5);  // other keys still count; the total stays pinned
    CHECK(s.estimate("b") >= 5ULL);
    CHECK_EQ(s.total(), kMax);

    // Approaching the limit in steps, one shared counter (width 1): exact until the very end.
    CountMinSketch one(1, 2, 1);
    one.add("x", kMax - 3);
    CHECK_EQ(one.estimate("x"), kMax - 3);
    one.add("y", 2);
    CHECK_EQ(one.estimate("anything"), kMax - 1);
    CHECK_EQ(one.total(), kMax - 1);
    one.add("z", 10);  // kMax - 1 + 10 overflows
    CHECK_EQ(one.estimate("x"), kMax);
    CHECK_EQ(one.total(), kMax);
}

TEST(CountMinSketch, ConservativeUpdateAndMergeSaturate) {
    CountMinSketch s(1, 3, 1);
    CHECK_EQ(s.update_conservative("x", kMax - 3), kMax - 3);
    CHECK_EQ(s.update_conservative("y", 10), kMax);  // min + count overflows: clamped, not wrapped
    CHECK_EQ(s.estimate("x"), kMax);
    CHECK_EQ(s.total(), kMax);
    s.add_conservative("z", kMax);
    CHECK_EQ(s.estimate("z"), kMax);
    CHECK_EQ(s.update_conservative("z", 1), kMax);

    CountMinSketch a(1, 2, 3), b(1, 2, 3);
    a.add("p", kMax - 1);
    b.add("q", 5);
    a.merge(b);
    CHECK_EQ(a.estimate("p"), kMax);
    CHECK_EQ(a.total(), kMax);

    // Saturation never lowers an estimate: a saturated counter stays an upper bound.
    CountMinSketch c(4, 2, 3);
    c.add("k", kMax);
    for (int i = 0; i < 100; ++i) c.add("k");
    CHECK_EQ(c.estimate("k"), kMax);
}

TEST(CountMinSketch, SaturatedMergeEqualsSaturatedConcatenation) {
    // Saturating addition of non-negative numbers is min(sum, kMax), so merge stays exact.
    CountMinSketch whole(8, 3, 4), a(8, 3, 4), b(8, 3, 4);
    const std::uint64_t big = kMax / 2 + 7;
    for (const char* key : {"u", "v", "w"}) {
        whole.add(key, big);
        whole.add(key, big);
        a.add(key, big);
        b.add(key, big);
    }
    a.merge(b);
    CHECK(a == whole);
    CHECK_EQ(whole.estimate("u"), kMax);
}

// ---------------------------------------------------------------------------------------
// Edge cases, clear, determinism
// ---------------------------------------------------------------------------------------

TEST(CountMinSketch, WidthOneAndDepthOneEdgeCases) {
    // width 1: every key shares the single column, so every estimate is the total.
    CountMinSketch narrow(1, 3, 2);
    narrow.add("a", 4);
    narrow.add("b", 6);
    narrow.add_conservative("c", 1);
    CHECK_EQ(narrow.estimate("a"), 11ULL);
    CHECK_EQ(narrow.estimate("never-seen"), 11ULL);
    CHECK_EQ(narrow.total(), 11ULL);

    // depth 1 is a plain hashed counter array: collisions are never filtered out.
    CountMinSketch shallow(1000, 1, 2);
    for (int i = 0; i < 50; ++i) shallow.add("key-" + std::to_string(i), 2);
    for (int i = 0; i < 50; ++i) CHECK(shallow.estimate("key-" + std::to_string(i)) >= 2ULL);

    CountMinSketch tiny(1, 1, 0);
    CHECK_EQ(tiny.estimate("x"), 0ULL);
    tiny.add("x", 3);
    CHECK_EQ(tiny.estimate("x"), 3ULL);
    CHECK_EQ(tiny.estimate("y"), 3ULL);
    CHECK_EQ(tiny.memory_bytes(), std::size_t{8});

    // Every depth: the rows of one key never lose counts, even when width < depth.
    for (std::size_t depth = 1; depth <= 9; ++depth) {
        CountMinSketch s(4, depth, 5);
        s.add("k", 3);
        CHECK_EQ(s.estimate("k"), 3ULL);
    }
}

TEST(CountMinSketch, ClearRestoresTheFreshState) {
    const Workload w = make_workload(100, 2000, 51, 3);
    CountMinSketch s(30, 3, 12);
    const CountMinSketch fresh = s;
    feed(s, w, Mode::Mixed);
    CHECK(s != fresh);
    s.clear();
    CHECK(s == fresh);
    CHECK_EQ(s.total(), 0ULL);
    CHECK(s.width() == 30 && s.depth() == 3 && s.seed() == 12);
    for (const std::string& key : w.keys) CHECK_EQ(s.estimate(key), 0ULL);
    // Reusable: the same stream gives the same table as on a brand new sketch.
    CountMinSketch again(30, 3, 12);
    feed(s, w, Mode::Standard);
    feed(again, w, Mode::Standard);
    CHECK(s == again);
}

TEST(CountMinSketch, SameSeedGivesTheSameTableDifferentSeedsGiveDifferentLayouts) {
    const Workload w = make_workload(400, 4000, 61);
    CountMinSketch a(64, 2, 1), b(64, 2, 1), other(64, 2, 2);
    feed(a, w, Mode::Standard);
    feed(b, w, Mode::Standard);
    feed(other, w, Mode::Standard);
    CHECK(a == b);
    CHECK(a != other);
    // Different seeds collide different keys: on a table this narrow most estimates differ.
    std::size_t differing = 0;
    for (const std::string& key : w.keys) differing += a.estimate(key) != other.estimate(key) ? 1 : 0;
    CHECK(differing * 2 > w.keys.size());
    // Both are valid sketches of the same stream.
    for (std::size_t r = 0; r < w.keys.size(); ++r) {
        CHECK(a.estimate(w.keys[r]) >= w.truth[r] && other.estimate(w.keys[r]) >= w.truth[r]);
    }
}

// ---------------------------------------------------------------------------------------
// Golden values
// ---------------------------------------------------------------------------------------

// Pinned from an independent Python re-implementation written from the specification
// (hash64 and mix64 ported from hash.hpp and validated against the vectors in hash_test.cpp
// first; then double hashing, standard and conservative updates). A change of platform,
// compiler, hash, column formula or update rule changes these numbers. To regenerate them:
//
//   M = (1 << 64) - 1                                       # hash64 / mix64 as in hash_test.cpp's port
//   def cols(key, w, d, seed):
//       h1 = hash64(key, seed); h2 = mix64(h1) | 1
//       return [((h1 + i * h2) & M) % w for i in range(d)]  # row i, column
//   standard:      for r, c in enumerate(cols(...)): cell[r][c] += count
//   conservative:  t = min(cell[r][c] for r, c in enumerate(cols(...))) + count
//                  for r, c in enumerate(cols(...)): cell[r][c] = max(cell[r][c], t)
//   estimate:      min(cell[r][c] for r, c in enumerate(cols(...)))
//   fingerprint:   f = 0; for e in estimates of item-0 .. item-249: f = mix64(f ^ e)
//
// Stream: event i (0 <= i < 20000): r = mix64(0xC0DE0000 + i), u = r % 1000,
// key = "item-" + str(u*u / 4000), count = 1 + ((r >> 32) % 4).
// Sketch: width 61, depth 3, seed 0xC0FFEE (narrow on purpose: heavy collisions).
TEST(CountMinSketch, GoldenValuesMatchTheIndependentPythonImplementation) {
    CountMinSketch standard(61, 3, 0xC0FFEE), conservative(61, 3, 0xC0FFEE);
    for (std::uint64_t i = 0; i < 20000; ++i) {
        const std::uint64_t r = mix64(0xC0DE0000ULL + i);
        const std::uint64_t u = r % 1000;
        const std::string key = "item-" + std::to_string(u * u / 4000);
        const std::uint64_t count = 1 + ((r >> 32) % 4);
        standard.add(key, count);
        conservative.add_conservative(key, count);
    }
    auto estimates = [](const CountMinSketch& s) {
        std::vector<std::uint64_t> all;
        for (int rank = 0; rank < 250; ++rank) all.push_back(s.estimate("item-" + std::to_string(rank)));
        return all;
    };
    const std::vector<std::uint64_t> std_est = estimates(standard);
    const std::vector<std::uint64_t> con_est = estimates(conservative);

    CHECK_EQ(standard.total(), 49949ULL);
    CHECK_EQ(conservative.total(), 49949ULL);

    CHECK_EQ(std_est[0], 3760ULL);
    CHECK_EQ(std_est[1], 1844ULL);
    CHECK_EQ(std_est[7], 538ULL);
    CHECK_EQ(std_est[100], 1198ULL);
    CHECK_EQ(std_est[249], 675ULL);
    CHECK_EQ(standard.estimate("item-250"), 693ULL);  // never added: pure collision noise
    CHECK_EQ(fingerprint(std_est), 0xc7d04e9c7474075dULL);

    CHECK_EQ(con_est[0], 3174ULL);
    CHECK_EQ(con_est[1], 1421ULL);
    CHECK_EQ(con_est[7], 538ULL);
    CHECK_EQ(con_est[100], 422ULL);
    CHECK_EQ(con_est[249], 386ULL);
    CHECK_EQ(conservative.estimate("item-250"), 422ULL);
    CHECK_EQ(fingerprint(con_est), 0xa133590d31953785ULL);

    // Sanity on the golden numbers themselves: the two layers of guarantees.
    for (std::size_t i = 0; i < 250; ++i) CHECK(con_est[i] <= std_est[i]);
}
