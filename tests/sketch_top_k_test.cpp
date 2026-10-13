#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "loganalyzer/count_min_sketch.hpp"
#include "loganalyzer/hash.hpp"
#include "loganalyzer/sketch_top_k.hpp"
#include "testkit.hpp"

using loganalyzer::CountMinSketch;
using loganalyzer::HeavyHitter;
using loganalyzer::mix64;
using loganalyzer::SketchTopK;

namespace {

constexpr std::uint64_t kMax = std::numeric_limits<std::uint64_t>::max();

// Integer-only generators (see count_min_sketch_test.cpp): every stream in this file, and so every
// thresholded or pinned number, is identical on every platform and compiler.
class Rng {
public:
    explicit Rng(std::uint64_t seed) : state_(seed) {}
    std::uint64_t next() { return mix64(state_++); }
    std::uint64_t below(std::uint64_t n) { return next() % n; }

private:
    std::uint64_t state_;
};

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
    std::vector<std::string> keys;
    std::vector<std::uint32_t> events;
    std::vector<std::uint64_t> counts;
    std::vector<std::uint64_t> truth;
    std::uint64_t total = 0;
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

void feed(SketchTopK& t, const Workload& w) {
    for (std::size_t i = 0; i < w.events.size(); ++i) t.add(w.keys[w.events[i]], w.counts[i]);
}

// Exact top-k by brute force: count everything, sort everything. estimate descending, key ascending.
std::vector<HeavyHitter> brute_force_top(const Workload& w, std::size_t k) {
    std::vector<std::size_t> seen;  // ranks that occurred
    for (std::size_t r = 0; r < w.truth.size(); ++r) {
        if (w.truth[r] > 0) seen.push_back(r);
    }
    const std::size_t take = std::min(k, seen.size());
    std::partial_sort(seen.begin(), seen.begin() + static_cast<std::ptrdiff_t>(take), seen.end(),
                      [&w](std::size_t a, std::size_t b) {
                          return w.truth[a] != w.truth[b] ? w.truth[a] > w.truth[b] : w.keys[a] < w.keys[b];
                      });
    std::vector<HeavyHitter> result;
    for (std::size_t i = 0; i < take; ++i) result.push_back(HeavyHitter{w.keys[seen[i]], w.truth[seen[i]]});
    return result;
}

std::string describe(const std::vector<HeavyHitter>& v) {
    std::string out = "[";
    for (const HeavyHitter& h : v) out += " " + h.key + ":" + std::to_string(h.estimate);
    return out + " ]";
}

void expect_same(const std::vector<HeavyHitter>& got, const std::vector<HeavyHitter>& want, const std::string& context) {
    if (got != want) {
        throw testkit::Failure{context + ": got " + describe(got) + ", expected " + describe(want)};
    }
}

// (estimate, key) beats (other_estimate, other_key) in the result order.
bool beats(std::uint64_t estimate, const std::string& key, std::uint64_t other_estimate, const std::string& other_key) {
    return estimate > other_estimate || (estimate == other_estimate && key < other_key);
}

// A deliberately naive tracker with the documented semantics: the same conservative sketch, but the
// candidate set is a std::map and the weakest candidate is found by scanning all of it. SketchTopK
// (lazy heap, stale entries, compaction, node reuse) must agree with it after every single add.
class NaiveTopK {
public:
    NaiveTopK(std::size_t k, std::size_t width, std::size_t depth, std::uint64_t seed)
        : k_(k), sketch_(width, depth, seed) {}

    void add(const std::string& key, std::uint64_t count) {
        if (count == 0) return;
        sketch_.add_conservative(key, count);
        const std::uint64_t estimate = sketch_.estimate(key);
        auto it = candidates_.find(key);
        if (it != candidates_.end()) {
            it->second = estimate;
        } else if (candidates_.size() < k_) {
            candidates_[key] = estimate;
        } else {
            auto weakest = candidates_.begin();
            for (auto c = candidates_.begin(); c != candidates_.end(); ++c) {
                if (beats(weakest->second, weakest->first, c->second, c->first)) weakest = c;
            }
            if (beats(estimate, key, weakest->second, weakest->first)) {
                candidates_.erase(weakest);
                candidates_[key] = estimate;
            }
        }
    }

    std::vector<HeavyHitter> top() const {
        std::vector<HeavyHitter> result;
        for (const auto& c : candidates_) result.push_back(HeavyHitter{c.first, c.second});
        std::sort(result.begin(), result.end(), [](const HeavyHitter& a, const HeavyHitter& b) {
            return beats(a.estimate, a.key, b.estimate, b.key);
        });
        return result;
    }

private:
    std::size_t k_;
    CountMinSketch sketch_;
    std::map<std::string, std::uint64_t> candidates_;
};

}  // namespace

// ---------------------------------------------------------------------------------------
// Construction, trivial cases
// ---------------------------------------------------------------------------------------

TEST(SketchTopK, ConstructorValidatesItsArguments) {
    CHECK_THROWS(SketchTopK(0, 64, 3), std::invalid_argument);
    CHECK_THROWS(SketchTopK(5, 0, 3), std::invalid_argument);
    CHECK_THROWS(SketchTopK(5, 64, 0), std::invalid_argument);
    CHECK_THROWS(SketchTopK(5, 65537, 32768), std::invalid_argument);  // sketch over the 2^31-cell cap
    SketchTopK t(5, 64, 3, 9);
    CHECK_EQ(t.k(), 5u);
    CHECK_EQ(t.total(), 0ULL);
    CHECK(t.top().empty());
    CHECK_EQ(t.candidate_count(), 0u);
    CHECK_EQ(t.heap_entries(), 0u);
    CHECK(t.sketch().width() == 64 && t.sketch().depth() == 3 && t.sketch().seed() == 9);
    CHECK(t.memory_bytes() >= t.sketch().memory_bytes());
    CHECK(t.memory_bytes() < t.sketch().memory_bytes() + 4096);  // nothing tracked yet: bookkeeping is tiny
    SketchTopK defaulted_seed(1, 8, 2);
    CHECK_EQ(defaulted_seed.sketch().seed(), 0ULL);
}

TEST(SketchTopK, HeavyHitterComparesByKeyAndEstimate) {
    const HeavyHitter a{"a", 3};
    CHECK((a == HeavyHitter{"a", 3}));
    CHECK((a != HeavyHitter{"a", 4}));
    CHECK((a != HeavyHitter{"b", 3}));
    CHECK_EQ(HeavyHitter().estimate, 0ULL);
    CHECK(HeavyHitter().key.empty());
}

TEST(SketchTopK, ZeroCountAddsAreIgnoredEntirely) {
    SketchTopK t(3, 64, 3, 1);
    const CountMinSketch fresh = t.sketch();
    t.add("x", 0);
    CHECK_EQ(t.total(), 0ULL);
    CHECK(t.top().empty());
    CHECK_EQ(t.candidate_count(), 0u);
    CHECK(t.sketch() == fresh);
    t.add("x", 2);
    t.add("y", 0);
    CHECK_EQ(t.candidate_count(), 1u);
    CHECK_EQ(t.top().size(), 1u);
}

TEST(SketchTopK, RepeatedAddsOfOneKeyKeepOneCandidateAndABoundedHeap) {
    constexpr std::size_t k = 3;
    SketchTopK t(k, 1024, 4, 5);
    for (int i = 1; i <= 5000; ++i) {
        t.add("only");
        if (t.heap_entries() > 2 * k) throw testkit::Failure{"heap grew past 2k at add " + std::to_string(i)};
    }
    CHECK_EQ(t.total(), 5000ULL);
    CHECK_EQ(t.candidate_count(), 1u);
    expect_same(t.top(), {HeavyHitter{"only", 5000}}, "repeated adds");

    // Once the counters saturate the estimate stops changing: no more heap entries are pushed.
    t.add("only", kMax);
    CHECK_EQ(t.top().front().estimate, kMax);
    const std::size_t heap_after_saturation = t.heap_entries();
    for (int i = 0; i < 1000; ++i) t.add("only");
    CHECK_EQ(t.heap_entries(), heap_after_saturation);
    CHECK_EQ(t.total(), kMax);
    CHECK_EQ(t.top().front().estimate, kMax);
}

TEST(SketchTopK, KLargerThanTheNumberOfDistinctKeysReturnsEveryKey) {
    for (std::size_t k : {std::size_t{100}, std::numeric_limits<std::size_t>::max() / 2 + 1,
                          std::numeric_limits<std::size_t>::max()}) {
        // A huge k must neither pre-allocate nor overflow the 2k heap limit.
        SketchTopK t(k, 4096, 4, 3);
        t.add("c", 3);
        t.add("a", 1);
        t.add("b", 3);
        t.add("d", 7);
        t.add("a", 1);
        t.add("e");
        expect_same(t.top(), {HeavyHitter{"d", 7}, HeavyHitter{"b", 3}, HeavyHitter{"c", 3}, HeavyHitter{"a", 2},
                              HeavyHitter{"e", 1}},
                    "k=" + std::to_string(k));
        CHECK_EQ(t.candidate_count(), 5u);
        CHECK_EQ(t.k(), k);
    }
}

TEST(SketchTopK, KeyOrderingIsBytewiseUnsignedAndTheEmptyKeyIsAKey) {
    SketchTopK t(10, 1 << 14, 4, 2);
    const std::string high = "\xff";
    const std::string nul("a\0b", 3);
    t.add(high, 2);
    t.add("a", 2);
    t.add("", 2);
    t.add(nul, 2);
    t.add("a\x01", 2);
    t.add("B", 5);
    // Ties on 2 resolve by key ascending, bytes compared as UNSIGNED: "" < "a" < "a\0b" < "a\x01" < "\xff".
    expect_same(t.top(), {HeavyHitter{"B", 5}, HeavyHitter{"", 2}, HeavyHitter{"a", 2}, HeavyHitter{nul, 2},
                          HeavyHitter{"a\x01", 2}, HeavyHitter{high, 2}},
                "byte order");
}

// ---------------------------------------------------------------------------------------
// Tie-breaking and admission rules
// ---------------------------------------------------------------------------------------

TEST(SketchTopK, EqualCountsKeepTheSmallestKeysWhateverTheArrivalOrder) {
    const std::vector<std::string> ascending = {"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"};
    std::vector<std::string> descending(ascending.rbegin(), ascending.rend());
    std::vector<std::string> shuffled = ascending;
    Rng rng(4);
    for (std::size_t i = shuffled.size(); i > 1; --i) std::swap(shuffled[i - 1], shuffled[rng.below(i)]);
    const std::vector<std::string>* const orders[] = {&ascending, &descending, &shuffled};
    for (const std::vector<std::string>* order : orders) {
        SketchTopK t(3, 1 << 14, 4, 6);
        for (int round = 0; round < 4; ++round) {
            for (const std::string& key : *order) t.add(key);
        }
        expect_same(t.top(), {HeavyHitter{"a", 4}, HeavyHitter{"b", 4}, HeavyHitter{"c", 4}}, "equal counts");
    }
}

TEST(SketchTopK, ANewcomerTyingTheWeakestCandidateWinsOnlyWithTheSmallerKey) {
    SketchTopK t(2, 1 << 14, 4, 8);
    t.add("m", 3);
    t.add("n", 3);
    expect_same(t.top(), {HeavyHitter{"m", 3}, HeavyHitter{"n", 3}}, "initial");
    t.add("z", 3);  // ties the weakest ("n" is weaker than "m": larger key) but has the larger key: rejected
    expect_same(t.top(), {HeavyHitter{"m", 3}, HeavyHitter{"n", 3}}, "z rejected");
    t.add("a", 3);  // ties but is smaller than "n": evicts "n", not "m"
    expect_same(t.top(), {HeavyHitter{"a", 3}, HeavyHitter{"m", 3}}, "a evicts n");
    t.add("b", 2);  // below the weakest estimate: rejected
    expect_same(t.top(), {HeavyHitter{"a", 3}, HeavyHitter{"m", 3}}, "b rejected");
    t.add("m");  // a candidate grows in place
    expect_same(t.top(), {HeavyHitter{"m", 4}, HeavyHitter{"a", 3}}, "m grows");
    t.add("b", 2);  // the sketch remembered b's first 2: now 4 and the key beats "a" (3)
    expect_same(t.top(), {HeavyHitter{"b", 4}, HeavyHitter{"m", 4}}, "b returns with its history");
}

TEST(SketchTopK, AnEvictedKeyComesBackWithEverythingTheSketchRemembered) {
    SketchTopK t(1, 1 << 14, 4, 3);
    t.add("a", 5);
    t.add("b", 6);  // evicts a
    expect_same(t.top(), {HeavyHitter{"b", 6}}, "b evicts a");
    t.add("a", 2);  // a's 5 earlier occurrences are still in the sketch: 7 > 6
    expect_same(t.top(), {HeavyHitter{"a", 7}}, "a returns");
    CHECK_EQ(t.total(), 13ULL);
}

TEST(SketchTopK, ReportedEstimatesAreAsOfTheKeysLastAddNotTheSketchsCurrentOne) {
    // width 1: every key shares one counter, so the sketch's estimate of ANY key is the total.
    SketchTopK t(2, 1, 1, 0);
    t.add("a");  // recorded 1
    t.add("b");  // recorded 2; the shared counter is now 2, so the sketch says a == 2 too
    expect_same(t.top(), {HeavyHitter{"b", 2}, HeavyHitter{"a", 1}}, "as of last add");
    CHECK_EQ(t.sketch().estimate("a"), 2ULL);
    // Both facts of the contract: >= the true count (1), <= the sketch's current estimate (2).
    for (const HeavyHitter& h : t.top()) CHECK(h.estimate <= t.sketch().estimate(h.key));
}

// ---------------------------------------------------------------------------------------
// The exact regime, and the reference model
// ---------------------------------------------------------------------------------------

TEST(SketchTopK, ExactRegimeEqualsBruteForceTopK) {
    // 65,536 columns for ~200 keys: each key has a collision-free row, so every estimate is exact
    // and top() must be exactly the true top-k, ties by key, counts included.
    int compared = 0;
    for (std::uint64_t seed = 1; seed <= 5; ++seed) {
        const Workload w = make_workload(200, 10000, 900 + seed, 3);
        for (std::size_t k : {std::size_t{1}, std::size_t{2}, std::size_t{3}, std::size_t{10}, std::size_t{50},
                              std::size_t{199}, std::size_t{200}, std::size_t{1000}}) {
            SketchTopK t(k, 1 << 16, 4, seed);
            feed(t, w);
            expect_same(t.top(), brute_force_top(w, k), "seed " + std::to_string(seed) + " k " + std::to_string(k));
            CHECK_EQ(t.total(), w.total);
            ++compared;
        }
    }
    CHECK_EQ(compared, 40);
}

TEST(SketchTopK, MatchesANaiveReferenceAfterEveryAddEvenWhenCollisionsAreHeavy) {
    // Tiny tables and tiny counts: constant collisions, constant ties, constant evictions, so the
    // lazy heap (stale entries, compaction every ~k adds, node reuse) is exercised on every path.
    // The reference scans every candidate to find the weakest.
    for (std::size_t k : {std::size_t{1}, std::size_t{2}, std::size_t{3}, std::size_t{7}, std::size_t{20}}) {
        for (std::uint64_t seed = 1; seed <= 4; ++seed) {
            const Workload w = make_workload(60, 2500, 40 * seed + k, 2);
            const std::size_t width = 4 + 5 * static_cast<std::size_t>(seed);
            const std::size_t depth = 1 + static_cast<std::size_t>(seed % 3);
            SketchTopK t(k, width, depth, seed);
            NaiveTopK reference(k, width, depth, seed);
            for (std::size_t i = 0; i < w.events.size(); ++i) {
                t.add(w.keys[w.events[i]], w.counts[i]);
                reference.add(w.keys[w.events[i]], w.counts[i]);
                if (t.heap_entries() > 2 * k) throw testkit::Failure{"heap exceeded 2k"};
                if (i % 7 == 0 || i + 1 == w.events.size()) {
                    expect_same(t.top(), reference.top(),
                                "k " + std::to_string(k) + " seed " + std::to_string(seed) + " after add " +
                                    std::to_string(i));
                }
            }
        }
    }
}

TEST(SketchTopK, ReportsOnlyKeysItSawAndNeverUndercountsAndMissingKeysAreOutrankedByInflatedOnes) {
    int checked_missing = 0;
    for (std::uint64_t seed = 1; seed <= 8; ++seed) {
        const Workload w = make_workload(300, 5000, 60 + seed, 3);
        for (std::size_t k : {std::size_t{1}, std::size_t{5}, std::size_t{20}}) {
            const std::size_t width = 16 + 16 * static_cast<std::size_t>(seed % 4);
            SketchTopK t(k, width, 2 + static_cast<std::size_t>(seed % 2), seed);
            feed(t, w);
            const std::vector<HeavyHitter> top = t.top();
            CHECK_EQ(top.size(), k);  // 300 distinct keys were seen: the set is full
            std::map<std::string, std::size_t> rank_of;
            for (std::size_t i = 0; i < w.keys.size(); ++i) rank_of[w.keys[i]] = i;
            std::map<std::string, bool> reported;
            for (std::size_t i = 0; i < top.size(); ++i) {
                const HeavyHitter& h = top[i];
                if (i > 0 && !beats(top[i - 1].estimate, top[i - 1].key, h.estimate, h.key)) {
                    throw testkit::Failure{"top() is not ordered estimate descending, key ascending"};
                }
                CHECK(reported.emplace(h.key, true).second);  // no key twice
                const std::uint64_t truth = w.truth[rank_of.at(h.key)];
                CHECK(truth > 0);                                    // only keys that were added
                CHECK(h.estimate >= truth);                          // never an undercount
                CHECK(h.estimate <= t.sketch().estimate(h.key));     // recorded no later than the sketch's value
                CHECK(h.estimate <= t.total());
            }
            // The documented "missing keys" guarantee: every key absent from top() is outranked, even
            // with its TRUE count, by every reported entry (in particular by the weakest, the last).
            const HeavyHitter& weakest = top.back();
            for (std::size_t r = 0; r < w.keys.size(); ++r) {
                if (w.truth[r] == 0 || reported.count(w.keys[r]) != 0) continue;
                if (!beats(weakest.estimate, weakest.key, w.truth[r], w.keys[r])) {
                    throw testkit::Failure{"seed " + std::to_string(seed) + " k " + std::to_string(k) + ": " +
                                           w.keys[r] + " (true count " + std::to_string(w.truth[r]) +
                                           ") is missing but the weakest reported entry " + weakest.key + ":" +
                                           std::to_string(weakest.estimate) + " does not outrank it"};
                }
                ++checked_missing;
            }
        }
    }
    CHECK(checked_missing > 3000);  // the missing-key branch was exercised thousands of times
}

// ---------------------------------------------------------------------------------------
// Bounded memory
// ---------------------------------------------------------------------------------------

TEST(SketchTopK, HeapAndMemoryStayBoundedOverAMillionAddsOfAFewThousandKeys) {
    constexpr std::size_t k = 8;
    SketchTopK t(k, 4096, 4, 77);
    const std::size_t table = t.sketch().memory_bytes();
    std::vector<std::string> keys;  // 21+ characters: longer than any small-string buffer
    for (int i = 0; i < 3000; ++i) keys.push_back("service-" + std::to_string(i) + "/endpoint-v1");
    Rng rng(1);
    const Zipf zipf(keys.size());
    std::size_t peak_heap = 0;
    std::size_t peak_memory = 0;
    std::size_t lowest_memory = std::numeric_limits<std::size_t>::max();
    for (int i = 0; i < 1000000; ++i) {
        t.add(keys[zipf.draw(rng)]);
        const std::size_t heap = t.heap_entries();
        if (heap > 2 * k) throw testkit::Failure{"heap holds " + std::to_string(heap) + " entries at add " + std::to_string(i)};
        peak_heap = std::max(peak_heap, heap);
        if (i % 100000 == 99999) {
            peak_memory = std::max(peak_memory, t.memory_bytes());
            lowest_memory = std::min(lowest_memory, t.memory_bytes());
        }
    }
    CHECK_EQ(t.total(), 1000000ULL);
    CHECK_EQ(t.candidate_count(), k);
    CHECK(peak_heap > k);  // the heap really is lazy: it does hold stale entries between compactions
    CHECK(peak_heap <= 2 * k);
    // Table + a few KiB of bookkeeping, the same at the 100,000th add and at the 1,000,000th: nothing
    // accumulates. (An unbounded lazy heap would hold one entry per add: ~60 MB here.)
    CHECK(peak_memory >= table);
    CHECK(peak_memory <= table + 16 * 1024);
    CHECK(peak_memory - lowest_memory <= 2048);
}

TEST(SketchTopK, ALongTailOfOneOffKeysDoesNotGrowMemoryAndTheHeavyKeysSurvive) {
    constexpr std::size_t k = 5;
    SketchTopK t(k, 1 << 14, 4, 21);
    const std::size_t table = t.sketch().memory_bytes();
    std::size_t peak_memory = 0;
    std::uint64_t unique = 0;
    for (std::uint64_t e = 0; e < 220000; ++e) {
        if (e % 11 == 0) {
            t.add("heavy-" + std::to_string((e / 11) % 5));  // 5 keys x 4000 events
        } else {
            t.add("once-" + std::to_string(unique++));  // 200,000 distinct keys, one event each
        }
        if (e % 20000 == 19999) peak_memory = std::max(peak_memory, t.memory_bytes());
        if (t.heap_entries() > 2 * k) throw testkit::Failure{"heap exceeded 2k"};
    }
    CHECK_EQ(unique, 200000ULL);
    CHECK(peak_memory <= table + 16 * 1024);
    const std::vector<HeavyHitter> top = t.top();
    CHECK_EQ(top.size(), k);
    std::vector<std::string> found;
    for (const HeavyHitter& h : top) {
        found.push_back(h.key);
        // 4000 true events; the tail adds ~13 events per counter on average, and the conservative minimum
        // over 4 rows keeps almost all of it out.
        CHECK(h.estimate >= 4000 && h.estimate <= 4200);
    }
    std::sort(found.begin(), found.end());
    CHECK(found == (std::vector<std::string>{"heavy-0", "heavy-1", "heavy-2", "heavy-3", "heavy-4"}));
}

TEST(SketchTopK, MemoryBytesCountsTheSketchAndTheCandidatesKeys) {
    SketchTopK t(4, 1024, 3, 1);
    const std::size_t empty = t.memory_bytes();
    CHECK(empty >= 1024u * 3u * 8u);
    const std::string long_key(500, 'k');
    for (int i = 0; i < 4; ++i) t.add(long_key + std::to_string(i), 1000);
    // Each of the 4 candidates stores its 500+ byte key in the map AND in a heap entry.
    CHECK(t.memory_bytes() >= empty + 4 * 2 * 500);
    const std::size_t full = t.memory_bytes();
    // A tail of 2000 distinct light keys (estimates in the tens at most, far below 1000) is turned
    // away without storing anything.
    for (int i = 0; i < 2000; ++i) t.add("tail-" + std::to_string(i));
    CHECK(t.memory_bytes() <= full + 4 * 1024);
    CHECK_EQ(t.candidate_count(), 4u);
    for (const HeavyHitter& h : t.top()) CHECK(h.key.size() > 500);
}

// ---------------------------------------------------------------------------------------
// Accuracy on a skewed stream
// ---------------------------------------------------------------------------------------

TEST(SketchTopK, RecoversTheTrueTop10OfAZipfStreamWithAModestSketch) {
    // 200,000 events over 50,000 keys (Zipf, s = 1); sketch 2048 x 4 = 64 KiB, which is 0.3% of what
    // exact counting of the ~25,000 distinct keys seen would cost with 64-byte keys, and k = 10.
    // epsilon = e / 2048 = 0.0013, so epsilon * N = 265, and the true counts around the cut are
    // 10th = 1725 vs 11th = 1605: a 120-event gap, i.e. less than half of the error bound. A
    // swap at the boundary is therefore expected to happen sometimes: a key outside the top 10 whose
    // estimate gets inflated past the 10th key. The other failure mode of double hashing is a rare
    // key that collides with a very heavy one in EVERY row (probability ~ 1/width^2 per pair), which
    // also costs exactly one slot. The assertion allows ONE miss per seed and demands a mean of at
    // least 9.5 out of 10 (two or more misses on average would mean the sketch is not working).
    // Measured: all 6 seeds below recover 10 of 10; a separate 20-seed calibration run on other
    // streams had a minimum of 9 and a mean of 9.9, which is where the one-miss allowance comes
    // from. The streams are integer-exact, so the numbers are identical on every platform.
    constexpr int seeds = 6;
    double mean_recall = 0;
    int worst_recall = 10;
    for (int seed = 1; seed <= seeds; ++seed) {
        const Workload w = make_workload(50000, 200000, 7000 + static_cast<std::uint64_t>(seed));
        SketchTopK t(10, 2048, 4, static_cast<std::uint64_t>(seed));
        feed(t, w);
        const std::vector<HeavyHitter> truth = brute_force_top(w, 10);
        const std::vector<HeavyHitter> got = t.top();
        CHECK_EQ(got.size(), 10u);
        int recall = 0;
        for (const HeavyHitter& g : got) {
            for (const HeavyHitter& real : truth) {
                if (g.key == real.key) {
                    ++recall;
                    CHECK(g.estimate >= real.estimate);          // never an undercount
                    CHECK(g.estimate <= real.estimate + 265 * 2);  // within 2 * epsilon * N for the keys found
                }
            }
        }
        worst_recall = std::min(worst_recall, recall);
        mean_recall += static_cast<double>(recall) / seeds;
    }
    CHECK(worst_recall >= 9);
    CHECK(mean_recall >= 9.5);
}

// ---------------------------------------------------------------------------------------
// Determinism and copies
// ---------------------------------------------------------------------------------------

TEST(SketchTopK, SameSeedAndStreamGiveTheSameResultAndCopiesAreIndependent) {
    const Workload w = make_workload(500, 6000, 3, 3);
    SketchTopK a(10, 128, 3, 42), b(10, 128, 3, 42);
    feed(a, w);
    feed(b, w);
    expect_same(a.top(), b.top(), "determinism");
    CHECK(a.sketch() == b.sketch());
    CHECK_EQ(a.heap_entries(), b.heap_entries());

    SketchTopK copy = a;
    expect_same(copy.top(), a.top(), "copy");
    const std::vector<HeavyHitter> before = a.top();
    for (int i = 0; i < 5000; ++i) copy.add("fresh-key");
    expect_same(a.top(), before, "original after the copy changed");
    CHECK_EQ(copy.top().front().key, std::string("fresh-key"));
    // 5000 true events plus whatever the narrow table's collisions add (about 100 per counter).
    CHECK(copy.top().front().estimate >= 5000 && copy.top().front().estimate <= 6000);

    SketchTopK moved(std::move(a));  // a "move" is a copy: the source stays valid
    expect_same(moved.top(), before, "moved");
    expect_same(a.top(), before, "moved-from");  // NOLINT(bugprone-use-after-move)
}

TEST(SketchTopK, DifferentSeedsCanDisagreeOnANarrowSketchButEachStaysConsistent) {
    const Workload w = make_workload(300, 4000, 12, 2);
    bool any_difference = false;
    for (std::uint64_t seed = 1; seed <= 6; ++seed) {
        SketchTopK a(5, 24, 2, seed), b(5, 24, 2, seed + 100);
        feed(a, w);
        feed(b, w);
        any_difference = any_difference || a.top() != b.top();
        for (const SketchTopK* t : {&a, &b}) {
            for (const HeavyHitter& h : t->top()) CHECK(h.estimate <= t->total());
        }
    }
    CHECK(any_difference);
}

// ---------------------------------------------------------------------------------------
// Golden values
// ---------------------------------------------------------------------------------------

// Pinned from an independent Python implementation of the SPECIFICATION (a conservative sketch plus
// a plain dict of candidates with a linear scan for the weakest: no heap at all), whose hash64 /
// mix64 were first validated against the vectors in hash_test.cpp. The narrow tables make
// collisions decide the outcome: e.g. in the first case item-52 and item-132, true counts far below
// the heavy items, are reported because collisions inflated them (the documented failure mode), and
// a wide sketch would not report them.
//
// Stream: event i (0 <= i < 20000): r = mix64(0xC0DE0000 + i), u = r % 1000,
// key = "item-" + str(u*u / 4000), count = 1 + ((r >> 32) % 4); total 49949.
namespace {

SketchTopK golden_run(std::size_t k, std::size_t width, std::size_t depth, std::uint64_t seed) {
    SketchTopK t(k, width, depth, seed);
    for (std::uint64_t i = 0; i < 20000; ++i) {
        const std::uint64_t r = mix64(0xC0DE0000ULL + i);
        const std::uint64_t u = r % 1000;
        t.add("item-" + std::to_string(u * u / 4000), 1 + ((r >> 32) % 4));
    }
    return t;
}

}  // namespace

TEST(SketchTopK, GoldenTopKMatchesTheIndependentPythonSimulation) {
    const SketchTopK a = golden_run(5, 40, 3, 0xBADC0DE);
    CHECK_EQ(a.total(), 49949ULL);
    expect_same(a.top(),
                {HeavyHitter{"item-0", 3174}, HeavyHitter{"item-1", 1421}, HeavyHitter{"item-2", 1206},
                 HeavyHitter{"item-52", 1156}, HeavyHitter{"item-132", 939}},
                "golden k=5 width=40 depth=3");

    const SketchTopK b = golden_run(12, 97, 4, 12345);
    expect_same(b.top(),
                {HeavyHitter{"item-0", 3174}, HeavyHitter{"item-1", 1421}, HeavyHitter{"item-2", 1009},
                 HeavyHitter{"item-3", 851}, HeavyHitter{"item-4", 735}, HeavyHitter{"item-5", 669},
                 HeavyHitter{"item-6", 625}, HeavyHitter{"item-8", 575}, HeavyHitter{"item-9", 553},
                 HeavyHitter{"item-7", 538}, HeavyHitter{"item-12", 476}, HeavyHitter{"item-11", 471}},
                "golden k=12 width=97 depth=4");

    // An extreme case: 7 x 2 counters, so every estimate is close to the total and keys that are
    // far from the true top win by collision luck alone.
    const SketchTopK c = golden_run(3, 7, 2, 99);
    expect_same(c.top(), {HeavyHitter{"item-0", 4451}, HeavyHitter{"item-7", 4449}, HeavyHitter{"item-84", 4448}},
                "golden k=3 width=7 depth=2");
}
