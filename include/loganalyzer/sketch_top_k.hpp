#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "loganalyzer/count_min_sketch.hpp"
#include "loganalyzer/min_heap.hpp"

namespace loganalyzer {

/// One heavy hitter: a key and the sketch's estimate of its count.
struct HeavyHitter {
    std::string key;
    std::uint64_t estimate = 0;

    friend bool operator==(const HeavyHitter& a, const HeavyHitter& b) {
        return a.estimate == b.estimate && a.key == b.key;
    }
    friend bool operator!=(const HeavyHitter& a, const HeavyHitter& b) { return !(a == b); }
};

/// Approximate top-k over an unbounded stream of keys in bounded memory: a Count-Min Sketch
/// counts every key, and a small candidate set remembers which (at most k) keys currently
/// have the largest estimates. Memory is the sketch table plus O(k) candidates, independent
/// of the number of distinct keys, which is the point: TopKErrors keeps one counter per
/// distinct group, this one does not.
///
/// TYPICAL USE
///   SketchTopK heavy(10, 4096, 4, seed);  // 128 KiB of counters plus room for 10 candidates
///   for (const auto& entry : entries) heavy.add(signature_of(entry));
///   for (const HeavyHitter& h : heavy.top()) report(h.key, h.estimate);
///
/// HOW IT WORKS
///   add(key, c) first updates the sketch (conservative update: it never gives a larger
///   estimate than the standard one and keeps the never-underestimate property, see
///   CountMinSketch) and reads the key's new estimate e. Then:
///     * key is already a candidate: its recorded estimate becomes e;
///     * the set has fewer than k candidates: the key becomes one;
///     * the set is full and (e, key) BEATS the weakest candidate: the key replaces it;
///     * otherwise nothing happens (the sketch has still counted the key, so nothing is lost:
///       when it is added again its estimate includes every earlier occurrence).
///   "Beats" is the total order the results use: higher estimate first, and for equal
///   estimates the smaller key (bytewise, unsigned). Because keys are distinct, two different
///   keys never tie, so the weakest candidate is always unique and the outcome is
///   deterministic. A candidate's recorded estimate is the sketch's estimate at the moment of
///   its LAST add; it only changes on add, and never decreases.
///
/// GUARANTEES, and what is NOT guaranteed
///   1. top() has at most k entries, every key at most once, ordered by estimate descending
///      then key ascending.
///   2. Estimates never undercount: every reported estimate >= the key's true count, because
///      the sketch never underestimates and the true count of a key only changes when the
///      key itself is added. A reported estimate is also <= sketch().estimate(key) (counters
///      only grow after the recording). With a sketch built by with_error, estimate - true
///      <= epsilon * N holds with probability >= 1 - delta per key, with the caveats stated
///      in CountMinSketch (the error is absolute: for rare keys it is large relative to
///      their count).
///   3. Missing keys. If a key x with true count c is NOT in top() (and top() is full, i.e.
///      has k entries), then every one of the k reported entries (estimate e_y, key y)
///      beats (c, x): e_y > c, or e_y == c and y < x. Proof: let r >= c be the estimate x got
///      at its last add. Then x was rejected (the weakest candidate W at that moment beat or
///      equalled (r, x)) or admitted and evicted later (at that moment W was x itself, with
///      estimate r). Either way the set was full and its weakest entry was at least as strong
///      as (r, x). The weakest entry never gets weaker (an eviction replaces it by something
///      that beats it; a hit only raises a recorded estimate), so at the end each of the k
///      reported entries is at least as strong as (r, x), and since none of them is x it is
///      strictly stronger, hence stronger than (c, x). So a key can only be missing when k
///      other keys have estimates at least as large as its TRUE count: because collisions
///      inflated other keys, or because the key really is not in the top k.
///   4. Exact regime. If the sketch is wide enough that every key has a collision-free row
///      (width in the tens of thousands or more for a few hundred distinct keys), all
///      estimates equal the true counts and top() is EXACTLY the true top-k with exact
///      counts, ties broken by key. This is tested, not proved: it depends on the seed.
///   Not guaranteed: that the keys reported are the true top-k when the sketch is narrow (a
///   key may be reported with an inflated estimate, a true heavy key may be crowded out), or
///   that the result does not depend on the order of the stream (the candidate set is a
///   function of the stream and the seed, deterministic, but not of the multiset of keys
///   alone; recorded estimates are as of each key's last add).
///
/// THE LAZY HEAP
///   The weakest candidate is found with a loganalyzer::MinHeap of (estimate, key) entries
///   ordered weakest first. When a candidate's estimate rises the old heap entry is not
///   removed (MinHeap cannot delete from the middle); a new entry is pushed and the old one
///   becomes STALE: an entry is valid iff the candidates map holds exactly its key with
///   exactly its estimate. Stale entries are skipped when they reach the top (each is popped
///   once, so skipping is amortised O(log k)), and the heap is COMPACTED, rebuilt from the
///   candidates map with one entry per candidate, as soon as it holds more than 2k entries.
///   Estimates of one key strictly increase between pushes (an add with count > 0 raises the
///   estimate unless the counters are saturated, in which case nothing is pushed), so a key
///   never has two valid entries.
///
///   Invariants after every call: (I1) every candidate has at least one valid heap entry;
///   (I2) the heap holds at most 2k entries. Proof of I2: right after a compaction the heap
///   holds exactly one entry per candidate, at most k. Every add pushes at most one entry
///   (a hit pushes one, an admission pushes one, an eviction pops one and pushes one, a
///   rejection pushes none) and pops only shrink the heap, so from a size of at most 2k an
///   add can reach at most 2k + 1; when it does (size > 2k) the add compacts before
///   returning. Cost: a compaction is O(k log k) and, because it leaves at most k entries and
///   the next one needs more than 2k, at least k + 1 pushes happen in between: O(log k)
///   amortised per add. I1 holds because a candidate's entry is pushed before the candidate's
///   estimate is recorded, and compaction recreates one per candidate; I1 is what makes
///   "the weakest candidate" a valid entry once stale tops are skipped.
///
///   Fast path: when the set is full and the new estimate is below the estimate of the heap's
///   top entry, add() returns at once. The top entry may be stale, but the heap's minimum is
///   never above the minimum over its valid entries (a subset), which is the weakest
///   candidate's estimate; so the key's estimate is below the weakest candidate's. It can then
///   be neither a candidate (the new estimate of a candidate is at least its recorded one,
///   which is at least the weakest's) nor an admission. It costs one comparison, no hash
///   lookup, no copy of the key: that is what makes a long tail of one-off keys cheap. A key
///   that passes the test but would still be rejected is settled by the exact slow path.
///
/// COMPLEXITY (d = sketch depth)
///   add: O(d + |key|) for the sketch plus amortised O(log k) for the heap plus an expected
///   O(|key|) hash lookup (and a copy of the key when it is admitted or its estimate rises).
///   top(): O(k log k) (drains a MinHeap in result order). Memory: the sketch table plus
///   O(k) bookkeeping, see memory_bytes().
///
/// EXCEPTIONS
///   Constructor: std::invalid_argument for k == 0 or unusable sketch dimensions. add() throws
///   only std::bad_alloc. If it does, the sketch has already counted the key (the count is
///   not lost) and the candidate set is consistent but may miss that last update; every
///   structural step is ordered so that a failed allocation leaves only a harmless stale
///   heap entry behind.
///
/// COPY / MOVE
///   Copyable; moving is copying (see CountMinSketch), so a "moved-from" object stays intact.
///
/// THREADING
///   const members (top, total, sketch, ...) keep no scratch state and may run concurrently
///   with each other; add() must not run concurrently with anything.
class SketchTopK {
public:
    /// Tracks the k heaviest keys using a width x depth sketch seeded with `seed`. Throws
    /// std::invalid_argument if k == 0 or the sketch dimensions are invalid
    /// (see CountMinSketch).
    SketchTopK(std::size_t k, std::size_t width, std::size_t depth, std::uint64_t seed = 0)
        : sketch_(width, depth, seed), k_(k) {
        if (k == 0) throw std::invalid_argument("SketchTopK: k must be at least 1");
    }

    SketchTopK(const SketchTopK&) = default;
    SketchTopK& operator=(const SketchTopK&) = default;

    /// Counts `count` occurrences of `key` (count == 0 does nothing, not even creating a
    /// candidate) and updates the candidate set.
    void add(std::string_view key, std::uint64_t count = 1) {
        if (count == 0) return;
        const std::uint64_t estimate = sketch_.update_conservative(key, count);

        const bool full = candidates_.size() >= k_;
        if (full && estimate < heap_.top().estimate) return;  // fast path, see THE LAZY HEAP

        std::string owned(key);
        const auto hit = candidates_.find(owned);
        if (hit != candidates_.end()) {
            if (estimate != hit->second) {  // equal only when the counters are saturated
                heap_push(Entry{estimate, owned});
                hit->second = estimate;
            }
        } else if (!full) {
            heap_push(Entry{estimate, owned});
            candidates_.emplace(std::move(owned), estimate);
        } else if (stronger(estimate, owned, weakest())) {
            // The new entry is pushed first: it can throw, and the weakest candidate is
            // still the heap's top afterwards because the newcomer is strictly stronger.
            heap_push(Entry{estimate, owned});
            const Entry evicted = heap_pop();
            auto node = candidates_.extract(evicted.key);  // reuse the node: nothing can throw below
            node.key() = std::move(owned);
            node.mapped() = estimate;
            candidates_.insert(std::move(node));
        }
        if (heap_.size() > heap_limit()) compact();
    }

    /// The tracked keys, up to k of them: estimate descending, then key ascending (bytewise,
    /// unsigned). Estimates are as of each key's last add (see GUARANTEES).
    std::vector<HeavyHitter> top() const {
        MinHeap<HeavyHitter, StrongestFirst> order;
        for (const auto& candidate : candidates_) order.push(HeavyHitter{candidate.first, candidate.second});
        std::vector<HeavyHitter> result;
        result.reserve(order.size());
        while (!order.empty()) result.push_back(order.pop());
        return result;
    }

    /// Sum of all counts added, saturating at UINT64_MAX (the sketch's N).
    std::uint64_t total() const noexcept { return sketch_.total(); }

    std::size_t k() const noexcept { return k_; }

    const CountMinSketch& sketch() const noexcept { return sketch_; }

    /// Number of keys currently tracked (at most k).
    std::size_t candidate_count() const noexcept { return candidates_.size(); }

    /// Entries currently in the lazy heap, valid and stale (at most 2k after every call).
    std::size_t heap_entries() const noexcept { return heap_.size(); }

    /// Bytes held: the sketch's counter table PLUS the candidate bookkeeping (the candidates
    /// map with its bucket array, the lazy heap, and the heap-allocated characters of the keys
    /// both of them store; short keys live inside std::string and cost nothing extra). It is
    /// an estimate computed from the live element counts and the library types' sizeof, so
    /// it ignores allocator headers and the spare capacity of the heap's vector (at most
    /// twice its largest size, which is O(k)); it is deterministic in the logical state
    /// except for the unordered_map's bucket count. What it does promise: it is the sketch
    /// plus O(k) and never grows with the number of distinct keys or adds.
    std::size_t memory_bytes() const noexcept {
        std::size_t bytes = sketch_.memory_bytes();
        bytes += candidates_.bucket_count() * sizeof(void*);
        bytes += candidates_.size() * (sizeof(std::pair<const std::string, std::uint64_t>) + sizeof(void*));
        for (const auto& candidate : candidates_) bytes += out_of_line_bytes(candidate.first);
        bytes += heap_.size() * sizeof(Entry) + heap_key_bytes_;
        return bytes;
    }

private:
    struct Entry {
        std::uint64_t estimate;
        std::string key;
    };

    // `a` is the weaker one: lower estimate, or equal estimate and the LARGER key (results
    // list smaller keys first, so a larger key is the first to go). A MinHeap with this
    // comparator keeps the weakest candidate on top.
    struct WeakestFirst {
        bool operator()(const Entry& a, const Entry& b) const {
            return a.estimate < b.estimate || (a.estimate == b.estimate && b.key < a.key);
        }
    };

    struct StrongestFirst {
        bool operator()(const HeavyHitter& a, const HeavyHitter& b) const {
            return a.estimate > b.estimate || (a.estimate == b.estimate && a.key < b.key);
        }
    };

    // (estimate, key) strictly beats the entry `other`.
    static bool stronger(std::uint64_t estimate, const std::string& key, const Entry& other) {
        return estimate > other.estimate || (estimate == other.estimate && key < other.key);
    }

    // Heap bytes a key's characters need beyond the std::string object itself. Computed from
    // size(), not capacity(): a string's size survives the moves the heap makes, so the running
    // total in heap_key_bytes_ always balances.
    static std::size_t out_of_line_bytes(const std::string& s) noexcept {
        static const std::size_t inline_capacity = std::string().capacity();
        return s.size() > inline_capacity ? s.size() + 1 : 0;
    }

    std::size_t heap_limit() const noexcept {
        return k_ > std::numeric_limits<std::size_t>::max() / 2 ? std::numeric_limits<std::size_t>::max() : 2 * k_;
    }

    void heap_push(Entry entry) {
        const std::size_t bytes = out_of_line_bytes(entry.key);
        heap_.push(std::move(entry));
        heap_key_bytes_ += bytes;
    }

    Entry heap_pop() {
        Entry entry = heap_.pop();
        heap_key_bytes_ -= out_of_line_bytes(entry.key);
        return entry;
    }

    // The weakest candidate's heap entry. Requires at least one candidate. Pops stale
    // entries off the top first; I1 guarantees a valid one exists, so this ends.
    // The reference is invalidated by the next push or pop.
    const Entry& weakest() {
        while (true) {
            const Entry& top = heap_.top();
            const auto it = candidates_.find(top.key);
            if (it != candidates_.end() && it->second == top.estimate) return top;
            (void)heap_pop();
        }
    }

    // Rebuilds the heap with exactly one entry per candidate. Built on the side and swapped in
    // at the end, so a failed allocation leaves the old heap in place.
    void compact() {
        MinHeap<Entry, WeakestFirst> rebuilt;
        std::size_t bytes = 0;
        for (const auto& candidate : candidates_) {
            bytes += out_of_line_bytes(candidate.first);
            rebuilt.push(Entry{candidate.second, candidate.first});
        }
        heap_ = std::move(rebuilt);
        heap_key_bytes_ = bytes;
    }

    CountMinSketch sketch_;
    std::size_t k_;
    std::unordered_map<std::string, std::uint64_t> candidates_;  // key -> recorded estimate
    MinHeap<Entry, WeakestFirst> heap_;
    std::size_t heap_key_bytes_ = 0;  // out-of-line key characters held by heap_ entries
};

}  // namespace loganalyzer
