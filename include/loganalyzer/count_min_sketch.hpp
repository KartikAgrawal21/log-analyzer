#pragma once

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <vector>

#include "loganalyzer/hash.hpp"

namespace loganalyzer {

/// Count-Min Sketch, written from scratch: a fixed-size table of counters that answers
/// "how many times was this key added?" for an unbounded number of distinct keys, in memory
/// that does not depend on that number. The price is that answers can be too HIGH (never
/// too low), by a bounded amount.
///
/// The table has `depth` rows of `width` 64-bit counters. add(key, c) bumps one counter in
/// every row (the column is chosen by a hash of the key) and estimate(key) returns the
/// smallest of those `depth` counters: every counter the key touches is the key's true
/// count plus whatever other keys that hash to the same column contributed, so the smallest
/// one is the least contaminated.
///
/// TYPICAL USE
///   auto cms = CountMinSketch::with_error(0.001, 0.01, seed);  // 2719 x 5 counters, about 106 KiB
///   cms.add_conservative(signature);                           // once per log entry
///   cms.estimate(signature);                                   // >= the true count, always
///
/// HASHING
///   h1 = hash64(key, seed) and h2 = mix64(h1) | 1; row i (0-based) uses the column
///       (h1 + i * h2) mod 2^64  mod  width
///   (Kirsch-Mitzenmacher double hashing: two hash computations give every row, instead of
///   `depth` separate hashes). h2 is forced odd so that, for a power-of-two width, the rows
///   of one key land in distinct columns (an odd stride is coprime to the width). The
///   reduction is a plain modulo: x mod width is exactly uniform when x is uniform on
///   [0, width * m) and for a uniform 64-bit x the most over-represented column has
///   probability ceil(2^64 / width) / 2^64, i.e. a relative bias below width / 2^64 <= 2^-33
///   (width <= 2^31), far below the statistical noise of any realistic stream. A
///   multiply-shift reduction would avoid the division but needs a 64x64 -> 128 bit product,
///   which is not portable C++17 (no __int128 on MSVC); depth divisions per update are cheap
///   next to the cache misses of touching depth rows.
///   The empty key and keys with embedded NUL or high bytes are ordinary keys.
///
/// COUNTERS SATURATE
///   Counters are uint64_t and saturate at UINT64_MAX instead of wrapping: a counter that
///   would exceed it stays at UINT64_MAX, and so does total(). Wrapping would turn a huge
///   count into a tiny one and break the never-underestimate guarantee; saturating keeps it
///   in the form "estimate(x) >= min(true(x), UINT64_MAX)". Saturating addition of
///   non-negative numbers is min(sum, UINT64_MAX), so it is exactly associative and
///   commutative and every statement below about sums remains true under saturation.
///
/// UPDATES
///   add(key, c)               standard update: every row's counter += c.
///   add_conservative(key, c)  conservative update: let m = estimate(key) before the update;
///                             raise to m + c only the counters that are below m + c, leave
///                             the others alone. Counters that already exceed what this key
///                             can account for (they are inflated by other keys) are not
///                             inflated further, so collisions hurt less.
///   add(key, 0) and add_conservative(key, 0) do nothing at all. The two kinds of update may
///   be mixed freely on one sketch.
///
/// GUARANTEES (N = total(), true(x) = the sum of the counts added for x)
///   1. Never an underestimate, always, with no probability involved:
///          estimate(x) >= min(true(x), UINT64_MAX)
///      for standard updates, conservative updates, any mix of the two, and after merge().
///      Proof: every counter in any of x's rows is >= true(x) at all times. Initially 0.
///      A standard update of x adds c to all of them. A conservative update of x raises every
///      one of them to at least m + c >= true(x) + c, because m is the minimum of counters
///      that were all >= true(x). Updates of other keys never lower a counter. Counters
///      only ever grow, so the invariant is permanent, and a minimum of values that are all
///      >= true(x) is >= true(x).
///   2. Never above the total: estimate(x) <= N (every counter is at most the sum of all
///      counts, because a counter only receives counts that were added).
///   3. Conservative never exceeds standard: if two sketches with the same dimensions and
///      seed process the same stream, one with add() and the other with add_conservative()
///      (or any mix of the two), then EVERY counter of the second is <= the matching
///      counter of the first, so every estimate is too. Proof by induction over the stream.
///      Suppose every counter of S (standard) is >= the matching counter of C
///      (conservative or mixed) before an update (y, c). In each row r of y, S sets its
///      counter to s_r + c. C sets it either to c_r + c (a standard update) or to
///      max(c_r, m + c), where m is the smallest counter of y in C, so m <= c_r. Since
///      c_r <= s_r, all of c_r + c, c_r and m + c are <= s_r + c. Other counters are
///      untouched on both sides.
///   4. Error bound, probabilistic. For a sketch built by with_error(epsilon, delta):
///          Pr[ estimate(x) > true(x) + epsilon * N ] <= delta
///      for every key x, over the random choice of the seed, for a stream fixed in advance;
///      N is the total of everything added, and the bound holds for standard, conservative
///      and mixed updates (guarantee 3 turns the bound for the standard sketch into a bound
///      for the others). Why: in one row the other keys put at most E = N / width =
///      epsilon * N / e into x's counter on average, so by Markov's inequality the counter
///      exceeds true(x) + epsilon * N with probability at most 1/e; the estimate exceeds it
///      only if ALL depth rows do, probability e^-depth <= delta if the rows are independent.
///      HONEST CAVEAT: the rows of this class are not independent. Double hashing makes them
///      only pairwise independent, and two distinct keys collide in EVERY row with
///      probability of the order of 1/width^2 (when h1 and h2 agree modulo width) instead of
///      width^-depth. So the row-independence step of the proof is an assumption here, the
///      bound is the textbook bound rather than a theorem about this exact hashing scheme,
///      and it is checked statistically in tests/count_min_sketch_test.cpp rather than
///      proved. Its practical weak spot: a "heavy" key (count >= epsilon * N, at most
///      1/epsilon of them) that collides with x in all rows at once gives x an error of
///      >= epsilon * N whatever the depth, with probability about
///      (1/epsilon) / width^2 ~ epsilon / e^2. This is below delta only if epsilon is not
///      much larger than delta (roughly epsilon <= 7 * delta); asking for a tiny delta with a
///      big epsilon cannot be honoured by this hashing no matter how deep the table is.
///      Guarantee 1 is unaffected: it never relied on the hash at all.
///   The bound speaks about N, the whole stream: the sketch cannot tell a rare key from a
///   key hidden under collisions with heavy ones, so estimates of rare keys have an ABSOLUTE
///   error of about N/width and are useful for heavy keys, not for the long tail.
///
/// MERGING
///   merge(other) adds the two tables cell by cell. For sketches built with standard updates
///   merge is EXACT: merge(A, B) is the very table (and total) that one sketch would hold
///   after processing the concatenation of the two streams, because every counter of a
///   standard sketch is the sum of the counts that hash to it, and sums of disjoint parts
///   add. After conservative updates the merged table is still a valid sketch (an upper
///   bound, guarantee 1) but is not the table the conservative sketch of the concatenation
///   would hold: a conservative counter is not the sum of the counts hashed into it (updates
///   deliberately leave counters that are already high untouched), so adding two of them is
///   a valid but different table from replaying both streams into one sketch. It satisfies
///   guarantee 1 because every counter in x's rows is >= true_A(x) in A and >= true_B(x) in
///   B, so in the merge it is >= true_A(x) + true_B(x), and so is their minimum. It
///   satisfies guarantee 4 because by guarantee 3 it is cellwise <= the merged standard
///   sketch, which is exactly the standard sketch of the concatenation. Only sketches with
///   the same width, depth and seed can be merged (they must map every key to the same
///   cells).
///
/// COMPLEXITY (d = depth, w = width)
///   add / estimate: O(d + |key|) time; add_conservative: 2 passes over the d rows. merge:
///   O(w * d). Memory: exactly 8 * w * d bytes of counters plus a few words. Sizing:
///   with_error picks w = ceil(e / epsilon), d = ceil(ln(1 / delta)).
///
/// EXCEPTIONS
///   Constructors and with_error throw std::invalid_argument for unusable dimensions (and
///   std::bad_alloc when the table cannot be allocated: the 2^31-cell cap is a sanity limit,
///   not a promise that 16 GiB are available). Nothing else throws; a failed merge changes
///   nothing.
///
/// DETERMINISM
///   Table contents depend only on (width, depth, seed) and the sequence of updates, never
///   on the platform: no floating point and no unordered container decides a cell.
///   (with_error's two floating-point formulas are IEEE double division, ceil and
///   multiplication, all exactly specified; see with_error.)
///
/// COPY / MOVE
///   Copyable. There is deliberately no separate move: a sketch has no cheap valid empty
///   state (width and depth must be >= 1), so a "move" is a copy and leaves the source intact
///   and usable. Returning a temporary (as with_error does) never copies: guaranteed elision.
///
/// THREADING
///   const members keep no scratch state: any number of threads may call them concurrently
///   as long as nobody calls a non-const member at the same time.
class CountMinSketch {
public:
    /// Largest table accepted: width * depth <= 2^31 counters (16 GiB).
    static constexpr std::uint64_t kMaxCells = std::uint64_t{1} << 31;

    /// Throws std::invalid_argument if width == 0, depth == 0, or width * depth would exceed
    /// kMaxCells (checked without overflowing, for any size_t arguments).
    CountMinSketch(std::size_t width, std::size_t depth, std::uint64_t seed = 0)
        : width_(width), depth_(depth), seed_(seed) {
        if (width == 0) throw std::invalid_argument("CountMinSketch: width must be at least 1");
        if (depth == 0) throw std::invalid_argument("CountMinSketch: depth must be at least 1");
        if (static_cast<std::uint64_t>(width) > kMaxCells / static_cast<std::uint64_t>(depth)) {
            throw std::invalid_argument("CountMinSketch: width * depth exceeds 2^31 counters");
        }
        cells_.assign(width * depth, 0);
    }

    CountMinSketch(const CountMinSketch&) = default;
    CountMinSketch& operator=(const CountMinSketch&) = default;

    /// Sizes the table for an error of epsilon * N with probability >= 1 - delta (guarantee 4):
    /// width = ceil(e / epsilon), depth = ceil(ln(1 / delta)). Throws std::invalid_argument
    /// unless 0 < epsilon < 1 and 0 < delta < 1 (NaN and infinities included), and when the
    /// resulting table would exceed kMaxCells.
    ///
    /// Both formulas are evaluated so that the platform cannot change the answer: the width is
    /// one IEEE-754 double division and a ceil (both exactly specified), and the depth is the
    /// smallest d >= 1 with e^-d <= delta, found by repeated multiplication with the double
    /// nearest to 1/e instead of calling std::log (whose last bit differs between math
    /// libraries and would flip the result at an exact boundary). That is the same number as
    /// ceil(ln(1 / delta)) except for a delta within a few ulps of some e^-d.
    static CountMinSketch with_error(double epsilon, double delta, std::uint64_t seed = 0) {
        if (!(epsilon > 0.0 && epsilon < 1.0)) {
            throw std::invalid_argument("CountMinSketch::with_error: epsilon must be in (0, 1)");
        }
        if (!(delta > 0.0 && delta < 1.0)) {
            throw std::invalid_argument("CountMinSketch::with_error: delta must be in (0, 1)");
        }
        const double width = std::ceil(kE / epsilon);
        if (!(width <= static_cast<double>(kMaxCells))) {  // also catches an infinite quotient
            throw std::invalid_argument("CountMinSketch::with_error: epsilon is too small (width > 2^31)");
        }
        return CountMinSketch(static_cast<std::size_t>(width), depth_for(delta), seed);
    }

    /// Standard update: every row's counter += count (saturating). count == 0 does nothing.
    void add(std::string_view key, std::uint64_t count = 1) {
        if (count == 0) return;
        const Probe p = probe(key);
        std::uint64_t x = p.h1;
        std::size_t row_base = 0;
        for (std::size_t row = 0; row < depth_; ++row, row_base += width_, x += p.h2) {
            std::uint64_t& cell = cells_[row_base + column(x)];
            cell = saturating_add(cell, count);
        }
        total_ = saturating_add(total_, count);
    }

    /// Conservative update (see UPDATES). count == 0 does nothing.
    void add_conservative(std::string_view key, std::uint64_t count = 1) {
        (void)update_conservative(key, count);
    }

    /// add_conservative that also returns the key's estimate AFTER the update, which it
    /// computes for free: the update raises every counter of the key to at least
    /// target = min_before + count, and the counter that held the minimum becomes exactly
    /// target, so the new estimate is target. SketchTopK needs that number on every add.
    /// With count == 0 nothing changes and the current estimate is returned.
    std::uint64_t update_conservative(std::string_view key, std::uint64_t count = 1) {
        if (count == 0) return estimate(key);
        const Probe p = probe(key);
        std::uint64_t smallest = std::numeric_limits<std::uint64_t>::max();
        std::uint64_t x = p.h1;
        std::size_t row_base = 0;
        for (std::size_t row = 0; row < depth_; ++row, row_base += width_, x += p.h2) {
            const std::uint64_t cell = cells_[row_base + column(x)];
            if (cell < smallest) smallest = cell;
        }
        const std::uint64_t target = saturating_add(smallest, count);
        x = p.h1;
        row_base = 0;
        for (std::size_t row = 0; row < depth_; ++row, row_base += width_, x += p.h2) {
            std::uint64_t& cell = cells_[row_base + column(x)];
            if (cell < target) cell = target;
        }
        total_ = saturating_add(total_, count);
        return target;
    }

    /// Upper bound on the number of times `key` was added (guarantees 1, 2 and 4). A key that
    /// was never added gets the smallest counter among its rows, usually 0 in a sparse table.
    std::uint64_t estimate(std::string_view key) const {
        const Probe p = probe(key);
        std::uint64_t smallest = std::numeric_limits<std::uint64_t>::max();
        std::uint64_t x = p.h1;
        std::size_t row_base = 0;
        for (std::size_t row = 0; row < depth_; ++row, row_base += width_, x += p.h2) {
            const std::uint64_t cell = cells_[row_base + column(x)];
            if (cell < smallest) smallest = cell;
            if (smallest == 0) break;  // cannot get lower
        }
        return smallest;
    }

    /// N: the sum of all counts added (and merged in), saturating at UINT64_MAX.
    std::uint64_t total() const noexcept { return total_; }

    /// Cell-wise sum with another sketch (see MERGING). Throws std::invalid_argument unless
    /// width, depth and seed all match; throws BEFORE changing anything. Merging a sketch with
    /// itself doubles every counter (the sketch of the stream followed by itself).
    void merge(const CountMinSketch& other) {
        if (width_ != other.width_ || depth_ != other.depth_ || seed_ != other.seed_) {
            throw std::invalid_argument("CountMinSketch::merge: width, depth and seed must all match");
        }
        for (std::size_t i = 0; i < cells_.size(); ++i) cells_[i] = saturating_add(cells_[i], other.cells_[i]);
        total_ = saturating_add(total_, other.total_);
    }

    /// Back to the freshly constructed state (same dimensions and seed, all counters 0).
    void clear() noexcept {
        for (std::uint64_t& cell : cells_) cell = 0;
        total_ = 0;
    }

    std::size_t width() const noexcept { return width_; }
    std::size_t depth() const noexcept { return depth_; }
    std::uint64_t seed() const noexcept { return seed_; }

    /// Bytes of the counter table: width * depth * 8.
    std::size_t memory_bytes() const noexcept { return cells_.size() * sizeof(std::uint64_t); }

    /// The epsilon this table's width gives: e / width (the 1 - delta error bound is
    /// epsilon * N). Informational only; never used to decide a counter.
    double epsilon() const noexcept { return kE / static_cast<double>(width_); }

    /// The delta this table's depth gives: exp(-depth). Informational only.
    double delta() const noexcept { return std::exp(-static_cast<double>(depth_)); }

    /// Same dimensions, seed, total and every counter. (Two sketches with different seeds are
    /// never equal even if both are empty: they are not interchangeable.)
    friend bool operator==(const CountMinSketch& a, const CountMinSketch& b) {
        return a.width_ == b.width_ && a.depth_ == b.depth_ && a.seed_ == b.seed_ && a.total_ == b.total_ &&
               a.cells_ == b.cells_;
    }
    friend bool operator!=(const CountMinSketch& a, const CountMinSketch& b) { return !(a == b); }

private:
    // The double nearest to e and to 1/e (the only floating-point constants; see with_error).
    static constexpr double kE = 2.718281828459045;
    static constexpr double kInverseE = 0.36787944117144233;

    struct Probe {
        std::uint64_t h1;
        std::uint64_t h2;
    };

    static std::size_t depth_for(double delta) noexcept {
        double power = kInverseE;  // e^-d, rounded at every step (error ~ d ulps: irrelevant)
        std::size_t depth = 1;
        while (power > delta) {  // ends: power reaches 0 after ~745 steps and delta > 0
            power *= kInverseE;
            ++depth;
        }
        return depth;
    }

    static constexpr std::uint64_t saturating_add(std::uint64_t a, std::uint64_t b) noexcept {
        return a > std::numeric_limits<std::uint64_t>::max() - b ? std::numeric_limits<std::uint64_t>::max() : a + b;
    }

    Probe probe(std::string_view key) const noexcept {
        const std::uint64_t h1 = hash64(key, seed_);
        return {h1, mix64(h1) | 1};
    }

    std::size_t column(std::uint64_t x) const noexcept { return static_cast<std::size_t>(x % width_); }

    std::size_t width_;
    std::size_t depth_;
    std::uint64_t seed_;
    std::uint64_t total_ = 0;
    std::vector<std::uint64_t> cells_;  // row-major: row * width + column
};

}  // namespace loganalyzer
