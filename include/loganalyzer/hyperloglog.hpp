#pragma once

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

#include "loganalyzer/hash.hpp"

namespace loganalyzer {

namespace detail {

/// leading_zeros[v] = number of leading zero bits of the 8-bit value v (8 for v == 0, which the
/// sketch never looks up). Built at compile time.
struct HllLeadingZeroTable {
    std::uint8_t leading_zeros[256];
    constexpr HllLeadingZeroTable() : leading_zeros() {
        for (unsigned v = 0; v < 256; ++v) {
            unsigned zeros = 0;
            for (unsigned bit = 0x80; bit != 0 && (v & bit) == 0; bit >>= 1) ++zeros;
            leading_zeros[v] = static_cast<std::uint8_t>(zeros);
        }
    }
};

inline constexpr HllLeadingZeroTable kHllLeadingZeroTable{};

}  // namespace detail

/// HyperLogLog distinct-count sketch, written from scratch: estimates how many DIFFERENT
/// keys were added (distinct services, users, IPs, ...) in m = 2^precision one-byte
/// registers, however many keys flow through. Memory is fixed (16 KiB at the default
/// precision 14, 4 KiB at 12), add() is O(1), estimate() is O(m), and two sketches built
/// on separate machines / threads / days merge into the sketch of the union.
///
/// ADDING A KEY (exact, platform independent; this is what makes sketches comparable)
///   x   = hash64(key, seed)            (hash.hpp; never std::hash)
///   i   = the LOW `precision` bits of x                      -> the register index
///   w   = x >> precision                                      -> a (64 - precision)-bit value
///   rho = 1 + (number of leading zero bits of w inside its (64 - precision)-bit width),
///         i.e. the 1-based position of the leftmost set bit of w counted from the top of
///         the width; rho = (64 - precision) + 1 when w == 0.
///   register[i] = max(register[i], rho).
///   Registers are bytes: rho <= 64 - 4 + 1 = 61. Everything here is integer arithmetic, so
///   the registers after any sequence of add() and merge() calls are bit-identical on every
///   platform and compiler for the same keys and seed.
///   Consequences: adding a key twice never changes anything (same x, same register, same
///   rho); the order of adds does not matter (max is commutative and associative); the empty
///   key is an ordinary key (with seed 0 its hash is 0: register 0 gets the maximal rho, and
///   it counts as exactly one distinct key like any other).
///
/// ESTIMATE
///   Let V = number of registers equal to 0 and S = sum over all registers of 2^-register.
///     raw = alpha_m * m^2 / S
///   with alpha_16 = 0.673, alpha_32 = 0.697, alpha_64 = 0.709 and, for m >= 128,
///   alpha_m = 0.7213 / (1 + 1.079 / m) (Flajolet, Fusy, Gandouet, Meunier 2007). Precisions
///   4, 5 and 6 (m = 16, 32, 64) use the three constants.
///     small range: if raw <= 2.5 * m and V > 0, the estimate is the linear-counting value
///                  m * ln(m / V): while many registers are still empty it is far more
///                  accurate than raw, which is biased there (raw of an empty sketch would be
///                  alpha_m * m, not 0).
///     otherwise:   raw.
///   An empty sketch estimates exactly 0 (checked explicitly, not left to ln(1)).
///   NO LARGE-RANGE CORRECTION. The original paper corrects the estimate near 2^32 distinct
///   keys because its hash was 32 bits wide and distinct keys started to share hash values.
///   Here the hash has 64 bits: the expected fraction of keys lost to full-hash collisions is
///   about n / 2^65 (3e-8 even for n = 10^12, against a standard error of 0.8%), and the
///   registers (which hold rho <= 64 - precision + 1) cannot saturate before n is of the
///   order 2^64, more than a 64-bit count can express. The 32-bit correction would be wrong
///   here, so none is applied.
///   count() is estimate() rounded to the nearest integer (halves round up; a value that does
///   not fit std::uint64_t, which no real stream can produce, saturates at UINT64_MAX).
///
///   How S is computed: no std::pow and no per-register floating-point addition. Every term
///   2^-r is accumulated EXACTLY as an integer in two 64-bit accumulators (terms with r <= 32
///   scaled by 2^32, terms with r > 32 scaled by 2^61; they cannot overflow, the largest
///   possible totals are 2^50 and 2^46) and converted once. Both accumulators and both
///   conversions are exact, so S is the correctly rounded exact sum: it does not depend on
///   the order of the registers at all (the loop runs in index order anyway). The remaining
///   arithmetic is evaluated in the fixed order ((alpha * (m * m)) / S) with correctly
///   rounded IEEE-754 binary64 operations.
///
/// DETERMINISM
///   Registers are integers produced by integer arithmetic only: bit-identical on every
///   platform and compiler for the same keys and seed, and independent of the order of adds.
///   estimate() is a deterministic function of the registers: S is exact, and the raw branch
///   uses nothing but correctly rounded binary64 +, * and /, so it is bit-identical on every
///   IEEE-754 platform that evaluates doubles without excess precision (x86-64 SSE2, ARM64,
///   ...; not 32-bit x87 code). The linear-counting branch calls std::log, which C libraries
///   may round differently in the last place: across platforms the same registers can give
///   estimates that differ by about 1e-16 relative (count() then differs only if an estimate
///   lies within that distance of a .5 boundary). Inside one build everything repeats
///   exactly. The tests compare estimates across platforms at 1e-12 relative and pin the
///   registers exactly.
///
/// ACCURACY
///   Relative standard error: about 1.04 / sqrt(m), standard_error(): 0.81% at precision 14,
///   1.6% at 12, 0.20% at 18, 26% at 4. Halving the error costs four times the memory. The
///   figure is asymptotic (large n, large m): measured on this implementation with distinct
///   keys far above 5 * m the rms error is 0.85 - 0.95 of it at precisions 10 - 16 (mean
///   absolute error 0.7 SE), but at m = 16 the distribution is skewed with a long right tail
///   (99.9th percentile of |error| about 5 SE, largest of 15000 runs 9.9 SE). It is a statistical
///   property of the hash, NOT a bound for a given stream, and an adversary who knows the
///   seed can craft keys that skew it. Below 2.5 * m the error is much smaller than the
///   standard error because linear counting is nearly exact: 1, 2, 3 keys at precision 14
///   estimate 1.00003, 2.0001, 3.0003, and 100 keys at most a few tenths too high; a register
///   collision costs about one key, so tiny counts can come out one or two too low.
///
///   KNOWN BIAS IN THE TRANSITION REGION. This is the original estimator of the paper, with a
///   hard switch from linear counting to raw at raw = 2.5 * m, and raw itself overestimates
///   just above the switch. Measured here as the mean of (estimate / n - 1) over 200 - 1500
///   seeds per precision (10, 12, 14, 16; distinct 8-byte keys), r = n / m:
///
///        r       2.0    2.4         2.5     2.6     3.0     3.5     4.0     5.0    >= 6
///        bias    0.0%   +0.9 .. 0%  +2.4%   +2.0%   +1.05%  +0.45%  +0.2%   <0.1%  0.0%
///
///   (at r = 2.4 the bias is +0.9% at precision 10 and 0.0% at precision 16: the cliff at the
///   switch is sharper the more registers there are; the error of one sketch is a mixture of
///   the two formulas there, reaching 5 SE at precision 12 in 1000 runs). The bias in PERCENT
///   is the same at every precision while the standard error shrinks, so in units of SE the
///   bump grows with precision: +0.6 SE at precision 10, +1.5 at 12, +3.0 at 14, +5.9 at 16.
///   At precision 18, 10^6 keys (r = 3.8) are already +0.27% = 1.4 SE too high. Newer
///   estimators (HyperLogLog++ bias tables, LogLog-Beta, Ertl's maximum-likelihood
///   estimator) remove the bump; they are deliberately left out so the algorithm stays the
///   one in the paper. Outside r = 2.2 ... 5.5 no bias is measurable (below 0.1% against a
///   standard error of the mean of 0.03 - 0.1%).
///
///   SEEDS AND SHORT KEYS. hash64 combines the seed with the key by XOR; for keys of 8 bytes
///   or more the key has been mixed first, so different seeds are independent hash functions.
///   For keys shorter than 8 bytes the XOR meets the raw key bytes: two seeds then differ
///   by a translation of the key space, so on a key set with exactly that kind of structure
///   (every value of a small counter, say) two small seeds can produce nearly identical
///   sketches. Irrelevant for log text; do not rely on seeds to decorrelate sketches of
///   dense short binary ids.
///
/// MERGE
///   merge(other) is the register-wise maximum. It is commutative, associative and idempotent
///   (a sketch merged with itself, or with any sketch it already contains, does not change),
///   and EXACT: after a.merge(b), a has precisely the registers (and so precisely the
///   estimate) of one sketch that saw both streams, in any order. That is what makes
///   sharding possible: one sketch per file / service / hour, merged on demand, and the
///   union's distinct count needs no re-reading. Sketches merge only when precision AND seed
///   match (different seeds mean different hash functions, so their registers say nothing
///   about each other); otherwise std::invalid_argument is thrown and neither object changes.
///   The intersection of two sets is NOT available from a merge.
///
/// COMPLEXITY (m = 2^precision)
///   add          O(|key|) for hash64 (it reads each key byte once), then O(1): one byte
///                compare-and-store. Nothing grows with the number of keys added.
///   estimate     O(m), independent of how many keys were added: it reads only the register
///                array, once, and counts nothing else. count() is the same.
///   merge        O(m).
///   clear        O(m) (zero fill; the storage is kept for reuse).
///   empty        O(1) (a count of non-zero registers is maintained by add and merge).
///   Memory: exactly m bytes of registers (memory_bytes()), plus a few words.
///
/// EXCEPTIONS AND GUARANTEES
///   The constructor throws std::invalid_argument unless 4 <= precision <= 18 (and allocates
///   nothing in that case), or std::bad_alloc. add() and merge() throw std::bad_alloc only
///   when a moved-from sketch has to re-allocate its registers, and change nothing in that
///   case. merge() checks precision and seed before touching anything (std::invalid_argument,
///   strong guarantee). register_value throws std::out_of_range for a bad index. Nothing else
///   throws: estimate, count, clear, empty, the accessors and == never allocate. Copy
///   assignment has the strong guarantee; the moves are noexcept.
///
/// THREADING
///   const members keep no scratch state: any number of threads may call them concurrently
///   as long as nobody calls a non-const member at the same time.
///
/// COPY / MOVE
///   Copyable (a deep copy of the register array) and movable; copy and move assignment
///   replace precision and seed too, since a sketch is a value. A moved-from sketch is
///   empty, keeps its precision and seed, owns no storage (memory_bytes() == 0, estimate()
///   == 0) and is fully reusable: the next add() or a merge of a non-empty sketch
///   re-allocates the registers. That is why the moves are noexcept and cheap.
class HyperLogLog {
public:
    static constexpr unsigned kMinPrecision = 4;
    static constexpr unsigned kMaxPrecision = 18;

    /// 2^precision registers; precision outside [4, 18] throws std::invalid_argument.
    /// `seed` selects the hash function: sketches only merge with sketches of the same
    /// precision and seed.
    explicit HyperLogLog(unsigned precision = 14, std::uint64_t seed = 0)
        : precision_(checked_precision(precision)),
          seed_(seed),
          registers_(std::size_t{1} << precision_, std::uint8_t{0}) {}

    HyperLogLog(const HyperLogLog&) = default;

    HyperLogLog& operator=(const HyperLogLog& other) {
        if (this != &other) {
            HyperLogLog copy(other);  // copy-and-move: a failed allocation leaves *this untouched
            *this = std::move(copy);
        }
        return *this;
    }

    HyperLogLog(HyperLogLog&& other) noexcept
        : precision_(other.precision_),
          seed_(other.seed_),
          registers_(std::move(other.registers_)),
          nonzero_(other.nonzero_) {
        other.registers_.clear();  // a moved-from vector is only "valid but unspecified"
        other.nonzero_ = 0;
    }

    HyperLogLog& operator=(HyperLogLog&& other) noexcept {
        if (this != &other) {
            precision_ = other.precision_;
            seed_ = other.seed_;
            registers_ = std::move(other.registers_);
            nonzero_ = other.nonzero_;
            other.registers_.clear();
            other.nonzero_ = 0;
        }
        return *this;
    }

    /// Records one key (any byte string, embedded NULs and the empty key included).
    /// Idempotent per key; see "ADDING A KEY" above.
    void add(std::string_view key) {
        const std::uint64_t x = hash64(key, seed_);
        ensure_storage();  // before the first change, so a bad_alloc leaves the sketch untouched
        const std::uint64_t index_mask = register_count() - 1;
        const auto index = static_cast<std::size_t>(x & index_mask);
        // rho = 1 + leading zeros of w inside its (64 - precision)-bit width. Shifting w back up
        // (x with the index bits cleared) puts the top of that width at bit 63, and planting a 1
        // just below it (bit precision - 1, where the index bits were) makes the word non-zero
        // and counts the w == 0 case right with no special branch: the sentinel is then the
        // leftmost set bit, 64 - precision zeros from the top, so rho = width + 1.
        const std::uint64_t shifted = (x & ~index_mask) | ((index_mask >> 1) + 1);
        const auto rho = static_cast<std::uint8_t>(1 + leading_zeros_nonzero(shifted));
        std::uint8_t& slot = registers_[index];
        if (rho > slot) {
            if (slot == 0) ++nonzero_;
            slot = rho;
        }
    }

    /// Estimated number of distinct keys added; see "ESTIMATE" and "ACCURACY" above.
    /// 0 exactly for an empty sketch. O(m), independent of the number of keys added.
    double estimate() const {
        if (nonzero_ == 0) return 0.0;  // also the storage-less moved-from state

        // The only pass over data: one read per register, in index order. Exact integer
        // accumulation of 2^-r (see the header comment), plus the number of empty registers.
        std::uint64_t coarse = 0;  // sum of 2^(32 - r) over registers with r <= 32
        std::uint64_t fine = 0;    // sum of 2^(61 - r) over registers with r > 32
        std::size_t zeros = 0;
        const std::size_t m = registers_.size();
        for (std::size_t i = 0; i < m; ++i) {
            const unsigned r = registers_[i];
            if (r == 0) ++zeros;
            if (r <= 32) coarse += std::uint64_t{1} << (32u - r);
            else fine += std::uint64_t{1} << (61u - r);
        }
        const double md = static_cast<double>(m);
        const double sum = static_cast<double>(coarse) / 4294967296.0 +              // 2^32
                           static_cast<double>(fine) / 2305843009213693952.0;        // 2^61
        const double raw = alpha(m) * (md * md) / sum;
        if (raw <= 2.5 * md && zeros > 0) return md * std::log(md / static_cast<double>(zeros));
        return raw;
    }

    /// estimate() rounded to the nearest integer (halves round up), saturating at UINT64_MAX.
    std::uint64_t count() const {
        const double e = estimate();
        if (!(e < 18446744073709551616.0)) return std::numeric_limits<std::uint64_t>::max();  // 2^64
        const double whole = std::floor(e);
        const auto rounded = static_cast<std::uint64_t>(whole);
        // e - whole is exact; comparing the fraction avoids the e + 0.5 trap (0.49999999999999994 + 0.5 == 1.0).
        return (e - whole >= 0.5) ? rounded + 1 : rounded;
    }

    /// Becomes the sketch of the union of both streams: register-wise maximum. Throws
    /// std::invalid_argument, changing nothing, unless precision AND seed both match.
    /// merge(*this) is a no-op.
    void merge(const HyperLogLog& other) {
        if (precision_ != other.precision_) {
            throw std::invalid_argument("HyperLogLog::merge: precision mismatch");
        }
        if (seed_ != other.seed_) {
            throw std::invalid_argument("HyperLogLog::merge: seed mismatch");
        }
        if (other.nonzero_ == 0) return;  // the identity element; also covers a moved-from `other`
        ensure_storage();                 // the only step that can throw
        const std::size_t m = registers_.size();
        for (std::size_t i = 0; i < m; ++i) {
            const std::uint8_t theirs = other.registers_[i];
            if (theirs > registers_[i]) {
                if (registers_[i] == 0) ++nonzero_;
                registers_[i] = theirs;
            }
        }
    }

    /// Forgets every key. The register storage is kept for reuse (like std::vector::clear).
    void clear() noexcept {
        for (std::uint8_t& r : registers_) r = 0;
        nonzero_ = 0;
    }

    /// True if no key was ever added (since construction or clear()); O(1).
    bool empty() const noexcept { return nonzero_ == 0; }

    unsigned precision() const noexcept { return precision_; }
    std::size_t register_count() const noexcept { return std::size_t{1} << precision_; }
    std::uint64_t seed() const noexcept { return seed_; }

    /// Bytes of the register array: register_count() for any sketch that has not been moved
    /// from, 0 for a moved-from one until it is reused.
    std::size_t memory_bytes() const noexcept { return registers_.size(); }

    /// 1.04 / sqrt(m): the relative standard error of estimate() for large counts.
    double standard_error() const noexcept { return 1.04 / std::sqrt(static_cast<double>(register_count())); }

    /// Value of one register, 0 <= value <= 64 - precision + 1. Mostly for tests and
    /// diagnostics. Throws std::out_of_range if index >= register_count().
    std::uint8_t register_value(std::size_t index) const {
        if (index >= register_count()) throw std::out_of_range("HyperLogLog::register_value: index out of range");
        return registers_.empty() ? std::uint8_t{0} : registers_[index];
    }

    /// Same precision, same seed and identical registers (a moved-from sketch equals a
    /// freshly constructed empty one of the same configuration).
    friend bool operator==(const HyperLogLog& a, const HyperLogLog& b) noexcept {
        if (a.precision_ != b.precision_ || a.seed_ != b.seed_ || a.nonzero_ != b.nonzero_) return false;
        if (a.nonzero_ == 0) return true;  // both all-zero, with or without storage
        return a.registers_ == b.registers_;
    }
    friend bool operator!=(const HyperLogLog& a, const HyperLogLog& b) noexcept { return !(a == b); }

private:
    static constexpr unsigned checked_precision(unsigned precision) {
        if (precision < kMinPrecision || precision > kMaxPrecision) {
            throw std::invalid_argument("HyperLogLog: precision must be between 4 and 18");
        }
        return precision;
    }

    // Leading zero bits of a NON-ZERO word: portable (no compiler intrinsic, no floating point).
    // Skips all-zero bytes from the top, then one table lookup. add() passes words whose top
    // byte is zero with probability 1/256 only, so the loop almost never iterates and its
    // branch is predictable. Counting bit by bit, or halving with an `if` per step, costs a
    // long dependent chain (or, on coin-flip data, mispredicted branches), about as much as
    // the hash itself.
    static unsigned leading_zeros_nonzero(std::uint64_t word) noexcept {
        unsigned zeros = 0;
        while ((word >> 56) == 0) {
            word <<= 8;
            zeros += 8;
        }
        return zeros + detail::kHllLeadingZeroTable.leading_zeros[word >> 56];
    }

    static double alpha(std::size_t m) noexcept {
        switch (m) {
            case 16: return 0.673;
            case 32: return 0.697;
            case 64: return 0.709;
            default: return 0.7213 / (1.0 + 1.079 / static_cast<double>(m));
        }
    }

    // Only a moved-from sketch has no storage; every other path finds it already allocated.
    void ensure_storage() {
        if (registers_.empty()) registers_.assign(register_count(), std::uint8_t{0});
    }

    unsigned precision_;
    std::uint64_t seed_;
    std::vector<std::uint8_t> registers_;  // size m, or 0 for a moved-from sketch (= all zero)
    std::size_t nonzero_ = 0;              // number of registers > 0; empty() is nonzero_ == 0
};

}  // namespace loganalyzer
