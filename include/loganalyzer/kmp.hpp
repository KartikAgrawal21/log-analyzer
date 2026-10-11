#pragma once

#include <cstddef>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace loganalyzer {

/// Knuth-Morris-Pratt substring matcher, written from scratch (no std::string::find, no
/// std::search, no std::boyer_moore_searcher).
///
/// Construction precomputes the prefix function ("failure table") of the pattern once in
/// O(|pattern|); every search afterwards is a single left-to-right pass over the text in
/// O(|text|) that never moves backwards, so one matcher is cheap to reuse across millions
/// of log lines. The pattern is copied, so the string_view passed to the constructor does not
/// need to outlive it; texts passed to the search functions are only read during the call.
/// All search functions are const and safe to call concurrently on one matcher.
///
/// Why the pass is linear: let k be the number of pattern bytes currently matched. Each text
/// byte raises k by at most one, and every fallback step (k = failure()[k - 1]) strictly
/// lowers it and k never drops below 0. So fallbacks over the whole search are bounded by the
/// increments, i.e. by |text|: the loop takes at most |text| advances plus |text| fallbacks,
/// each O(1). That holds for the classic worst cases such as "aaa...ab" against "aaaa..." too:
/// text is never re-scanned, so there is no hidden O(|pattern| * |text|) behaviour. The same
/// argument bounds the preprocessing by 2 * |pattern| steps.
///
/// Matching rules
///  * Text and pattern are treated as raw bytes (compared as unsigned char), so embedded NULs
///    and bytes >= 128 work; nothing is ever interpreted as a C string.
///  * Matches may overlap: "aa" occurs 3 times in "aaaa" (start indices 0, 1, 2).
///  * ignore_case folds the ASCII letters A-Z onto a-z and nothing else. It does not consult
///    the C locale (no tolower / toupper) and bytes >= 128 are compared exactly, so the UTF-8
///    encodings of "E-acute" and "e-acute" differ, and so do 0xC1 and 'A'. Pattern and text are
///    folded on the fly while comparing; the stored pattern keeps its original bytes.
///  * Empty pattern: matches at every index from 0 to text.size() inclusive (text.size() + 1
///    positions, including the empty position at the very end). find(text, from) therefore
///    returns `from` when from <= text.size(), and npos otherwise.
///  * A non-empty pattern longer than the text (or than text[from..]) finds nothing.
///    from > text.size() always yields npos.
///
/// Copying duplicates the pattern and table; copy assignment has the strong exception guarantee
/// (if it throws std::bad_alloc, the target is unchanged). Moving is noexcept and leaves the
/// source as a valid matcher of the empty pattern (its ignore_case flag is kept).
class KmpMatcher {
public:
    static constexpr std::size_t npos = std::string_view::npos;

    /// Copies `pattern` and builds the failure table (may throw std::bad_alloc).
    explicit KmpMatcher(std::string_view pattern, bool ignore_case = false)
        : pattern_(pattern), ignore_case_(ignore_case) {
        if (ignore_case_) {
            build_failure<FoldAscii>();
        } else {
            build_failure<FoldNone>();
        }
    }

    KmpMatcher(const KmpMatcher&) = default;

    // Not = default: a defaulted assignment copies the pattern and then the table, and an
    // allocation failure in between would leave the new pattern next to a stale (or, on some
    // standard libraries, emptied) table. The scan indexes the table by pattern position, so
    // that is an out-of-bounds read, not just a wrong answer. Copying into a temporary first
    // and committing with the noexcept move assignment makes the update all-or-nothing.
    KmpMatcher& operator=(const KmpMatcher& other) {
        if (this != &other) {
            KmpMatcher copy(other);  // the only step that can throw; *this is untouched so far
            *this = std::move(copy);
        }
        return *this;
    }

    // Spelled out (instead of = default) so the moved-from object is guaranteed to satisfy
    // the invariant failure().size() == pattern_size(): a moved-from std::string is only
    // "valid but unspecified", and a mismatch between the two would make the scan read
    // out of bounds.
    KmpMatcher(KmpMatcher&& other) noexcept
        : pattern_(std::move(other.pattern_)),
          failure_(std::move(other.failure_)),
          ignore_case_(other.ignore_case_) {
        other.pattern_.clear();
        other.failure_.clear();
    }

    KmpMatcher& operator=(KmpMatcher&& other) noexcept {
        if (this != &other) {
            pattern_ = std::move(other.pattern_);
            failure_ = std::move(other.failure_);
            ignore_case_ = other.ignore_case_;
            other.pattern_.clear();
            other.failure_.clear();
        }
        return *this;
    }

    std::size_t pattern_size() const noexcept { return pattern_.size(); }
    bool ignore_case() const noexcept { return ignore_case_; }

    /// Start index of the first match that begins at an index >= from, or npos. O(|text| - from),
    /// and the scan stops at the first match. `from` may be any value; text before it is
    /// never examined, so a match straddling `from` is not reported.
    ///
    /// Every call is an independent search: nothing is remembered between calls, so each one
    /// starts with zero bytes matched at `from` and re-reads up to |pattern| - 1 bytes that the
    /// previous call already examined. Walking all matches with
    /// `for (p = find(t); p != npos; p = find(t, p + 1))` therefore costs
    /// O(|text| + matches * |pattern|), not one pass: with a long periodic pattern it is close
    /// to quadratic (a^k in a^n takes about (n - k + 1) * k steps). To enumerate or count
    /// matches use find_all / count, which stay in one O(|text| + matches) pass.
    std::size_t find(std::string_view text, std::size_t from = 0) const noexcept {
        return ignore_case_ ? find_impl<FoldAscii>(text, from) : find_impl<FoldNone>(text, from);
    }

    bool contains(std::string_view text) const noexcept { return find(text) != npos; }

    /// Every start index, ascending, overlapping matches included. O(|text| + matches) time:
    /// each match is one push_back during the same single pass, never a rescan. Memory is the
    /// result vector (one index per match, geometric growth) and nothing proportional to the
    /// text, so "a" in a million 'a' bytes costs a million indices and a linear amount of work.
    std::vector<std::size_t> find_all(std::string_view text) const {
        return ignore_case_ ? find_all_impl<FoldAscii>(text) : find_all_impl<FoldNone>(text);
    }

    /// Number of (overlapping) matches; same as find_all(text).size() without storing them.
    std::size_t count(std::string_view text) const noexcept {
        return ignore_case_ ? count_impl<FoldAscii>(text) : count_impl<FoldNone>(text);
    }

    /// The classic prefix function of the pattern: failure()[i] is the length of the longest
    /// PROPER prefix of pattern[0..i] that is also a suffix of pattern[0..i] (its longest
    /// "border"). Examples: "abab" -> 0 0 1 2, "aabaaab" -> 0 1 0 1 2 2 3,
    /// "abcabcabd" -> 0 0 0 1 2 3 4 5 0. With ignore_case the table describes the case-folded
    /// pattern ("AbAB" -> 0 0 1 2), because that is the comparison the search uses.
    /// Size is pattern_size(); empty for the empty pattern.
    const std::vector<std::size_t>& failure() const noexcept { return failure_; }

private:
    // Byte comparison policies. Templating the loops on them keeps the case-sensitive path
    // free of any per-byte branch for folding.
    struct FoldNone {
        static unsigned char apply(char c) noexcept { return static_cast<unsigned char>(c); }
    };

    struct FoldAscii {
        // Explicit range test rather than `c | 0x20`, which would also fold '@' to '`',
        // '[' to '{', and so on.
        static unsigned char apply(char c) noexcept {
            const unsigned char u = static_cast<unsigned char>(c);
            return (u >= 0x41 && u <= 0x5A) ? static_cast<unsigned char>(u + 0x20) : u;
        }
    };

    template <class Fold>
    void build_failure() {
        const std::size_t m = pattern_.size();
        failure_.assign(m, std::size_t{0});
        // k = length of the border of pattern[0..i-1] that we are trying to extend.
        for (std::size_t i = 1, k = 0; i < m; ++i) {
            const unsigned char c = Fold::apply(pattern_[i]);
            while (k > 0 && c != Fold::apply(pattern_[k])) k = failure_[k - 1];
            if (c == Fold::apply(pattern_[k])) ++k;
            failure_[i] = k;
        }
    }

    // The public queries only pick the comparison policy; the logic lives in these templates.
    // Not noexcept themselves so that a test policy may throw (see KmpMatcherTestAccess below).

    template <class Fold>
    std::size_t find_impl(std::string_view text, std::size_t from) const {
        if (from > text.size()) return npos;
        if (pattern_.empty()) return from;
        std::size_t found = npos;
        scan<Fold>(text, from, [&found](std::size_t start) {
            found = start;
            return false;  // first hit is all we need
        });
        return found;
    }

    template <class Fold>
    std::vector<std::size_t> find_all_impl(std::string_view text) const {
        std::vector<std::size_t> positions;
        if (pattern_.empty()) {
            positions.reserve(text.size() + 1);
            for (std::size_t i = 0; i <= text.size(); ++i) positions.push_back(i);
            return positions;
        }
        scan<Fold>(text, 0, [&positions](std::size_t start) {
            positions.push_back(start);
            return true;
        });
        return positions;
    }

    template <class Fold>
    std::size_t count_impl(std::string_view text) const {
        if (pattern_.empty()) return text.size() + 1;
        std::size_t matches = 0;
        scan<Fold>(text, 0, [&matches](std::size_t) {
            ++matches;
            return true;
        });
        return matches;
    }

    // The one search loop shared by find / find_all / count. Preconditions: non-empty
    // pattern, from <= text.size(). Calls on_match(start) for every match in ascending order
    // and stops as soon as it returns false.
    template <class Fold, class OnMatch>
    void scan(std::string_view text, std::size_t from, OnMatch&& on_match) const {
        const std::size_t m = pattern_.size();
        if (text.size() - from < m) return;  // not even room for one match
        std::size_t k = 0;                   // pattern bytes matched ending at text[i]
        for (std::size_t i = from; i < text.size(); ++i) {
            const unsigned char c = Fold::apply(text[i]);
            while (k > 0 && c != Fold::apply(pattern_[k])) k = failure_[k - 1];
            if (c == Fold::apply(pattern_[k])) ++k;
            if (k == m) {
                if (!on_match(i + 1 - m)) return;
                // Fall back to the longest border rather than 0: the next match may overlap
                // this one, and this is what makes "aa" in "aaaa" report 3 hits.
                k = failure_[m - 1];
            }
        }
    }

    // Test hook: tests/kmp_test.cpp instantiates the templates above with a policy that counts
    // byte comparisons, so "linear time" is asserted as a deterministic step budget rather than
    // with a (flaky) clock. It is defined only in that file; the long name keeps another
    // module's test helper from ever being granted access to the private state by accident.
    friend struct KmpMatcherTestAccess;

    std::string pattern_;
    std::vector<std::size_t> failure_;  // always the same size as pattern_
    bool ignore_case_ = false;
};

}  // namespace loganalyzer
