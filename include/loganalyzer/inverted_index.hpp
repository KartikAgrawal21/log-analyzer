#pragma once

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <memory>
#include <random>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

#include "loganalyzer/keyed_hash.hpp"
#include "loganalyzer/min_heap.hpp"

namespace loganalyzer {

/// Document identifier: the 0-based position of a document in insertion order.
using DocId = std::uint32_t;

namespace detail {

// Explicit ASCII ranges instead of std::isalnum / std::tolower: those consult the C locale,
// and an index built under one locale must answer queries identically under another.
constexpr bool is_token_char(char ch) noexcept {
    const auto c = static_cast<unsigned char>(ch);
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
}

constexpr char ascii_lower(char ch) noexcept {
    return (ch >= 'A' && ch <= 'Z') ? static_cast<char>(ch - 'A' + 'a') : ch;
}

constexpr bool is_query_space(char ch) noexcept {
    return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\v' || ch == '\f' || ch == '\r';
}

// Yields the tokens of a text one at a time into a caller-owned string, so a caller that
// handles one token at a time (InvertedIndex::add, the query parser) never holds them all:
// peak memory is the longest token, not 32 bytes per token of the text. tokenize() is the
// vector-building front end of the same scanner, so both always agree on what a token is.
class TokenScanner {
public:
    explicit TokenScanner(std::string_view text) noexcept : text_(text) {}

    // Replaces `token` by the next token (lower-cased) and returns true; false at the end of
    // the text. Only a fully scanned token advances end(), so if this throws (the string could
    // not grow) the scanner still describes exactly the tokens handed out before.
    bool next(std::string& token) {
        const std::size_t n = text_.size();
        std::size_t begin = pos_;
        while (begin < n && !is_token_char(text_[begin])) ++begin;
        if (begin == n) return false;
        std::size_t end = begin + 1;
        while (end < n && is_token_char(text_[end])) ++end;
        token.assign(text_.data() + begin, end - begin);
        for (char& ch : token) ch = ascii_lower(ch);
        pos_ = end;
        return true;
    }

    // Offset just past the last token returned by next() (0 before the first one).
    std::size_t end() const noexcept { return pos_; }

private:
    std::string_view text_;
    std::size_t pos_ = 0;
};

}  // namespace detail

/// Splits text into index terms.
///
///  - ASCII letters are lower-cased; nothing else is ever case-folded.
///  - A token is a maximal run of ASCII letters and digits.
///  - EVERYTHING else separates tokens: spaces, punctuation ('-', '_', '.', ':', '=', ...),
///    control characters, NUL, and every byte >= 128 (so UTF-8 text is split at each
///    non-ASCII character rather than guessed at).
///  - Empty tokens are never produced; text without any token gives an empty vector.
///
///   tokenize("Payment-Service timeout=3000ms")  ->  payment, service, timeout, 3000ms
///
/// The result does not depend on the C locale. O(|text|).
inline std::vector<std::string> tokenize(std::string_view text) {
    std::vector<std::string> tokens;
    detail::TokenScanner scanner(text);
    std::string token;
    while (scanner.next(token)) tokens.push_back(token);
    return tokens;
}

// ---------------------------------------------------------------------------------------
// Sorted-list set algebra. Every list passed in must be strictly ascending (sorted and
// duplicate-free) - which is exactly what InvertedIndex produces - and every result is
// strictly ascending too. Behavior on unsorted input is unspecified, but memory-safe.
// Ids are only ever compared with < and ==, never subtracted, so the full DocId range up to
// UINT32_MAX is safe.
// ---------------------------------------------------------------------------------------

/// A list this many times shorter than the other is intersected by galloping.
inline constexpr std::size_t kGallopRatio = 16;

/// The dispatch rule of intersect(): true when the shorter list is at least kGallopRatio
/// times shorter than the longer one (shorter * 16 <= longer, written division-first so it
/// cannot overflow). The ratio, not the absolute size, decides: the merge costs
/// O(short + long) and galloping O(short * log(long / short)), which only wins once
/// long / short is comfortably above the log factor.
constexpr bool intersect_uses_galloping(std::size_t a_size, std::size_t b_size) noexcept {
    const std::size_t shorter = a_size < b_size ? a_size : b_size;
    const std::size_t longer = a_size < b_size ? b_size : a_size;
    return shorter <= longer / kGallopRatio;
}

namespace detail {

// Probe hook of the list kernels (intersection, difference, k-way union): called once per
// step that examines list elements one by one (bulk copies are not counted). The default does
// nothing and optimizes away; tests pass a counter to check the work bounds and the
// merge-vs-gallop dispatch deterministically, instead of timing anything.
struct NoProbe {
    void operator()() const noexcept {}
};

template <class Probe>
std::vector<DocId> merge_intersect(const std::vector<DocId>& a, const std::vector<DocId>& b, Probe probe) {
    std::vector<DocId> out;
    std::size_t i = 0;
    std::size_t j = 0;
    while (i < a.size() && j < b.size()) {
        probe();
        if (a[i] < b[j]) {
            ++i;
        } else if (b[j] < a[i]) {
            ++j;
        } else {
            out.push_back(a[i]);
            ++i;
            ++j;
        }
    }
    return out;
}

// First index in [from, list.size()) holding a value >= target, or list.size() if none.
// Exponential probe (offsets 0, 1, 3, 7, ... from `from`) to bracket the answer, then a
// binary search inside the bracket: O(log d) where d is how far the answer is from `from`.
// Never looks below `from`.
template <class Probe>
std::size_t gallop_lower_bound(const std::vector<DocId>& list, std::size_t from, DocId target, Probe& probe) {
    const std::size_t n = list.size();
    auto below_target = [&](std::size_t i) {
        probe();
        return list[i] < target;
    };
    std::size_t lo = from;  // every index below lo holds a value < target
    std::size_t hi = from;  // invariant: hi == n or list[hi] >= target (once the loop exits)
    std::size_t step = 1;
    while (hi < n && below_target(hi)) {
        lo = hi + 1;
        hi = (n - hi > step) ? hi + step : n;  // clamp instead of overflowing
        step <<= 1;
    }
    while (lo < hi) {
        const std::size_t mid = lo + (hi - lo) / 2;
        if (below_target(mid)) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return lo;
}

template <class Probe>
std::vector<DocId> gallop_intersect(const std::vector<DocId>& a, const std::vector<DocId>& b, Probe probe) {
    const std::vector<DocId>& shorter = a.size() <= b.size() ? a : b;
    const std::vector<DocId>& longer = a.size() <= b.size() ? b : a;
    std::vector<DocId> out;
    out.reserve(shorter.size());
    std::size_t pos = 0;  // never decreases: both lists ascend, so earlier elements are behind us for good
    for (const DocId id : shorter) {
        pos = gallop_lower_bound(longer, pos, id, probe);
        if (pos == longer.size()) break;
        if (longer[pos] == id) {
            out.push_back(id);
            ++pos;
        }
    }
    return out;
}

template <class Probe>
std::vector<DocId> adaptive_intersect(const std::vector<DocId>& a, const std::vector<DocId>& b, Probe probe) {
    if (a.empty() || b.empty()) return {};
    if (a.back() < b.front() || b.back() < a.front()) return {};
    return intersect_uses_galloping(a.size(), b.size()) ? gallop_intersect(a, b, probe)
                                                        : merge_intersect(a, b, probe);
}

template <class Probe>
std::vector<DocId> difference_impl(const std::vector<DocId>& a, const std::vector<DocId>& b, Probe probe) {
    std::vector<DocId> out;
    out.reserve(a.size());
    std::size_t i = 0;
    std::size_t j = 0;
    while (i < a.size()) {
        if (j == b.size()) {
            out.insert(out.end(), a.begin() + static_cast<std::ptrdiff_t>(i), a.end());
            break;
        }
        probe();
        if (a[i] < b[j]) {
            out.push_back(a[i]);
            ++i;
        } else if (b[j] < a[i]) {
            ++j;
        } else {
            ++i;
            ++j;
        }
    }
    return out;
}

}  // namespace detail

/// Classic two-pointer intersection. O(|a| + |b|). Exposed so tests can compare strategies.
inline std::vector<DocId> intersect_merge(const std::vector<DocId>& a, const std::vector<DocId>& b) {
    return detail::merge_intersect(a, b, detail::NoProbe{});
}

/// Intersection by galloping: walks the SHORTER list and locates each of its elements in
/// the longer one with an exponential probe followed by a binary search, resuming from the
/// previous hit so the search position never moves backwards. O(s * log(l / s)) for s = the
/// shorter and l = the longer length. Correct for any sizes (the argument order is
/// irrelevant); it is just slower than the merge when the lists have similar length.
inline std::vector<DocId> intersect_gallop(const std::vector<DocId>& a, const std::vector<DocId>& b) {
    return detail::gallop_intersect(a, b, detail::NoProbe{});
}

/// Ids present in both lists. Adaptive: when one list is at least kGallopRatio (16) times
/// shorter than the other (see intersect_uses_galloping) it gallops through the long list,
/// otherwise it runs the plain two-pointer merge; both strategies return identical results.
/// Empty inputs and lists whose id ranges do not overlap return in O(1).
inline std::vector<DocId> intersect(const std::vector<DocId>& a, const std::vector<DocId>& b) {
    return detail::adaptive_intersect(a, b, detail::NoProbe{});
}

/// Ids in `a` that are not in `b` (a minus b), by a linear merge. O(|a| + |b|).
inline std::vector<DocId> difference(const std::vector<DocId>& a, const std::vector<DocId>& b) {
    return detail::difference_impl(a, b, detail::NoProbe{});
}

namespace detail {

// A half-open view [first, last) of one posting list. Lets the k-way merge work on lists it
// does not own (InvertedIndex merges its own postings without copying them first).
struct Span {
    const DocId* first;
    const DocId* last;
};

inline Span span_of(const std::vector<DocId>& list) noexcept {
    return Span{list.data(), list.data() + list.size()};
}

// The heap holds one small cursor per live list, never list contents.
struct HeadCursor {
    DocId value;  // cached current element, so heap comparisons never dereference
    const DocId* next;
    const DocId* last;
};

struct HeadLess {
    bool operator()(const HeadCursor& a, const HeadCursor& b) const noexcept { return a.value < b.value; }
};

template <class Probe>
std::vector<DocId> unite_spans(const std::vector<Span>& spans, Probe probe) {
    // Empty lists never enter the heap. Spans that are literally the same list (the same
    // term named twice in one query) are merged once: without this, "a|a|a|..." would cost
    // k full passes over the same postings.
    std::vector<Span> live;
    live.reserve(spans.size());
    for (const Span& s : spans) {
        if (s.first != s.last) live.push_back(s);
    }
    const std::less<const DocId*> before{};
    std::sort(live.begin(), live.end(), [&before](const Span& x, const Span& y) {
        if (before(x.first, y.first)) return true;
        if (before(y.first, x.first)) return false;
        return before(x.last, y.last);
    });
    live.erase(std::unique(live.begin(), live.end(),
                           [](const Span& x, const Span& y) { return x.first == y.first && x.last == y.last; }),
               live.end());

    if (live.empty()) return {};
    if (live.size() == 1) return std::vector<DocId>(live.front().first, live.front().last);

    MinHeap<HeadCursor, HeadLess> heap;
    std::size_t widest = 0;
    for (const Span& s : live) {
        widest = std::max(widest, static_cast<std::size_t>(s.last - s.first));
        heap.push(HeadCursor{*s.first, s.first + 1, s.last});
    }

    // `cur` is always the global minimum. After advancing it, it only goes back into the heap
    // when another list now holds something smaller, so a run from one list costs one
    // comparison per element instead of a full sift_down + sift_up. Worst case O(N log k).
    std::vector<DocId> out;
    out.reserve(widest);  // lower bound on the answer; vector growth handles the rest
    HeadCursor cur = heap.pop();
    for (;;) {
        probe();
        if (out.empty() || out.back() != cur.value) out.push_back(cur.value);  // dedup across lists
        if (cur.next == cur.last) {
            if (heap.empty()) break;
            cur = heap.pop();
        } else {
            cur.value = *cur.next++;
            if (!heap.empty() && heap.top().value < cur.value) {
                heap.push(cur);
                cur = heap.pop();
            }
        }
    }
    return out;
}

inline std::vector<DocId> unite_spans(const std::vector<Span>& spans) { return unite_spans(spans, NoProbe{}); }

// The union of many OWNED lists that arrive one at a time, without ever holding them all:
// pending lists sit on a stack and the top two are merged whenever the one below is not more
// than twice as long (the carry chain of a binary counter). The stack therefore stays about
// log2(N) deep and its lists add up to little more than the final answer, instead of all k
// inputs being alive at once; every id takes part in O(log N) merges, so the total is still
// O(N log N) (each merge is a MinHeap k-way merge with k = 2).
template <class Probe>
class UnionAccumulator {
public:
    explicit UnionAccumulator(Probe probe) : probe_(std::move(probe)) {}

    void add(std::vector<DocId> part) {
        if (part.empty()) return;
        stack_.push_back(std::move(part));
        while (stack_.size() >= 2 && stack_[stack_.size() - 2].size() / 2 <= stack_.back().size()) merge_top_two();
    }

    // Everything added so far, united; the accumulator is empty afterwards.
    std::vector<DocId> take() {
        while (stack_.size() >= 2) merge_top_two();
        if (stack_.empty()) return {};
        std::vector<DocId> result = std::move(stack_.back());
        stack_.clear();
        return result;
    }

    // Lists currently held (at most about log2 of the total number of ids). For tests.
    std::size_t pending() const noexcept { return stack_.size(); }

private:
    void merge_top_two() {
        std::vector<DocId> merged =
            unite_spans({span_of(stack_[stack_.size() - 2]), span_of(stack_.back())}, probe_);
        stack_.pop_back();
        stack_.back() = std::move(merged);
    }

    Probe probe_;
    std::vector<std::vector<DocId>> stack_;
};

// Intersects all lists, smallest first, stopping as soon as the running result is empty.
// Starting from the shortest list keeps every later step "short vs long", which is exactly
// when intersect() gallops. Lists that are the same object are intersected once.
template <class Probe>
std::vector<DocId> intersect_smallest_first(std::vector<const std::vector<DocId>*> lists, Probe probe) {
    if (lists.empty()) return {};
    const std::less<const std::vector<DocId>*> before{};
    std::sort(lists.begin(), lists.end(), [&before](const std::vector<DocId>* x, const std::vector<DocId>* y) {
        if (x->size() != y->size()) return x->size() < y->size();
        return before(x, y);  // total order, so equal lists end up adjacent for unique()
    });
    lists.erase(std::unique(lists.begin(), lists.end()), lists.end());
    if (lists.size() == 1) return *lists.front();
    std::vector<DocId> result = adaptive_intersect(*lists[0], *lists[1], probe);
    for (std::size_t i = 2; i < lists.size() && !result.empty(); ++i) {
        result = adaptive_intersect(result, *lists[i], probe);
    }
    return result;
}

inline std::vector<DocId> intersect_smallest_first(std::vector<const std::vector<DocId>*> lists) {
    return intersect_smallest_first(std::move(lists), NoProbe{});
}

// ---- query building blocks -------------------------------------------------------------
// A query is resolved against the index while it is parsed: every token becomes a pointer to
// its postings list (an unknown token is a list that is known to be empty and is dropped at
// once). The canonical forms below make equal pieces of a query compare equal, so they are
// evaluated once however often the query repeats them.

using ListPtr = const std::vector<DocId>*;

// Documents containing ALL of these lists' terms: sorted by address, duplicate-free, never empty.
using Conjunction = std::vector<ListPtr>;

// Documents matching AT LEAST ONE of these conjunctions: sorted, duplicate-free.
using Disjunction = std::vector<Conjunction>;

struct ListPtrLess {
    bool operator()(ListPtr a, ListPtr b) const noexcept { return std::less<ListPtr>{}(a, b); }
};

struct ConjunctionLess {
    bool operator()(const Conjunction& a, const Conjunction& b) const noexcept {
        return std::lexicographical_compare(a.begin(), a.end(), b.begin(), b.end(), ListPtrLess{});
    }
};

struct DisjunctionLess {
    bool operator()(const Disjunction& a, const Disjunction& b) const noexcept {
        return std::lexicographical_compare(a.begin(), a.end(), b.begin(), b.end(), ConjunctionLess{});
    }
};

inline void canonicalize(Disjunction& word) {
    std::sort(word.begin(), word.end(), ConjunctionLess{});
    word.erase(std::unique(word.begin(), word.end()), word.end());
}

// An upper bound on how many documents a disjunction can match: each conjunction matches at
// most as many as its shortest list. Used to evaluate the cheapest required word first.
inline std::uint64_t estimated_size(const Disjunction& word) {
    std::uint64_t total = 0;
    for (const Conjunction& conjunction : word) {
        std::size_t smallest = std::numeric_limits<std::size_t>::max();
        for (const ListPtr list : conjunction) smallest = std::min(smallest, list->size());
        total += smallest;
    }
    return total;
}

// ---- term table ------------------------------------------------------------------------

// Hash of the term table. std::hash<std::string> is no defense: MSVC's is unseeded FNV-1a
// with a power-of-two bucket mask, so a few hundred KB of crafted log text pile every term
// into one bucket and turn add() and every lookup quadratic (measured: 6,000 colliding
// tokens made add() 96 times slower, and the gap grows with the square of the count). The
// keyed SipHash and the per-table random key live in keyed_hash.hpp, shared with TopKErrors.
struct TermHash {
    std::uint64_t key0 = 0;
    std::uint64_t key1 = 0;

    std::size_t operator()(const std::string& term) const noexcept {
        return static_cast<std::size_t>(siphash24(key0, key1, term.data(), term.size()));
    }
};

// A new random key for every index.
inline TermHash fresh_term_hash() {
    const HashKeys keys = fresh_hash_keys();
    TermHash hash;
    hash.key0 = keys.key0;
    hash.key1 = keys.key1;
    return hash;
}
// Node-based, so the address of a postings list survives rehashing and every later add().
using TermMap = std::unordered_map<std::string, std::vector<DocId>, TermHash>;

// Where InvertedIndex::add() calls its hook. Production code passes NoHook, which compiles
// away; tests inject failures between the steps of a half-finished add().
enum class AddStage { BeforeLookup, BeforeAppend };

struct NoHook {
    void operator()(AddStage, std::size_t, std::size_t) const noexcept {}
};

// Outcome of looking up the tokens of one query alternative; see InvertedIndex::resolve().
enum class Resolved { NoTokens, Unknown, Known };

}  // namespace detail

/// Union of any number of sorted lists (empty lists and an empty `lists` are fine), with ids
/// that occur in several lists reported once. A k-way merge over a MinHeap of small cursors:
/// O(N log k) for N total elements in k non-empty lists. A list that is the same object as
/// another one is merged once.
inline std::vector<DocId> unite(const std::vector<std::vector<DocId>>& lists) {
    std::vector<detail::Span> spans;
    spans.reserve(lists.size());
    for (const std::vector<DocId>& list : lists) spans.push_back(detail::span_of(list));
    return detail::unite_spans(spans);
}

struct InvertedIndexTestAccess;

/// Inverted index over short texts (log messages): term -> ascending list of the documents
/// containing it, plus AND / OR / NOT search over those lists.
///
/// Terms and queries share one definition: tokenize() above. Everything is therefore
/// case-insensitive ("TimeOut" == "timeout") and punctuation-insensitive, and a term is a
/// whole token: there is no prefix, substring or wildcard matching ("time" does not find
/// "timeout", "3000" does not find "3000ms").
///
/// Looking up a "term" you pass in (postings, search_and, search_or, and the alternatives
/// inside search()) first tokenizes it:
///   - exactly one token: that token is looked up;
///   - zero tokens ("", "---", "!!"): the term matches nothing at all;
///   - several tokens ("payment-service"): the term means ALL of those tokens at once, i.e.
///     a document matches when it contains payment AND service (in any order and place -
///     this is not a phrase search).
///
/// Document ids are 0, 1, 2, ... in insertion order, so every postings list is ascending
/// and duplicate-free as a by-product of appending, with no sorting anywhere.
///
/// The term table is a hash table keyed with SipHash and a random per-index key, so text
/// chosen by an attacker (log lines are attacker-influenced) cannot be crafted to make adds
/// and lookups degrade: expected O(|token|) per token, whatever the tokens are.
///
/// Value semantics. Copying duplicates the whole index. Moving is O(1) and noexcept, so
/// std::vector<InvertedIndex> grows without deep copies, and a postings reference taken
/// before a move keeps denoting the same list, which now belongs to the destination. A
/// moved-from index is a valid EMPTY index: doc_count() == 0, no terms, and add() starts
/// again at id 0 (it keeps its capacity setting). Assigning to an index invalidates the
/// postings references it handed out.
///
/// Thread safety: const members may run concurrently with each other; add() needs exclusive
/// access.
class InvertedIndex {
public:
    /// Size of the DocId space: documents 0 .. 2^32 - 1.
    static constexpr std::uint64_t kMaxDocuments = std::uint64_t{std::numeric_limits<DocId>::max()} + 1;

    /// An empty index with room for the whole DocId space. Implicit, so `InvertedIndex x = {};`
    /// and `return {};` work.
    InvertedIndex() = default;

    /// An empty index that accepts at most `max_documents` documents (larger values are
    /// clamped to kMaxDocuments). It exists so the overflow behavior of add() can be
    /// exercised without allocating four billion documents.
    explicit InvertedIndex(std::uint64_t max_documents) : max_documents_(std::min(max_documents, kMaxDocuments)) {}

    InvertedIndex(const InvertedIndex& other)
        : terms_(clone(other.terms_)), doc_count_(other.doc_count_), max_documents_(other.max_documents_) {}

    InvertedIndex(InvertedIndex&& other) noexcept
        : terms_(std::move(other.terms_)), doc_count_(other.doc_count_), max_documents_(other.max_documents_) {
        other.doc_count_ = 0;  // terms_ was emptied by the move; keep the source self-consistent
    }

    InvertedIndex& operator=(const InvertedIndex& other) {
        if (this != &other) *this = InvertedIndex(other);  // copy first, so a failed copy changes nothing
        return *this;
    }

    InvertedIndex& operator=(InvertedIndex&& other) noexcept {
        if (this != &other) {
            terms_ = std::move(other.terms_);
            doc_count_ = other.doc_count_;
            max_documents_ = other.max_documents_;
            other.doc_count_ = 0;
        }
        return *this;
    }

    ~InvertedIndex() = default;

    /// Indexes `text` as the next document and returns its id (0 for the first call, then
    /// 1, 2, ...). The DISTINCT tokens of the text are indexed: a token repeated inside the
    /// document is recorded once. A document with no tokens at all ("" or "--- !!") still
    /// consumes an id (it counts in doc_count() and is returned by an all-negated query).
    ///
    /// Throws std::length_error, and changes nothing, when the id space is exhausted
    /// (doc_count() has reached the capacity: 2^32 documents by default). If an allocation
    /// fails midway, the partially indexed document is rolled back before the exception
    /// propagates, so the index stays consistent (strong guarantee).
    ///
    /// O(|text|) expected: one hash lookup and one amortized-O(1) append per token. The text
    /// is scanned in place, one token at a time, so beyond the index's own growth the extra
    /// memory is the longest token, however many tokens the text has.
    DocId add(std::string_view text) { return add_with(text, detail::NoHook{}); }

    /// Number of documents added so far (also the next id that add() will return).
    std::size_t doc_count() const noexcept { return static_cast<std::size_t>(doc_count_); }

    /// Number of distinct terms (tokens) across all documents.
    std::size_t term_count() const noexcept { return terms_ ? terms_->size() : 0; }

    /// Ids of the documents containing `term`, ascending and duplicate-free.
    ///
    /// The term is tokenized first (see the class comment). If it yields exactly one token,
    /// that token's list is returned. If it yields zero tokens or several tokens the result
    /// is the empty list: a multi-token term has no single list of its own, so use
    /// search_and({term}) for "contains every token of term". An unknown term also gives the
    /// empty list.
    ///
    /// The empty list is one shared static vector, so the reference stays valid even after
    /// the index is destroyed. A reference to a real list stays valid (and keeps tracking
    /// later add() calls) until the index itself is destroyed or assigned to; add() never
    /// invalidates it, though the vector's elements may move, and moving the index hands the
    /// list over to the destination.
    const std::vector<DocId>& postings(std::string_view term) const {
        detail::TokenScanner scanner(term);
        std::string first;
        if (!scanner.next(first)) return empty_list();
        std::string second;
        if (scanner.next(second)) return empty_list();
        const std::vector<DocId>* list = find_list(first);
        return list != nullptr ? *list : empty_list();
    }

    /// Documents containing every term (each term may itself be several tokens, which all
    /// must be present). An empty `terms` returns empty, as does any unknown term and any
    /// term without tokens. Postings lists are intersected smallest first, so the cost is
    /// governed by the rarest term, and the work stops as soon as the running result is
    /// empty. Ascending, duplicate-free.
    std::vector<DocId> search_and(const std::vector<std::string>& terms) const {
        std::vector<detail::ListPtr> lists;
        std::string token;
        for (const std::string& term : terms) {
            detail::TokenScanner scanner(term);
            bool any = false;
            while (scanner.next(token)) {
                any = true;
                const std::vector<DocId>* list = find_list(token);
                if (list == nullptr) return {};
                lists.push_back(list);
            }
            if (!any) return {};
        }
        return detail::intersect_smallest_first(std::move(lists));
    }

    /// Documents containing at least one term (a multi-token term counts when the document
    /// has all of its tokens). Unknown terms and terms without tokens contribute nothing;
    /// an empty `terms` returns empty. Equal terms (after tokenizing) are merged once, and
    /// the union is a MinHeap k-way merge, so O(N log k) for N postings in k distinct terms.
    /// Ascending, duplicate-free.
    std::vector<DocId> search_or(const std::vector<std::string>& terms) const {
        return search_or_with(terms, detail::NoProbe{});
    }

    /// Query language: whitespace-separated WORDS (space, \t, \n, \v, \f, \r).
    ///
    ///   timeout                 documents containing "timeout"
    ///   timeout refused         ... containing BOTH (words are ANDed)
    ///   timeout|refused         ... containing EITHER ('|' separates alternatives)
    ///   payment-service         ... containing payment AND service (several tokens in one
    ///                           alternative must all be present)
    ///   -debug                  a leading '-' NEGATES the word: documents with none of its
    ///                           alternatives ("-a|b" excludes documents with a or with b)
    ///   error -timeout          error AND NOT timeout
    ///   -timeout -refused       only negations: every document that has neither
    ///
    /// Result = (documents matching EVERY non-negated word) minus (documents matching ANY
    /// negated word). A query made only of negated words starts from the universe of all
    /// documents 0 .. doc_count()-1, which is why empty documents show up in such results.
    ///
    /// Words are parsed leniently, and search() never throws on odd input (apart from
    /// allocation failure):
    ///   - an alternative that tokenizes to zero tokens is ignored ("a||b" == "a|b");
    ///   - a word left with no usable alternative ("|", "-", "--", "-|") is ignored;
    ///   - only ONE leading '-' negates: "--x" is the negated word "-x", i.e. NOT x;
    ///   - if no word is usable ("", "   ", "|", "-"), the result is empty - a query
    ///     asking for nothing returns nothing, not everything;
    ///   - a usable word whose tokens match no document (an unknown term) is NOT ignored:
    ///     as a required word it makes the whole result empty; as a negated word it
    ///     excludes nothing.
    ///
    /// How it is evaluated (the cost model):
    ///   - The query is resolved against the index while it is parsed, so a required word
    ///     that can match nothing ends the search at once, before any list is touched.
    ///   - Equal words, equal alternatives and equal negated alternatives (the same tokens
    ///     in any order or case) are evaluated ONCE, however often the query repeats them,
    ///     so the work is bounded by the distinct pieces rather than by the query's length.
    ///   - Required words run one at a time, the one expected to match least first. The first
    ///     is materialized; each later one is intersected into the running result (an
    ///     alternative is intersected with it directly, which gallops through a long list
    ///     when the result is short) and nothing else is kept alive, so memory follows the
    ///     running result and not the query. The search stops as soon as that is empty.
    ///   - A negated alternative is applied to the running result only: the candidates are
    ///     looked up in its postings by galloping, so "rare -common" costs about
    ///     O(|rare| log |common|) and never copies or scans common's list. The matches are
    ///     removed with one linear difference.
    ///   - A query of only negated words walks the id space once and skips the excluded ids.
    /// Postings are read in place; only intermediate results (bounded as above) are built.
    /// Ascending, duplicate-free.
    std::vector<DocId> search(std::string_view query) const { return search_with(query, detail::NoProbe{}); }

private:
    friend struct InvertedIndexTestAccess;

    // What a query means once it has been parsed and resolved: see search().
    struct ParsedQuery {
        std::set<detail::Disjunction, detail::DisjunctionLess> required;  // distinct usable non-negated words
        std::set<detail::Conjunction, detail::ConjunctionLess> excluded;  // distinct live alternatives of negated words
        bool usable = false;      // some word had at least one alternative with a token
        bool impossible = false;  // a required word can match no document at all
    };

    static std::unique_ptr<detail::TermMap> clone(const std::unique_ptr<detail::TermMap>& terms) {
        if (!terms) return nullptr;
        return std::make_unique<detail::TermMap>(*terms);
    }

    static const std::vector<DocId>& empty_list() {
        static const std::vector<DocId> empty;  // function-local: safe to use during static init
        return empty;
    }

    const std::vector<DocId>* find_list(const std::string& token) const {
        if (!terms_) return nullptr;
        const auto it = terms_->find(token);
        return it == terms_->end() ? nullptr : &it->second;
    }

    // add() with a hook for tests; see detail::AddStage. `index` counts the tokens of this
    // document handled so far and `consumed` is the scanner's offset, which shows that the
    // text is processed as it is scanned and never tokenized up front.
    template <class Hook>
    DocId add_with(std::string_view text, Hook&& hook) {
        if (doc_count_ >= max_documents_) {
            throw std::length_error("InvertedIndex::add: document id space exhausted");
        }
        const DocId id = static_cast<DocId>(doc_count_);
        if (!terms_) terms_ = std::make_unique<detail::TermMap>(std::size_t{0}, detail::fresh_term_hash());

        detail::TokenScanner scanner(text);
        std::string token;
        std::size_t index = 0;
        try {
            while (scanner.next(token)) {
                hook(detail::AddStage::BeforeLookup, index, scanner.end());
                std::vector<DocId>& list = (*terms_)[token];
                hook(detail::AddStage::BeforeAppend, index, scanner.end());
                // id is larger than every id already stored, so "my id is already last" is
                // the whole duplicate check for a token repeated within this document.
                if (list.empty() || list.back() != id) list.push_back(id);
                ++index;
            }
        } catch (...) {
            rollback(text.substr(0, scanner.end()), token, id);
            throw;
        }
        ++doc_count_;
        return id;
    }

    // Undoes a partially applied add() by scanning the tokens it had reached again. `id` is
    // larger than every id of a finished document, so a list ending in it was touched by this
    // add(), and a list that is EMPTY can only be a term this add() created and failed to
    // fill. `scratch` is the string add() scanned into: it already has room for every one of
    // these tokens, so scanning them again allocates nothing, and none of these steps throws.
    void rollback(std::string_view processed, std::string& scratch, DocId id) noexcept {
        detail::TokenScanner scanner(processed);
        while (scanner.next(scratch)) {
            const auto it = terms_->find(scratch);
            if (it == terms_->end()) continue;
            std::vector<DocId>& list = it->second;
            if (!list.empty() && list.back() == id) list.pop_back();
            if (list.empty()) terms_->erase(it);
        }
    }

    // Looks up the tokens of `text`. Known: `out` holds the postings list of every distinct
    // token (sorted by address, so equal texts give equal conjunctions). Unknown: some token
    // is in no document, so nothing matches. NoTokens: the text has no token at all.
    detail::Resolved resolve(std::string_view text, detail::Conjunction& out) const {
        out.clear();
        detail::TokenScanner scanner(text);
        std::string token;
        bool any = false;
        while (scanner.next(token)) {
            any = true;
            const std::vector<DocId>* list = find_list(token);
            if (list == nullptr) return detail::Resolved::Unknown;
            out.push_back(list);
        }
        if (!any) return detail::Resolved::NoTokens;
        std::sort(out.begin(), out.end(), detail::ListPtrLess{});
        out.erase(std::unique(out.begin(), out.end()), out.end());
        return detail::Resolved::Known;
    }

    ParsedQuery parse(std::string_view query) const {
        ParsedQuery parsed;
        detail::Conjunction conjunction;
        const std::size_t n = query.size();
        std::size_t pos = 0;
        while (pos < n) {
            while (pos < n && detail::is_query_space(query[pos])) ++pos;
            const std::size_t begin = pos;
            while (pos < n && !detail::is_query_space(query[pos])) ++pos;
            if (pos == begin) break;

            std::string_view body = query.substr(begin, pos - begin);
            const bool negated = body.front() == '-';
            if (negated) body.remove_prefix(1);

            detail::Disjunction word;  // the live alternatives of this word
            bool usable = false;       // ... and whether any alternative had a token at all
            std::size_t start = 0;
            for (std::size_t i = 0; i <= body.size(); ++i) {
                if (i != body.size() && body[i] != '|') continue;
                const detail::Resolved resolved = resolve(body.substr(start, i - start), conjunction);
                start = i + 1;
                if (resolved == detail::Resolved::NoTokens) continue;
                usable = true;
                // Repeating one alternative back to back is the cheap case to spot right here.
                if (resolved == detail::Resolved::Known && (word.empty() || word.back() != conjunction)) {
                    word.push_back(conjunction);
                }
            }
            if (!usable) continue;
            parsed.usable = true;
            if (negated) {
                for (detail::Conjunction& alternative : word) parsed.excluded.insert(std::move(alternative));
            } else if (word.empty()) {
                parsed.impossible = true;  // a required word that matches nothing: the answer is empty
                return parsed;
            } else {
                detail::canonicalize(word);
                parsed.required.insert(std::move(word));
            }
        }
        return parsed;
    }

    template <class Probe>
    std::vector<DocId> search_or_with(const std::vector<std::string>& terms, Probe probe) const {
        detail::Disjunction word;
        detail::Conjunction conjunction;
        for (const std::string& term : terms) {
            if (resolve(term, conjunction) != detail::Resolved::Known) continue;
            if (word.empty() || word.back() != conjunction) word.push_back(conjunction);
        }
        detail::canonicalize(word);
        return evaluate_union(word, probe);
    }

    template <class Probe>
    std::vector<DocId> search_with(std::string_view query, Probe probe) const {
        const ParsedQuery parsed = parse(query);
        if (!parsed.usable || parsed.impossible) return {};
        const detail::Disjunction negated(parsed.excluded.begin(), parsed.excluded.end());

        if (parsed.required.empty()) return complement(doc_count_, evaluate_union(negated, probe));

        // Cheapest word first: it is the only one that is materialized in full.
        std::vector<std::pair<std::uint64_t, const detail::Disjunction*>> order;
        order.reserve(parsed.required.size());
        for (const detail::Disjunction& word : parsed.required) order.emplace_back(detail::estimated_size(word), &word);
        std::stable_sort(order.begin(), order.end(), [](const auto& x, const auto& y) { return x.first < y.first; });

        std::vector<DocId> matches = evaluate_union(*order.front().second, probe);
        for (std::size_t i = 1; i < order.size() && !matches.empty(); ++i) {
            matches = restrict_to(matches, *order[i].second, probe);
        }
        if (negated.empty() || matches.empty()) return matches;
        return exclude(std::move(matches), negated, probe);
    }

    // base AND every list of the conjunction. `base` is usually the shortest operand, so this
    // gallops through the postings.
    template <class Probe>
    static std::vector<DocId> intersect_with(const std::vector<DocId>& base, const detail::Conjunction& conjunction,
                                             Probe probe) {
        std::vector<detail::ListPtr> lists;
        lists.reserve(conjunction.size() + 1);
        lists.push_back(&base);
        lists.insert(lists.end(), conjunction.begin(), conjunction.end());
        return detail::intersect_smallest_first(std::move(lists), probe);
    }

    // The union of a disjunction's conjunctions. A conjunction of one list is merged straight
    // from the index's own list; the others are intersected into owned lists, which are united
    // as they arrive (see UnionAccumulator) rather than all kept alive.
    template <class Probe>
    static std::vector<DocId> evaluate_union(const detail::Disjunction& word, Probe probe) {
        std::vector<detail::Span> borrowed;
        detail::UnionAccumulator<Probe> owned(probe);
        for (const detail::Conjunction& conjunction : word) {
            if (conjunction.size() == 1) {
                borrowed.push_back(detail::span_of(*conjunction.front()));
            } else {
                owned.add(detail::intersect_smallest_first(conjunction, probe));
            }
        }
        std::vector<DocId> merged = owned.take();
        if (borrowed.empty()) return merged;
        if (!merged.empty()) borrowed.push_back(detail::span_of(merged));
        return detail::unite_spans(borrowed, probe);
    }

    // base AND (the disjunction). Distributes over the union - base AND (x OR y) is
    // (base AND x) OR (base AND y) - so no alternative is ever materialized in full: every
    // piece is bounded by |base|.
    template <class Probe>
    static std::vector<DocId> restrict_to(const std::vector<DocId>& base, const detail::Disjunction& word,
                                          Probe probe) {
        detail::UnionAccumulator<Probe> hits(probe);
        for (const detail::Conjunction& conjunction : word) hits.add(intersect_with(base, conjunction, probe));
        return hits.take();
    }

    // base minus every document matching one of the conjunctions: only base's own ids are
    // looked up in the postings, then removed with a single linear pass over base.
    template <class Probe>
    static std::vector<DocId> exclude(std::vector<DocId> base, const detail::Disjunction& negated, Probe probe) {
        detail::UnionAccumulator<Probe> hits(probe);
        for (const detail::Conjunction& conjunction : negated) hits.add(intersect_with(base, conjunction, probe));
        const std::vector<DocId> removed = hits.take();  // a subset of base
        if (removed.empty()) return base;
        if (removed.size() == base.size()) return {};
        return detail::difference_impl(base, removed, probe);
    }

    // Every id in [0, universe) that is not in `removed` (ascending, all below `universe`).
    static std::vector<DocId> complement(std::uint64_t universe, const std::vector<DocId>& removed) {
        std::vector<DocId> out;
        const auto total = static_cast<std::size_t>(universe);
        out.reserve(total > removed.size() ? total - removed.size() : 0);
        std::size_t next = 0;
        for (std::uint64_t id = 0; id < universe; ++id) {
            if (next < removed.size() && removed[next] == id) {
                ++next;
            } else {
                out.push_back(static_cast<DocId>(id));
            }
        }
        return out;
    }

    // Null until the first add(), and again after the index has been moved from.
    std::unique_ptr<detail::TermMap> terms_;
    std::uint64_t doc_count_ = 0;  // 64-bit: 2^32 documents must be countable
    std::uint64_t max_documents_ = kMaxDocuments;
};

static_assert(std::is_nothrow_move_constructible<InvertedIndex>::value, "moving an index must not copy it");
static_assert(std::is_nothrow_move_assignable<InvertedIndex>::value, "moving an index must not copy it");

}  // namespace loganalyzer
