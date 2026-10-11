#include <algorithm>
#include <atomic>
#include <cctype>
#include <clocale>
#include <cstddef>
#include <cstdlib>
#include <initializer_list>
#include <limits>
#include <memory>
#include <new>
#include <random>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

#include "loganalyzer/kmp.hpp"
#include "testkit.hpp"

using loganalyzer::KmpMatcher;

// ---------------------------------------------------------------------------------------------
// Allocation probe. The matcher takes no allocator, so exception safety and allocation counts
// can only be observed by wrapping the global operator new. It forwards to malloc and is inert
// (one thread-local counter bump per allocation) unless a test arms it, so it is harmless to
// every other test that shares this executable.
//
// Maintenance note: a program has exactly one global operator new, and CMake links every
// tests/*.cpp into one executable, so no other test file may define it (that is a duplicate
// symbol at link time, by design: two probes would silently fight). A second module that wants
// allocation counting should move this probe into a shared test header instead of copying it.
//
// The counters are thread_local: only allocations made by the thread that reads them are
// counted or failed, so a background thread (the thread tests below start some) can neither
// perturb a measurement nor receive an injected std::bad_alloc. Constant-initialised
// thread_locals need no guard, which makes them safe to touch from operator new at any time.

namespace {

namespace alloc_probe {

// >= 0: that many further allocations succeed, then every allocation (of this thread) throws
// std::bad_alloc.
thread_local long succeed_before_failing = -1;
thread_local std::size_t allocations = 0;  // total calls to operator new on this thread so far

// Arms the failure injection for the lifetime of the object; always disarms, even on throw.
struct FailAfter {
    explicit FailAfter(long successes) { succeed_before_failing = successes; }
    ~FailAfter() { succeed_before_failing = -1; }
    FailAfter(const FailAfter&) = delete;
    FailAfter& operator=(const FailAfter&) = delete;
};

}  // namespace alloc_probe

}  // namespace

void* operator new(std::size_t size) {
    ++alloc_probe::allocations;
    if (alloc_probe::succeed_before_failing == 0) throw std::bad_alloc();
    if (alloc_probe::succeed_before_failing > 0) --alloc_probe::succeed_before_failing;
    if (void* p = std::malloc(size == 0 ? 1 : size)) return p;
    throw std::bad_alloc();
}

// malloc / free is a correct pair here, but once GCC inlines these it pairs the replaced
// operator new with them and reports the free() as a mismatched deallocation.
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmismatched-new-delete"
#endif
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

namespace {

using Positions = std::vector<std::size_t>;

constexpr std::size_t kNpos = KmpMatcher::npos;

// The API promises: noexcept queries, cheap noexcept moves, explicit construction.
static_assert(KmpMatcher::npos == std::string_view::npos, "npos must be string_view's npos");
static_assert(KmpMatcher::npos == std::string::npos, "npos must be string's npos");
static_assert(noexcept(std::declval<const KmpMatcher&>().find(std::string_view{}, 0)), "find is noexcept");
static_assert(noexcept(std::declval<const KmpMatcher&>().contains(std::string_view{})), "contains is noexcept");
static_assert(noexcept(std::declval<const KmpMatcher&>().count(std::string_view{})), "count is noexcept");
static_assert(noexcept(std::declval<const KmpMatcher&>().pattern_size()), "pattern_size is noexcept");
static_assert(noexcept(std::declval<const KmpMatcher&>().ignore_case()), "ignore_case is noexcept");
static_assert(noexcept(std::declval<const KmpMatcher&>().failure()), "failure is noexcept");
static_assert(std::is_nothrow_move_constructible<KmpMatcher>::value, "move construction is noexcept");
static_assert(std::is_nothrow_move_assignable<KmpMatcher>::value, "move assignment is noexcept");
static_assert(std::is_copy_constructible<KmpMatcher>::value && std::is_copy_assignable<KmpMatcher>::value,
              "matchers are copyable");
static_assert(!std::is_convertible<std::string_view, KmpMatcher>::value, "construction is explicit");

// ---------------------------------------------------------------------------------------------
// Trivially-correct references. They deliberately share no code with the header.

unsigned char ref_fold(unsigned char c) {
    return (c >= 'A' && c <= 'Z') ? static_cast<unsigned char>(c - 'A' + 'a') : c;
}

bool ref_equal(char a, char b, bool ignore_case) {
    unsigned char x = static_cast<unsigned char>(a);
    unsigned char y = static_cast<unsigned char>(b);
    if (ignore_case) {
        x = ref_fold(x);
        y = ref_fold(y);
    }
    return x == y;
}

std::string ref_lower(const std::string& s) {
    std::string out = s;
    for (char& c : out) c = static_cast<char>(ref_fold(static_cast<unsigned char>(c)));
    return out;
}

// O(n * m): try every start index. An empty pattern matches at 0..n inclusive.
Positions naive_find_all(const std::string& pattern, const std::string& text, bool ignore_case) {
    Positions out;
    for (std::size_t start = 0; start + pattern.size() <= text.size(); ++start) {
        bool match = true;
        for (std::size_t j = 0; j < pattern.size() && match; ++j) {
            match = ref_equal(pattern[j], text[start + j], ignore_case);
        }
        if (match) out.push_back(start);
    }
    return out;
}

// std::string::find baseline, stepping one past each hit so overlaps are found.
Positions std_find_all(const std::string& pattern, const std::string& text) {
    Positions out;
    for (std::size_t pos = text.find(pattern); pos != std::string::npos; pos = text.find(pattern, pos + 1)) {
        out.push_back(pos);
    }
    return out;
}

// The prefix function straight from its definition: for each i the longest proper prefix of
// pattern[0..i] that is also a suffix of it, found by trying every length. O(m^3).
Positions naive_failure(const std::string& pattern, bool ignore_case) {
    Positions out(pattern.size(), 0);
    for (std::size_t i = 0; i < pattern.size(); ++i) {
        for (std::size_t len = i; len > 0; --len) {  // proper: len < i + 1
            bool border = true;
            for (std::size_t j = 0; j < len && border; ++j) {
                border = ref_equal(pattern[j], pattern[i + 1 - len + j], ignore_case);
            }
            if (border) {
                out[i] = len;
                break;
            }
        }
    }
    return out;
}

// ---------------------------------------------------------------------------------------------
// Helpers

std::string bytes(std::initializer_list<int> values) {
    std::string s;
    for (int v : values) s.push_back(static_cast<char>(v));
    return s;
}

Positions iota_positions(std::size_t first, std::size_t count) {
    Positions out(count);
    for (std::size_t i = 0; i < count; ++i) out[i] = first + i;
    return out;
}

std::string printable(const std::string& s) {
    static const char* const hex = "0123456789abcdef";
    std::string out;
    for (char ch : s) {
        const unsigned char c = static_cast<unsigned char>(ch);
        if (c >= 0x20 && c < 0x7F && c != '\\') {
            out += ch;
        } else {
            out += "\\x";
            out += hex[c >> 4];
            out += hex[c & 15];
        }
    }
    return out;
}

std::string case_message(const std::string& what, const std::string& pattern, const std::string& text,
                         bool ignore_case) {
    return "kmp_test: " + what + " (pattern=\"" + printable(pattern) + "\" text=\"" + printable(text) +
           "\" ignore_case=" + (ignore_case ? "true" : "false") + ")";
}

[[noreturn]] void fail_case(const std::string& what, const std::string& pattern, const std::string& text,
                            bool ignore_case) {
    throw testkit::Failure{case_message(what, pattern, text, ignore_case)};
}

// Deterministic across standard libraries: only mt19937's (specified) raw output is used.
std::size_t below(std::mt19937& rng, std::size_t n) { return static_cast<std::size_t>(rng() % n); }

std::string random_string(std::mt19937& rng, const std::string& symbols, std::size_t length) {
    std::string s(length, '\0');
    for (char& c : s) c = symbols[below(rng, symbols.size())];
    return s;
}

std::string cycle_to_length(const std::string& unit, std::size_t length) {
    std::string s(length, '\0');
    for (std::size_t i = 0; i < length; ++i) s[i] = unit[i % unit.size()];
    return s;
}

// Every string over `symbols` of length 0..max_length, shortest first.
std::vector<std::string> all_strings(const std::string& symbols, std::size_t max_length) {
    std::vector<std::string> out{std::string()};
    std::size_t level_begin = 0;
    for (std::size_t length = 1; length <= max_length; ++length) {
        const std::size_t level_end = out.size();
        for (std::size_t i = level_begin; i < level_end; ++i) {
            for (char c : symbols) out.push_back(out[i] + c);
        }
        level_begin = level_end;
    }
    return out;
}

// Checks every query of one matcher against the references, for one (pattern, text).
void check_case(const std::string& pattern, const std::string& text, bool ignore_case,
                std::size_t& total_matches) {
    const KmpMatcher m(pattern, ignore_case);
    const Positions expected = naive_find_all(pattern, text, ignore_case);
    total_matches += expected.size();

    if (m.pattern_size() != pattern.size()) fail_case("pattern_size", pattern, text, ignore_case);
    if (m.ignore_case() != ignore_case) fail_case("ignore_case", pattern, text, ignore_case);
    if (m.failure() != naive_failure(pattern, ignore_case)) fail_case("failure", pattern, text, ignore_case);
    if (m.find_all(text) != expected) fail_case("find_all", pattern, text, ignore_case);
    if (m.count(text) != expected.size()) fail_case("count", pattern, text, ignore_case);
    if (m.contains(text) != !expected.empty()) fail_case("contains", pattern, text, ignore_case);

    // from past the end (text.size() + 1, + 2) must give npos, even for the empty pattern.
    for (std::size_t from = 0; from <= text.size() + 2; ++from) {
        const auto it = std::lower_bound(expected.begin(), expected.end(), from);
        const std::size_t want = it == expected.end() ? kNpos : *it;
        if (m.find(text, from) != want) {
            fail_case("find(from=" + std::to_string(from) + ")", pattern, text, ignore_case);
        }
        // Cross-checks the reference itself against the standard library.
        if (!ignore_case && text.find(pattern, from) != want) {
            fail_case("reference vs std::string::find(from=" + std::to_string(from) + ")", pattern, text,
                      ignore_case);
        }
    }
    if (!ignore_case && std_find_all(pattern, text) != expected) {
        fail_case("reference vs std::string::find loop", pattern, text, ignore_case);
    }

    // Folding must be equivalent to lower-casing both sides and matching exactly.
    if (ignore_case) {
        const KmpMatcher lowered(ref_lower(pattern));
        if (lowered.find_all(ref_lower(text)) != expected) fail_case("fold == lower both", pattern, text, true);
        if (lowered.failure() != m.failure()) fail_case("failure of folded pattern", pattern, text, true);
    }
}

// Random pattern/text over a tiny alphabet (2..4 symbols from `pool`) so that partial matches
// and overlapping matches are the norm, not the exception.
void random_cases(unsigned seed, int iterations, const std::string& pool, bool ignore_case) {
    std::mt19937 rng(seed);
    std::size_t total_matches = 0;
    for (int iter = 0; iter < iterations; ++iter) {
        std::string symbols = pool;
        for (std::size_t i = symbols.size(); i > 1; --i) std::swap(symbols[i - 1], symbols[below(rng, i)]);
        symbols.resize(std::min(symbols.size(), 2 + below(rng, 3)));

        std::string text = random_string(rng, symbols, below(rng, 65));
        std::string pattern;
        switch (below(rng, 3)) {
            case 0:  // unrelated random pattern
                pattern = random_string(rng, symbols, below(rng, 9));
                break;
            case 1: {  // a slice of the text: a match is guaranteed
                const std::size_t len = below(rng, std::min<std::size_t>(text.size(), 8) + 1);
                pattern = text.substr(below(rng, text.size() - len + 1), len);
                break;
            }
            default: {  // periodic pattern against periodic text with a few typos
                const std::string unit = random_string(rng, symbols, 1 + below(rng, 3));
                pattern = cycle_to_length(unit, below(rng, 9));
                text = cycle_to_length(unit, below(rng, 65));
                for (std::size_t typos = below(rng, 3); typos > 0 && !text.empty(); --typos) {
                    text[below(rng, text.size())] = symbols[below(rng, symbols.size())];
                }
                break;
            }
        }
        check_case(pattern, text, ignore_case, total_matches);
    }
    // Guards against a vacuous test: matches really do occur all the time.
    CHECK(total_matches > static_cast<std::size_t>(iterations));
}

std::string fibonacci_word(int n) {  // f1 = "b", f2 = "a", fn = f(n-1) + f(n-2): very periodic
    std::string older = "b";
    std::string newer = "a";
    for (int i = 3; i <= n; ++i) {
        std::string next = newer + older;
        older = std::move(newer);
        newer = std::move(next);
    }
    return n == 1 ? older : newer;
}

// Counts every byte read through the case-folding hook (pattern bytes and text bytes alike) and
// fails the running test the moment more than `limit` have been read. The fold is the identity,
// so results are those of a case-sensitive matcher. Since the matcher's loops are templated on
// this hook, "linear time" becomes a deterministic step budget instead of a clock reading: an
// O(m^2) table build, a find() that does not stop at its first match, or a restart-on-mismatch
// search blows the budget after a few hundred thousand steps (and throws, so even a loop that
// would never terminate fails the test instead of hanging it).
struct CountingFold {
    static inline std::size_t used = 0;
    static inline std::size_t limit = std::numeric_limits<std::size_t>::max();

    static unsigned char apply(char c) {
        if (++used > limit) {
            throw testkit::Failure{"kmp_test: step budget exceeded (" + std::to_string(limit) +
                                   " byte reads): the algorithm is no longer linear"};
        }
        return static_cast<unsigned char>(c);
    }
};

// Arms the budget for its lifetime. Per input byte the real loops read the byte once, make one
// pattern read per fallback step plus two more (the loop's last check and the final comparison),
// and fallback steps in total are bounded by the number of advances, i.e. by the input size: at
// most 4 reads per byte overall. A ceiling of 6 per byte plus slack leaves room for harmless
// changes while any super-linear behaviour overshoots it by orders of magnitude.
struct StepBudget {
    explicit StepBudget(std::size_t bytes) {
        CountingFold::used = 0;
        CountingFold::limit = 6 * bytes + 16;
    }
    ~StepBudget() { CountingFold::limit = std::numeric_limits<std::size_t>::max(); }
    StepBudget(const StepBudget&) = delete;
    StepBudget& operator=(const StepBudget&) = delete;
    static std::size_t steps() { return CountingFold::used; }
};

// Identity fold that throws when it is shown a NUL byte. Run on NUL-free inputs it turns any
// read of a terminator into a failure: std::string keeps a '\0' at data()[size()], and the
// matcher stores its pattern in a std::string, so an off-by-one read of either the pattern or
// a text held in a std::string sees exactly that byte. (AddressSanitizer cannot see such a
// read, because the terminator is inside the allocation.)
struct NulTrap {
    static unsigned char apply(char c) {
        if (c == '\0') {
            throw testkit::Failure{"kmp_test: the matcher read a NUL byte from NUL-free input: a read "
                                   "past the end of the pattern or of the text"};
        }
        return static_cast<unsigned char>(c);
    }
};

}  // namespace

namespace loganalyzer {

// Befriended by KmpMatcher: runs its private loops with a caller-chosen comparison policy.
struct KmpMatcherTestAccess {
    template <class Fold>
    static std::vector<std::size_t> failure_table(std::string_view pattern) {
        KmpMatcher m("");
        m.pattern_.assign(pattern.data(), pattern.size());
        m.build_failure<Fold>();
        return m.failure_;
    }

    template <class Fold>
    static std::size_t find(const KmpMatcher& m, std::string_view text, std::size_t from) {
        return m.find_impl<Fold>(text, from);
    }

    template <class Fold>
    static std::vector<std::size_t> find_all(const KmpMatcher& m, std::string_view text) {
        return m.find_all_impl<Fold>(text);
    }

    template <class Fold>
    static std::size_t count(const KmpMatcher& m, std::string_view text) {
        return m.count_impl<Fold>(text);
    }
};

}  // namespace loganalyzer

using KmpTestAccess = loganalyzer::KmpMatcherTestAccess;

namespace {

// ---------------------------------------------------------------------------------------------
// Budgeted complexity checks. The deterministic complexity tests run them on large inputs; the
// heavy tests (200,000-byte texts, a million matches) run the same checks on small inputs first
// through require_linear_scaling(), so that a quadratic regression fails within milliseconds
// instead of grinding through the heavy inputs for minutes.

std::vector<std::string> failure_build_patterns(std::size_t n, int fib_order, std::mt19937& rng) {
    return {
        "",
        "a",
        std::string(n, 'a'),                          // longest possible borders, no fallbacks
        std::string(n - 1, 'a') + "b",                // one long fallback chain at the very end
        cycle_to_length("ab", n) + "c",               // every position falls back through the chain
        cycle_to_length("aab", n) + "b",
        fibonacci_word(fib_order),                    // deeply nested borders
        random_string(rng, "ab", n),
        random_string(rng, "abc", n),
        std::string(n / 4, 'a') + "b" + std::string(n / 4, 'a') + "b" + std::string(n / 4, 'a') + "c",
    };
}

void check_failure_build_is_linear(const std::vector<std::string>& patterns) {
    for (const std::string& pattern : patterns) {
        Positions table;
        {
            StepBudget budget(pattern.size());
            table = KmpTestAccess::failure_table<CountingFold>(pattern);
            CHECK(StepBudget::steps() > 0 || pattern.size() <= 1);  // the budget really was observed
        }
        CHECK(table == KmpMatcher(pattern).failure());
        CHECK_EQ(table.size(), pattern.size());
        // Properties every prefix function has (the exact tables of small patterns are checked
        // against the definition elsewhere; naive_failure is too slow for these sizes): a border
        // is proper, it grows by at most one byte per pattern byte, and it really is both a
        // prefix and a suffix.
        for (std::size_t i = 0; i < table.size(); ++i) {
            if (i == 0) {
                CHECK_EQ(table[0], std::size_t{0});
                continue;
            }
            CHECK(table[i] <= table[i - 1] + 1);
            CHECK(table[i] <= i);
            CHECK(pattern.compare(0, table[i], pattern, i + 1 - table[i], table[i]) == 0);
        }
    }
}

struct SearchCase {
    std::string pattern;
    std::string text;
};

std::vector<SearchCase> search_cases(std::size_t n, int fib_pattern, int fib_text, std::mt19937& rng) {
    const std::size_t k = n / 2;
    return {
        {std::string(k, 'a') + "b", std::string(n, 'a')},            // near-misses everywhere
        {std::string(k, 'a'), std::string(n, 'a')},                  // k + 1 overlapping matches
        {cycle_to_length("ab", k) + "c", cycle_to_length("ab", n)},
        {"a", std::string(n, 'a')},                                  // a match per byte
        {"aa", std::string(n, 'a')},
        {"ab", cycle_to_length("ab", n)},
        {fibonacci_word(fib_pattern), fibonacci_word(fib_text)},
        {random_string(rng, "ab", 12), random_string(rng, "ab", n)},
        {random_string(rng, "abc", 200), cycle_to_length("abc", n)},
    };
}

void check_search_is_linear(const std::vector<SearchCase>& cases) {
    for (const SearchCase& c : cases) {
        // The budgeted table build runs first: a super-linear build must fail here, not hang
        // inside the real constructor below.
        {
            StepBudget budget(c.pattern.size());
            (void)KmpTestAccess::failure_table<CountingFold>(c.pattern);
        }
        const KmpMatcher m(c.pattern);
        Positions expected;
        {
            StepBudget budget(c.text.size());
            expected = KmpTestAccess::find_all<CountingFold>(m, c.text);
        }
        {
            StepBudget budget(c.text.size());
            CHECK_EQ(KmpTestAccess::count<CountingFold>(m, c.text), expected.size());
        }
        // find stops at its first match, so it never costs more than a full pass either.
        for (std::size_t from : {std::size_t{0}, c.text.size() / 2}) {
            StepBudget budget(c.text.size() - from);
            const auto it = std::lower_bound(expected.begin(), expected.end(), from);
            CHECK_EQ(KmpTestAccess::find<CountingFold>(m, c.text, from), it == expected.end() ? kNpos : *it);
        }
        // The public functions agree with the instrumented loops (and only now are they run).
        CHECK(m.find_all(c.text) == expected);
        CHECK_EQ(m.count(c.text), expected.size());
    }
}

// A reallocation per match (for instance reserve(size() + 1) before every push_back, which
// copies the whole result each time) is quadratic in the number of matches: `matches`
// allocations. Geometric growth needs a few dozen at most.
void check_find_all_grows_geometrically(std::size_t matches) {
    const std::string lower(matches, 'a');
    const std::string upper(matches, 'A');
    for (bool ic : {false, true}) {
        const KmpMatcher m("A", ic);
        const std::string& haystack = ic ? lower : upper;
        const std::size_t before = alloc_probe::allocations;
        const Positions all = m.find_all(haystack);
        const std::size_t used = alloc_probe::allocations - before;
        CHECK_EQ(all.size(), matches);
        CHECK(used <= 64);
        CHECK(used >= 1);
        CHECK(all.capacity() <= 2 * all.size() + 1);
        CHECK(all == iota_positions(0, matches));
    }
}

void run_scaling_guard() {
    std::mt19937 rng(31337);
    check_failure_build_is_linear(failure_build_patterns(2000, 14, rng));
    check_search_is_linear(search_cases(4000, 9, 17, rng));
    check_find_all_grows_geometrically(5000);
}

// The guard runs once per process and its verdict is remembered, so every heavy test that asks
// gets the same fast answer.
const std::string& scaling_guard_verdict() {
    static const std::string verdict = [] {
        try {
            run_scaling_guard();
        } catch (const testkit::Failure& failure) {
            return failure.message;
        }
        return std::string();
    }();
    return verdict;
}

void require_linear_scaling() {
    const std::string& verdict = scaling_guard_verdict();
    if (!verdict.empty()) {
        throw testkit::Failure{"kmp_test: large input not run because the small-scale complexity guard "
                               "failed first: " + verdict};
    }
}

// Switches LC_CTYPE to a Latin-1-style locale for the lifetime of the object, when the platform
// has one: in such a locale the C library's own tolower / toupper DO map 0xC0 <-> 0xE0 and
// friends, which is exactly what ignore_case must not do. `active` says whether a locale that
// really changes those functions was found (the names are platform specific); the previous
// locale is always restored.
struct LatinCtypeLocale {
    bool active = false;

    LatinCtypeLocale() {
        const char* current = std::setlocale(LC_CTYPE, nullptr);
        previous_ = current != nullptr ? current : "C";
        for (const char* name : {".1252", "en_US.CP1252", "en_US.ISO-8859-1", "en_US.ISO8859-1",
                                 "de_DE.ISO-8859-1", "fr_FR.ISO-8859-1", "French_France.1252",
                                 "German_Germany.1252"}) {
            if (std::setlocale(LC_CTYPE, name) != nullptr && std::tolower(0xC0) == 0xE0 &&
                std::toupper(0xE0) == 0xC0) {
                active = true;
                return;
            }
        }
        std::setlocale(LC_CTYPE, previous_.c_str());
    }
    ~LatinCtypeLocale() { std::setlocale(LC_CTYPE, previous_.c_str()); }
    LatinCtypeLocale(const LatinCtypeLocale&) = delete;
    LatinCtypeLocale& operator=(const LatinCtypeLocale&) = delete;

private:
    std::string previous_;
};

// Every byte against every byte, single-byte pattern and text. A `c | 0x20` fold would equate
// '@' with '`' and '[' with '{'; masking with 0x7F would equate 0xC1 with 'A'; a fold built on
// the C library's tolower / toupper would equate Latin-1 pairs such as 0xC0 / 0xE0 as soon as
// the locale says so (see IgnoreCaseDoesNotDependOnTheCLocale).
void check_fold_is_exactly_ascii() {
    for (int a = 0; a < 256; ++a) {
        const std::string pattern(1, static_cast<char>(a));
        const KmpMatcher folding(pattern, true);
        const KmpMatcher exact(pattern, false);
        for (int b = 0; b < 256; ++b) {
            const std::string text(1, static_cast<char>(b));
            const bool want_fold = ref_fold(static_cast<unsigned char>(a)) == ref_fold(static_cast<unsigned char>(b));
            if (folding.contains(text) != want_fold) {
                fail_case("fold a=" + std::to_string(a) + " b=" + std::to_string(b), pattern, text, true);
            }
            if (exact.contains(text) != (a == b)) fail_case("exact", pattern, text, false);
        }
    }
    for (char lower = 'a'; lower <= 'z'; ++lower) {
        const char upper = static_cast<char>(lower - 'a' + 'A');
        CHECK(KmpMatcher(std::string(1, lower), true).contains(std::string(1, upper)));
        CHECK(KmpMatcher(std::string(1, upper), true).contains(std::string(1, lower)));
        CHECK(!KmpMatcher(std::string(1, lower), false).contains(std::string(1, upper)));
    }
    CHECK(!KmpMatcher("@", true).contains("`"));
    CHECK(!KmpMatcher("`", true).contains("@"));
    CHECK(!KmpMatcher("[", true).contains("{"));
    CHECK(!KmpMatcher("^", true).contains("~"));
}

// No budget at all: the policy decides what is checked (NulTrap) and nothing is bounded.
struct NoBudget {
    explicit NoBudget(std::size_t) {}
};

// What the small grid saw: the number of matches the reference found, and a description of the
// first answer that differed from it (empty when every answer was right).
struct GridResult {
    std::size_t matches = 0;
    std::string first_wrong_answer;
};

// Every pattern up to 4 bytes over {a,b,c} against every text up to 7 bytes over {a,b} (partial
// matches and overlaps everywhere) and every `from`, through the private loops with the
// comparison policy `Fold`, compared with the naive reference. `Budget` is armed around every
// call: with StepBudget a loop that spins throws instead of hanging. A wrong answer does not
// stop the run (it is recorded), so one bad answer cannot hide a spinning loop further on.
template <class Fold, class Budget>
GridResult run_small_grid() {
    const std::vector<std::string> patterns = all_strings("abc", 4);
    const std::vector<std::string> texts = all_strings("ab", 7);
    GridResult result;
    const auto wrong = [&result](const std::string& what, const std::string& pattern, const std::string& text) {
        if (result.first_wrong_answer.empty()) result.first_wrong_answer = case_message(what, pattern, text, false);
    };
    for (const std::string& pattern : patterns) {
        Positions table;
        {
            Budget budget(pattern.size());
            table = KmpTestAccess::failure_table<Fold>(pattern);
        }
        const KmpMatcher m(pattern);  // only after the budgeted build above came back
        if (table != m.failure()) wrong("failure_table vs failure()", pattern, "");
        for (const std::string& text : texts) {
            const Positions expected = naive_find_all(pattern, text, false);
            result.matches += expected.size();
            {
                Budget budget(text.size());
                if (KmpTestAccess::find_all<Fold>(m, text) != expected) wrong("find_all", pattern, text);
            }
            {
                Budget budget(text.size());
                if (KmpTestAccess::count<Fold>(m, text) != expected.size()) wrong("count", pattern, text);
            }
            for (std::size_t from = 0; from <= text.size() + 1; ++from) {
                const auto it = std::lower_bound(expected.begin(), expected.end(), from);
                Budget budget(text.size());
                if (KmpTestAccess::find<Fold>(m, text, from) != (it == expected.end() ? kNpos : *it)) {
                    wrong("find(from=" + std::to_string(from) + ")", pattern, text);
                }
            }
        }
    }
    return result;
}

// The matcher at its most basic, checked through the step-budgeted hook: every pattern up to 5
// bytes over {a,b,c} has the failure table its definition gives, and the small grid above
// answers like the reference.
//
// Two kinds of verdict, because they call for different reactions. A HAZARD is something that
// can make the search loops spin forever: a table entry that is not smaller than its index
// (the fallback k = failure[k - 1] then never lowers k), or a loop that overran its step budget
// on a tiny input. One such bug would otherwise hang the first ordinary search test with no
// verdict at all, so every test below refuses to run while a hazard stands. A WRONG ANSWER
// cannot hang anything: the other tests run and report it in their own, more specific words.
struct BasicGuardVerdict {
    std::string hazard;
    std::string wrong_answer;
};

BasicGuardVerdict run_basic_guard() {
    BasicGuardVerdict verdict;
    try {
        for (const std::string& pattern : all_strings("abc", 5)) {
            Positions table;
            {
                StepBudget budget(pattern.size());
                table = KmpTestAccess::failure_table<CountingFold>(pattern);
            }
            for (std::size_t i = 0; i < table.size(); ++i) {
                if (table[i] > i) {
                    throw testkit::Failure{case_message("failure table entry " + std::to_string(i) + " is " +
                                                            std::to_string(table[i]) +
                                                            ": a border is never longer than the prefix minus one",
                                                        pattern, "", false)};
                }
            }
            if (table != naive_failure(pattern, false) && verdict.wrong_answer.empty()) {
                verdict.wrong_answer = case_message("the failure table is not the prefix function", pattern, "", false);
            }
        }
        const GridResult grid = run_small_grid<CountingFold, StepBudget>();
        if (verdict.wrong_answer.empty()) verdict.wrong_answer = grid.first_wrong_answer;
    } catch (const testkit::Failure& failure) {
        verdict.hazard = failure.message;
    }
    return verdict;
}

const BasicGuardVerdict& basic_guard_verdict() {
    static const BasicGuardVerdict verdict = run_basic_guard();
    return verdict;
}

void require_sound_matcher() {
    const std::string& hazard = basic_guard_verdict().hazard;
    if (!hazard.empty()) {
        throw testkit::Failure{"kmp_test: not run: the matcher's failure table or search loop is unsound even "
                               "on tiny inputs, so running on could loop forever: " + hazard};
    }
}

}  // namespace

// KMP_TEST(Name) is TEST(Kmp, Name) behind require_sound_matcher(): see run_basic_guard.
#define KMP_TEST(name)                                          \
    static void Kmp_##name##_body();                            \
    TEST(Kmp, name) {                                           \
        require_sound_matcher();                                \
        Kmp_##name##_body();                                    \
    }                                                           \
    static void Kmp_##name##_body()

// ---------------------------------------------------------------------------------------------
// Failure (prefix) function

// Reports the basic guard's own verdict in detail (it is plain TEST, not KMP_TEST, so it runs
// even when the guard finds a hazard: the other tests then say "not run" and point here).
TEST(Kmp, TinyInputsAreSoundAndTheLoopsTerminate) {
    const BasicGuardVerdict& verdict = basic_guard_verdict();
    if (!verdict.hazard.empty()) throw testkit::Failure{verdict.hazard};
    if (!verdict.wrong_answer.empty()) throw testkit::Failure{verdict.wrong_answer};
}

KMP_TEST(FailureTableOfClassicPatterns) {
    CHECK((KmpMatcher("abab").failure() == Positions{0, 0, 1, 2}));
    CHECK((KmpMatcher("aabaaab").failure() == Positions{0, 1, 0, 1, 2, 2, 3}));
    CHECK((KmpMatcher("abcabcabd").failure() == Positions{0, 0, 0, 1, 2, 3, 4, 5, 0}));
    CHECK((KmpMatcher("abababca").failure() == Positions{0, 0, 1, 2, 3, 4, 0, 1}));
    CHECK((KmpMatcher("aaaa").failure() == Positions{0, 1, 2, 3}));
    CHECK((KmpMatcher("abcd").failure() == Positions{0, 0, 0, 0}));
    CHECK((KmpMatcher("a").failure() == Positions{0}));
    CHECK((KmpMatcher("aabaabaaa").failure() == Positions{0, 1, 0, 1, 2, 3, 4, 5, 2}));
}

KMP_TEST(FailureTableIsAsLongAsThePattern) {
    CHECK(KmpMatcher("").failure().empty());
    CHECK_EQ(KmpMatcher("").pattern_size(), std::size_t{0});
    CHECK_EQ(KmpMatcher("abcabc").failure().size(), std::size_t{6});
    CHECK_EQ(KmpMatcher("abcabc").pattern_size(), std::size_t{6});
    // Proper prefix: a border is never the whole prefix, so entry i is at most i.
    const KmpMatcher as(std::string(50, 'a'));
    for (std::size_t i = 0; i < as.failure().size(); ++i) CHECK_EQ(as.failure()[i], i);
    CHECK_EQ(as.failure().back(), std::size_t{49});
}

KMP_TEST(FailureTableMatchesItsDefinitionOnRandomPatterns) {
    std::mt19937 rng(20261010);
    const std::string symbols = "abc";
    for (int iter = 0; iter < 1500; ++iter) {
        const std::string alphabet = symbols.substr(0, 2 + below(rng, 2));
        const std::string pattern = random_string(rng, alphabet, 1 + below(rng, 40));
        const KmpMatcher m(pattern);
        if (m.failure() != naive_failure(pattern, false)) fail_case("failure", pattern, "", false);
    }
}

KMP_TEST(FailureTableDescribesTheFoldedPatternWhenIgnoringCase) {
    // "AbAB" has border "A" case-sensitively but "ab" once folded: the table must be the
    // one the search actually uses.
    CHECK((KmpMatcher("AbAB").failure() == Positions{0, 0, 1, 0}));
    CHECK((KmpMatcher("AbAB", true).failure() == Positions{0, 0, 1, 2}));
    CHECK((KmpMatcher("AbAB", true).failure() == KmpMatcher("abab").failure()));
    // The overlap after a match depends on it: a case-sensitive table would lose the hit at 2.
    CHECK((KmpMatcher("aBaB", true).find_all("abababab") == Positions{0, 2, 4}));
}

// ---------------------------------------------------------------------------------------------
// Basic behaviour

KMP_TEST(FindsAKeywordInALogMessage) {
    const std::string line = "Timeout calling bank gateway after 3000ms (retrying) - timeout again";
    const KmpMatcher exact("timeout");
    CHECK_EQ(exact.find(line), std::size_t{55});
    CHECK((exact.find_all(line) == Positions{55}));
    CHECK(exact.contains(line));

    const KmpMatcher folded("timeout", true);
    CHECK((folded.find_all(line) == Positions{0, 55}));
    CHECK_EQ(folded.count(line), std::size_t{2});

    CHECK((KmpMatcher("Timeout").find_all(line) == Positions{0}));
    CHECK(!KmpMatcher("gateway timeout").contains(line));
    CHECK(KmpMatcher("bank gateway").contains(line));
    CHECK_EQ(KmpMatcher("3000ms").find(line), std::size_t{35});
}

KMP_TEST(MatchesAtTheStartAndAtTheEnd) {
    const KmpMatcher m("abc");
    CHECK_EQ(m.find("abcxxabc"), std::size_t{0});
    CHECK((m.find_all("abcxxabc") == Positions{0, 5}));
    CHECK((m.find_all("xxabc") == Positions{2}));
    CHECK((m.find_all("abcxx") == Positions{0}));
    CHECK(!m.contains("ab"));
    CHECK(!m.contains("xabxc"));
}

KMP_TEST(MatchesOverlap) {
    CHECK((KmpMatcher("aa").find_all("aaaa") == Positions{0, 1, 2}));
    CHECK_EQ(KmpMatcher("aa").count("aaaa"), std::size_t{3});
    CHECK((KmpMatcher("aba").find_all("ababababa") == Positions{0, 2, 4, 6}));
    CHECK((KmpMatcher("abab").find_all("abababab") == Positions{0, 2, 4}));
    CHECK((KmpMatcher("aabaa").find_all("aabaabaabaa") == Positions{0, 3, 6}));
    CHECK_EQ(KmpMatcher("aaa").count("aaaaaaaaaa"), std::size_t{8});
}

KMP_TEST(FindHonoursFrom) {
    const KmpMatcher m("abc");
    const std::string text = "abcabcabc";
    CHECK_EQ(m.find(text, 0), std::size_t{0});
    CHECK_EQ(m.find(text, 1), std::size_t{3});
    CHECK_EQ(m.find(text, 3), std::size_t{3});  // a match starting exactly at `from` counts
    CHECK_EQ(m.find(text, 4), std::size_t{6});
    CHECK_EQ(m.find(text, 6), std::size_t{6});
    CHECK_EQ(m.find(text, 7), kNpos);
    CHECK_EQ(m.find(text, 9), kNpos);  // from == size
    CHECK_EQ(m.find(text, 10), kNpos);
    CHECK_EQ(m.find(text, kNpos), kNpos);

    // Text before `from` is never examined, so a match straddling it is not reported.
    CHECK_EQ(KmpMatcher("ab").find("xab", 1), std::size_t{1});
    CHECK_EQ(KmpMatcher("ab").find("xab", 2), kNpos);
    CHECK_EQ(KmpMatcher("aa").find("aaaa", 1), std::size_t{1});
    CHECK_EQ(KmpMatcher("aa").find("aaaa", 2), std::size_t{2});
    CHECK_EQ(KmpMatcher("aa").find("aaaa", 3), kNpos);
}

KMP_TEST(FromNearTheLimitsOfSizeTNeverWrapsOrTruncates) {
    // A `from` that does not fit in 32 (or 16, or 31) bits must still compare as "past the
    // end". Truncating it (to unsigned, say) would turn 2^32 into 0 and 2^32 + 1 into 1, and
    // report a match of the text's first bytes. Only npos used to be tried, and npos survives
    // such truncation (0xFFFFFFFF is still far past a short text).
    constexpr std::size_t max = std::numeric_limits<std::size_t>::max();
    std::vector<std::size_t> huge = {max, max - 1, max - 2, max / 2 + 1, max / 2, max / 2 - 1};
    for (int shift = 15; shift < std::numeric_limits<std::size_t>::digits; ++shift) {
        const std::size_t power = std::size_t{1} << shift;
        huge.push_back(power - 1);
        huge.push_back(power);
        huge.push_back(power + 1);
    }
    for (bool ic : {false, true}) {
        const KmpMatcher one("a", ic);
        const KmpMatcher two("xa", ic);
        const KmpMatcher none("", ic);
        for (const std::size_t from : huge) {
            CHECK_EQ(one.find("xa", from), kNpos);
            CHECK_EQ(one.find("a", from), kNpos);
            CHECK_EQ(two.find("xaxa", from), kNpos);
            CHECK_EQ(none.find("xa", from), kNpos);  // the empty pattern, too
            CHECK_EQ(none.find("", from), kNpos);
        }
    }
    // Sanity of the loop itself: just inside the text everything still works.
    CHECK_EQ(KmpMatcher("a").find("xa", 1), std::size_t{1});
    CHECK_EQ(KmpMatcher("").find("xa", 2), std::size_t{2});
}

KMP_TEST(ResultsAreAscendingRealMatches) {
    const std::string text = "abababababbabababaabab";
    const KmpMatcher m("abab");
    const Positions hits = m.find_all(text);
    CHECK(!hits.empty());
    for (std::size_t i = 0; i < hits.size(); ++i) {
        if (i > 0) CHECK(hits[i - 1] < hits[i]);
        CHECK(text.compare(hits[i], 4, "abab") == 0);
    }
}

KMP_TEST(MatcherIsReusableAcrossTexts) {
    // No search state lives in the matcher: interleaved searches give independent answers.
    const KmpMatcher m("abab");
    std::mt19937 rng(77);
    for (int iter = 0; iter < 3000; ++iter) {
        const std::string text = random_string(rng, "ab", below(rng, 40));
        if (m.find_all(text) != naive_find_all("abab", text, false)) fail_case("reuse", "abab", text, false);
    }
    CHECK_EQ(m.count("ababab"), std::size_t{2});
    CHECK_EQ(m.count("abab"), std::size_t{1});
    CHECK_EQ(m.count("ababab"), std::size_t{2});
}

// ---------------------------------------------------------------------------------------------
// Empty pattern, empty text, length edge cases

KMP_TEST(EmptyPatternMatchesAtEveryIndexIncludingTheEnd) {
    for (bool ic : {false, true}) {
        const KmpMatcher m("", ic);
        CHECK_EQ(m.pattern_size(), std::size_t{0});
        CHECK(m.failure().empty());
        CHECK_EQ(m.ignore_case(), ic);

        CHECK_EQ(m.find("abc"), std::size_t{0});
        CHECK_EQ(m.find("abc", 0), std::size_t{0});
        CHECK_EQ(m.find("abc", 2), std::size_t{2});
        CHECK_EQ(m.find("abc", 3), std::size_t{3});  // the empty match at the very end
        CHECK_EQ(m.find("abc", 4), kNpos);
        CHECK_EQ(m.find("abc", kNpos), kNpos);

        CHECK(m.contains("abc"));
        CHECK(m.contains(""));
        CHECK((m.find_all("abc") == Positions{0, 1, 2, 3}));
        CHECK_EQ(m.find_all("abc").size(), std::size_t{4});
        CHECK_EQ(m.count("abc"), std::size_t{4});

        CHECK_EQ(m.find(""), std::size_t{0});
        CHECK_EQ(m.find("", 0), std::size_t{0});
        CHECK_EQ(m.find("", 1), kNpos);
        CHECK((m.find_all("") == Positions{0}));
        CHECK_EQ(m.count(""), std::size_t{1});
    }
}

KMP_TEST(RepeatedFindWalksEveryMatchLikeFindAll) {
    // The "next match" loop must visit exactly find_all's positions. (It is correct but not
    // cheap: every find() restarts from zero matched bytes, so the loop costs O(|pattern|) per
    // match; find_all / count are the one-pass way to enumerate. See the header.)
    for (const char* pat : {"aa", "aba", "x", ""}) {
        for (bool ic : {false, true}) {
            const std::string text = "aabaaAbabaxAAaa";
            const KmpMatcher m(pat, ic);
            Positions walked;
            for (std::size_t pos = m.find(text); pos != kNpos; pos = m.find(text, pos + 1)) {
                walked.push_back(pos);
                // The walk visits at most text.size() + 1 positions (the empty pattern's, the
                // most there are). The bound makes a find() that wrongly answers `from` for a
                // `from` past the end fail this test instead of looping until memory is gone.
                CHECK(walked.size() <= text.size() + 1);
            }
            CHECK(walked == m.find_all(text));
            CHECK_EQ(walked.size(), m.count(text));
        }
    }
}

KMP_TEST(EmptyPatternOnALongText) {
    const KmpMatcher m("");
    const std::string text(1000, 'x');
    CHECK((m.find_all(text) == iota_positions(0, 1001)));
    CHECK_EQ(m.count(text), std::size_t{1001});
}

KMP_TEST(NonEmptyPatternNeverMatchesAnEmptyText) {
    for (bool ic : {false, true}) {
        const KmpMatcher m("a", ic);
        CHECK_EQ(m.find(""), kNpos);
        CHECK_EQ(m.find("", 0), kNpos);
        CHECK_EQ(m.find("", 1), kNpos);
        CHECK(!m.contains(""));
        CHECK(m.find_all("").empty());
        CHECK_EQ(m.count(""), std::size_t{0});
    }
}

KMP_TEST(PatternLongerThanTheTextFindsNothing) {
    for (bool ic : {false, true}) {
        const KmpMatcher m("abcd", ic);
        CHECK_EQ(m.find("abc"), kNpos);  // exactly one byte too long
        CHECK(!m.contains("abc"));
        CHECK(m.find_all("abc").empty());
        CHECK_EQ(m.count("abc"), std::size_t{0});
        CHECK_EQ(m.find("xabcd", 2), kNpos);  // text[2..] is shorter than the pattern
        CHECK_EQ(m.find("xabcd", 1), std::size_t{1});
        CHECK(m.find_all("a").empty());
        CHECK(m.find_all("").empty());
        CHECK(!KmpMatcher(std::string(1000, 'a'), ic).contains(std::string(999, 'a')));
    }
}

KMP_TEST(PatternEqualToTheText) {
    for (bool ic : {false, true}) {
        const std::string text = "gateway timeout 504";
        const KmpMatcher m(text, ic);
        CHECK_EQ(m.find(text), std::size_t{0});
        CHECK(m.contains(text));
        CHECK((m.find_all(text) == Positions{0}));
        CHECK_EQ(m.count(text), std::size_t{1});
        CHECK_EQ(m.find(text, 1), kNpos);
        CHECK_EQ(m.find(text, text.size()), kNpos);
    }
    CHECK((KmpMatcher("a").find_all("a") == Positions{0}));
    CHECK((KmpMatcher("aaa").find_all("aaa") == Positions{0}));
}

KMP_TEST(PatternOneShorterThanTheText) {
    CHECK((KmpMatcher("aaa").find_all("aaaa") == Positions{0, 1}));
    CHECK((KmpMatcher("abc").find_all("abcd") == Positions{0}));
    CHECK((KmpMatcher("bcd").find_all("abcd") == Positions{1}));
    CHECK((KmpMatcher("bcd").find_all("bcda") == Positions{0}));
}

// ---------------------------------------------------------------------------------------------
// ignore_case

KMP_TEST(IgnoreCaseMatchesMixedCaseText) {
    const KmpMatcher m("ERROR", true);
    CHECK(m.ignore_case());
    CHECK((m.find_all("Error ERROR error eRRoR") == Positions{0, 6, 12, 18}));
    CHECK_EQ(m.count("Error ERROR error eRRoR"), std::size_t{4});
    CHECK(m.contains("an Error occurred"));
    CHECK(!m.contains("an Errol occurred"));

    // Pattern case does not matter either.
    CHECK((KmpMatcher("eRrOr", true).find_all("ERROR error") == Positions{0, 6}));
    CHECK((KmpMatcher("error", true).find_all("ERROR error") == Positions{0, 6}));

    // Without the flag the match is exact.
    const KmpMatcher exact("ERROR");
    CHECK(!exact.ignore_case());
    CHECK((exact.find_all("Error ERROR error eRRoR") == Positions{6}));
    CHECK(!exact.contains("an Error occurred"));
}

KMP_TEST(IgnoreCaseLeavesNonLettersExact) {
    const KmpMatcher m("A-1_b.C", true);
    CHECK(m.contains("xx a-1_B.c xx"));
    CHECK(!m.contains("xx a-2_B.c xx"));
    CHECK(!m.contains("xx a-1 B.c xx"));
    CHECK((KmpMatcher("[ERR]", true).find_all("[err] {err} [ERR]") == Positions{0, 12}));
}

KMP_TEST(IgnoreCaseFoldsExactlyTheAsciiLetters) {
    check_fold_is_exactly_ascii();
}

KMP_TEST(IgnoreCaseDoesNotDependOnTheCLocale) {
    // The spec: ignore_case never consults the C locale. The default "C" locale cannot tell an
    // ASCII-only fold from a tolower / toupper call (both touch A-Z only), so this test switches
    // LC_CTYPE to a Latin-1 locale, where tolower(0xC0) really is 0xE0, and requires the exact
    // same answers. (If the platform has no such locale the checks below simply run in the
    // default one: they hold there too, they just cannot tell the two implementations apart.)
    const LatinCtypeLocale latin;
    check_fold_is_exactly_ascii();

    CHECK(!KmpMatcher(bytes({0xC0}), true).contains(bytes({0xE0})));
    CHECK(!KmpMatcher(bytes({0xE9}), true).contains(bytes({0xC9})));
    CHECK(KmpMatcher(bytes({0xC0}), true).contains(bytes({0xC0})));
    // The table and the overlaps depend on the fold too: {C0, E0} has no border, {C0, C0} has.
    CHECK((KmpMatcher(bytes({0xC0, 0xE0}), true).failure() == Positions{0, 0}));
    CHECK((KmpMatcher(bytes({0xC0, 0xC0}), true).failure() == Positions{0, 1}));
    CHECK((KmpMatcher(bytes({0xC0, 0xC0}), true).find_all(bytes({0xE0, 0xC0, 0xC0, 0xE0})) == Positions{1}));
    CHECK_EQ(KmpMatcher(bytes({0xC0, 0xC0}), true).count(bytes({0xC0, 0xC0, 0xC0})), std::size_t{2});
    // ASCII letters still fold, next to bytes that must not.
    CHECK((KmpMatcher("CAF" + bytes({0xC9}), true).find_all("caf" + bytes({0xC9}) + "CAF" + bytes({0xE9})) ==
           Positions{0}));
}

KMP_TEST(IgnoreCaseDoesNotFoldBytesAbove127) {
    // UTF-8 "E-acute" (C3 89) and "e-acute" (C3 A9) are different bytes and stay different.
    const std::string big = bytes({0xC3, 0x89});
    const std::string small = bytes({0xC3, 0xA9});
    const KmpMatcher m("CAF" + big, true);
    CHECK(m.contains("xx caf" + big + " yy"));
    CHECK(m.contains("xx CAF" + big + " yy"));
    CHECK(!m.contains("xx caf" + small + " yy"));
    CHECK(KmpMatcher(big, true).contains(big));
    CHECK(!KmpMatcher(big, true).contains(small));
    CHECK(!KmpMatcher(small, true).contains(big));

    // Latin-1 pairs, and the high-bit twins of ASCII letters.
    CHECK(!KmpMatcher(bytes({0xC0}), true).contains(bytes({0xE0})));
    CHECK(!KmpMatcher(bytes({0xC1}), true).contains("A"));
    CHECK(!KmpMatcher(bytes({0xC1}), true).contains("a"));
    CHECK(!KmpMatcher("A", true).contains(bytes({0xC1})));
    CHECK(!KmpMatcher("a", true).contains(bytes({0xE1})));
    CHECK(!KmpMatcher(bytes({0xC1}), true).contains(bytes({0xE1})));
    CHECK(KmpMatcher(bytes({0xC1}), true).contains(bytes({0xC1})));
    CHECK(KmpMatcher(bytes({0xFF, 0x80}), true).contains(bytes({0x01, 0xFF, 0x80, 0x02})));
}

KMP_TEST(HighBytesMatchExactlyAndAreNotSignExtended) {
    // 0x00..0xFF in order: every pattern of consecutive bytes is found where it must be, whether
    // `char` is signed or not.
    std::string all;
    for (int v = 0; v < 256; ++v) all.push_back(static_cast<char>(v));
    const KmpMatcher across_the_sign_boundary(bytes({0x7F, 0x80, 0x81}));
    CHECK_EQ(across_the_sign_boundary.find(all), std::size_t{127});
    CHECK((across_the_sign_boundary.find_all(all) == Positions{127}));
    CHECK_EQ(KmpMatcher(bytes({0xFE, 0xFF})).find(all), std::size_t{254});
    CHECK_EQ(KmpMatcher(bytes({0xFF}), true).find(all), std::size_t{255});
    CHECK_EQ(KmpMatcher(bytes({0x00, 0x01})).find(all), std::size_t{0});

    std::size_t unused = 0;
    for (std::size_t start = 0; start + 3 <= all.size(); ++start) {
        for (bool ic : {false, true}) check_case(all.substr(start, 3), all, ic, unused);
    }
    // 0xFF != 0x7F: a pattern byte must not equal the text byte with its top bit dropped.
    CHECK(!KmpMatcher(bytes({0xFF})).contains(bytes({0x7F})));
    CHECK(!KmpMatcher(bytes({0x80})).contains(bytes({0x00})));
}

// ---------------------------------------------------------------------------------------------
// Embedded NULs

KMP_TEST(EmbeddedNulsAreOrdinaryBytes) {
    const std::string pattern("a\0b", 3);
    const KmpMatcher m(pattern);
    CHECK_EQ(m.pattern_size(), std::size_t{3});
    CHECK((m.failure() == Positions{0, 0, 0}));

    const std::string text("xxa\0byya\0b", 10);
    CHECK_EQ(m.find(text), std::size_t{2});
    CHECK((m.find_all(text) == Positions{2, 7}));
    CHECK_EQ(m.count(text), std::size_t{2});
    CHECK_EQ(m.find(text, 3), std::size_t{7});

    CHECK(!m.contains(std::string("a\0c", 3)));
    CHECK(!m.contains("ab"));                     // the NUL is part of the pattern
    CHECK(!m.contains(std::string("a\0", 2)));    // text ends inside the pattern
    CHECK(m.contains(std::string("\0a\0b\0", 5)));

    // The text continues past a NUL.
    CHECK_EQ(KmpMatcher("tail").find(std::string("head\0tail", 9)), std::size_t{5});
}

KMP_TEST(NulOnlyPatterns) {
    CHECK((KmpMatcher(std::string(1, '\0')).find_all(std::string("a\0b\0\0", 5)) == Positions{1, 3, 4}));
    const KmpMatcher two(std::string(2, '\0'));
    CHECK((two.failure() == Positions{0, 1}));
    CHECK((two.find_all(std::string(3, '\0')) == Positions{0, 1}));
    CHECK(!two.contains(std::string("\0a\0", 3)));
    CHECK_EQ(two.count(std::string(5, '\0')), std::size_t{4});
}

// ---------------------------------------------------------------------------------------------
// Randomized comparison against the references

KMP_TEST(RandomSmallAlphabetsMatchReferences) {
    random_cases(1, 6000, "abcd", false);
}

KMP_TEST(RandomSmallAlphabetsMatchReferencesIgnoringCase) {
    random_cases(2, 2500, "abcd", true);
    random_cases(3, 4000, "aAbBzZ@[`{", true);
}

KMP_TEST(RandomCaseMixedAlphabetsStayExactWhenCaseSensitive) {
    random_cases(4, 3000, "aAbBzZ@[`{", false);
}

KMP_TEST(RandomBinaryAlphabetsMatchReferences) {
    // NULs, DEL, the sign boundary, 0xFF and high-bit twins of 'A' / 'a', in both modes.
    const std::string pool = bytes({0x00, 0x7F, 0x80, 0xFF, 'a', 'A', 0xC1, 0xE1});
    random_cases(5, 3000, pool, false);
    random_cases(6, 3000, pool, true);
}

KMP_TEST(RandomLongerTextsMatchReferences) {
    std::mt19937 rng(99);
    std::size_t total_matches = 0;
    for (int iter = 0; iter < 100; ++iter) {
        const std::string text = random_string(rng, "ab", 400 + below(rng, 800));
        const std::string pattern = random_string(rng, "ab", 1 + below(rng, 12));
        check_case(pattern, text, false, total_matches);
    }
    CHECK(total_matches > 1000);
}

KMP_TEST(FibonacciWordsMatchStdFind) {
    // Highly periodic: deep failure chains and constant overlap.
    const std::string text = fibonacci_word(24);
    CHECK_EQ(text.size(), std::size_t{46368});
    for (int n : {2, 3, 5, 8, 12, 15}) {
        const std::string pattern = fibonacci_word(n);
        const KmpMatcher m(pattern);
        const Positions expected = std_find_all(pattern, text);
        CHECK(!expected.empty());
        CHECK(m.find_all(text) == expected);
        CHECK_EQ(m.count(text), expected.size());
        if (pattern.size() <= 40) CHECK(m.failure() == naive_failure(pattern, false));  // naive is O(m^3)
    }
}

// ---------------------------------------------------------------------------------------------
// Deterministic complexity guards: step budgets and allocation counts instead of clocks (see
// CountingFold). They sit BEFORE the heavy inputs below on purpose: tests run in registration
// order, and a quadratic regression should be reported by these in milliseconds.

// Plain TEST, like TinyInputsAreSoundAndTheLoopsTerminate: reports the scaled-down guard's own
// verdict in detail, even when that verdict is what makes the large tests below refuse to run.
TEST(Kmp, ScaledDownComplexityGuardPasses) {
    // The small-input version of the budget checks below; every test that uses large inputs
    // consults it first (require_linear_scaling), and it includes the allocation-growth check
    // whose violation (a reallocation per match) is the one a large input cannot survive.
    const std::string& verdict = scaling_guard_verdict();
    if (!verdict.empty()) throw testkit::Failure{verdict};
    CHECK(CountingFold::limit == std::numeric_limits<std::size_t>::max());  // budgets are always disarmed
}

KMP_TEST(FailureTableBuildStepsAreLinearInThePatternLength) {
    require_linear_scaling();
    std::mt19937 rng(424242);
    check_failure_build_is_linear(failure_build_patterns(20000, 20, rng));  // fib(20): 6765 bytes
}

KMP_TEST(SearchStepsAreLinearInTheTextOnWorstCaseInputs) {
    require_linear_scaling();
    std::mt19937 rng(777);
    check_search_is_linear(search_cases(200000, 15, 24, rng));  // fib: 610 bytes in 46368
}

KMP_TEST(FindStopsAtItsFirstMatch) {
    // The match ends at byte 6 of a 200006-byte text: a find() that kept scanning to the end
    // would blow a budget sized for the bytes up to the match by four orders of magnitude.
    const std::string text = "xxxabc" + std::string(200000, 'y');
    const KmpMatcher m("abc");
    {
        StepBudget budget(6);
        CHECK_EQ(KmpTestAccess::find<CountingFold>(m, text, 0), std::size_t{3});
    }
    {
        StepBudget budget(6);  // from > 0: the bytes before `from` are not read at all
        CHECK_EQ(KmpTestAccess::find<CountingFold>(m, text, 3), std::size_t{3});
    }
    // A late match: the budget is the distance scanned, not the text length.
    const std::string late = std::string(100000, 'x') + "abc" + std::string(100000, 'x');
    {
        StepBudget budget(3 + 10);
        CHECK_EQ(KmpTestAccess::find<CountingFold>(m, late, 99990), std::size_t{100000});
    }
    // And the real (non-instrumented) function agrees.
    CHECK_EQ(m.find(text), std::size_t{3});
    CHECK_EQ(m.find(late, 99990), std::size_t{100000});
}

KMP_TEST(FindAllGrowsItsResultGeometrically) {
    check_find_all_grows_geometrically(20000);
}

KMP_TEST(FindAllHoldsOnlyTheMatches) {
    // "No more than the matches": nothing proportional to the text, neither a reserve() sized
    // by it nor a copy of it (say a lower-cased copy made for ignore_case; the text is folded
    // on the fly). Three matches in two million bytes.
    std::string text(2000000, 'x');
    for (const std::size_t at : {std::size_t{10}, std::size_t{1000000}, std::size_t{1999994}}) {
        text.replace(at, 6, "NeEdLe");
    }
    for (bool ic : {false, true}) {
        const KmpMatcher hits(ic ? "needle" : "NeEdLe", ic);
        const KmpMatcher misses("zzz", ic);

        const std::size_t before = alloc_probe::allocations;
        const Positions all = hits.find_all(text);
        const std::size_t used = alloc_probe::allocations - before;
        CHECK((all == Positions{10, 1000000, 1999994}));
        CHECK(all.capacity() <= 2 * all.size() + 1);  // growth slack only, nothing text-sized
        CHECK(used <= all.size());                    // at most one allocation per growth step

        const std::size_t before_none = alloc_probe::allocations;
        const Positions none = misses.find_all(text);
        CHECK_EQ(alloc_probe::allocations - before_none, std::size_t{0});
        CHECK(none.empty());
        CHECK_EQ(none.capacity(), std::size_t{0});
    }
    // The empty pattern is the one case whose result is as long as the text: exactly that long.
    const Positions every = KmpMatcher("").find_all(std::string(5000, 'x'));
    CHECK_EQ(every.size(), std::size_t{5001});
    CHECK(every.capacity() <= 2 * every.size() + 1);
}

KMP_TEST(NeverReadsTheTerminatorsBehindThePatternOrTheText) {
    // The small grid (every pattern up to 4 bytes over {a,b,c} against every text up to 7 bytes
    // over {a,b}, every `from`) through a fold that throws when it sees a NUL. The inputs
    // contain none, so the only NULs there are to read are the terminators a std::string keeps
    // just past its last byte: an off-by-one read of the pattern (which the matcher holds in a
    // std::string) or of a text is caught here even though it stays inside the allocation, where
    // AddressSanitizer cannot see it.
    const GridResult grid = run_small_grid<NulTrap, NoBudget>();
    if (!grid.first_wrong_answer.empty()) throw testkit::Failure{grid.first_wrong_answer};
    // Not vacuous: matches really do occur. The total was cross-checked with an independent
    // enumeration, so a grid that silently shrank would be noticed too.
    CHECK_EQ(grid.matches, std::size_t{6431});
}

// ---------------------------------------------------------------------------------------------
// Pathological inputs: no wall-clock assertions. Each quadratic-at-heart search below would
// need on the order of 10^10 byte comparisons (tens of seconds) from a restart-on-mismatch
// implementation, so a regression cannot hide; KMP does a few hundred thousand. Each test asks
// require_linear_scaling() first, so a regression is reported at once instead of after minutes.

KMP_TEST(AllAsThenBAgainstAllAsDoesNotRescan) {
    require_linear_scaling();
    const std::size_t n = 200000;
    const std::size_t k = 100000;
    const std::string text(n, 'a');
    const KmpMatcher m(std::string(k, 'a') + "b");
    CHECK_EQ(m.pattern_size(), k + 1);
    CHECK_EQ(m.find(text), kNpos);
    CHECK_EQ(m.find(text, 50000), kNpos);
    CHECK(!m.contains(text));
    CHECK(m.find_all(text).empty());
    CHECK_EQ(m.count(text), std::size_t{0});

    // The same text with a closing 'b': exactly one match, at the end.
    std::string with_b = text;
    with_b.back() = 'b';
    CHECK_EQ(m.find(with_b), n - k - 1);
    CHECK((m.find_all(with_b) == Positions{n - k - 1}));
    CHECK_EQ(m.count(with_b), std::size_t{1});
    CHECK_EQ(m.find(with_b, n - k - 1), n - k - 1);
    CHECK_EQ(m.find(with_b, n - k), kNpos);
}

KMP_TEST(MaximallyOverlappingMatches) {
    require_linear_scaling();
    const std::size_t n = 200000;
    const std::size_t k = 100000;
    const std::string text(n, 'a');
    const KmpMatcher m(std::string(k, 'a'));
    const Positions all = m.find_all(text);
    CHECK_EQ(all.size(), n - k + 1);
    CHECK(all == iota_positions(0, n - k + 1));
    CHECK_EQ(m.count(text), n - k + 1);
    CHECK_EQ(m.find(text, n - k), n - k);
    CHECK_EQ(m.find(text, n - k + 1), kNpos);
}

KMP_TEST(PeriodicPatternWithABadLastByte) {
    require_linear_scaling();
    // (ab)^50000 + 'c': every even offset matches 100000 bytes before failing.
    const std::size_t pairs = 50000;
    std::string pattern;
    for (std::size_t i = 0; i < pairs; ++i) pattern += "ab";
    pattern += 'c';
    const KmpMatcher m(pattern);
    CHECK_EQ(m.failure().back(), std::size_t{0});

    std::string text;
    for (std::size_t i = 0; i < 2 * pairs; ++i) text += "ab";
    CHECK_EQ(text.size(), std::size_t{200000});
    CHECK_EQ(m.find(text), kNpos);
    CHECK_EQ(m.count(text), std::size_t{0});

    // (ab)^99999 + 'c': the pattern fits only at the tail, after 99998 bytes of near-misses.
    std::string tail_match;
    for (std::size_t i = 0; i < 2 * pairs - 1; ++i) tail_match += "ab";
    tail_match += 'c';
    const std::size_t tail_start = tail_match.size() - pattern.size();
    CHECK_EQ(tail_start, std::size_t{99998});
    CHECK_EQ(m.find(tail_match), tail_start);
    CHECK((m.find_all(tail_match) == Positions{tail_start}));
}

KMP_TEST(OneCharacterPatternInAMillionMatches) {
    require_linear_scaling();
    // find_all must be linear in the number of matches, and hold only the matches.
    const std::string text(1000000, 'a');
    const KmpMatcher one("a");
    const Positions all = one.find_all(text);
    CHECK_EQ(all.size(), std::size_t{1000000});
    CHECK(all == iota_positions(0, 1000000));
    CHECK_EQ(one.count(text), std::size_t{1000000});

    const KmpMatcher two("aa");
    CHECK_EQ(two.find_all(text).size(), std::size_t{999999});
    CHECK_EQ(two.count(text), std::size_t{999999});
}

KMP_TEST(PathologicalInputsIgnoringCase) {
    require_linear_scaling();
    const std::size_t n = 200000;
    const std::size_t k = 100000;
    std::string text(n, 'a');
    for (std::size_t i = 1; i < n; i += 2) text[i] = 'A';  // aAaA...
    const KmpMatcher m(std::string(k, 'A') + "b", true);
    CHECK_EQ(m.find(text), kNpos);
    CHECK_EQ(m.count(text), std::size_t{0});

    text.back() = 'B';
    CHECK_EQ(m.find(text), n - k - 1);
    CHECK((m.find_all(text) == Positions{n - k - 1}));

    // Case-sensitively the alternating text has no run of k equal letters at all.
    CHECK_EQ(KmpMatcher(std::string(3, 'a')).find(text), kNpos);
    CHECK_EQ(KmpMatcher(std::string(3, 'a'), true).find(text), std::size_t{0});
}

// ---------------------------------------------------------------------------------------------
// Memory safety, copies and moves

KMP_TEST(NeverReadsPastTheText) {
    // Exact-size heap buffer for the text: any off-by-one read of it is an AddressSanitizer
    // error under -Asan. (Reads of the pattern, which the matcher copies into a std::string
    // whose terminator ASan cannot see, are covered by the NulTrap test above.)
    const std::string source = "xxabcabcabyy";
    auto text_buffer = std::make_unique<char[]>(source.size());
    std::copy(source.begin(), source.end(), text_buffer.get());

    const std::string pattern_source = "abcab";
    auto pattern_buffer = std::make_unique<char[]>(pattern_source.size());
    std::copy(pattern_source.begin(), pattern_source.end(), pattern_buffer.get());

    for (bool ic : {false, true}) {
        // The constructor must read exactly pattern_source.size() bytes of the exact-size buffer.
        const KmpMatcher m(std::string_view(pattern_buffer.get(), pattern_source.size()), ic);
        for (std::size_t offset = 0; offset <= source.size(); ++offset) {
            for (std::size_t len = 0; offset + len <= source.size(); ++len) {
                const std::string_view view(text_buffer.get() + offset, len);
                const std::string as_string(view);
                if (m.find_all(view) != naive_find_all(pattern_source, as_string, ic)) {
                    fail_case("find_all on a sub-view", pattern_source, as_string, ic);
                }
                if (m.count(view) != naive_find_all(pattern_source, as_string, ic).size()) {
                    fail_case("count on a sub-view", pattern_source, as_string, ic);
                }
            }
        }
    }
    // A view into the middle of a longer string is not NUL-terminated and must be honoured.
    const std::string_view window = std::string_view("abcabcabc").substr(0, 4);  // "abca"
    CHECK((KmpMatcher("abc").find_all(window) == Positions{0}));
    CHECK(!KmpMatcher("abcab").contains(window));
}

KMP_TEST(ThePatternIsCopiedAtConstruction) {
    std::string pattern = "needle";
    const KmpMatcher m(pattern);
    pattern.assign("zzzzzz");  // overwrite the caller's buffer
    CHECK_EQ(m.find("hayneedlehay"), std::size_t{3});
    CHECK(!m.contains("zzzzzz"));
    {
        const std::string temporary = "needle";
        const KmpMatcher from_temporary(temporary);
        CHECK(from_temporary.contains("a needle"));
    }
}

KMP_TEST(CopiesAreEqualAndIndependent) {
    const KmpMatcher original("abab", true);
    KmpMatcher copy(original);
    CHECK_EQ(copy.pattern_size(), std::size_t{4});
    CHECK(copy.ignore_case());
    CHECK(copy.failure() == original.failure());
    CHECK((copy.find_all("xABABab") == Positions{1, 3}));

    KmpMatcher assigned("zzz");
    CHECK(!assigned.ignore_case());
    assigned = original;
    CHECK_EQ(assigned.pattern_size(), std::size_t{4});
    CHECK(assigned.ignore_case());
    CHECK((assigned.find_all("xABABab") == Positions{1, 3}));
    CHECK(!assigned.contains("zzz"));

    // The original is untouched by what happened to its copies.
    CHECK((original.find_all("xABABab") == Positions{1, 3}));
    CHECK(original.failure() == (Positions{0, 0, 1, 2}));

    // Self-assignment (through an alias, to keep compilers quiet) changes nothing.
    KmpMatcher& alias = assigned;
    assigned = alias;
    CHECK_EQ(assigned.pattern_size(), std::size_t{4});
    CHECK((assigned.find_all("xABABab") == Positions{1, 3}));
}

KMP_TEST(CopyAssignmentKeepsTheTargetIntactWhenAllocationFails) {
    // Copying allocates twice (pattern, then table). Fail the assignment after 0, 1, 2, ...
    // successful allocations: the invariant failure().size() == pattern_size() must hold at
    // every step (the scan indexes the table by pattern position), and a failed assignment must
    // leave the target exactly as it was. A defaulted copy assignment assigns the members one
    // by one, so a failure in between leaves the new pattern next to the old (or an empty) table.
    const KmpMatcher source(std::string(1000, 'a') + "B", true);
    bool saw_failure = false;
    bool saw_success = false;
    for (long successes = 0; successes < 16 && !saw_success; ++successes) {
        KmpMatcher target("abab");
        bool threw = false;
        {
            alloc_probe::FailAfter inject(successes);
            try {
                target = source;
            } catch (const std::bad_alloc&) {
                threw = true;
            }
        }
        CHECK_EQ(target.failure().size(), target.pattern_size());
        if (threw) {
            saw_failure = true;
            CHECK_EQ(target.pattern_size(), std::size_t{4});
            CHECK(!target.ignore_case());
            CHECK((target.failure() == Positions{0, 0, 1, 2}));
            CHECK((target.find_all("xababab") == Positions{1, 3}));
            CHECK(!target.contains(std::string(1000, 'a') + "b"));
        } else {
            saw_success = true;
            CHECK_EQ(target.pattern_size(), source.pattern_size());
            CHECK(target.ignore_case());
            CHECK(target.failure() == source.failure());
            CHECK_EQ(target.find(std::string(5, 'x') + std::string(1000, 'A') + "b"), std::size_t{5});
        }
        // The source is only read.
        CHECK_EQ(source.pattern_size(), std::size_t{1001});
        CHECK_EQ(source.failure().size(), std::size_t{1001});
    }
    // Guards against a vacuous test: the injection really did make an assignment fail, and the
    // assignment does succeed once enough allocations are allowed.
    CHECK(saw_failure);
    CHECK(saw_success);
}

KMP_TEST(SearchingNeverAllocates) {
    const std::string text = "gateway timeout; Timeout again; TIMEOUT; no luck here, timeou";
    for (bool ic : {false, true}) {
        const KmpMatcher m("timeout", ic);
        const KmpMatcher empty("", ic);
        const std::size_t before = alloc_probe::allocations;
        const std::size_t first = m.find(text);
        const std::size_t later = m.find(text, first + 1);
        const bool hit = m.contains(text);
        const std::size_t total = m.count(text);
        const std::size_t empty_total = empty.count(text) + empty.find(text, 3);
        const std::size_t used = alloc_probe::allocations - before;
        CHECK_EQ(used, std::size_t{0});
        CHECK_EQ(first, std::size_t{8});
        CHECK_EQ(later, ic ? std::size_t{17} : kNpos);
        CHECK(hit);
        CHECK_EQ(total, ic ? std::size_t{3} : std::size_t{1});
        CHECK_EQ(empty_total, text.size() + 1 + 3);
    }
}

KMP_TEST(AllocationProbeIgnoresOtherThreads) {
    // Regression test for the probe itself: its counters used to be process-wide, so a thread
    // allocating in the background made SearchingNeverAllocates-style checks fail at random.
    // The worker below allocates continuously; this thread searches (which allocates nothing)
    // until the worker has made 200 allocations, and must still see a count of exactly zero.
    const KmpMatcher m("timeout", true);
    const std::string text = "gateway timeout; Timeout again; TIMEOUT; no luck here, timeou";

    std::atomic<bool> stop{false};
    std::atomic<std::size_t> worker_allocations{0};
    std::atomic<int*> sink{nullptr};  // keeps the compiler from optimising the new/delete pair away
    std::thread worker;
    bool worker_started = false;
    try {
        worker = std::thread([&] {
            while (!stop.load()) {
                sink.store(new int(7));
                delete sink.exchange(nullptr);
                worker_allocations.fetch_add(1);
            }
        });
        worker_started = true;
    } catch (const std::system_error&) {
        // No thread support linked in (see the thread test below): nothing to disturb the probe.
    }

    const std::size_t before = alloc_probe::allocations;
    const std::size_t worker_start = worker_allocations.load();
    std::size_t rounds = 0;
    std::size_t found = 0;
    do {
        found += m.count(text);
        std::this_thread::yield();
    } while (worker_started && worker_allocations.load() < worker_start + 200 && ++rounds < 200000);
    const std::size_t used = alloc_probe::allocations - before;

    stop.store(true);
    if (worker_started) worker.join();
    CHECK_EQ(used, std::size_t{0});
    CHECK(found >= 3);
}

KMP_TEST(ConstQueriesAreSafeFromSeveralThreads) {
    // The header promises that every search function is const and safe to call concurrently on
    // one matcher. A hidden mutable scan state (a member used as the "bytes matched" counter,
    // a cache of the last search) would still give right answers single-threaded, so only
    // concurrent use can show it: every thread runs the same searches on shared matchers and
    // must get the single-threaded answers every time.
    constexpr std::size_t kThreads = 4;
    constexpr int kRounds = 8;

    std::mt19937 rng(8675309);
    const std::string exact_text = random_string(rng, "ab", 200000);
    const std::string folded_text = random_string(rng, "aAbB", 200000);
    const KmpMatcher exact("abab");
    const KmpMatcher folded("aBAb", true);
    const Positions want_exact = naive_find_all("abab", exact_text, false);
    const Positions want_folded = naive_find_all("aBAb", folded_text, true);
    const std::size_t want_exact_from = [&] {
        const auto it = std::lower_bound(want_exact.begin(), want_exact.end(), std::size_t{150000});
        return it == want_exact.end() ? kNpos : *it;
    }();
    CHECK(want_exact.size() > 1000);
    CHECK(want_folded.size() > 1000);
    CHECK(want_exact_from != kNpos);

    std::atomic<bool> go{false};
    std::vector<int> ok(kThreads + 1, 1);  // one slot per worker (int, not bool: no shared bits)
    const auto work = [&](std::size_t slot) {
        while (!go.load()) std::this_thread::yield();
        for (int round = 0; round < kRounds; ++round) {
            if (exact.find_all(exact_text) != want_exact) ok[slot] = 0;
            if (folded.find_all(folded_text) != want_folded) ok[slot] = 0;
            if (exact.count(exact_text) != want_exact.size()) ok[slot] = 0;
            if (folded.count(folded_text) != want_folded.size()) ok[slot] = 0;
            if (exact.find(exact_text, 150000) != want_exact_from) ok[slot] = 0;
            if (!folded.contains(folded_text)) ok[slot] = 0;
        }
    };

    std::vector<std::thread> threads;
    bool threads_unavailable = false;
    try {
        for (std::size_t slot = 0; slot < kThreads; ++slot) threads.emplace_back(work, slot);
    } catch (const std::system_error&) {
        // A toolchain without thread support linked in (std::thread throws instead of failing
        // to link): fall back to running the work once on this thread, which still checks the
        // answers, just not the concurrency.
        threads_unavailable = true;
    } catch (...) {
        go.store(true);
        for (std::thread& t : threads) t.join();
        throw;
    }
    go.store(true);
    for (std::thread& t : threads) t.join();
    if (threads_unavailable) work(kThreads);

    for (std::size_t slot = 0; slot < ok.size(); ++slot) {
        if (ok[slot] == 0) {
            throw testkit::Failure{"kmp_test: a concurrent search on a shared matcher gave a wrong answer "
                                   "(worker " + std::to_string(slot) + ")"};
        }
    }
}

KMP_TEST(MovedMatchersKeepWorking) {
    KmpMatcher source("Needle", true);
    KmpMatcher moved(std::move(source));
    CHECK_EQ(moved.pattern_size(), std::size_t{6});
    CHECK(moved.ignore_case());
    CHECK((moved.failure() == Positions{0, 0, 0, 0, 0, 0}));
    CHECK((moved.find_all("a NEEDLE and a needle") == Positions{2, 15}));

    // A moved-from matcher is a valid matcher of the empty pattern (and may be reused); the
    // header promises it keeps its ignore_case flag.
    CHECK_EQ(source.pattern_size(), std::size_t{0});
    CHECK(source.ignore_case());
    CHECK(source.failure().empty());
    CHECK_EQ(source.find("abc"), std::size_t{0});
    CHECK_EQ(source.count("abc"), std::size_t{4});
    source = KmpMatcher("xyz");
    CHECK((source.find_all("axyzxyz") == Positions{1, 4}));
    CHECK(!source.ignore_case());

    KmpMatcher target("zzzz");
    KmpMatcher donor("abcabd", true);
    target = std::move(donor);
    CHECK_EQ(target.pattern_size(), std::size_t{6});
    CHECK(target.ignore_case());
    CHECK((target.failure() == Positions{0, 0, 0, 1, 2, 0}));
    CHECK((target.find_all("xabcabdABCABD") == Positions{1, 7}));
    CHECK_EQ(donor.pattern_size(), std::size_t{0});
    CHECK(donor.ignore_case());
    CHECK(donor.failure().empty());

    KmpMatcher& alias = target;
    target = std::move(alias);  // self-move leaves the matcher usable
    CHECK_EQ(target.pattern_size(), std::size_t{6});
    CHECK((target.find_all("xabcabdabcabd") == Positions{1, 7}));
}

KMP_TEST(MatchersSurviveContainerRelocation) {
    // Even slots ignore case (and are probed with upper-case text), odd slots are exact.
    std::vector<KmpMatcher> matchers;
    for (std::size_t i = 0; i < 60; ++i) matchers.emplace_back(std::string(i % 7 + 1, 'a') + "b", i % 2 == 0);
    const auto check_all = [](const std::vector<KmpMatcher>& ms) {
        for (std::size_t i = 0; i < ms.size(); ++i) {
            const std::string hit = "xx" + std::string(i % 7 + 1, i % 2 == 0 ? 'A' : 'a') + "bxx";
            CHECK_EQ(ms[i].pattern_size(), i % 7 + 2);
            CHECK_EQ(ms[i].ignore_case(), i % 2 == 0);
            CHECK_EQ(ms[i].find(hit), std::size_t{2});
            CHECK((ms[i].find_all(hit) == Positions{2}));
        }
    };
    check_all(matchers);
    const std::vector<KmpMatcher> copied = matchers;
    CHECK_EQ(copied.size(), matchers.size());
    check_all(copied);
}
