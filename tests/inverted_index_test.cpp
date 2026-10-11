#include <algorithm>
#include <cctype>
#include <clocale>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <iterator>
#include <limits>
#include <map>
#include <new>
#include <random>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_set>
#include <utility>
#include <vector>

#include "loganalyzer/inverted_index.hpp"
#include "testkit.hpp"

using loganalyzer::DocId;
using loganalyzer::InvertedIndex;
using loganalyzer::difference;
using loganalyzer::intersect;
using loganalyzer::intersect_gallop;
using loganalyzer::intersect_merge;
using loganalyzer::intersect_uses_galloping;
using loganalyzer::tokenize;
using loganalyzer::unite;

// Friend of InvertedIndex (see the header). Reaches the private hooks the tests need: a probe
// through the whole query pipeline, a hook between the steps of add(), and a few internals.
namespace loganalyzer {

struct InvertedIndexTestAccess {
    template <class Hook>
    static DocId add(InvertedIndex& index, std::string_view text, Hook&& hook) {
        return index.add_with(text, std::forward<Hook>(hook));
    }

    template <class Probe>
    static std::vector<DocId> search(const InvertedIndex& index, std::string_view query, Probe probe) {
        return index.search_with(query, probe);
    }

    template <class Probe>
    static std::vector<DocId> search_or(const InvertedIndex& index, const std::vector<std::string>& terms,
                                        Probe probe) {
        return index.search_or_with(terms, probe);
    }

    // What the parser made of a query, after equal pieces were merged.
    static std::size_t distinct_required_words(const InvertedIndex& index, std::string_view query) {
        return index.parse(query).required.size();
    }
    static std::size_t distinct_excluded_alternatives(const InvertedIndex& index, std::string_view query) {
        return index.parse(query).excluded.size();
    }
    static bool query_is_impossible(const InvertedIndex& index, std::string_view query) {
        return index.parse(query).impossible;
    }

    static std::uint64_t capacity(const InvertedIndex& index) { return index.max_documents_; }

    static std::size_t largest_bucket(const InvertedIndex& index) {
        if (!index.terms_) return 0;
        std::size_t largest = 0;
        for (std::size_t b = 0; b < index.terms_->bucket_count(); ++b) {
            largest = std::max(largest, index.terms_->bucket_size(b));
        }
        return largest;
    }

    static std::pair<std::uint64_t, std::uint64_t> hash_key(const InvertedIndex& index) {
        const detail::TermHash hash = index.terms_->hash_function();
        return {hash.key0, hash.key1};
    }
};

}  // namespace loganalyzer

using loganalyzer::InvertedIndexTestAccess;

namespace {

using Ids = std::vector<DocId>;
using Strings = std::vector<std::string>;

constexpr DocId kMax = std::numeric_limits<DocId>::max();

Ids ids(std::initializer_list<DocId> list) { return Ids(list); }
Strings strs(std::initializer_list<const char*> list) { return Strings(list.begin(), list.end()); }

std::string preview(const Ids& v) {
    std::string s = "[";
    for (std::size_t i = 0; i < v.size() && i < 16; ++i) {
        if (i != 0) s += ' ';
        s += std::to_string(v[i]);
    }
    if (v.size() > 16) s += " ...";
    s += "] (" + std::to_string(v.size()) + " ids)";
    return s;
}

// Printable form of arbitrary bytes, for failure messages only.
std::string escaped(const std::string& text) {
    static const char kHex[] = "0123456789abcdef";
    std::string out;
    for (const char ch : text) {
        const auto c = static_cast<unsigned char>(ch);
        if (c >= 32 && c < 127) {
            out += ch;
        } else {
            out += "\\x";
            out += kHex[c >> 4];
            out += kHex[c & 15];
        }
    }
    return out;
}

// Compares id lists and, on mismatch, shows the first few ids of both (the stock CHECK_EQ
// would print "<unprintable>" for a vector). `ctx` is only evaluated when the check fails.
#define CHECK_IDS_CTX(actual, expected, ctx)                                                  \
    do {                                                                                      \
        const Ids _ids_a = (actual);                                                          \
        const Ids _ids_e = (expected);                                                        \
        if (_ids_a != _ids_e)                                                                 \
            throw ::testkit::Failure{::testkit::where(__FILE__, __LINE__) + "CHECK_IDS(" #actual \
                                     ", " #expected ") failed: " + preview(_ids_a) + " vs " + \
                                     preview(_ids_e) + " [" + (ctx) + "]"};                   \
    } while (0)
#define CHECK_IDS(actual, expected) CHECK_IDS_CTX(actual, expected, "")

// mt19937's output sequence is fixed by the standard; the distributions are not, so the
// tests derive everything from raw output and stay reproducible on every compiler.
class Rng {
public:
    explicit Rng(std::uint32_t seed) : gen_(seed) {}
    std::uint32_t next() { return static_cast<std::uint32_t>(gen_()); }
    std::uint32_t below(std::uint32_t n) { return next() % n; }  // n > 0
    bool chance(double p) { return static_cast<double>(next()) < p * 4294967296.0; }

private:
    std::mt19937 gen_;
};

// Strictly ascending list of at most `count` ids drawn from [base, base + span].
Ids random_list(Rng& rng, std::size_t count, DocId base, std::uint32_t span) {
    std::set<DocId> picked;
    for (std::size_t i = 0; i < count; ++i) picked.insert(base + rng.below(span + 1));
    return Ids(picked.begin(), picked.end());
}

// Every id in [0, limit) independently with the given probability: the cheap way to get a
// list with a million elements (std::set insertion would dominate the test's run time).
Ids dense_random_list(Rng& rng, DocId limit, double probability) {
    Ids out;
    for (DocId id = 0; id < limit; ++id) {
        if (rng.chance(probability)) out.push_back(id);
    }
    return out;
}

// ---- trivially correct references (std algorithms / std::set) ----

Ids ref_intersect(const Ids& a, const Ids& b) {
    Ids out;
    std::set_intersection(a.begin(), a.end(), b.begin(), b.end(), std::back_inserter(out));
    return out;
}

Ids ref_difference(const Ids& a, const Ids& b) {
    Ids out;
    std::set_difference(a.begin(), a.end(), b.begin(), b.end(), std::back_inserter(out));
    return out;
}

Ids ref_union(const std::vector<Ids>& lists) {
    std::set<DocId> all;
    for (const Ids& list : lists) all.insert(list.begin(), list.end());
    return Ids(all.begin(), all.end());
}

// Every intersection entry point, both argument orders, against std::set_intersection.
void check_intersection_all_ways(const Ids& a, const Ids& b) {
    const Ids expected = ref_intersect(a, b);
    const std::string ctx = "a=" + preview(a) + " b=" + preview(b);
    CHECK_IDS_CTX(intersect(a, b), expected, "intersect " + ctx);
    CHECK_IDS_CTX(intersect(b, a), expected, "intersect swapped " + ctx);
    CHECK_IDS_CTX(intersect_merge(a, b), expected, "merge " + ctx);
    CHECK_IDS_CTX(intersect_merge(b, a), expected, "merge swapped " + ctx);
    CHECK_IDS_CTX(intersect_gallop(a, b), expected, "gallop " + ctx);
    CHECK_IDS_CTX(intersect_gallop(b, a), expected, "gallop swapped " + ctx);
}

}  // namespace

// =========================================================================================
// tokenize
// =========================================================================================

TEST(IndexTokenize, SpecExample) {
    CHECK((tokenize("Payment-Service timeout=3000ms") == strs({"payment", "service", "timeout", "3000ms"})));
}

TEST(IndexTokenize, NoTokens) {
    for (const char* text : {"", " ", "---", "...!!", "\t\n\r", "_", "=:;,", "[]{}()<>"}) {
        CHECK(tokenize(text).empty());
    }
}

TEST(IndexTokenize, LowercasesAsciiLettersAndKeepsDigits) {
    CHECK((tokenize("ERROR Error eRRor error") == strs({"error", "error", "error", "error"})));
    CHECK((tokenize("ABCxyz019") == strs({"abcxyz019"})));
    CHECK((tokenize("0xFF") == strs({"0xff"})));
    CHECK((tokenize("HTTP500") == strs({"http500"})));
}

TEST(IndexTokenize, TokensAreMaximalRunsOfLettersAndDigits) {
    CHECK((tokenize("a1b2 c3") == strs({"a1b2", "c3"})));
    CHECK((tokenize("3000ms") == strs({"3000ms"})));
    CHECK((tokenize("10.0.0.1:443") == strs({"10", "0", "0", "1", "443"})));
    CHECK((tokenize("  leading and trailing  ") == strs({"leading", "and", "trailing"})));
    CHECK((tokenize("x") == strs({"x"})));
}

TEST(IndexTokenize, PunctuationAlwaysSeparates) {
    CHECK((tokenize("a-b_c.d:e/f\\g,h;i=j@k#l") ==
           strs({"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l"})));
    CHECK((tokenize("--a--b--") == strs({"a", "b"})));
    CHECK((tokenize("snake_case-kebab.dot") == strs({"snake", "case", "kebab", "dot"})));
}

TEST(IndexTokenize, EveryByteValueIsClassifiedCorrectly) {
    // The expected classification is written independently of the implementation: a byte is
    // a token character iff it occurs in one of these two alphabets (and so is NOT one for
    // '@', '[', '`', '{', '/', ':', every control byte, and every byte >= 128).
    const std::string lower = "abcdefghijklmnopqrstuvwxyz";
    const std::string upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const std::string digits = "0123456789";
    for (int b = 0; b < 256; ++b) {
        const char c = static_cast<char>(b);
        std::string text = "x";
        text += c;
        text += 'y';
        Strings expected;
        const std::size_t upper_at = upper.find(c);
        if (upper_at != std::string::npos) {
            expected = {std::string("x") + lower[upper_at] + "y"};
        } else if (lower.find(c) != std::string::npos || digits.find(c) != std::string::npos) {
            expected = {text};
        } else {
            expected = {"x", "y"};
        }
        CHECK_EQ(tokenize(text) == expected, true);
    }
}

TEST(IndexTokenize, HighBytesSeparate) {
    // "café naïve" in UTF-8: every byte of the multi-byte sequences is a separator.
    CHECK((tokenize("caf" "\xC3" "\xA9" " na" "\xC3" "\xAF" "ve") == strs({"caf", "na", "ve"})));
    CHECK((tokenize("\x80" "a" "\xFF" "b" "\xFE") == strs({"a", "b"})));
    CHECK(tokenize("\xE2" "\x9C" "\x93").empty());
}

TEST(IndexTokenize, NulSeparatesAndDoesNotTruncate) {
    CHECK((tokenize(std::string_view("ab\0cd", 5)) == strs({"ab", "cd"})));
    CHECK(tokenize(std::string_view("\0\0\0", 3)).empty());
    CHECK((tokenize(std::string_view("\0a\0", 3)) == strs({"a"})));
    CHECK((tokenize(std::string_view("one\0two\0three", 13)) == strs({"one", "two", "three"})));
}

TEST(IndexTokenize, LongInputs) {
    std::string many;
    for (int i = 0; i < 100000; ++i) many += "Ab ";
    const Strings tokens = tokenize(many);
    CHECK_EQ(tokens.size(), std::size_t{100000});
    CHECK_EQ(tokens.front(), std::string("ab"));
    CHECK_EQ(tokens.back(), std::string("ab"));

    const Strings one = tokenize(std::string(1000000, 'Q'));
    CHECK_EQ(one.size(), std::size_t{1});
    CHECK(one.front() == std::string(1000000, 'q'));
}

// =========================================================================================
// intersect / unite / difference
// =========================================================================================

TEST(IndexSetOps, IntersectStructuredCases) {
    check_intersection_all_ways({}, {});
    check_intersection_all_ways({}, ids({1, 2, 3}));
    check_intersection_all_ways(ids({1, 2, 3}), ids({1, 2, 3}));
    check_intersection_all_ways(ids({1, 3, 5}), ids({2, 4, 6}));
    check_intersection_all_ways(ids({1, 2, 3, 4}), ids({2, 3}));
    check_intersection_all_ways(ids({5}), ids({1, 2, 3, 4, 5}));
    check_intersection_all_ways(ids({1}), ids({1, 2, 3, 4, 5}));
    check_intersection_all_ways(ids({0}), ids({0}));
    check_intersection_all_ways(ids({0}), ids({1}));
    check_intersection_all_ways(ids({1, 2, 3}), ids({10, 20, 30}));  // disjoint ranges
    check_intersection_all_ways(ids({10, 20, 30}), ids({1, 2, 3}));
    check_intersection_all_ways(ids({1, 5, 9}), ids({5}));
    check_intersection_all_ways(ids({1, 5}), ids({5, 9}));  // ranges that merely touch at one id
    check_intersection_all_ways(ids({5, 9}), ids({1, 5}));
    check_intersection_all_ways(ids({1, 2, 3}), ids({3}));
    check_intersection_all_ways(ids({3}), ids({3, 4, 5}));
    CHECK_IDS(intersect(ids({1, 5}), ids({5, 9})), ids({5}));
    CHECK_IDS(intersect(ids({5, 9}), ids({1, 5})), ids({5}));

    CHECK_IDS(intersect(ids({1, 2, 3, 4}), ids({2, 3, 9})), ids({2, 3}));
    CHECK_IDS(intersect(ids({}), ids({})), ids({}));
}

TEST(IndexSetOps, IntersectMatchesStdOnRandomLists) {
    Rng rng(1001);
    const std::size_t sizes[] = {0, 1, 2, 3, 5, 15, 16, 17, 40, 100, 255, 256, 700, 2000};
    for (int round = 0; round < 4; ++round) {
        // Odd rounds live at the very top of the id space.
        const DocId base = (round % 2 == 0) ? 0 : kMax - 5000;
        for (const std::size_t sa : sizes) {
            for (const std::size_t sb : sizes) {
                const std::size_t biggest = std::max(sa, sb);
                const std::uint32_t span = static_cast<std::uint32_t>(biggest + biggest / 2 + 4);
                check_intersection_all_ways(random_list(rng, sa, base, span),
                                            random_list(rng, sb, base, span));
            }
        }
    }
}

TEST(IndexSetOps, IntersectShortListInsideLongList) {
    Rng rng(1002);
    const Ids long_list = random_list(rng, 6000, 0, 9000);
    for (int round = 0; round < 60; ++round) {
        // A random subset of the long list, from 1 to 50 elements (ratio far above 16).
        std::set<DocId> picked;
        const std::size_t want = 1 + rng.below(50);
        for (std::size_t i = 0; i < want; ++i) picked.insert(long_list[rng.below(static_cast<std::uint32_t>(long_list.size()))]);
        const Ids short_list(picked.begin(), picked.end());
        CHECK(intersect_uses_galloping(short_list.size(), long_list.size()));
        CHECK_IDS(intersect(short_list, long_list), short_list);
        check_intersection_all_ways(short_list, long_list);
    }
}

TEST(IndexSetOps, GallopIsExhaustivelyCorrectOnSmallShapes) {
    // Long list = 1, 4, 7, ... so probes land on and between every element; the short list
    // is every single value and every pair of values around it. Covers the first element, the
    // last element, values past both ends, and every probe-window boundary (offsets 0,1,3,7..).
    for (std::uint32_t n = 1; n <= 20; ++n) {
        Ids long_list;
        for (std::uint32_t i = 0; i < n; ++i) long_list.push_back(3 * i + 1);
        const std::uint32_t top = 3 * n + 3;
        for (std::uint32_t x = 0; x <= top; ++x) {
            check_intersection_all_ways(ids({x}), long_list);
            for (std::uint32_t y = x + 1; y <= top; ++y) {
                check_intersection_all_ways(ids({x, y}), long_list);
            }
        }
    }
    // Single probes against longer lists, to cross several doubling steps.
    for (std::uint32_t n = 1; n <= 70; ++n) {
        Ids long_list;
        for (std::uint32_t i = 0; i < n; ++i) long_list.push_back(2 * i);
        for (std::uint32_t x = 0; x <= 2 * n + 1; ++x) check_intersection_all_ways(ids({x}), long_list);
    }
}

TEST(IndexSetOps, MillionVersusFive) {
    Ids big(1000000);
    for (std::size_t i = 0; i < big.size(); ++i) big[i] = static_cast<DocId>(i * 3);  // 0, 3, ..., 2999997

    // 0, 1234563 and 2999997 (the very last element) are present; 4 and 3000000 are not.
    const Ids tiny = ids({0, 4, 1234563, 2999997, 3000000});
    CHECK(intersect_uses_galloping(tiny.size(), big.size()));
    CHECK_IDS(intersect(tiny, big), ids({0, 1234563, 2999997}));
    CHECK_IDS(intersect(big, tiny), ids({0, 1234563, 2999997}));
    check_intersection_all_ways(tiny, big);

    const Ids all_present = ids({big[0], big[1], big[500000], big[999998], big[999999]});
    CHECK_IDS(intersect(all_present, big), all_present);
    check_intersection_all_ways(all_present, big);

    const Ids none_present = ids({1, 4, 2999998, 2999999, 4000000});
    CHECK_IDS(intersect(none_present, big), ids({}));
    check_intersection_all_ways(none_present, big);

    const Ids before_and_after = ids({2999997, 3000001});
    CHECK_IDS(intersect(before_and_after, big), ids({2999997}));

    // And against a random long list instead of an arithmetic progression.
    Rng rng(1003);
    const Ids random_big = dense_random_list(rng, 3000000, 0.4);
    CHECK(random_big.size() > 1000000);
    const Ids random_tiny = random_list(rng, 5, 0, 3000000);
    check_intersection_all_ways(random_tiny, random_big);
    Ids probes;
    for (std::size_t i : {std::size_t{0}, random_big.size() / 3, random_big.size() / 2, random_big.size() - 1}) {
        probes.push_back(random_big[i]);
    }
    check_intersection_all_ways(probes, random_big);
    CHECK_IDS(intersect(probes, random_big), probes);
}

TEST(IndexSetOps, GallopWorkIsLogarithmicAndNeverRestarts) {
    // Counts list elements examined (the probe hook) instead of timing anything: the bound is
    // exact and deterministic. A linear scan would examine ~10^6 elements in every case below.
    Ids big(1000000);
    for (std::size_t i = 0; i < big.size(); ++i) big[i] = static_cast<DocId>(i);
    std::size_t probes = 0;
    const auto count = [&probes]() { ++probes; };

    // Five scattered ids: each costs about 2 * log2(distance) <= ~40 probes.
    const Ids tiny = ids({0, 4, 123456, 999999, 1000000});
    CHECK_IDS(loganalyzer::detail::gallop_intersect(tiny, big, count), ids({0, 4, 123456, 999999}));
    CHECK(probes > 0);
    CHECK(probes < 200);

    // Twenty consecutive ids at the very end: only the first one pays the long search. If every
    // element restarted from the front of the list this would cost ~20 * 40 probes.
    probes = 0;
    Ids tail;
    for (DocId id = 999980; id < 1000000; ++id) tail.push_back(id);
    CHECK_IDS(loganalyzer::detail::gallop_intersect(tail, big, count), tail);
    CHECK(probes < 100);

    // 1000 evenly spread ids: ~2 * log2(1000) each, nowhere near a pass over the long list.
    probes = 0;
    Ids spread;
    for (DocId id = 0; id < 1000000; id += 1000) spread.push_back(id);
    CHECK_IDS(loganalyzer::detail::gallop_intersect(spread, big, count), spread);
    CHECK(probes < 30000);

    // Argument order is irrelevant: the shorter list is always the one that is walked.
    probes = 0;
    CHECK_IDS(loganalyzer::detail::gallop_intersect(big, tiny, count), ids({0, 4, 123456, 999999}));
    CHECK(probes < 200);
}

TEST(IndexSetOps, IntersectGallopsOnlyWhenOneListIsSixteenTimesShorter) {
    // The same probe counter observes which strategy intersect() really ran: galloping examines
    // ~log2(16) * 2 elements per short-list element, the merge examines every element of the
    // longer list that precedes the last match.
    std::size_t probes = 0;
    const auto count = [&probes]() { ++probes; };

    // Ratio exactly 16: 1000 ids against 16000 -> galloping (about 8 probes per id).
    Ids long16;
    for (DocId id = 0; id < 16000; ++id) long16.push_back(id);
    Ids short16;
    for (DocId id = 0; id < 16000; id += 16) short16.push_back(id);
    CHECK_EQ(short16.size(), std::size_t{1000});
    CHECK_IDS(loganalyzer::detail::adaptive_intersect(short16, long16, count), short16);
    CHECK(probes < 12000);
    probes = 0;
    CHECK_IDS(loganalyzer::detail::adaptive_intersect(long16, short16, count), short16);  // order is irrelevant
    CHECK(probes < 12000);

    // Ratio 15: 1000 ids against 15000 -> the plain merge walks (nearly) the whole long list.
    probes = 0;
    Ids long15;
    for (DocId id = 0; id < 15000; ++id) long15.push_back(id);
    Ids short15;
    for (DocId id = 0; id < 15000; id += 15) short15.push_back(id);
    CHECK_EQ(short15.size(), std::size_t{1000});
    CHECK_IDS(loganalyzer::detail::adaptive_intersect(short15, long15, count), short15);
    CHECK(probes >= 14000);

    // Empty inputs and non-overlapping id ranges are answered without examining a single element.
    probes = 0;
    CHECK_IDS(loganalyzer::detail::adaptive_intersect(Ids{}, long16, count), ids({}));
    CHECK_IDS(loganalyzer::detail::adaptive_intersect(long16, Ids{}, count), ids({}));
    CHECK_IDS(loganalyzer::detail::adaptive_intersect(long16, ids({16000, 16001}), count), ids({}));
    CHECK_IDS(loganalyzer::detail::adaptive_intersect(ids({100000}), long16, count), ids({}));
    CHECK_EQ(probes, std::size_t{0});
}

TEST(IndexSetOps, IntersectingManyListsStartsFromTheSmallest) {
    // search_and / search() intersect their lists smallest first. Starting with the two huge
    // lists would cost a ~2,000,000-step merge; starting with the 3-element list costs two
    // galloping passes of about a hundred probes. The probe count tells them apart exactly.
    Ids dense(1000000);
    Ids evens(1000000);
    for (std::size_t i = 0; i < dense.size(); ++i) {
        dense[i] = static_cast<DocId>(i);
        evens[i] = static_cast<DocId>(2 * i);
    }
    const Ids tiny = ids({7, 500000, 999999});

    std::size_t probes = 0;
    const auto count = [&probes]() { ++probes; };
    using ListPtrs = std::vector<const Ids*>;
    const ListPtrs orders[] = {{&dense, &evens, &tiny}, {&tiny, &dense, &evens}, {&evens, &tiny, &dense},
                               {&dense, &tiny, &evens}, {&evens, &dense, &tiny}, {&tiny, &evens, &dense}};
    std::size_t first_probes = 0;
    for (const ListPtrs& order : orders) {
        probes = 0;
        CHECK_IDS(loganalyzer::detail::intersect_smallest_first(order, count), ids({500000}));
        CHECK(probes > 0);
        CHECK(probes < 1000);
        if (first_probes == 0) first_probes = probes;
        CHECK_EQ(probes, first_probes);  // the argument order cannot change the work done
    }

    // The same list named twice is intersected once; a single list comes back as a copy.
    probes = 0;
    CHECK_IDS(loganalyzer::detail::intersect_smallest_first(ListPtrs{&dense, &tiny, &dense}, count),
              ids({7, 500000, 999999}));
    CHECK(probes < 1000);
    CHECK_IDS(loganalyzer::detail::intersect_smallest_first(ListPtrs{&tiny}, count), tiny);
    CHECK_IDS(loganalyzer::detail::intersect_smallest_first(ListPtrs{}, count), ids({}));
    // ... so two references to the same million-element list cost no comparisons at all.
    probes = 0;
    CHECK_IDS(loganalyzer::detail::intersect_smallest_first(ListPtrs{&dense, &dense}, count), dense);
    CHECK_EQ(probes, std::size_t{0});
}

TEST(IndexSetOps, DispatchRuleIsAtLeastSixteenTimesShorter) {
    CHECK(intersect_uses_galloping(1, 16));
    CHECK(!intersect_uses_galloping(1, 15));
    CHECK(intersect_uses_galloping(16, 1));
    CHECK(!intersect_uses_galloping(15, 1));
    CHECK(intersect_uses_galloping(2, 32));
    CHECK(!intersect_uses_galloping(2, 31));
    CHECK(intersect_uses_galloping(5, 80));
    CHECK(!intersect_uses_galloping(5, 79));
    CHECK(intersect_uses_galloping(1000, 16000));
    CHECK(!intersect_uses_galloping(1000, 15999));
    CHECK(!intersect_uses_galloping(1, 1));
    CHECK(!intersect_uses_galloping(100, 100));
    CHECK(!intersect_uses_galloping(7, 100));
    // No overflow on absurd sizes.
    const std::size_t huge = std::numeric_limits<std::size_t>::max();
    CHECK(intersect_uses_galloping(1, huge));
    CHECK(!intersect_uses_galloping(huge, huge));
    CHECK(!intersect_uses_galloping(huge / 2, huge));
}

TEST(IndexSetOps, IdsNearUint32Max) {
    const Ids a = ids({0, 1, kMax - 3, kMax - 2, kMax - 1, kMax});
    const Ids b = ids({1, kMax - 2, kMax});
    check_intersection_all_ways(a, b);
    CHECK_IDS(intersect(a, b), ids({1, kMax - 2, kMax}));
    CHECK_IDS(difference(a, b), ids({0, kMax - 3, kMax - 1}));
    CHECK_IDS(difference(b, a), ids({}));
    CHECK_IDS(unite({a, b}), a);

    // Gallop path (ratio >= 16) with the top of the id space at the end of the long list.
    Ids top;
    for (DocId id = kMax - 99; id != kMax; ++id) top.push_back(id);
    top.push_back(kMax);
    CHECK_EQ(top.size(), std::size_t{100});
    CHECK(intersect_uses_galloping(1, top.size()));
    check_intersection_all_ways(ids({kMax}), top);
    check_intersection_all_ways(ids({kMax - 99}), top);
    check_intersection_all_ways(ids({kMax - 200, kMax - 50, kMax}), top);
    CHECK_IDS(intersect(ids({kMax - 200, kMax - 50, kMax}), top), ids({kMax - 50, kMax}));
    CHECK_IDS(intersect(ids({0, kMax}), top), ids({kMax}));
    CHECK_IDS(intersect(ids({0}), top), ids({}));

    // Unite must not wrap around or confuse kMax with a sentinel.
    CHECK_IDS(unite({ids({kMax}), ids({kMax}), ids({0})}), ids({0, kMax}));
    CHECK_IDS(unite({ids({kMax - 1, kMax}), ids({kMax}), ids({})}), ids({kMax - 1, kMax}));
    CHECK_IDS(difference(ids({kMax}), ids({0})), ids({kMax}));
    CHECK_IDS(difference(ids({0, kMax}), ids({kMax})), ids({0}));
}

TEST(IndexSetOps, UniteStructuredCases) {
    const std::vector<Ids> none;
    CHECK_IDS(unite(none), ids({}));
    CHECK_IDS(unite({ids({})}), ids({}));
    CHECK_IDS(unite({ids({}), ids({}), ids({})}), ids({}));
    CHECK_IDS(unite({ids({1, 2, 3})}), ids({1, 2, 3}));
    CHECK_IDS(unite({ids({1, 3, 5}), ids({2, 4, 6})}), ids({1, 2, 3, 4, 5, 6}));
    CHECK_IDS(unite({ids({1, 2, 3}), ids({1, 2, 3})}), ids({1, 2, 3}));
    CHECK_IDS(unite({ids({1, 2}), ids({}), ids({2, 3}), ids({})}), ids({1, 2, 3}));
    CHECK_IDS(unite({ids({5}), ids({5}), ids({5})}), ids({5}));
    CHECK_IDS(unite({ids({1, 2, 3, 4, 5}), ids({3})}), ids({1, 2, 3, 4, 5}));
    CHECK_IDS(unite({ids({10}), ids({1}), ids({5})}), ids({1, 5, 10}));
    CHECK_IDS(unite({ids({0, 1000000}), ids({500000})}), ids({0, 500000, 1000000}));
    CHECK_IDS(unite({ids({0}), ids({0}), ids({1}), ids({1})}), ids({0, 1}));
}

TEST(IndexSetOps, UniteMatchesStdSetOnRandomLists) {
    Rng rng(2001);
    const std::size_t sizes[] = {0, 1, 3, 10, 50, 200};
    for (int round = 0; round < 400; ++round) {
        const DocId base = (round % 2 == 0) ? 0 : kMax - 1000;
        const std::uint32_t k = rng.below(13);  // includes zero lists
        std::vector<Ids> lists;
        for (std::uint32_t i = 0; i < k; ++i) {
            lists.push_back(random_list(rng, sizes[rng.below(6)], base, 400));
        }
        CHECK_IDS_CTX(unite(lists), ref_union(lists), "round " + std::to_string(round));
    }
}

TEST(IndexSetOps, UniteManyListsAndLongRuns) {
    Rng rng(2002);
    // Thousands of tiny lists: a deep heap with lots of duplicates.
    std::vector<Ids> many;
    for (int i = 0; i < 3000; ++i) many.push_back(random_list(rng, rng.below(6), 0, 2000));
    CHECK_IDS(unite(many), ref_union(many));

    // One huge list among tiny ones: the "leader" fast path inside the merge.
    std::vector<Ids> skewed;
    Ids huge;
    for (DocId i = 0; i < 20000; ++i) huge.push_back(i * 2);
    skewed.push_back(huge);
    skewed.push_back(ids({1, 2, 39999}));
    skewed.push_back(ids({5000, 5001, 100000}));
    skewed.push_back(ids({}));
    skewed.push_back(ids({0}));
    CHECK_IDS(unite(skewed), ref_union(skewed));

    // Non-overlapping consecutive blocks: each list is a run of the output.
    std::vector<Ids> blocks;
    for (DocId b = 0; b < 50; ++b) {
        Ids block;
        for (DocId i = 0; i < 100; ++i) block.push_back(b * 100 + i);
        blocks.push_back(block);
    }
    std::reverse(blocks.begin(), blocks.end());
    CHECK_IDS(unite(blocks), ref_union(blocks));
}

TEST(IndexSetOps, UniteDoesNotModifyItsInputs) {
    const std::vector<Ids> lists = {ids({1, 4, 9}), ids({2, 4}), ids({})};
    const std::vector<Ids> copy = lists;
    CHECK_IDS(unite(lists), ids({1, 2, 4, 9}));
    CHECK(lists == copy);
}

TEST(IndexSetOps, DifferenceStructuredCases) {
    CHECK_IDS(difference(ids({}), ids({})), ids({}));
    CHECK_IDS(difference(ids({}), ids({1, 2})), ids({}));
    CHECK_IDS(difference(ids({1, 2, 3}), ids({})), ids({1, 2, 3}));
    CHECK_IDS(difference(ids({1, 2, 3}), ids({1, 2, 3})), ids({}));
    CHECK_IDS(difference(ids({1, 2, 3}), ids({4, 5})), ids({1, 2, 3}));
    CHECK_IDS(difference(ids({4, 5}), ids({1, 2, 3})), ids({4, 5}));
    CHECK_IDS(difference(ids({1, 2, 3, 4, 5}), ids({2, 4})), ids({1, 3, 5}));
    CHECK_IDS(difference(ids({1, 2, 3}), ids({0, 1, 2, 3, 4})), ids({}));
    CHECK_IDS(difference(ids({1, 3, 5}), ids({2, 4, 6})), ids({1, 3, 5}));
    CHECK_IDS(difference(ids({1, 3, 5, 7, 9}), ids({9})), ids({1, 3, 5, 7}));
    CHECK_IDS(difference(ids({1, 3, 5, 7, 9}), ids({1})), ids({3, 5, 7, 9}));
}

TEST(IndexSetOps, DifferenceMatchesStdOnRandomLists) {
    Rng rng(3001);
    const std::size_t sizes[] = {0, 1, 2, 5, 16, 50, 300, 1000};
    for (int round = 0; round < 6; ++round) {
        const DocId base = (round % 2 == 0) ? 0 : kMax - 3000;
        for (const std::size_t sa : sizes) {
            for (const std::size_t sb : sizes) {
                const std::size_t biggest = std::max(sa, sb);
                const std::uint32_t span = static_cast<std::uint32_t>(biggest + biggest / 2 + 4);
                const Ids a = random_list(rng, sa, base, span);
                const Ids b = random_list(rng, sb, base, span);
                CHECK_IDS_CTX(difference(a, b), ref_difference(a, b), "a=" + preview(a) + " b=" + preview(b));
            }
        }
    }
}

TEST(IndexSetOps, IdentitiesBetweenTheThreeOperations) {
    Rng rng(4001);
    for (int round = 0; round < 100; ++round) {
        const Ids a = random_list(rng, rng.below(200), 0, 300);
        const Ids b = random_list(rng, rng.below(200), 0, 300);
        // a = (a n b) u (a \ b), and (a \ b) is disjoint from b.
        CHECK_IDS(unite({intersect(a, b), difference(a, b)}), a);
        CHECK_IDS(intersect(difference(a, b), b), ids({}));
        // |a u b| = |a| + |b| - |a n b|
        CHECK_EQ(unite({a, b}).size() + intersect(a, b).size(), a.size() + b.size());
    }
}

// =========================================================================================
// InvertedIndex: construction, add, postings
// =========================================================================================

TEST(InvertedIndex, StartsEmpty) {
    const InvertedIndex index;
    CHECK_EQ(index.doc_count(), std::size_t{0});
    CHECK_EQ(index.term_count(), std::size_t{0});
    CHECK(index.postings("anything").empty());
    CHECK(index.search_and({"a"}).empty());
    CHECK(index.search_or({"a"}).empty());
    CHECK(index.search("a").empty());
    CHECK(index.search("-a").empty());  // empty universe
    CHECK(index.search("").empty());
}

TEST(InvertedIndex, AddAssignsSequentialIdsAndCounts) {
    InvertedIndex index;
    CHECK_EQ(index.add("alpha beta"), DocId{0});
    CHECK_EQ(index.add("beta gamma"), DocId{1});
    CHECK_EQ(index.add(""), DocId{2});
    CHECK_EQ(index.add("alpha"), DocId{3});
    CHECK_EQ(index.doc_count(), std::size_t{4});
    CHECK_EQ(index.term_count(), std::size_t{3});
    CHECK_IDS(index.postings("alpha"), ids({0, 3}));
    CHECK_IDS(index.postings("beta"), ids({0, 1}));
    CHECK_IDS(index.postings("gamma"), ids({1}));
}

TEST(InvertedIndex, RepeatedTokenInsideADocumentCountsOnce) {
    InvertedIndex index;
    index.add("error error ERROR timeout error");
    CHECK_IDS(index.postings("error"), ids({0}));
    CHECK_IDS(index.postings("timeout"), ids({0}));
    index.add("error");
    CHECK_IDS(index.postings("error"), ids({0, 1}));
    index.add("a a a b a b x-x_x.x");
    CHECK_IDS(index.postings("a"), ids({2}));
    CHECK_IDS(index.postings("b"), ids({2}));
    CHECK_IDS(index.postings("x"), ids({2}));
    CHECK_EQ(index.term_count(), std::size_t{5});
    CHECK_EQ(index.doc_count(), std::size_t{3});
}

TEST(InvertedIndex, EmptyAndTokenlessDocumentsGetIds) {
    InvertedIndex index;
    CHECK_EQ(index.add(""), DocId{0});
    CHECK_EQ(index.add("--- !!"), DocId{1});
    CHECK_EQ(index.add("   "), DocId{2});
    CHECK_EQ(index.add("\xFF" "\xFE"), DocId{3});
    CHECK_EQ(index.add(std::string_view("\0\0", 2)), DocId{4});
    CHECK_EQ(index.doc_count(), std::size_t{5});
    CHECK_EQ(index.term_count(), std::size_t{0});
    CHECK_EQ(index.add("real"), DocId{5});
    CHECK_IDS(index.postings("real"), ids({5}));
    // The universe includes the empty documents.
    CHECK_IDS(index.search("-real"), ids({0, 1, 2, 3, 4}));
    CHECK_IDS(index.search("-nothing"), ids({0, 1, 2, 3, 4, 5}));
    CHECK_IDS(index.search("real"), ids({5}));
    CHECK(index.search_and({"real", "nothing"}).empty());
}

TEST(InvertedIndex, LookupsAreCaseInsensitive) {
    InvertedIndex index;
    index.add("Timeout ERROR");
    index.add("timeout error");
    index.add("TIMEOUT");
    CHECK_EQ(index.term_count(), std::size_t{2});
    CHECK_IDS(index.postings("TimeOut"), ids({0, 1, 2}));
    CHECK(&index.postings("TimeOut") == &index.postings("timeout"));
    CHECK_IDS(index.postings("ERROR"), ids({0, 1}));
    CHECK_IDS(index.search_and({"TIMEOUT", "Error"}), ids({0, 1}));
    CHECK_IDS(index.search_or({"eRrOr"}), ids({0, 1}));
    CHECK_IDS(index.search("TIMEOUT -ERROR"), ids({2}));
    CHECK_IDS(index.search("tImEoUt|nothing"), ids({0, 1, 2}));
}

TEST(InvertedIndex, PostingsTokenizesTheTerm) {
    InvertedIndex index;
    index.add("payment service up");
    index.add("payment down");
    CHECK_IDS(index.postings("payment"), ids({0, 1}));
    CHECK_IDS(index.postings("  Payment!! "), ids({0, 1}));  // exactly one token
    CHECK_IDS(index.postings("payment-service"), ids({}));   // several tokens: empty by contract
    CHECK_IDS(index.postings("payment service"), ids({}));
    CHECK_IDS(index.postings(""), ids({}));
    CHECK_IDS(index.postings("---"), ids({}));
    CHECK_IDS(index.postings("pay"), ids({}));  // whole tokens only, never prefixes
    CHECK_IDS(index.postings("payments"), ids({}));
}

TEST(InvertedIndex, UnknownTermReferenceStaysValid) {
    InvertedIndex index;
    const Ids& none = index.postings("nope");
    CHECK(none.empty());
    CHECK(&none == &index.postings("zzz"));  // one shared empty list
    {
        InvertedIndex other;
        other.add("something");
        CHECK(&other.postings("elsewhere") == &none);  // shared across instances too
    }

    // Many adds rehash the hash table and reallocate list storage; the reference must survive.
    for (int i = 0; i < 5000; ++i) index.add("alpha t" + std::to_string(i));
    CHECK(none.empty());
    CHECK(&none == &index.postings("nope"));

    // Even once "nope" becomes a real term, the old reference keeps denoting the empty list.
    index.add("nope");
    CHECK(none.empty());
    CHECK_EQ(index.postings("nope").size(), std::size_t{1});
    CHECK(&index.postings("nope") != &none);

    // Multi-token and token-less terms answer with that same shared list.
    CHECK(&index.postings("alpha-t1") == &none);
    CHECK(&index.postings("") == &none);
    CHECK(&index.postings("***") == &none);

    // The empty list outlives every index.
    const Ids* escaped_reference = nullptr;
    {
        InvertedIndex temporary;
        escaped_reference = &temporary.postings("gone");
    }
    CHECK(escaped_reference->empty());
    CHECK(escaped_reference == &none);
}

TEST(InvertedIndex, ReferenceToARealListSurvivesGrowth) {
    InvertedIndex index;
    index.add("alpha");
    const Ids& alpha = index.postings("alpha");
    CHECK_EQ(alpha.size(), std::size_t{1});
    for (int i = 0; i < 20000; ++i) index.add("alpha filler" + std::to_string(i));  // forces rehashing
    CHECK(&alpha == &index.postings("alpha"));
    CHECK_EQ(alpha.size(), std::size_t{20001});
    CHECK_EQ(alpha.front(), DocId{0});
    CHECK_EQ(alpha.back(), DocId{20000});
}

TEST(InvertedIndex, PostingsAreAscendingAndDuplicateFreeOnLargeInput) {
    Rng rng(5001);
    InvertedIndex index;
    const std::uint32_t vocabulary = 60;
    std::vector<Ids> expected(vocabulary);
    for (DocId doc = 0; doc < 20000; ++doc) {
        std::string text = "common";
        std::set<std::uint32_t> present;
        const std::uint32_t n = rng.below(6);
        for (std::uint32_t i = 0; i < n; ++i) {
            const std::uint32_t w = rng.below(vocabulary);
            text += (i % 2 == 0 ? " w" : "-W") + std::to_string(w);  // mixed separators and case
            present.insert(w);
            if (rng.chance(0.3)) text += " w" + std::to_string(w);  // in-document repeat
        }
        CHECK_EQ(index.add(text), doc);
        for (const std::uint32_t w : present) expected[w].push_back(doc);
    }
    CHECK_EQ(index.doc_count(), std::size_t{20000});
    CHECK_EQ(index.postings("common").size(), std::size_t{20000});
    for (std::uint32_t w = 0; w < vocabulary; ++w) {
        const Ids& list = index.postings("w" + std::to_string(w));
        CHECK_IDS_CTX(list, expected[w], "w" + std::to_string(w));
        CHECK(std::adjacent_find(list.begin(), list.end(), [](DocId x, DocId y) { return x >= y; }) == list.end());
    }
    CHECK_EQ(index.term_count(), std::size_t{1} + [&] {
        std::size_t used = 0;
        for (const Ids& list : expected) {
            if (!list.empty()) ++used;
        }
        return used;
    }());
}

TEST(InvertedIndex, AddThrowsLengthErrorWhenIdSpaceIsExhausted) {
    CHECK(InvertedIndex::kMaxDocuments == std::uint64_t{4294967296ULL});

    InvertedIndex index(3);
    index.add("one");
    index.add("two");
    index.add("three one");
    CHECK_EQ(index.doc_count(), std::size_t{3});
    const std::size_t terms_before = index.term_count();

    CHECK_THROWS(index.add("four brandnew"), std::length_error);
    CHECK_THROWS(index.add(""), std::length_error);
    // A rejected add changes nothing: no id consumed, no token indexed.
    CHECK_EQ(index.doc_count(), std::size_t{3});
    CHECK_EQ(index.term_count(), terms_before);
    CHECK(index.postings("brandnew").empty());
    CHECK_IDS(index.postings("one"), ids({0, 2}));
    CHECK_IDS(index.search("-one"), ids({1}));

    InvertedIndex none_allowed(0);
    CHECK_THROWS(none_allowed.add("x"), std::length_error);
    CHECK_EQ(none_allowed.doc_count(), std::size_t{0});

    // A capacity above the DocId space is clamped, not honored; adding still works normally.
    InvertedIndex clamped(std::numeric_limits<std::uint64_t>::max());
    CHECK_EQ(clamped.add("fine"), DocId{0});
}

TEST(InvertedIndex, CopiesAreIndependent) {
    InvertedIndex index;
    index.add("alpha beta");
    index.add("beta");
    InvertedIndex copy = index;
    CHECK_EQ(copy.add("alpha gamma"), DocId{2});
    CHECK_EQ(index.doc_count(), std::size_t{2});
    CHECK_EQ(copy.doc_count(), std::size_t{3});
    CHECK_IDS(index.postings("alpha"), ids({0}));
    CHECK_IDS(copy.postings("alpha"), ids({0, 2}));
    CHECK(index.postings("gamma").empty());
    CHECK_IDS(copy.search("beta|gamma"), ids({0, 1, 2}));

    InvertedIndex moved = std::move(copy);
    CHECK_IDS(moved.postings("gamma"), ids({2}));
}

// =========================================================================================
// search_and / search_or
// =========================================================================================

namespace {

// Small fixed corpus with hand-computed answers.
//   0 timeout calling bank gateway after 3000ms
//   1 connection refused by upstream 10 0 0 1 443
//   2 payment service timeout 3000ms retry exhausted
//   3 user login ok
//   4 timeout while reading from cache connection reset
//   5 (no tokens)
//   6 disk usage at 91
InvertedIndex make_corpus() {
    InvertedIndex index;
    index.add("Timeout calling bank gateway after 3000ms");
    index.add("Connection refused by upstream 10.0.0.1:443");
    index.add("payment-service timeout=3000ms retry exhausted");
    index.add("User login ok");
    index.add("Timeout while reading from cache; connection reset");
    index.add("");
    index.add("Disk usage at 91%");
    return index;
}

}  // namespace

TEST(IndexSearch, AndIntersectsAllTerms) {
    const InvertedIndex index = make_corpus();
    CHECK_IDS(index.search_and({"timeout"}), ids({0, 2, 4}));
    CHECK_IDS(index.search_and({"timeout", "3000ms"}), ids({0, 2}));
    CHECK_IDS(index.search_and({"timeout", "connection"}), ids({4}));
    CHECK_IDS(index.search_and({"timeout", "connection", "cache"}), ids({4}));
    CHECK_IDS(index.search_and({"timeout", "refused"}), ids({}));
    CHECK_IDS(index.search_and({"10", "0", "443"}), ids({1}));
}

TEST(IndexSearch, AndEdgeCases) {
    const InvertedIndex index = make_corpus();
    CHECK_IDS(index.search_and({}), ids({}));                          // no terms
    CHECK_IDS(index.search_and({"nosuchterm"}), ids({}));              // unknown term
    CHECK_IDS(index.search_and({"timeout", "nosuchterm"}), ids({}));   // unknown among known
    CHECK_IDS(index.search_and({""}), ids({}));                        // zero tokens matches nothing
    CHECK_IDS(index.search_and({"timeout", "---"}), ids({}));
    CHECK_IDS(index.search_and({"timeout", "timeout"}), ids({0, 2, 4}));
    CHECK_IDS(index.search_and({"TIMEOUT", "timeout", "Timeout"}), ids({0, 2, 4}));
    CHECK_IDS(index.search_and({"3000"}), ids({}));                    // not a prefix match
    CHECK_IDS(index.search_and({"time"}), ids({}));
}

TEST(IndexSearch, AndMultiTokenTermMeansAllTokens) {
    const InvertedIndex index = make_corpus();
    CHECK_IDS(index.search_and({"payment-service"}), ids({2}));
    CHECK_IDS(index.search_and({"Service:Payment"}), ids({2}));  // order and separators are irrelevant
    CHECK_IDS(index.search_and({"payment-service", "timeout"}), ids({2}));
    CHECK_IDS(index.search_and({"payment-timeout"}), ids({2}));
    CHECK_IDS(index.search_and({"payment-login"}), ids({}));
    CHECK_IDS(index.search_and({"timeout-connection"}), ids({4}));
    CHECK_IDS(index.search_and({"10.0.0.1"}), ids({1}));
}

TEST(IndexSearch, AndIsIndependentOfTermOrder) {
    const InvertedIndex index = make_corpus();
    Strings terms = {"timeout", "connection", "cache", "reset"};
    std::sort(terms.begin(), terms.end());
    do {
        CHECK_IDS(index.search_and(terms), ids({4}));
    } while (std::next_permutation(terms.begin(), terms.end()));
}

TEST(IndexSearch, OrUnitesAllTerms) {
    const InvertedIndex index = make_corpus();
    CHECK_IDS(index.search_or({"timeout"}), ids({0, 2, 4}));
    CHECK_IDS(index.search_or({"timeout", "refused"}), ids({0, 1, 2, 4}));
    CHECK_IDS(index.search_or({"login", "disk", "cache"}), ids({3, 4, 6}));
    CHECK_IDS(index.search_or({"timeout", "timeout", "TIMEOUT"}), ids({0, 2, 4}));
    CHECK_IDS(index.search_or({"timeout", "3000ms", "payment"}), ids({0, 2, 4}));
}

TEST(IndexSearch, OrEdgeCases) {
    const InvertedIndex index = make_corpus();
    CHECK_IDS(index.search_or({}), ids({}));
    CHECK_IDS(index.search_or({"nosuchterm"}), ids({}));
    CHECK_IDS(index.search_or({"timeout", "nosuchterm"}), ids({0, 2, 4}));  // unknown ignored
    CHECK_IDS(index.search_or({""}), ids({}));
    CHECK_IDS(index.search_or({"", "---", "!!"}), ids({}));
    CHECK_IDS(index.search_or({"", "login", "---"}), ids({3}));             // zero-token terms ignored
}

TEST(IndexSearch, OrMultiTokenTermMeansAllTokens) {
    const InvertedIndex index = make_corpus();
    // "payment-service" matches only documents with both tokens, not either one.
    CHECK_IDS(index.search_or({"payment-service"}), ids({2}));
    CHECK_IDS(index.search_or({"payment-login"}), ids({}));
    CHECK_IDS(index.search_or({"payment-service", "login"}), ids({2, 3}));
    CHECK_IDS(index.search_or({"timeout-cache", "disk-usage"}), ids({4, 6}));
    CHECK_IDS(index.search_or({"timeout-refused", "ok"}), ids({3}));
}

TEST(IndexSearch, AndOrResultsAreIndependentOfStorageOrder) {
    // Documents containing the same tokens in a different order or case give the same hits.
    InvertedIndex index;
    index.add("a b c");
    index.add("C B A");
    index.add("b");
    CHECK_IDS(index.search_and({"a", "b", "c"}), ids({0, 1}));
    CHECK_IDS(index.search_or({"a", "c"}), ids({0, 1}));
    CHECK_IDS(index.search_or({"a", "b"}), ids({0, 1, 2}));
}

// =========================================================================================
// search(query)
// =========================================================================================

TEST(IndexSearch, QueryWordsAreAnded) {
    const InvertedIndex index = make_corpus();
    CHECK_IDS(index.search("timeout"), ids({0, 2, 4}));
    CHECK_IDS(index.search("TIMEOUT"), ids({0, 2, 4}));
    CHECK_IDS(index.search("timeout connection"), ids({4}));
    CHECK_IDS(index.search("timeout 3000ms"), ids({0, 2}));
    CHECK_IDS(index.search("  timeout \t 3000ms\n"), ids({0, 2}));
    CHECK_IDS(index.search("10 0 443"), ids({1}));
    CHECK_IDS(index.search("timeout refused"), ids({}));
}

TEST(IndexSearch, QueryAlternatives) {
    const InvertedIndex index = make_corpus();
    CHECK_IDS(index.search("timeout|refused"), ids({0, 1, 2, 4}));
    CHECK_IDS(index.search("login|disk|cache"), ids({3, 4, 6}));
    CHECK_IDS(index.search("timeout|nosuchterm"), ids({0, 2, 4}));
    CHECK_IDS(index.search("timeout|refused connection"), ids({1, 4}));
    CHECK_IDS(index.search("timeout|refused connection|login"), ids({1, 4}));
    CHECK_IDS(index.search("payment-service"), ids({2}));
    CHECK_IDS(index.search("payment-service|login"), ids({2, 3}));
    CHECK_IDS(index.search("payment-login|disk"), ids({6}));  // each alternative is a conjunction
    CHECK_IDS(index.search("Timeout|REFUSED"), ids({0, 1, 2, 4}));
}

TEST(IndexSearch, QueryNegation) {
    const InvertedIndex index = make_corpus();
    CHECK_IDS(index.search("timeout -connection"), ids({0, 2}));
    CHECK_IDS(index.search("connection -timeout"), ids({1}));
    CHECK_IDS(index.search("timeout -payment-service"), ids({0, 4}));  // negated multi-token alternative
    CHECK_IDS(index.search("timeout -payment"), ids({0, 4}));
    CHECK_IDS(index.search("timeout|connection -refused"), ids({0, 2, 4}));
    CHECK_IDS(index.search("timeout -refused|3000ms"), ids({4}));      // none of the alternatives
    CHECK_IDS(index.search("timeout -nosuchterm"), ids({0, 2, 4}));
    CHECK_IDS(index.search("timeout -timeout"), ids({}));
    CHECK_IDS(index.search("timeout -connection -payment"), ids({0}));
    CHECK_IDS(index.search("-connection timeout"), ids({0, 2}));       // word order is irrelevant
}

TEST(IndexSearch, NegatedOnlyQueryReturnsEveryNonMatchingDocument) {
    const InvertedIndex index = make_corpus();
    CHECK_IDS(index.search("-timeout"), ids({1, 3, 5, 6}));  // includes the empty document 5
    CHECK_IDS(index.search("-timeout -connection"), ids({3, 5, 6}));
    CHECK_IDS(index.search("-timeout|refused"), ids({3, 5, 6}));
    CHECK_IDS(index.search("-nosuchterm"), ids({0, 1, 2, 3, 4, 5, 6}));
    CHECK_IDS(index.search("-timeout -nosuchterm"), ids({1, 3, 5, 6}));
    CHECK_IDS(index.search("-payment-service"), ids({0, 1, 3, 4, 5, 6}));
    CHECK_IDS(index.search("-payment"), ids({0, 1, 3, 4, 5, 6}));
    CHECK_IDS(index.search("-timeout -connection -login -disk"), ids({5}));
    CHECK_IDS(index.search("-timeout -connection -login -disk -payment"), ids({5}));
    CHECK_IDS(index.search("-3000ms -usage -ok -cache -refused"), ids({5}));
    CHECK_IDS(index.search("-timeout|connection|login|disk -refused"), ids({5}));
    CHECK_IDS(index.search("-the -a"), ids({0, 1, 2, 3, 4, 5, 6}));
}

TEST(IndexSearch, UnknownWordsAreNotIgnored) {
    const InvertedIndex index = make_corpus();
    CHECK_IDS(index.search("nosuchterm"), ids({}));
    CHECK_IDS(index.search("timeout nosuchterm"), ids({}));
    CHECK_IDS(index.search("time"), ids({}));       // no prefix matching
    CHECK_IDS(index.search("3000"), ids({}));       // tokens are whole alphanumeric runs
    CHECK_IDS(index.search("timeout nosuchterm|refused"), ids({}));
    CHECK_IDS(index.search("timeout|nosuchterm|refused"), ids({0, 1, 2, 4}));
}

TEST(IndexSearch, OddQueriesNeverThrowAndAreIgnoredAsDocumented) {
    InvertedIndex index;
    index.add("a");      // 0
    index.add("b");      // 1
    index.add("c");      // 2
    index.add("a b");    // 3
    index.add("");       // 4

    // Nothing usable: empty, never "everything".
    for (const char* query : {"", " ", "   \t\n ", "|", "||", "|||||", "-", "--", "---", "- -", "-|", "|-", "-|-",
                              "- | -", "::", "!!", "_", "-::", "|::|", "\xFF", "-\xFF"}) {
        CHECK_IDS_CTX(index.search(query), ids({}), std::string("query ") + escaped(query));
    }

    CHECK_IDS(index.search("a||b"), ids({0, 1, 3}));  // empty alternative ignored
    CHECK_IDS(index.search("|a|"), ids({0, 3}));
    CHECK_IDS(index.search("a|"), ids({0, 3}));
    CHECK_IDS(index.search("|a"), ids({0, 3}));
    CHECK_IDS(index.search("a|||||b"), ids({0, 1, 3}));
    CHECK_IDS(index.search("a | b"), ids({3}));       // whitespace splits words: "a", "|", "b" => a AND b
    CHECK_IDS(index.search("a - b"), ids({3}));       // the lone "-" is an unusable word
    CHECK_IDS(index.search("a -"), ids({0, 3}));
    CHECK_IDS(index.search("- a"), ids({0, 3}));
    CHECK_IDS(index.search("a |"), ids({0, 3}));
    CHECK_IDS(index.search("--a"), ids({1, 2, 4}));   // only the first '-' negates; the rest is a separator
    CHECK_IDS(index.search("---a"), ids({1, 2, 4}));
    CHECK_IDS(index.search("--a --b"), ids({2, 4}));
    CHECK_IDS(index.search("-a|-b"), ids({2, 4}));    // '-' inside an alternative is a separator
    CHECK_IDS(index.search("a|-b"), ids({0, 1, 3}));  // not negated: starts with 'a'
    CHECK_IDS(index.search("|-b"), ids({1, 3}));      // starts with '|', so not negated: alternative "-b" == b
    CHECK_IDS(index.search("-|a"), ids({1, 2, 4}));   // negated, body "|a"
    CHECK_IDS(index.search("-a|"), ids({1, 2, 4}));
    CHECK_IDS(index.search("-- a"), ids({0, 3}));     // "--" is unusable
    CHECK_IDS(index.search("a -- -"), ids({0, 3}));
    CHECK_IDS(index.search("-a -"), ids({1, 2, 4}));
    CHECK_IDS(index.search("-|"), ids({}));
    CHECK_IDS(index.search("a\tb"), ids({3}));
    CHECK_IDS(index.search("a\nb"), ids({3}));
    CHECK_IDS(index.search("a\rb\vb\fa"), ids({3}));
    CHECK_IDS(index.search("a  \t\n  b"), ids({3}));
    CHECK_IDS(index.search("A|B -c"), ids({0, 1, 3}));
    CHECK_IDS(index.search("-a-b"), ids({0, 1, 2, 4}));  // negated alternative "a-b" = a AND b: only doc 3 has both
}

TEST(IndexSearch, EmbeddedNulAndHighBytesInQueries) {
    InvertedIndex index;
    index.add("a b");   // 0
    index.add("a");     // 1
    index.add("b");     // 2
    index.add("caf");   // 3
    // NUL is a token separator, not a word terminator and not whitespace: "a\0b" is one word
    // whose single alternative has two tokens.
    CHECK_IDS(index.search(std::string_view("a\0b", 3)), ids({0}));
    CHECK_IDS(index.search(std::string_view("\0a\0", 3)), ids({0, 1}));
    CHECK_IDS(index.search(std::string_view("a \0 b", 5)), ids({0}));  // the lone NUL word is unusable
    CHECK_IDS(index.search(std::string_view("-a\0b", 4)), ids({1, 2, 3}));
    CHECK_IDS(index.search(std::string_view("\0", 1)), ids({}));
    CHECK_IDS(index.search("caf" "\xC3" "\xA9"), ids({3}));  // "café" is the token "caf" plus a separator
    CHECK_IDS(index.search("\xC3" "\xA9" "caf"), ids({3}));
    CHECK_IDS(index.search("caf|\xFF"), ids({3}));
}

TEST(IndexSearch, VeryLongQueries) {
    const InvertedIndex index = make_corpus();

    std::string repeated;
    for (int i = 0; i < 50000; ++i) repeated += "timeout ";
    CHECK_IDS(index.search(repeated), ids({0, 2, 4}));

    std::string repeated_negation = "connection ";
    for (int i = 0; i < 50000; ++i) repeated_negation += "-refused ";
    CHECK_IDS(index.search(repeated_negation), ids({4}));

    std::string same_alternative = "timeout";
    for (int i = 0; i < 100000; ++i) same_alternative += "|timeout";
    CHECK_IDS(index.search(same_alternative), ids({0, 2, 4}));

    std::string distinct_unknown;
    for (int i = 0; i < 20000; ++i) distinct_unknown += "u" + std::to_string(i) + "|";
    CHECK_IDS(index.search(distinct_unknown + "login"), ids({3}));
    CHECK_IDS(index.search(distinct_unknown), ids({}));          // usable word, matches nothing
    CHECK_IDS(index.search("-" + distinct_unknown), ids({0, 1, 2, 3, 4, 5, 6}));

    std::string many_unknown_words;
    for (int i = 0; i < 20000; ++i) many_unknown_words += "w" + std::to_string(i) + " ";
    CHECK_IDS(index.search(many_unknown_words), ids({}));
    CHECK_IDS(index.search("timeout " + many_unknown_words), ids({}));

    CHECK_IDS(index.search(std::string(1000000, '|')), ids({}));
    CHECK_IDS(index.search(std::string(1000000, '-')), ids({}));
    CHECK_IDS(index.search(std::string(1000000, ' ')), ids({}));
    std::string lone_dashes;
    for (int i = 0; i < 100000; ++i) lone_dashes += "- ";
    CHECK_IDS(index.search(lone_dashes), ids({}));
    CHECK_IDS(index.search(lone_dashes + "login"), ids({3}));

    Strings many_terms(50000, "timeout");
    CHECK_IDS(index.search_and(many_terms), ids({0, 2, 4}));
    CHECK_IDS(index.search_or(many_terms), ids({0, 2, 4}));
    many_terms.push_back("nosuchterm");
    CHECK_IDS(index.search_and(many_terms), ids({}));
    CHECK_IDS(index.search_or(many_terms), ids({0, 2, 4}));
}

TEST(IndexSearch, UnitedAlternativesDoNotDuplicateDocuments) {
    // "a|b|c" over documents containing several of them: each id exactly once, ascending.
    InvertedIndex index;
    index.add("a b c");
    index.add("a b");
    index.add("c");
    index.add("b c");
    index.add("z");
    CHECK_IDS(index.search("a|b|c"), ids({0, 1, 2, 3}));
    CHECK_IDS(index.search("c|b|a|c|b|a"), ids({0, 1, 2, 3}));
    CHECK_IDS(index.search_or({"a", "b", "c"}), ids({0, 1, 2, 3}));
    CHECK_IDS(index.search("a|b|c -z"), ids({0, 1, 2, 3}));
    CHECK_IDS(index.search("a|b|c -c"), ids({1}));
}

// =========================================================================================
// Randomized comparisons against a brute-force scan of every document's token set
// =========================================================================================

namespace {

const char* const kVocab[] = {"error", "timeout", "refused", "payment", "service", "disk", "cache",
                              "retry", "user",    "login",   "db",      "queue",   "common", "rare"};
constexpr int kVocabSize = 14;
// Document frequency of each word: "common" is nearly everywhere and "rare" almost nowhere, so
// search_and regularly pairs lists whose lengths differ by far more than 16x (galloping).
const double kFrequency[kVocabSize] = {0.25, 0.30, 0.15, 0.20, 0.20, 0.10, 0.10,
                                       0.08, 0.35, 0.25, 0.12, 0.05, 0.92, 0.004};

char upper_char(char c) { return (c >= 'a' && c <= 'z') ? static_cast<char>(c - 'a' + 'A') : c; }

std::string random_case(Rng& rng, std::string word) {
    switch (rng.below(4)) {
        case 0: break;
        case 1:
            for (char& c : word) c = upper_char(c);
            break;
        case 2: word[0] = upper_char(word[0]); break;
        default:
            for (char& c : word) {
                if (rng.chance(0.5)) c = upper_char(c);
            }
    }
    return word;
}

// Between documents' words. Includes NUL, a UTF-8 sequence and plenty of punctuation, none
// of which may glue words together or split them.
const std::string& random_document_separator(Rng& rng) {
    static const std::vector<std::string> kSeparators = {
        " ", "-", "_", ":", ", ", "=", "\t", "\n", "/", "...", std::string(1, '\0'), "\xC3" "\xA9", "  ", ";"};
    return kSeparators[rng.below(static_cast<std::uint32_t>(kSeparators.size()))];
}

// Inside one query term (no whitespace, no '|', and never at the start of the term).
const std::string& random_term_joiner(Rng& rng) {
    static const std::vector<std::string> kJoiners = {"-", "_", ":", ".", ",", "=", "/", "\xC3" "\xA9",
                                                      std::string(1, '\0')};
    return kJoiners[rng.below(static_cast<std::uint32_t>(kJoiners.size()))];
}

struct Corpus {
    InvertedIndex index;
    std::vector<std::uint32_t> mask;  // bit i set <=> kVocab[i] occurs in the document
};

Corpus build_corpus(Rng& rng, std::size_t documents) {
    Corpus corpus;
    for (std::size_t d = 0; d < documents; ++d) {
        std::vector<std::string> parts;
        std::uint32_t mask = 0;
        for (int w = 0; w < kVocabSize; ++w) {
            if (!rng.chance(kFrequency[w])) continue;
            mask |= std::uint32_t{1} << w;
            const int copies = rng.chance(0.2) ? 2 : 1;  // repeated words inside a document
            for (int c = 0; c < copies; ++c) parts.push_back(random_case(rng, kVocab[w]));
        }
        if (rng.chance(0.3)) parts.push_back("x" + std::to_string(rng.below(5000)));  // noise token
        for (std::size_t i = parts.size(); i > 1; --i) {                              // shuffle
            std::swap(parts[i - 1], parts[rng.below(static_cast<std::uint32_t>(i))]);
        }
        std::string text;
        if (rng.chance(0.2)) text += random_document_separator(rng);
        for (std::size_t i = 0; i < parts.size(); ++i) {
            if (i != 0) text += random_document_separator(rng);
            text += parts[i];
        }
        if (rng.chance(0.2)) text += random_document_separator(rng);
        corpus.index.add(text);
        corpus.mask.push_back(mask);
    }
    return corpus;
}

// A generated query term together with what it means, known from construction.
struct QTerm {
    std::string text;
    std::uint32_t required = 0;  // vocabulary bits that must all be present
    bool never_matches = false;  // contains a token that no document has
    bool no_tokens = false;      // tokenizes to nothing at all

    bool matches(std::uint32_t doc_mask) const {
        return !no_tokens && !never_matches && (doc_mask & required) == required;
    }
};

QTerm make_term(Rng& rng) {
    QTerm term;
    const std::uint32_t pick = rng.below(100);
    const int tokens = pick < 5 ? 0 : pick < 75 ? 1 : pick < 95 ? 2 : 3;
    if (tokens == 0) {
        static const char* const kNoTokenTexts[] = {"", "::", "_!", "...", "!"};
        term.text = kNoTokenTexts[rng.below(5)];
        term.no_tokens = true;
        return term;
    }
    for (int i = 0; i < tokens; ++i) {
        if (i != 0) term.text += random_term_joiner(rng);
        if (rng.chance(0.9)) {
            const int w = static_cast<int>(rng.below(kVocabSize));
            term.required |= std::uint32_t{1} << w;
            term.text += random_case(rng, kVocab[w]);
        } else {
            term.text += random_case(rng, "zzz" + std::to_string(rng.below(4)));  // not in any document
            term.never_matches = true;
        }
    }
    return term;
}

bool is_non_empty(const Ids& v) { return !v.empty(); }

}  // namespace

TEST(IndexSearch, AndAndOrMatchBruteForceOnRandomCorpus) {
    Rng rng(6001);
    const Corpus corpus = build_corpus(rng, 3000);
    CHECK_EQ(corpus.index.doc_count(), std::size_t{3000});
    int non_empty_and = 0;
    int non_empty_or = 0;
    const int queries = 1000;
    for (int q = 0; q < queries; ++q) {
        std::vector<QTerm> terms;
        Strings texts;
        const std::uint32_t n = rng.below(5);  // 0..4 terms (zero exercises the empty case)
        for (std::uint32_t i = 0; i < n; ++i) {
            terms.push_back(make_term(rng));
            texts.push_back(terms.back().text);
        }

        Ids expected_and;
        Ids expected_or;
        bool any_no_tokens = false;
        for (const QTerm& t : terms) any_no_tokens = any_no_tokens || t.no_tokens;
        for (std::size_t d = 0; d < corpus.mask.size(); ++d) {
            bool all = !terms.empty() && !any_no_tokens;
            bool any = false;
            for (const QTerm& t : terms) {
                const bool hit = t.matches(corpus.mask[d]);
                all = all && hit;
                any = any || hit;
            }
            if (all) expected_and.push_back(static_cast<DocId>(d));
            if (any) expected_or.push_back(static_cast<DocId>(d));
        }

        std::string ctx = "terms:";
        for (const std::string& text : texts) ctx += " <" + escaped(text) + ">";
        CHECK_IDS_CTX(corpus.index.search_and(texts), expected_and, "AND " + ctx);
        CHECK_IDS_CTX(corpus.index.search_or(texts), expected_or, "OR " + ctx);
        non_empty_and += is_non_empty(expected_and) ? 1 : 0;
        non_empty_or += is_non_empty(expected_or) ? 1 : 0;
    }
    // Guard against a vacuous test: plenty of queries must actually return documents.
    CHECK(non_empty_and > queries / 6);
    CHECK(non_empty_or > queries / 2);
}

namespace {

struct QWord {
    bool negated = false;
    std::vector<QTerm> alternatives;
};

// Reference semantics for search(), evaluated directly on the generated structure.
Ids ref_search(const Corpus& corpus, const std::vector<QWord>& words) {
    bool any_usable = false;
    for (const QWord& w : words) {
        for (const QTerm& t : w.alternatives) any_usable = any_usable || !t.no_tokens;
    }
    Ids out;
    if (!any_usable) return out;
    for (std::size_t d = 0; d < corpus.mask.size(); ++d) {
        bool keep = true;
        for (const QWord& w : words) {
            bool usable = false;
            bool hit = false;
            for (const QTerm& t : w.alternatives) {
                if (t.no_tokens) continue;
                usable = true;
                hit = hit || t.matches(corpus.mask[d]);
            }
            if (!usable) continue;
            if (w.negated ? hit : !hit) {
                keep = false;
                break;
            }
        }
        if (keep) out.push_back(static_cast<DocId>(d));
    }
    return out;
}

std::string query_text(Rng& rng, const std::vector<QWord>& words) {
    static const char* const kGaps[] = {" ", "\t", "  ", "\n", " \r\n "};
    std::string text;
    if (rng.chance(0.2)) text += kGaps[rng.below(5)];
    for (std::size_t i = 0; i < words.size(); ++i) {
        if (i != 0) text += kGaps[rng.below(5)];
        if (words[i].negated) text += '-';
        for (std::size_t a = 0; a < words[i].alternatives.size(); ++a) {
            if (a != 0) text += '|';
            text += words[i].alternatives[a].text;
        }
    }
    return text;
}

}  // namespace

TEST(IndexSearch, QueryLanguageMatchesBruteForceOnRandomCorpus) {
    Rng rng(6002);
    const Corpus corpus = build_corpus(rng, 3000);
    int non_empty = 0;
    int negated_only_non_empty = 0;
    const int queries = 2000;
    for (int q = 0; q < queries; ++q) {
        std::vector<QWord> words(rng.below(5));  // 0..4 words
        bool all_negated = !words.empty();
        for (QWord& w : words) {
            w.negated = rng.chance(0.35);
            all_negated = all_negated && w.negated;
            const std::uint32_t alternatives = rng.chance(0.15) ? 0 : 1 + rng.below(3);
            for (std::uint32_t a = 0; a < alternatives; ++a) w.alternatives.push_back(make_term(rng));
            if (alternatives == 0) w.alternatives.push_back(QTerm{"", 0, false, true});  // text ""
        }
        const std::string text = query_text(rng, words);
        const Ids expected = ref_search(corpus, words);
        CHECK_IDS_CTX(corpus.index.search(text), expected, "query <" + escaped(text) + ">");
        if (!expected.empty()) {
            ++non_empty;
            if (all_negated) ++negated_only_non_empty;
        }
    }
    CHECK(non_empty > queries / 3);
    CHECK(negated_only_non_empty > 5);
}

namespace {

// Word id with a cubic popularity skew: word 0 is in a large share of all documents and the
// tail words are rare, so postings lists of wildly different lengths get intersected.
std::uint32_t skewed_word(Rng& rng, std::uint32_t vocabulary) {
    const std::uint64_t r = rng.below(1000);
    return static_cast<std::uint32_t>(std::uint64_t{vocabulary} * r * r * r / 1000000000ULL);
}

bool doc_has(const std::vector<std::uint32_t>& sorted_words, std::uint32_t word) {
    return std::binary_search(sorted_words.begin(), sorted_words.end(), word);
}

std::string word_text(std::uint32_t id) { return "w" + std::to_string(id); }

}  // namespace

TEST(IndexSearch, SkewedWideVocabularyMatchesBruteForce) {
    Rng rng(6003);
    const std::uint32_t vocabulary = 300;
    InvertedIndex index;
    std::vector<std::vector<std::uint32_t>> doc_words;  // sorted distinct word ids per document
    for (int d = 0; d < 3000; ++d) {
        std::set<std::uint32_t> words;
        std::string text;
        const std::uint32_t n = 1 + rng.below(8);
        for (std::uint32_t i = 0; i < n; ++i) {
            const std::uint32_t w = skewed_word(rng, vocabulary);
            words.insert(w);
            text += word_text(w) + (rng.chance(0.5) ? " " : "; ");
        }
        index.add(text);
        doc_words.emplace_back(words.begin(), words.end());
    }

    int non_empty = 0;
    for (int q = 0; q < 300; ++q) {
        // 1..3 required words with 1..2 alternatives each, 0..2 negated words with 1..2 each.
        std::vector<std::vector<std::uint32_t>> required(1 + rng.below(3));
        std::vector<std::vector<std::uint32_t>> forbidden(rng.below(3));
        std::string query;
        for (auto& word : required) {
            word.resize(1 + rng.below(2));
            for (std::size_t a = 0; a < word.size(); ++a) {
                word[a] = skewed_word(rng, vocabulary);
                query += (a == 0 ? "" : "|") + word_text(word[a]);
            }
            query += ' ';
        }
        for (auto& word : forbidden) {
            word.resize(1 + rng.below(2));
            query += '-';
            for (std::size_t a = 0; a < word.size(); ++a) {
                word[a] = skewed_word(rng, vocabulary);
                query += (a == 0 ? "" : "|") + word_text(word[a]);
            }
            query += ' ';
        }

        Ids expected;
        Ids expected_and;
        Ids expected_or;
        Strings terms;
        for (const auto& word : required) terms.push_back(word_text(word.front()));
        for (std::size_t d = 0; d < doc_words.size(); ++d) {
            auto any_of = [&](const std::vector<std::uint32_t>& word) {
                for (const std::uint32_t w : word) {
                    if (doc_has(doc_words[d], w)) return true;
                }
                return false;
            };
            bool keep = true;
            for (const auto& word : required) keep = keep && any_of(word);
            for (const auto& word : forbidden) keep = keep && !any_of(word);
            if (keep) expected.push_back(static_cast<DocId>(d));

            bool all = true;
            bool any = false;
            for (const auto& word : required) {
                const bool hit = doc_has(doc_words[d], word.front());
                all = all && hit;
                any = any || hit;
            }
            if (all) expected_and.push_back(static_cast<DocId>(d));
            if (any) expected_or.push_back(static_cast<DocId>(d));
        }
        CHECK_IDS_CTX(index.search(query), expected, "query <" + query + ">");
        CHECK_IDS_CTX(index.search_and(terms), expected_and, "AND of the first alternatives of <" + query + ">");
        CHECK_IDS_CTX(index.search_or(terms), expected_or, "OR of the first alternatives of <" + query + ">");
        non_empty += expected.empty() ? 0 : 1;
    }
    CHECK(non_empty > 100);
}

// =========================================================================================
// Fuzzing with arbitrary bytes against a reference that parses and tokenizes independently
// =========================================================================================

namespace {

// Tokenization by alphabet membership rather than character ranges.
Strings ref_tokens(const std::string& text) {
    const std::string lower = "abcdefghijklmnopqrstuvwxyz";
    const std::string upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const std::string digits = "0123456789";
    Strings tokens;
    std::string current;
    for (const char c : text) {
        const std::size_t upper_at = upper.find(c);
        if (upper_at != std::string::npos) {
            current += lower[upper_at];
        } else if (lower.find(c) != std::string::npos || digits.find(c) != std::string::npos) {
            current += c;
        } else {
            if (!current.empty()) tokens.push_back(current);
            current.clear();
        }
    }
    if (!current.empty()) tokens.push_back(current);
    return tokens;
}

using TokenSet = std::set<std::string>;

bool has_all(const TokenSet& doc, const Strings& tokens) {
    for (const std::string& t : tokens) {
        if (doc.count(t) == 0) return false;
    }
    return true;
}

struct RefWord {
    bool negated = false;
    std::vector<Strings> alternatives;  // only alternatives with at least one token
};

std::vector<RefWord> ref_parse(const std::string& query) {
    const std::string spaces = " \t\n\v\f\r";
    std::vector<std::string> raw;
    std::string current;
    for (const char c : query) {
        if (spaces.find(c) != std::string::npos) {
            if (!current.empty()) raw.push_back(current);
            current.clear();
        } else {
            current += c;
        }
    }
    if (!current.empty()) raw.push_back(current);

    std::vector<RefWord> words;
    for (const std::string& w : raw) {
        RefWord word;
        word.negated = w.front() == '-';
        std::string alternative;
        auto flush = [&] {
            const Strings tokens = ref_tokens(alternative);
            if (!tokens.empty()) word.alternatives.push_back(tokens);
            alternative.clear();
        };
        for (std::size_t i = word.negated ? 1 : 0; i < w.size(); ++i) {
            if (w[i] == '|') {
                flush();
            } else {
                alternative += w[i];
            }
        }
        flush();
        words.push_back(word);
    }
    return words;
}

Ids ref_query(const std::vector<TokenSet>& docs, const std::string& query) {
    const std::vector<RefWord> words = ref_parse(query);
    bool any_usable = false;
    for (const RefWord& w : words) any_usable = any_usable || !w.alternatives.empty();
    Ids out;
    if (!any_usable) return out;
    for (std::size_t d = 0; d < docs.size(); ++d) {
        bool keep = true;
        for (const RefWord& w : words) {
            if (w.alternatives.empty()) continue;
            bool hit = false;
            for (const Strings& alternative : w.alternatives) hit = hit || has_all(docs[d], alternative);
            if (w.negated == hit) keep = false;  // negated word hit, or required word missed
        }
        if (keep) out.push_back(static_cast<DocId>(d));
    }
    return out;
}

std::string random_string(Rng& rng, std::size_t max_length) {
    // Letters of both cases, a digit, every separator that matters to the query grammar,
    // whitespace, NUL and a high byte.
    static const char kAlphabet[] = "abcAB1-_, |\t\n\0\xFF";
    const std::uint32_t symbols = sizeof(kAlphabet) - 1;  // the literal contains a NUL of its own
    std::string s;
    const std::size_t length = rng.below(static_cast<std::uint32_t>(max_length + 1));
    for (std::size_t i = 0; i < length; ++i) s += kAlphabet[rng.below(symbols)];
    return s;
}

}  // namespace

TEST(IndexSearch, FuzzedQueriesMatchAnIndependentReference) {
    Rng rng(7001);
    InvertedIndex index;
    std::vector<TokenSet> docs;
    for (int d = 0; d < 150; ++d) {
        const std::string text = random_string(rng, 14);
        const Strings tokens = ref_tokens(text);
        index.add(text);
        docs.emplace_back(tokens.begin(), tokens.end());
    }
    std::size_t distinct_tokens = 0;
    {
        TokenSet all;
        for (const TokenSet& doc : docs) all.insert(doc.begin(), doc.end());
        distinct_tokens = all.size();
    }
    CHECK_EQ(index.term_count(), distinct_tokens);
    CHECK_EQ(index.doc_count(), docs.size());

    int non_empty = 0;
    int negated_queries = 0;
    for (int q = 0; q < 4000; ++q) {
        const std::string query = random_string(rng, 16);
        const Ids expected = ref_query(docs, query);
        CHECK_IDS_CTX(index.search(query), expected, "query <" + escaped(query) + ">");
        non_empty += expected.empty() ? 0 : 1;
        negated_queries += (query.find('-') != std::string::npos) ? 1 : 0;
    }
    CHECK(non_empty > 800);
    CHECK(negated_queries > 1000);

    for (int q = 0; q < 1500; ++q) {
        Strings terms;
        const std::uint32_t n = rng.below(4);
        for (std::uint32_t i = 0; i < n; ++i) terms.push_back(random_string(rng, 6));

        Ids expected_and;
        Ids expected_or;
        std::vector<Strings> term_tokens;
        bool any_empty = false;
        for (const std::string& term : terms) {
            term_tokens.push_back(ref_tokens(term));
            any_empty = any_empty || term_tokens.back().empty();
        }
        for (std::size_t d = 0; d < docs.size(); ++d) {
            bool all = !terms.empty() && !any_empty;
            bool any = false;
            for (const Strings& tokens : term_tokens) {
                const bool hit = !tokens.empty() && has_all(docs[d], tokens);
                all = all && hit;
                any = any || hit;
            }
            if (all) expected_and.push_back(static_cast<DocId>(d));
            if (any) expected_or.push_back(static_cast<DocId>(d));
        }
        std::string ctx = "terms:";
        for (const std::string& term : terms) ctx += " <" + escaped(term) + ">";
        CHECK_IDS_CTX(index.search_and(terms), expected_and, "AND " + ctx);
        CHECK_IDS_CTX(index.search_or(terms), expected_or, "OR " + ctx);
    }
}

// =========================================================================================
// Review fixes. Each test below pins down one reported defect; the comment says what the
// code did before the fix and how that shows up here.
// =========================================================================================

// Like CHECK, with a context string that is only evaluated when the check fails.
#define CHECK_CTX(cond, ctx)                                                                 \
    do {                                                                                     \
        if (!(cond))                                                                         \
            throw ::testkit::Failure{::testkit::where(__FILE__, __LINE__) + "CHECK(" #cond \
                                     ") failed [" + (ctx) + "]"};                            \
    } while (0)

// ---- special members --------------------------------------------------------------------

namespace {

// libstdc++'s idiom: whether `{}` can copy-list-initialize a T, i.e. `T x = {};`, `return {};`
// and an aggregate member all compile. False when the default constructor is explicit.
template <class T>
void takes_by_const_reference(const T&);

template <class T, class = void>
struct IsImplicitlyDefaultConstructible : std::false_type {};

template <class T>
struct IsImplicitlyDefaultConstructible<T, std::void_t<decltype(takes_by_const_reference<T>({}))>>
    : std::true_type {};

struct IndexHolder {
    InvertedIndex index;
    int unrelated = 0;
};

InvertedIndex make_empty_index() { return {}; }

}  // namespace

TEST(InvertedIndex, DefaultConstructorIsImplicit) {
    // The capacity constructor made the only default constructor explicit, so `= {}`,
    // `return {}` and aggregates holding an index failed with C2512 / "explicit constructor".
    CHECK(IsImplicitlyDefaultConstructible<InvertedIndex>::value);
    const InvertedIndex a = {};
    const InvertedIndex b = make_empty_index();
    const IndexHolder holder{};
    const InvertedIndex c{};
    CHECK_EQ(a.doc_count() + b.doc_count() + c.doc_count() + holder.index.doc_count(), std::size_t{0});
    CHECK((!std::is_convertible<std::uint64_t, InvertedIndex>::value));  // only the capacity constructor is explicit
    InvertedIndex d = {};
    CHECK_EQ(d.add("x"), DocId{0});
    CHECK_EQ(InvertedIndexTestAccess::capacity(d), InvertedIndex::kMaxDocuments);
}

TEST(InvertedIndex, MovesAreCheapAndNeverThrow) {
    // The MSVC unordered_map move constructor can throw, so the index was not
    // nothrow-move-constructible and std::vector<InvertedIndex> deep-copied on every growth.
    CHECK(std::is_nothrow_move_constructible<InvertedIndex>::value);
    CHECK(std::is_nothrow_move_assignable<InvertedIndex>::value);

    std::vector<InvertedIndex> indexes;
    indexes.reserve(1);
    indexes.emplace_back();
    indexes[0].add("alpha beta");
    const Ids* alpha = &indexes[0].postings("alpha");
    for (int i = 1; i < 40; ++i) {  // many reallocations
        indexes.emplace_back();
        indexes.back().add("only " + std::to_string(i));
    }
    // A move hands the lists over instead of copying them: the reference now belongs to the
    // index's new home and still reads the same ids.
    CHECK(alpha == &indexes[0].postings("alpha"));
    CHECK_IDS(*alpha, ids({0}));
    for (int i = 1; i < 40; ++i) CHECK_IDS(indexes[static_cast<std::size_t>(i)].postings(std::to_string(i)), ids({0}));
}

TEST(InvertedIndex, MovedFromIndexIsAValidEmptyIndex) {
    // The implicit move emptied the term table but left doc_count behind: a moved-from index
    // reported documents that no longer existed, a negated query returned their ids, and the
    // next add() continued at the old id.
    InvertedIndex source;
    source.add("x y");
    source.add("y z");
    const Ids* y = &source.postings("y");

    InvertedIndex target = std::move(source);
    CHECK_EQ(source.doc_count(), std::size_t{0});  // NOLINT: moved-from state is the subject here
    CHECK_EQ(source.term_count(), std::size_t{0});
    CHECK(source.postings("y").empty());
    CHECK(source.search("-x").empty());
    CHECK(source.search("x").empty());
    CHECK(source.search_and({"x"}).empty());
    CHECK(source.search_or({"x", "y"}).empty());

    CHECK_EQ(target.doc_count(), std::size_t{2});
    CHECK(&target.postings("y") == y);
    CHECK_IDS(target.postings("y"), ids({0, 1}));
    CHECK_IDS(target.search("-x"), ids({1}));

    // And it can be used again from scratch.
    CHECK_EQ(source.add("fresh start"), DocId{0});
    CHECK_IDS(source.postings("fresh"), ids({0}));
    CHECK_IDS(source.search("-fresh"), ids({}));
    CHECK(source.postings("x").empty());
    CHECK_EQ(source.doc_count(), std::size_t{1});

    // Move assignment: the source is emptied too, the old contents of the target are gone.
    InvertedIndex replaced;
    replaced.add("old content");
    replaced = std::move(target);
    CHECK_EQ(target.doc_count(), std::size_t{0});  // NOLINT
    CHECK_EQ(target.term_count(), std::size_t{0});
    CHECK(target.search("-x").empty());
    CHECK_EQ(replaced.doc_count(), std::size_t{2});
    CHECK(replaced.postings("old").empty());
    CHECK_IDS(replaced.postings("z"), ids({1}));

    // Self-assignment (through an alias, so no compiler can see it) is harmless.
    InvertedIndex& alias = replaced;
    replaced = std::move(alias);
    CHECK_EQ(replaced.doc_count(), std::size_t{2});
    replaced = alias;
    CHECK_EQ(replaced.doc_count(), std::size_t{2});
    CHECK_IDS(replaced.postings("y"), ids({0, 1}));
}

TEST(InvertedIndex, CapacityTravelsWithCopiesAndMoves) {
    InvertedIndex limited(2);
    limited.add("a");
    InvertedIndex copy = limited;
    CHECK_EQ(copy.add("b"), DocId{1});
    CHECK_THROWS(copy.add("c"), std::length_error);
    CHECK_EQ(limited.add("b"), DocId{1});  // the original is independent

    InvertedIndex moved = std::move(limited);
    CHECK_THROWS(moved.add("c"), std::length_error);
    // The moved-from index keeps its capacity setting but starts empty again.
    CHECK_EQ(limited.add("p"), DocId{0});  // NOLINT
    CHECK_EQ(limited.add("q"), DocId{1});
    CHECK_THROWS(limited.add("r"), std::length_error);
}

TEST(InvertedIndex, CopyAssignmentReplacesTheTargetAndStaysIndependent) {
    InvertedIndex target;
    target.add("one");
    InvertedIndex source;
    source.add("two three");
    source.add("three");
    target = source;
    CHECK_EQ(target.doc_count(), std::size_t{2});
    CHECK(target.postings("one").empty());
    CHECK_IDS(target.postings("three"), ids({0, 1}));
    source.add("four");
    CHECK(target.postings("four").empty());
    CHECK_EQ(target.add("five"), DocId{2});
    CHECK(source.postings("five").empty());

    InvertedIndex empty;
    target = empty;  // copying an index that never allocated its table
    CHECK_EQ(target.doc_count(), std::size_t{0});
    CHECK_EQ(target.term_count(), std::size_t{0});
    CHECK_EQ(target.add("again"), DocId{0});

    InvertedIndex& alias = target;
    target = alias;  // self copy-assignment
    CHECK_IDS(target.postings("again"), ids({0}));
}

// ---- tokenizer: locale, scanner --------------------------------------------------------

namespace {

// Restores the C locale settings that were active when it was built, even if a CHECK throws.
class LocaleGuard {
public:
    LocaleGuard() {
        const char* current = std::setlocale(LC_ALL, nullptr);
        saved_ = current != nullptr ? current : "C";
    }
    ~LocaleGuard() { std::setlocale(LC_ALL, saved_.c_str()); }
    LocaleGuard(const LocaleGuard&) = delete;
    LocaleGuard& operator=(const LocaleGuard&) = delete;

private:
    std::string saved_;
};

}  // namespace

TEST(IndexTokenize, DoesNotDependOnTheCLocale) {
    // The spec forbids std::isalnum / std::tolower, but in the "C" locale they agree with the
    // ASCII ranges, so no test that stays in "C" can tell them apart: an implementation using
    // them passed every other test here. In a Latin-1 / Windows-1252 locale 0xE9 is a letter and
    // 0xC9 lower-cases to it; in Windows-1251 the bytes 0xE0..0xFF are Cyrillic letters.
    const char* const candidates[] = {".1252",           "German_Germany.1252", "French_France.1252",
                                      ".1251",           ".28591",              "de_DE.ISO-8859-1",
                                      "de_DE.iso88591",  "fr_FR.ISO-8859-1",    "en_US.ISO-8859-1",
                                      "ru_RU.CP1251",    "ru_RU.ISO-8859-5"};
    const std::string latin = "caf\xE9 NA\xCF" "VE \xC9" "TE";
    const std::string cyrillic = "\xE4\xE0 abc \xC4\xC0";

    LocaleGuard guard;
    std::setlocale(LC_ALL, "C");
    InvertedIndex built_in_c;
    built_in_c.add(latin);
    built_in_c.add(cyrillic);

    int applied = 0;
    int effective = 0;  // locales in which the C library really treats those bytes as letters
    for (const char* name : candidates) {
        if (std::setlocale(LC_ALL, name) == nullptr) continue;  // not installed here
        ++applied;
        if (std::isalnum(0xE9) != 0 || std::isalnum(0xE4) != 0 || std::tolower(0xC9) != 0xC9) ++effective;

        CHECK_CTX((tokenize(latin) == strs({"caf", "na", "ve", "te"})), name);
        CHECK_CTX((tokenize(cyrillic) == strs({"abc"})), name);
        CHECK_CTX(tokenize("\xE9\xC9\xE4").empty(), name);

        InvertedIndex built_here;
        built_here.add(latin);
        built_here.add(cyrillic);
        CHECK_IDS_CTX(built_here.search("CAF NA ve TE"), ids({0}), name);
        CHECK_IDS_CTX(built_here.search("abc"), ids({1}), name);
        CHECK_IDS_CTX(built_here.search("-abc"), ids({0}), name);
        CHECK_IDS_CTX(built_in_c.search("caf te"), ids({0}), name);  // built in "C", queried here
    }
    std::setlocale(LC_ALL, "C");
    CHECK_IDS(built_in_c.search("caf te"), ids({0}));
    CHECK(applied >= effective);
#ifdef _WIN32
    CHECK(effective >= 1);  // the ANSI code page locales ship with every Windows
#endif
}

TEST(IndexTokenize, ScannerYieldsExactlyTheTokensOfTokenize) {
    // add() and the query parser scan token by token; tokenize() must be the same sequence.
    // add()'s rollback also relies on this: the text before end() holds exactly the tokens
    // handed out so far.
    Rng rng(9001);
    for (int round = 0; round < 600; ++round) {
        const std::string text = random_string(rng, 40);
        loganalyzer::detail::TokenScanner scanner(text);
        std::string token;
        Strings got;
        std::size_t previous_end = 0;
        CHECK_EQ(scanner.end(), std::size_t{0});
        while (scanner.next(token)) {
            got.push_back(token);
            CHECK(scanner.end() > previous_end);
            CHECK(scanner.end() <= text.size());
            previous_end = scanner.end();
            CHECK_CTX((tokenize(std::string_view(text).substr(0, scanner.end())) == got), escaped(text));
        }
        CHECK_CTX((got == tokenize(text)), escaped(text));
        CHECK_CTX((got == ref_tokens(text)), escaped(text));
        CHECK_EQ(scanner.end(), previous_end);  // running dry leaves it where the last token ended
        CHECK(!scanner.next(token));
        CHECK_EQ(scanner.end(), previous_end);
    }
    loganalyzer::detail::TokenScanner empty{std::string_view()};
    std::string token = "left over";
    CHECK(!empty.next(token));
    CHECK_EQ(token, std::string("left over"));  // untouched when there is nothing to yield
}

// ---- hash flooding ----------------------------------------------------------------------

namespace {

std::uint64_t fnv1a_64(const std::string& s) {
    std::uint64_t h = 14695981039346656037ULL;
    for (const char c : s) {
        h ^= static_cast<unsigned char>(c);
        h *= 1099511628211ULL;
    }
    return h;
}

// MSVC's std::hash<std::string> is FNV-1a and its table picks the bucket with `hash & mask`.
// The low K bits of FNV-1a depend only on the low K bits of the running state, and each byte
// maps that state through a bijection (xor, then multiply by an odd number), so strings that
// all end in the same low-16-bit state are cheap to build: meet in the middle over a 3-character
// prefix and a 3-character suffix. Returns `want` distinct 6-character tokens whose FNV-1a
// hashes all have low 16 bits equal to zero (the generator itself shares no code with the
// header, and the tests re-check every token with a full 64-bit FNV-1a).
std::vector<std::string> tokens_colliding_under_fnv1a(std::size_t want) {
    static const char kAlphabet[] = "0123456789abcdefghijklmnopqrstuvwxyz";
    constexpr std::uint32_t kPrime16 = 0x01b3;  // low 16 bits of the 64-bit FNV prime
    constexpr std::uint32_t kBasis16 = 0x2325;  // low 16 bits of the 64-bit offset basis
    std::uint32_t inverse = kPrime16;           // Newton iteration for the inverse mod 2^16
    for (int i = 0; i < 5; ++i) inverse = (inverse * (2 - kPrime16 * inverse)) & 0xFFFF;

    const auto three = [](std::uint32_t n) {
        std::string s;
        s += kAlphabet[n / 1296];
        s += kAlphabet[n / 36 % 36];
        s += kAlphabet[n % 36];
        return s;
    };
    constexpr std::uint32_t kThrees = 36 * 36 * 36;
    std::vector<std::vector<std::uint32_t>> prefixes_by_state(65536);
    for (std::uint32_t n = 0; n < kThrees; ++n) {
        std::uint32_t state = kBasis16;
        for (const char c : three(n)) state = ((state ^ static_cast<unsigned char>(c)) * kPrime16) & 0xFFFF;
        prefixes_by_state[state].push_back(n);
    }
    std::vector<std::string> tokens;
    for (std::uint32_t n = 0; n < kThrees && tokens.size() < want; ++n) {
        const std::string suffix = three(n);
        std::uint32_t needed = 0;  // the state before the suffix that ends in state 0 after it
        for (std::size_t i = suffix.size(); i-- > 0;) {
            needed = ((needed * inverse) & 0xFFFF) ^ static_cast<unsigned char>(suffix[i]);
        }
        for (const std::uint32_t prefix : prefixes_by_state[needed]) {
            tokens.push_back(three(prefix) + suffix);
            if (tokens.size() == want) break;
        }
    }
    return tokens;
}

}  // namespace

TEST(IndexHash, SipHash24MatchesThePublishedVectors) {
    // Key 00 01 .. 0f and message 00 01 .. (n-1): n = 15 is the paper's appendix A example, 0..8
    // are the first reference vectors, the rest were computed with an independent Python
    // implementation that reproduces all of those.
    using loganalyzer::detail::siphash24;
    const std::uint64_t key0 = 0x0706050403020100ULL;
    const std::uint64_t key1 = 0x0f0e0d0c0b0a0908ULL;
    std::string message;
    for (int i = 0; i < 65; ++i) message += static_cast<char>(i);
    struct Vector {
        std::size_t length;
        std::uint64_t hash;
    };
    const Vector vectors[] = {
        {0, 0x726fdb47dd0e0e31ULL},  {1, 0x74f839c593dc67fdULL},  {2, 0x0d6c8009d9a94f5aULL},
        {3, 0x85676696d7fb7e2dULL},  {4, 0xcf2794e0277187b7ULL},  {5, 0x18765564cd99a68dULL},
        {6, 0xcbc9466e58fee3ceULL},  {7, 0xab0200f58b01d137ULL},  {8, 0x93f5f5799a932462ULL},
        {9, 0x9e0082df0ba9e4b0ULL},  {15, 0xa129ca6149be45e5ULL}, {16, 0x3f2acc7f57c29bdbULL},
        {17, 0x699ae9f52cbe4794ULL}, {31, 0x32d892fad841c342ULL}, {63, 0x958a324ceb064572ULL},
        {64, 0xacd2c40b8502cad8ULL}, {65, 0x36b6bedb91a25924ULL}};
    for (const Vector& v : vectors) {
        CHECK_CTX(siphash24(key0, key1, message.data(), v.length) == v.hash, "length " + std::to_string(v.length));
    }
    // Other keys and bytes >= 128 (no sign extension) and a text that is not a prefix of the above.
    const std::string text = "payment-service timeout=3000ms";
    CHECK(siphash24(0x0123456789abcdefULL, 0xfedcba9876543210ULL, text.data(), text.size()) == 0xd7e378a771b26c9aULL);
    CHECK(siphash24(0x0123456789abcdefULL, 0xfedcba9876543210ULL, "", 0) == 0xb7e67c99394ba858ULL);
    CHECK(siphash24(0, 0, "a", 1) == 0x96c20860cd93a249ULL);
    const std::string high(40, static_cast<char>(0xff));
    CHECK(siphash24(0xffffffffffffffffULL, 0x8000000000000001ULL, high.data(), high.size()) == 0x2c61ddf8c819acf0ULL);
}

TEST(IndexHash, TermHashDependsOnTheKeyAndOnNothingElse) {
    using loganalyzer::detail::TermHash;
    const TermHash a{1, 2};
    const TermHash b{1, 2};
    const TermHash c{1, 3};
    const TermHash d{2, 2};
    int differing_c = 0;
    int differing_d = 0;
    for (int i = 0; i < 200; ++i) {
        const std::string term = "term" + std::to_string(i);
        CHECK(a(term) == b(term));  // same key, same hash, today and tomorrow
        if (a(term) != c(term)) ++differing_c;
        if (a(term) != d(term)) ++differing_d;
    }
    CHECK(differing_c >= 199);  // a different key gives (all but certainly) different hashes
    CHECK(differing_d >= 199);
    CHECK(a("") == b(""));
    CHECK(a(std::string("a\0b", 3)) != a(std::string("a\0c", 3)));  // NUL is an ordinary byte here
}

TEST(IndexHash, TermHashSpreadsTokensThatCollideUnderFnv1a) {
    const std::vector<std::string> tokens = tokens_colliding_under_fnv1a(20000);
    CHECK_EQ(tokens.size(), std::size_t{20000});
    const std::set<std::string> distinct(tokens.begin(), tokens.end());
    CHECK_EQ(distinct.size(), std::size_t{20000});
    for (const std::string& token : tokens) {
        CHECK_CTX((fnv1a_64(token) & 0xFFFF) == 0, token);  // the premise: one bucket under FNV-1a
    }

    const loganalyzer::detail::TermHash hash{0x0123456789abcdefULL, 0xfedcba9876543210ULL};
    std::map<std::size_t, std::size_t> per_bucket;
    for (const std::string& token : tokens) ++per_bucket[hash(token) & 0xFFFF];
    std::size_t largest = 0;
    for (const auto& entry : per_bucket) largest = std::max(largest, entry.second);
    // 20,000 tokens thrown at random into 65,536 buckets fill about 17,250 of them; the fullest
    // holds about 7. Under FNV-1a there is exactly one bucket with all 20,000.
    CHECK(per_bucket.size() > 15000);
    CHECK(largest <= 16);
}

TEST(InvertedIndex, CollidingTokensDoNotPileIntoOneBucket) {
    // With std::hash<std::string> every one of these tokens landed in the same bucket on MSVC, so
    // each add() and each lookup walked the whole chain: 6,000 of them already made add() 96
    // times slower than for random tokens, and the cost grows with the square of the count.
    const std::vector<std::string> tokens = tokens_colliding_under_fnv1a(20000);
    CHECK_EQ(tokens.size(), std::size_t{20000});
    InvertedIndex index;
    for (const std::string& token : tokens) index.add(token);
    CHECK_EQ(index.term_count(), std::size_t{20000});
    CHECK(InvertedIndexTestAccess::largest_bucket(index) <= 16);

    std::size_t wrong = 0;
    for (std::size_t i = 0; i < tokens.size(); ++i) {
        const Ids& list = index.postings(tokens[i]);
        if (list.size() != 1 || list.front() != static_cast<DocId>(i)) ++wrong;
    }
    CHECK_EQ(wrong, std::size_t{0});
    CHECK_IDS(index.search(tokens[7] + "|" + tokens[19999] + " -" + tokens[7]), ids({19999}));
}

TEST(InvertedIndex, EveryIndexDrawsItsOwnHashKey) {
    // A fixed key would let an attacker precompute colliding tokens once and for all.
    std::set<std::pair<std::uint64_t, std::uint64_t>> keys;
    for (int i = 0; i < 32; ++i) {
        InvertedIndex index;
        index.add("x");
        keys.insert(InvertedIndexTestAccess::hash_key(index));
    }
    CHECK_EQ(keys.size(), std::size_t{32});

    // The key belongs to the table, so copies and moves keep answering lookups with it.
    InvertedIndex original;
    original.add("alpha beta");
    const auto key = InvertedIndexTestAccess::hash_key(original);
    InvertedIndex copy = original;
    CHECK(InvertedIndexTestAccess::hash_key(copy) == key);
    InvertedIndex moved = std::move(original);
    CHECK(InvertedIndexTestAccess::hash_key(moved) == key);
    CHECK_IDS(copy.postings("beta"), ids({0}));
    CHECK_IDS(moved.postings("beta"), ids({0}));
}

// ---- add(): rollback and streaming --------------------------------------------------------

namespace {

using loganalyzer::detail::AddStage;

// Throws std::bad_alloc, as a failing allocation would, at one point of one add().
struct FailAt {
    AddStage stage;
    std::size_t token;

    void operator()(AddStage at, std::size_t index, std::size_t) const {
        if (at == stage && index == token) throw std::bad_alloc();
    }
};

// Everything the public API shows about the lists of a set of terms.
struct Observed {
    std::size_t documents = 0;
    std::size_t terms = 0;
    std::vector<Ids> lists;
    std::vector<const Ids*> addresses;

    bool operator==(const Observed& other) const {
        return documents == other.documents && terms == other.terms && lists == other.lists &&
               addresses == other.addresses;
    }
};

Observed observe(const InvertedIndex& index, const Strings& terms) {
    Observed seen;
    seen.documents = index.doc_count();
    seen.terms = index.term_count();
    for (const std::string& term : terms) {
        seen.lists.push_back(index.postings(term));
        seen.addresses.push_back(&index.postings(term));
    }
    return seen;
}

}  // namespace

TEST(InvertedIndex, FailedAddIsRolledBackWhereverItFails) {
    // add() has two points between which an allocation can fail for every token: creating the
    // term (the lookup) and appending the id. Failing at each of them, for each token of a
    // document, must leave the index exactly as it was - including the terms that the document
    // had created before the failure. Skipping the rollback, or erasing no emptied term, was
    // invisible to every other test: both mutants passed the whole suite.
    const char* const kTexts[] = {
        "new1 new2 new3",                                    // only new terms
        "alpha beta gamma",                                  // only existing terms
        "alpha new1 beta new2 gamma new3",                   // interleaved
        "new1 new1 new2 new1 alpha alpha",                   // repeats of new and old terms inside the document
        "A-VERY-LONG-TOKEN-THAT-IS-LONGER-THAN-ANY-SMALL-STRING-BUFFER new1 ALPHA",
        "x",                                                 // a single token
        "",                                                  // nothing to roll back
        "--- !!",
    };
    Strings probe_terms = {"alpha", "beta", "gamma", "new1", "new2", "new3", "x",
                           "a-very-long-token-that-is-longer-than-any-small-string-buffer"};
    for (int i = 0; i < 80; ++i) probe_terms.push_back("filler" + std::to_string(i));

    // Start from indexes of every size up to 80 terms, so that the failing add() lands on either
    // side of every rehash threshold of whatever table the standard library uses.
    for (int base = 0; base <= 80; ++base) {
        for (const char* text : kTexts) {
            InvertedIndex index;  // a fresh one per text, so that "new1" etc. really are new terms
            for (int i = 0; i < base; ++i) {
                index.add("alpha filler" + std::to_string(i) + (i % 3 == 0 ? " beta" : ""));
            }
            const std::size_t token_count = tokenize(text).size();
            for (std::size_t token = 0; token < token_count; ++token) {
                for (const AddStage stage : {AddStage::BeforeLookup, AddStage::BeforeAppend}) {
                    const Observed before = observe(index, probe_terms);
                    const std::string ctx = "base " + std::to_string(base) + " text <" + text + "> token " +
                                            std::to_string(token) +
                                            (stage == AddStage::BeforeLookup ? " before lookup" : " before append");
                    bool threw = false;
                    try {
                        InvertedIndexTestAccess::add(index, text, FailAt{stage, token});
                    } catch (const std::bad_alloc&) {
                        threw = true;
                    }
                    CHECK_CTX(threw, ctx);
                    CHECK_CTX(observe(index, probe_terms) == before, ctx);
                    CHECK_CTX(index.search("-alpha").size() == index.doc_count() - index.postings("alpha").size(), ctx);
                }
            }
            // After all those failures the very same add() still works and indexes the text.
            const Observed before = observe(index, probe_terms);
            const DocId id = index.add(text);
            CHECK_EQ(static_cast<std::size_t>(id), before.documents);
            const Observed after = observe(index, probe_terms);
            CHECK_EQ(after.documents, before.documents + 1);
            for (const std::string& token : tokenize(text)) {
                const Ids& list = index.postings(token);
                CHECK_CTX(!list.empty() && list.back() == id, token);
                CHECK_CTX(std::count(list.begin(), list.end(), id) == 1, token);
            }
        }
    }
}

TEST(InvertedIndex, FailedAddOnAnEmptyIndexLeavesItEmpty) {
    // The first add() also creates the term table; failing after it must not leave a document
    // or a term behind.
    InvertedIndex index;
    CHECK_THROWS(InvertedIndexTestAccess::add(index, "first second", FailAt{AddStage::BeforeAppend, 1}), std::bad_alloc);
    CHECK_EQ(index.doc_count(), std::size_t{0});
    CHECK_EQ(index.term_count(), std::size_t{0});
    CHECK(index.postings("first").empty());
    CHECK(index.search("-first").empty());
    CHECK_EQ(index.add("first second"), DocId{0});
    CHECK_IDS(index.postings("second"), ids({0}));
}

TEST(InvertedIndex, FailedAddDoesNotConsumeAnIdAtTheCapacityLimit) {
    InvertedIndex index(2);
    index.add("a");
    CHECK_THROWS(InvertedIndexTestAccess::add(index, "b c", FailAt{AddStage::BeforeAppend, 1}), std::bad_alloc);
    CHECK_EQ(index.doc_count(), std::size_t{1});
    CHECK_EQ(index.add("b c"), DocId{1});  // the id and the slot are still free
    CHECK_THROWS(index.add("d"), std::length_error);
}

TEST(InvertedIndex, AddIndexesEachTokenAsItIsScanned) {
    // add() used to tokenize the whole text into a vector of strings first: 32 bytes per token
    // plus heap storage, i.e. about 30 times the text size at its peak (a 4 MB text of one-letter
    // tokens needed 120 MB). The hook reports how far the scanner has got when a token is handled;
    // if the text were tokenized up front it would already be at the very end every time.
    std::string text;
    std::vector<std::size_t> token_ends;
    for (int i = 0; i < 2000; ++i) {
        text += "Tok" + std::to_string(i % 37);
        token_ends.push_back(text.size());
        text += (i % 3 == 0) ? " " : "-- ";
    }
    std::vector<std::size_t> seen_tokens;
    std::vector<std::size_t> seen_offsets;
    const auto record = [&](AddStage stage, std::size_t token, std::size_t consumed) {
        if (stage != AddStage::BeforeLookup) return;
        seen_tokens.push_back(token);
        seen_offsets.push_back(consumed);
    };
    InvertedIndex index;
    InvertedIndexTestAccess::add(index, text, record);
    CHECK_EQ(seen_tokens.size(), token_ends.size());
    bool streamed = true;
    for (std::size_t i = 0; i < token_ends.size(); ++i) {
        streamed = streamed && seen_tokens[i] == i && seen_offsets[i] == token_ends[i];
    }
    CHECK(streamed);
    CHECK_EQ(index.term_count(), std::size_t{37});
    CHECK_IDS(index.postings("tok36"), ids({0}));
}

TEST(InvertedIndex, AddCopesWithAHugeTextOfFewDistinctTokens) {
    std::string text;
    text.reserve(2000000);
    for (int i = 0; i < 1000000; ++i) text += "a ";
    InvertedIndex index;
    CHECK_EQ(index.add(text), DocId{0});
    CHECK_EQ(index.term_count(), std::size_t{1});
    CHECK_IDS(index.postings("A"), ids({0}));
    CHECK_EQ(index.add("b a"), DocId{1});
    CHECK_IDS(index.postings("a"), ids({0, 1}));

    const std::string one_giant_token(3000000, 'z');  // a single token longer than any buffer
    CHECK_EQ(index.add(one_giant_token), DocId{2});
    CHECK_IDS(index.postings(one_giant_token), ids({2}));
    CHECK_EQ(index.term_count(), std::size_t{3});
}

// ---- query cost -------------------------------------------------------------------------
// Costs are counted with the probe hook (one tick per element examined one by one by an
// intersection, a difference or a k-way merge; bulk copies do not tick), never timed.

namespace {

struct Counter {
    std::size_t* ticks;
    void operator()() const noexcept { ++*ticks; }
};

constexpr DocId kBigDocuments = 200000;

// 200,000 documents. Every one has "common"; the even ones also have "other"; five have "rare".
struct BigCorpus {
    InvertedIndex index;
    Ids rare;
    Ids even;
};

BigCorpus make_big_corpus() {
    BigCorpus corpus;
    const DocId rare_ids[] = {3, 70000, 100000, 150000, 199999};
    std::size_t next_rare = 0;
    for (DocId id = 0; id < kBigDocuments; ++id) {
        std::string text = "common";
        if (id % 2 == 0) {
            text += " other";
            corpus.even.push_back(id);
        }
        if (next_rare < 5 && rare_ids[next_rare] == id) {
            text += " rare";
            corpus.rare.push_back(id);
            ++next_rare;
        }
        corpus.index.add(text);
    }
    return corpus;
}

// Built once and shared by the tests below (they only read it).
const BigCorpus& big_corpus() {
    static const BigCorpus corpus = make_big_corpus();
    return corpus;
}

}  // namespace

TEST(IndexQueryCost, NegatedWordIsLookedUpNotScanned) {
    // "rare -common" used to copy common's whole postings list (a one-element union is a copy)
    // and then walk both lists linearly: 3.3 ms against 0.7 us for the equivalent galloping
    // intersection, with 200,000 documents it is still 1,000 times more work than needed.
    const BigCorpus& corpus = big_corpus();
    std::size_t ticks = 0;
    const Counter count{&ticks};
    const auto run = [&](std::string_view query) {
        ticks = 0;
        return InvertedIndexTestAccess::search(corpus.index, query, count);
    };

    CHECK_IDS(run("rare"), corpus.rare);
    CHECK_EQ(ticks, std::size_t{0});  // a single posting list is simply copied

    CHECK_IDS(run("rare -common"), ids({}));  // every rare document is also a common one
    CHECK(ticks > 0);
    CHECK(ticks < 500);
    CHECK_IDS(run("rare -other"), ids({3, 199999}));
    CHECK(ticks < 500);
    CHECK_IDS(run("-other rare"), ids({3, 199999}));  // word order is irrelevant
    CHECK(ticks < 500);
    CHECK_IDS(run("rare -common -other"), ids({}));
    CHECK(ticks < 1000);
    CHECK_IDS(run("rare -other|common"), ids({}));
    CHECK(ticks < 1000);
    CHECK_IDS(run("rare -nosuchterm"), corpus.rare);
    CHECK_EQ(ticks, std::size_t{0});  // an unknown negated word costs nothing at all
    CHECK_IDS(run("rare -common-other"), ids({3, 199999}));  // only documents with BOTH tokens are excluded
    CHECK(ticks < 1000);
}

TEST(IndexQueryCost, AlternativesAreIntersectedWithTheRunningResultNotUnitedFirst) {
    // "rare common|other" used to materialize the union of two 100,000+ lists (300,000 steps)
    // before looking at the five rare documents.
    const BigCorpus& corpus = big_corpus();
    std::size_t ticks = 0;
    const Counter count{&ticks};
    const auto run = [&](std::string_view query) {
        ticks = 0;
        return InvertedIndexTestAccess::search(corpus.index, query, count);
    };
    CHECK_IDS(run("rare common|other"), corpus.rare);
    CHECK(ticks > 0);
    CHECK(ticks < 1000);
    CHECK_IDS(run("common|other rare"), corpus.rare);
    CHECK(ticks < 1000);
    CHECK_IDS(run("rare other-rare"), ids({70000, 100000, 150000}));  // a multi-token alternative
    CHECK(ticks < 1000);
    CHECK_IDS(run("rare|other-rare common"), ids({3, 70000, 100000, 150000, 199999}));
    CHECK(ticks < 1000);
}

TEST(IndexQueryCost, NegatedOnlyQueriesReturnTheComplementOfTheUnion) {
    const BigCorpus& corpus = big_corpus();
    Ids not_rare;
    Ids odd_not_rare;
    for (DocId id = 0; id < kBigDocuments; ++id) {
        if (std::binary_search(corpus.rare.begin(), corpus.rare.end(), id)) continue;
        not_rare.push_back(id);
        if (id % 2 == 1) odd_not_rare.push_back(id);
    }
    CHECK_IDS(corpus.index.search("-rare"), not_rare);
    CHECK_IDS(corpus.index.search("-rare -nosuchterm"), not_rare);
    CHECK_IDS(corpus.index.search("-common"), ids({}));
    CHECK_EQ(corpus.index.search("-other").size(), std::size_t{kBigDocuments / 2});
    CHECK_IDS(corpus.index.search("-other|rare"), odd_not_rare);
    CHECK_IDS(corpus.index.search("-other -rare"), odd_not_rare);
    CHECK_IDS(corpus.index.search("-other-common -rare"), odd_not_rare);
}

TEST(IndexQueryCost, EqualPiecesOfAQueryAreEvaluatedOnce) {
    // A multi-token alternative used to be intersected afresh for every copy of it in the query
    // (and all the copies were kept alive at once): 40 copies of "a-b" cost 40 times as much and
    // 20,000 of them ran out of memory.
    InvertedIndex index;
    for (int i = 0; i < 20000; ++i) {
        static const char* const kTexts[] = {"a b", "a", "b", "c"};
        index.add(kTexts[i % 4]);
    }
    std::size_t ticks = 0;
    const Counter count{&ticks};
    const auto run = [&](const std::string& query) {
        ticks = 0;
        return InvertedIndexTestAccess::search(index, query, count);
    };
    Ids a_and_b;
    for (DocId id = 0; id < 20000; id += 4) a_and_b.push_back(id);

    CHECK_IDS(run("a-b"), a_and_b);
    const std::size_t single = ticks;
    CHECK(single > 1000);  // one real intersection of two long lists

    std::string alternatives = "a-b";
    for (int i = 0; i < 999; ++i) alternatives += (i % 3 == 0) ? "|B-a" : (i % 3 == 1) ? "|A_b" : "|a.b.a";
    CHECK_IDS(run(alternatives), a_and_b);
    CHECK_EQ(ticks, single);  // the same conjunction in any spelling, 1000 times: still one intersection
    CHECK_EQ(InvertedIndexTestAccess::distinct_required_words(index, alternatives), std::size_t{1});

    CHECK_IDS(run("a|b"), ref_union({index.postings("a"), index.postings("b")}));
    const std::size_t one_union = ticks;
    CHECK(one_union > 1000);
    std::string words;
    for (int i = 0; i < 2000; ++i) words += (i % 2 == 0) ? "a|b " : "B|A ";
    CHECK_IDS(run(words), ref_union({index.postings("a"), index.postings("b")}));
    CHECK_EQ(ticks, one_union);  // 2000 equal words, one union
    CHECK_EQ(InvertedIndexTestAccess::distinct_required_words(index, words), std::size_t{1});
    CHECK_EQ(InvertedIndexTestAccess::distinct_required_words(index, "a b|c a|b a"), std::size_t{3});

    // search_or goes through the same machinery.
    const Strings many(1000, "a-b");
    ticks = 0;
    CHECK_IDS(InvertedIndexTestAccess::search_or(index, many, count), a_and_b);
    CHECK_EQ(ticks, single);
    Strings mixed = many;
    mixed.push_back("B-A");
    mixed.push_back("c");
    ticks = 0;
    CHECK_IDS(InvertedIndexTestAccess::search_or(index, mixed, count), ref_union({a_and_b, index.postings("c")}));

    // Negated alternatives are merged the same way.
    CHECK_EQ(InvertedIndexTestAccess::distinct_excluded_alternatives(index, "c -a -A -a|a -b -a-b -B-A -c"), std::size_t{4});
    CHECK_IDS(index.search("a -a -A -a|a -b -a-b -B-A"), ids({}));
    CHECK_IDS(index.search("a|b|c -a-b -a-b"), index.search("a|b|c -b-a"));
}

TEST(IndexQueryCost, ARequiredWordThatMatchesNothingEndsTheSearchImmediately) {
    // The query used to be evaluated word by word to the end even though one required word
    // could not match anything: "zzz" plus 2,000 words took 0.87 s to return nothing.
    InvertedIndex index;
    for (int i = 0; i < 20000; ++i) index.add(i % 2 == 0 ? "a b" : "a");
    std::string tail;
    for (int i = 0; i < 2000; ++i) tail += (i % 2 == 0) ? "a|b " : "a-b ";
    std::size_t ticks = 0;
    const Counter count{&ticks};
    const std::vector<std::string> queries = {"zzz " + tail, tail + "zzz", tail + "-b zzz|yyy", "a zzz-a b",
                                              "a|zzz-b zzz-b"};
    for (const std::string& query : queries) {
        ticks = 0;
        CHECK_CTX(InvertedIndexTestAccess::search(index, query, count).empty(), query.substr(0, 40));
        CHECK_CTX(ticks == 0, query.substr(0, 40));
        CHECK_CTX(InvertedIndexTestAccess::query_is_impossible(index, query), query.substr(0, 40));
    }
    // An unknown alternative or an unknown negated word is harmless, though.
    CHECK(!InvertedIndexTestAccess::query_is_impossible(index, "a|zzz"));
    CHECK(!InvertedIndexTestAccess::query_is_impossible(index, "a -zzz"));
    CHECK(!InvertedIndexTestAccess::query_is_impossible(index, "-zzz"));
    CHECK_EQ(index.search("a|zzz").size(), std::size_t{20000});
}

TEST(IndexQueryCost, RequiredWordsRunCheapestFirstWhateverTheirOrder) {
    InvertedIndex index;
    for (int i = 0; i < 100000; ++i) index.add((i == 7 || i == 50000 || i == 99999) ? "a b c" : "a b");
    std::size_t ticks = 0;
    const Counter count{&ticks};
    Strings words = {"a", "b", "c"};
    std::size_t reference_ticks = 0;
    do {
        const std::string query = words[0] + " " + words[1] + " " + words[2];
        ticks = 0;
        CHECK_IDS_CTX(InvertedIndexTestAccess::search(index, query, count), ids({7, 50000, 99999}), query);
        CHECK_CTX(ticks < 1000, query);
        if (reference_ticks == 0) reference_ticks = ticks;
        CHECK_CTX(ticks == reference_ticks, query);
    } while (std::next_permutation(words.begin(), words.end()));

    // With an alternative in the middle: the union of a and b (200,000 steps) is never built.
    for (const char* query : {"a|b c", "c a|b", "a|b c a|b", "c a|b b|a"}) {
        ticks = 0;
        CHECK_IDS_CTX(InvertedIndexTestAccess::search(index, query, count), ids({7, 50000, 99999}), query);
        CHECK_CTX(ticks < 1000, query);
    }
}

TEST(IndexSetOps, UniteMergesEqualSpansOnce) {
    // The pointer-identity dedupe inside the k-way merge has no visible effect on results, so the
    // probe is the only way to see it: the same list named k times is merged as one list.
    Rng rng_a(9201);
    Rng rng_b(9202);
    const Ids list = random_list(rng_a, 500, 0, 5000);
    const loganalyzer::detail::Span span = loganalyzer::detail::span_of(list);
    std::size_t ticks = 0;
    CHECK_IDS(loganalyzer::detail::unite_spans({span, span, span, span}, Counter{&ticks}), list);
    CHECK_EQ(ticks, std::size_t{0});  // a single live span is copied, not merged

    const Ids other = random_list(rng_b, 300, 0, 5000);
    const loganalyzer::detail::Span other_span = loganalyzer::detail::span_of(other);
    ticks = 0;
    const Ids merged = loganalyzer::detail::unite_spans({span, other_span, span, other_span, span}, Counter{&ticks});
    CHECK_IDS(merged, ref_union({list, other}));
    CHECK_EQ(ticks, list.size() + other.size());  // each element of each distinct list, once
}

// ---- UnionAccumulator --------------------------------------------------------------------

TEST(IndexSetOps, UnionAccumulatorMatchesTheUnionAndStaysShallow) {
    using Accumulator = loganalyzer::detail::UnionAccumulator<loganalyzer::detail::NoProbe>;
    Rng rng(8001);
    for (int round = 0; round < 300; ++round) {
        const DocId base = (round % 2 == 0) ? 0 : kMax - 2000;
        Accumulator accumulator{loganalyzer::detail::NoProbe{}};
        std::vector<Ids> parts;
        const std::uint32_t k = rng.below(60);
        for (std::uint32_t i = 0; i < k; ++i) {
            parts.push_back(random_list(rng, rng.below(4) == 0 ? 0 : rng.below(300), base, 1000));
            accumulator.add(parts.back());
            CHECK(accumulator.pending() <= 12);
        }
        CHECK_IDS_CTX(accumulator.take(), ref_union(parts), "round " + std::to_string(round));
        CHECK_EQ(accumulator.pending(), std::size_t{0});
        CHECK_IDS(accumulator.take(), ids({}));  // empty after take
    }

    // Many equal parts never pile up: they merge into one list as they arrive.
    Accumulator equal{loganalyzer::detail::NoProbe{}};
    Ids block;
    for (DocId i = 0; i < 500; ++i) block.push_back(i * 3);
    for (int i = 0; i < 2000; ++i) {
        equal.add(block);
        CHECK(equal.pending() <= 2);
    }
    CHECK_IDS(equal.take(), block);

    // Twenty thousand one-element parts: the stack stays about log2(20000) deep, not 20000.
    Accumulator singles{loganalyzer::detail::NoProbe{}};
    std::size_t deepest = 0;
    Ids expected;
    for (DocId i = 0; i < 20000; ++i) {
        const DocId id = (i % 2 == 0) ? i : 40000 - i;  // alternating ends: not simply ascending
        singles.add(Ids{id});
        expected.push_back(id);
        deepest = std::max(deepest, singles.pending());
    }
    std::sort(expected.begin(), expected.end());
    CHECK(deepest <= 17);
    CHECK_IDS(singles.take(), expected);
}

// ---- remaining nits ----------------------------------------------------------------------

TEST(IndexSearch, EveryQueryWhitespaceCharacterSeparatesWords) {
    // Dropping '\f', '\v' or '\r' from the whitespace set changed nothing in any other test:
    // those characters are token separators anyway, so only a '-' or '|' next to them can tell.
    InvertedIndex index;
    index.add("a");      // 0
    index.add("a b");    // 1
    index.add("b");      // 2
    for (const char space : {' ', '\t', '\n', '\v', '\f', '\r'}) {
        const std::string ctx = "character " + std::to_string(static_cast<int>(space));
        CHECK_IDS_CTX(index.search(std::string("a") + space + "-b"), ids({0}), ctx);   // a AND NOT b
        CHECK_IDS_CTX(index.search(std::string("-b") + space + "a"), ids({0}), ctx);
        CHECK_IDS_CTX(index.search(std::string("a") + space + "|b"), ids({1}), ctx);   // a AND b (the word "|b")
        CHECK_IDS_CTX(index.search(std::string("a") + space + space + "b"), ids({1}), ctx);
        CHECK_IDS_CTX(index.search(std::string(1, space) + "-a" + space), ids({2}), ctx);
    }
    // Other control characters are plain separators INSIDE a word, not word boundaries.
    for (const char control : {'\x01', '\x1f', '\x7f', '\0'}) {
        const std::string joined = std::string("a") + control + "-b";  // one word: the alternative "a-b"
        CHECK_IDS_CTX(index.search(std::string_view(joined)), ids({1}), std::to_string(static_cast<int>(control)));
    }
}

TEST(InvertedIndex, CapacityAboveTheIdSpaceIsClamped) {
    // The wrap-around the clamp prevents needs 2^32 adds, so it cannot be provoked through add():
    // look at the capacity itself.
    CHECK_EQ(InvertedIndexTestAccess::capacity(InvertedIndex()), InvertedIndex::kMaxDocuments);
    CHECK_EQ(InvertedIndexTestAccess::capacity(InvertedIndex(std::numeric_limits<std::uint64_t>::max())),
             InvertedIndex::kMaxDocuments);
    CHECK_EQ(InvertedIndexTestAccess::capacity(InvertedIndex(InvertedIndex::kMaxDocuments + 1)),
             InvertedIndex::kMaxDocuments);
    CHECK_EQ(InvertedIndexTestAccess::capacity(InvertedIndex(InvertedIndex::kMaxDocuments)),
             InvertedIndex::kMaxDocuments);
    CHECK_EQ(InvertedIndexTestAccess::capacity(InvertedIndex(7)), std::uint64_t{7});
    CHECK_EQ(InvertedIndexTestAccess::capacity(InvertedIndex(0)), std::uint64_t{0});
}

// ---- larger randomized comparisons -------------------------------------------------------

TEST(IndexSearch, ManyMultiTokenAlternativesMatchBruteForce) {
    // Words made of dozens of "ti-tj" alternatives, the way the union accumulator is exercised
    // (owned intersections arriving one after another), required and negated, against a scan.
    Rng rng(9101);
    const std::uint32_t vocabulary = 24;
    InvertedIndex index;
    std::vector<std::uint32_t> masks;
    for (int d = 0; d < 3000; ++d) {
        std::uint32_t mask = 0;
        std::string text;
        for (std::uint32_t w = 0; w < vocabulary; ++w) {
            if (!rng.chance(0.18)) continue;
            mask |= std::uint32_t{1} << w;
            text += "T" + std::to_string(w) + " ";
        }
        index.add(text);
        masks.push_back(mask);
    }

    // An alternative is a set of 1..3 vocabulary words, spelled with random separators.
    struct Alternative {
        std::uint32_t need = 0;
        std::string text;
    };
    const auto make_alternative = [&]() {
        Alternative alt;
        const std::uint32_t tokens = 1 + rng.below(3);
        for (std::uint32_t i = 0; i < tokens; ++i) {
            const std::uint32_t w = rng.below(vocabulary);
            alt.need |= std::uint32_t{1} << w;
            if (i != 0) alt.text += (rng.below(2) == 0) ? "-" : ".";
            alt.text += (rng.below(2) == 0) ? "t" : "T";
            alt.text += std::to_string(w);
        }
        return alt;
    };
    using Word = std::vector<Alternative>;
    const auto word_hits = [](const Word& word, std::uint32_t mask) {
        for (const Alternative& alt : word) {
            if ((mask & alt.need) == alt.need) return true;
        }
        return false;
    };
    const auto word_text = [](const Word& word, bool negated) {
        std::string text = negated ? "-" : "";
        for (std::size_t i = 0; i < word.size(); ++i) text += (i == 0 ? "" : "|") + word[i].text;
        return text;
    };

    int non_empty = 0;
    for (int q = 0; q < 150; ++q) {
        std::vector<Word> required(1 + rng.below(3));
        std::vector<Word> forbidden(rng.below(3));
        for (Word& word : required) {
            word.resize(1 + rng.below(rng.below(3) == 0 ? 120 : 8));
            for (Alternative& alt : word) alt = make_alternative();
        }
        for (Word& word : forbidden) {
            word.resize(1 + rng.below(40));
            for (Alternative& alt : word) alt = make_alternative();
        }
        std::string query;
        for (const Word& word : required) query += word_text(word, false) + " ";
        for (const Word& word : forbidden) query += word_text(word, true) + " ";

        Ids expected;
        Ids expected_or;
        for (std::size_t d = 0; d < masks.size(); ++d) {
            bool keep = true;
            for (const Word& word : required) keep = keep && word_hits(word, masks[d]);
            for (const Word& word : forbidden) keep = keep && !word_hits(word, masks[d]);
            if (keep) expected.push_back(static_cast<DocId>(d));
            if (word_hits(required.front(), masks[d])) expected_or.push_back(static_cast<DocId>(d));
        }
        CHECK_IDS_CTX(index.search(query), expected, "query <" + query.substr(0, 200) + ">");
        Strings or_terms;
        for (const Alternative& alt : required.front()) or_terms.push_back(alt.text);
        CHECK_IDS_CTX(index.search_or(or_terms), expected_or, "OR of <" + query.substr(0, 200) + ">");
        non_empty += expected.empty() ? 0 : 1;
    }
    CHECK(non_empty > 40);
}

TEST(IndexSearch, LongFuzzedQueriesMatchAnIndependentReference) {
    // A second pass of the byte-level fuzz with longer documents and queries over the same
    // small alphabet: many repeated words, alternatives and negations in every query.
    Rng rng(7002);
    InvertedIndex index;
    std::vector<TokenSet> docs;
    for (int d = 0; d < 400; ++d) {
        const std::string text = random_string(rng, 30);
        const Strings tokens = ref_tokens(text);
        index.add(text);
        docs.emplace_back(tokens.begin(), tokens.end());
    }
    int non_empty = 0;
    for (int q = 0; q < 1500; ++q) {
        const std::string query = random_string(rng, 70);
        const Ids expected = ref_query(docs, query);
        CHECK_IDS_CTX(index.search(query), expected, "query <" + escaped(query) + ">");
        non_empty += expected.empty() ? 0 : 1;
    }
    CHECK(non_empty > 100);
}
