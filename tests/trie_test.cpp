#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <limits>
#include <map>
#include <random>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "loganalyzer/trie.hpp"
#include "testkit.hpp"

using loganalyzer::Completion;
using loganalyzer::Trie;

namespace {

constexpr std::size_t kAll = std::numeric_limits<std::size_t>::max();

// ---- helpers: byte strings --------------------------------------------------------

std::string bytes(std::initializer_list<int> values) {
    std::string s;
    for (const int v : values) s.push_back(static_cast<char>(v));
    return s;
}

// Explicitly unsigned, so the reference does not depend on the same char_traits trick
// the implementation relies on.
bool bytes_less(const std::string& a, const std::string& b) {
    const std::size_t n = std::min(a.size(), b.size());
    for (std::size_t i = 0; i < n; ++i) {
        const auto x = static_cast<unsigned char>(a[i]);
        const auto y = static_cast<unsigned char>(b[i]);
        if (x != y) return x < y;
    }
    return a.size() < b.size();
}

bool starts_with(const std::string& s, const std::string& prefix) {
    return s.size() >= prefix.size() && std::equal(prefix.begin(), prefix.end(), s.begin());
}

std::string escape(const std::string& s) {
    static const char* const hex = "0123456789abcdef";
    std::string out;
    for (const char c : s) {
        const auto b = static_cast<unsigned char>(c);
        if (b >= 0x20 && b < 0x7f && b != '\\') {
            out += c;
        } else {
            out += "\\x";
            out += hex[b >> 4];
            out += hex[b & 15];
        }
    }
    return out;
}

std::string render(const std::vector<Completion>& completions) {
    std::string out = "[";
    for (std::size_t i = 0; i < completions.size(); ++i) {
        if (i != 0) out += ", ";
        out += escape(completions[i].key) + ":" + std::to_string(completions[i].weight);
    }
    return out + "]";
}

// ---- brute-force reference --------------------------------------------------------

using Reference = std::map<std::string, std::uint64_t>;
using Order = std::vector<const Reference::value_type*>;

// Every key with the prefix, best first: weight descending, then key ascending (unsigned).
Order reference_order(const Reference& ref, const std::string& prefix) {
    Order order;
    for (const auto& entry : ref) {
        if (starts_with(entry.first, prefix)) order.push_back(&entry);
    }
    std::sort(order.begin(), order.end(), [](const Reference::value_type* a, const Reference::value_type* b) {
        if (a->second != b->second) return a->second > b->second;
        return bytes_less(a->first, b->first);
    });
    return order;
}

std::vector<Completion> take(const Order& order, std::size_t k) {
    std::vector<Completion> out;
    const std::size_t n = std::min(k, order.size());
    for (std::size_t i = 0; i < n; ++i) out.push_back(Completion{order[i]->first, order[i]->second});
    return out;
}

std::vector<Completion> reference_complete(const Reference& ref, const std::string& prefix, std::size_t k) {
    return take(reference_order(ref, prefix), k);
}

// Empty string when the results agree, a readable diff otherwise (so CHECK_EQ prints it).
std::string mismatch(const std::vector<Completion>& got, const std::vector<Completion>& want,
                     const std::string& context) {
    if (got == want) return std::string();
    return context + "\n  got:  " + render(got) + "\n  want: " + render(want);
}

void expect_same(const std::vector<Completion>& got, const std::vector<Completion>& want,
                 std::uint64_t seed, const std::string& prefix, std::size_t k) {
    if (got == want) return;
    const std::string context = "seed=" + std::to_string(seed) + " prefix='" + escape(prefix) +
                                "' k=" + (k == kAll ? std::string("ALL") : std::to_string(k));
    CHECK_EQ(mismatch(got, want, context), std::string());
}

void expect_complete(const Trie& trie, const Reference& ref, const std::string& prefix, std::size_t k,
                     std::uint64_t seed) {
    expect_same(trie.complete(prefix, k), reference_complete(ref, prefix, k), seed, prefix, k);
}

// ---- deterministic randomness -----------------------------------------------------
// mt19937_64 is fully specified and `% n` is too (std::uniform_int_distribution is not), so
// a failing seed reproduces the same sequence on every standard library.

std::size_t below(std::mt19937_64& rng, std::size_t n) { return static_cast<std::size_t>(rng() % n); }

std::string random_key(std::mt19937_64& rng, const std::string& alphabet, std::size_t max_len) {
    const std::size_t len = 1 + below(rng, max_len);
    std::string key;
    for (std::size_t i = 0; i < len; ++i) key.push_back(alphabet[below(rng, alphabet.size())]);
    return key;
}

// Mostly small so that ties are everywhere, sometimes 0, occasionally a big jump that
// reshuffles the caches.
std::uint64_t random_weight(std::mt19937_64& rng) {
    const std::size_t r = below(rng, 20);
    if (r == 0) return 0;
    if (r == 1) return 1000 + below(rng, 1000);
    return 1 + below(rng, 4);
}

std::string random_prefix(std::mt19937_64& rng, const std::vector<std::string>& seen,
                          const std::string& alphabet, std::size_t max_len) {
    const std::size_t r = below(rng, 10);
    if (r < 5 && !seen.empty()) {
        const std::string& key = seen[below(rng, seen.size())];
        return key.substr(0, below(rng, key.size() + 1));
    }
    if (r < 8) {
        std::string prefix;
        const std::size_t len = below(rng, max_len + 2);
        for (std::size_t i = 0; i < len; ++i) prefix.push_back(alphabet[below(rng, alphabet.size())]);
        return prefix;
    }
    return std::string();
}

std::size_t random_k(std::mt19937_64& rng, std::size_t cached_k) {
    const std::size_t choices[] = {0, 1, 2, cached_k, cached_k + 1, 2 * cached_k + 3, 500};
    return choices[below(rng, sizeof(choices) / sizeof(choices[0]))];
}

std::string full_alphabet() {
    std::string all;
    for (int b = 0; b < 256; ++b) all.push_back(static_cast<char>(b));
    return all;
}

// Builds a Trie and a Reference side by side from `inserts` random insertions, comparing
// them while the trie is still growing (the caches are only interesting mid-flight) and
// then exhaustively over every prefix of every key.
void run_scenario(std::uint64_t seed, std::size_t cached_k, const std::string& alphabet,
                  std::size_t max_len, std::size_t inserts) {
    std::mt19937_64 rng(seed);
    Trie trie(cached_k);
    Reference ref;
    std::vector<std::string> seen;
    seen.reserve(inserts);

    for (std::size_t i = 0; i < inserts; ++i) {
        std::string key = random_key(rng, alphabet, max_len);
        const std::uint64_t w = random_weight(rng);
        trie.insert(key, w);
        ref[key] += w;  // operator[] creates the key at 0 first, like a weight-0 insert
        seen.push_back(std::move(key));
        if (i % 8 == 7) {
            for (int q = 0; q < 4; ++q) {
                expect_complete(trie, ref, random_prefix(rng, seen, alphabet, max_len),
                                random_k(rng, cached_k), seed);
            }
        }
    }

    CHECK_EQ(trie.size(), ref.size());
    for (const auto& entry : ref) {
        CHECK(trie.contains(entry.first));
        CHECK_EQ(trie.weight(entry.first), entry.second);
    }

    std::set<std::string> prefixes{std::string()};
    for (const auto& entry : ref) {
        for (std::size_t len = 1; len <= entry.first.size(); ++len) prefixes.insert(entry.first.substr(0, len));
    }
    prefixes.insert(alphabet.substr(0, 1) + alphabet.substr(0, 1) + alphabet.substr(0, 1) + "zz");  // absent
    const std::size_t ks[] = {1, 2, cached_k, cached_k + 1, 3 * cached_k + 1, 1000, kAll};
    for (const std::string& prefix : prefixes) {
        const Order order = reference_order(ref, prefix);
        for (const std::size_t k : ks) {
            expect_same(trie.complete(prefix, k), take(order, k), seed, prefix, k);
        }
    }
}

const std::size_t kCachedKs[] = {1, 2, 3, 4, 8, 64, 1000};  // 1000 > any key count used here

}  // namespace

// ---- basics -----------------------------------------------------------------------

TEST(Trie, EmptyTrieAnswersEverythingWithNothing) {
    Trie t;
    CHECK_EQ(t.size(), std::size_t{0});
    CHECK(!t.contains("a"));
    CHECK(!t.contains(""));
    CHECK_EQ(t.weight("a"), std::uint64_t{0});
    CHECK(t.complete("", 5).empty());
    CHECK(t.complete("a", 5).empty());
    CHECK(t.complete("", kAll).empty());
    t.clear();  // clearing an empty trie is fine
    CHECK_EQ(t.size(), std::size_t{0});
}

TEST(Trie, ConstructorAndInsertValidateArguments) {
    CHECK_THROWS(Trie(0), std::invalid_argument);
    Trie t(1);
    CHECK_EQ(t.cached_k(), std::size_t{1});
    CHECK_EQ(Trie().cached_k(), std::size_t{10});
    CHECK_THROWS(t.insert(""), std::invalid_argument);
    CHECK_THROWS(t.insert(std::string_view(), 5), std::invalid_argument);
    CHECK_EQ(t.size(), std::size_t{0});
    CHECK(t.complete("", 5).empty());
    t.insert("ok");  // still fully usable after the failed attempts
    CHECK(t.contains("ok"));
}

TEST(Trie, OrdersByWeightDescendingThenKeyAscending) {
    Trie t(10);
    t.insert("apple", 3);
    t.insert("app", 5);
    t.insert("apply", 3);
    t.insert("apt", 3);
    t.insert("banana", 10);
    CHECK_EQ(render(t.complete("ap", 10)), std::string("[app:5, apple:3, apply:3, apt:3]"));
    CHECK_EQ(render(t.complete("", 10)), std::string("[banana:10, app:5, apple:3, apply:3, apt:3]"));
    CHECK_EQ(render(t.complete("ap", 2)), std::string("[app:5, apple:3]"));
    CHECK_EQ(render(t.complete("b", 1)), std::string("[banana:10]"));
}

TEST(Trie, AKeyIsACompletionOfItselfAndMissesAreEmpty) {
    Trie t(3);
    t.insert("apple", 2);
    t.insert("app", 1);
    CHECK_EQ(render(t.complete("app", 5)), std::string("[apple:2, app:1]"));
    CHECK_EQ(render(t.complete("apple", 5)), std::string("[apple:2]"));
    CHECK(t.complete("applesauce", 5).empty());  // longer than every key
    CHECK(t.complete("appx", 5).empty());         // diverges inside the trie
    CHECK(t.complete("zzz", 5).empty());          // first byte unknown
    CHECK(t.contains("app"));
    CHECK(!t.contains("ap"));  // a prefix of a key is not itself a key
    CHECK(!t.contains("apples"));
}

TEST(Trie, KZeroIsEmptyAndKBeyondMatchesReturnsAllMatches) {
    Trie t(2);
    for (const char* key : {"a", "ab", "abc", "b"}) t.insert(key, 1);
    CHECK(t.complete("", 0).empty());
    CHECK(t.complete("a", 0).empty());
    CHECK_EQ(t.complete("a", 3).size(), std::size_t{3});
    CHECK_EQ(t.complete("a", 4).size(), std::size_t{3});     // k > matches, k > K
    CHECK_EQ(t.complete("a", 1000).size(), std::size_t{3});
    CHECK_EQ(t.complete("", kAll).size(), std::size_t{4});   // k = SIZE_MAX must not allocate k slots
    CHECK_EQ(t.complete("b", 2).size(), std::size_t{1});     // k <= K but only one match
}

TEST(Trie, RepeatedInsertAccumulatesWeight) {
    Trie t(3);
    for (int i = 0; i < 5; ++i) t.insert("x");  // default weight 1
    CHECK_EQ(t.weight("x"), std::uint64_t{5});
    CHECK_EQ(t.size(), std::size_t{1});
    t.insert("x", 10);
    CHECK_EQ(t.weight("x"), std::uint64_t{15});
    CHECK_EQ(render(t.complete("", 5)), std::string("[x:15]"));

    t.insert("y", 20);
    CHECK_EQ(render(t.complete("", 5)), std::string("[y:20, x:15]"));
    t.insert("x", 6);  // x overtakes y; the cache must be re-sorted, not just updated
    CHECK_EQ(render(t.complete("", 5)), std::string("[x:21, y:20]"));
    CHECK_EQ(t.size(), std::size_t{2});
}

TEST(Trie, ZeroWeightCreatesTheKeyAndRanksLast) {
    Trie t(3);
    t.insert("zero", 0);
    CHECK(t.contains("zero"));
    CHECK_EQ(t.size(), std::size_t{1});
    CHECK_EQ(t.weight("zero"), std::uint64_t{0});
    CHECK_EQ(render(t.complete("", 5)), std::string("[zero:0]"));

    t.insert("one", 1);
    CHECK_EQ(render(t.complete("", 5)), std::string("[one:1, zero:0]"));
    t.insert("alpha", 0);
    CHECK_EQ(render(t.complete("", 5)), std::string("[one:1, alpha:0, zero:0]"));  // 0-ties by key

    t.insert("zero", 0);  // adding nothing to an existing key changes nothing
    CHECK_EQ(t.size(), std::size_t{3});
    CHECK_EQ(render(t.complete("", 5)), std::string("[one:1, alpha:0, zero:0]"));
    t.insert("zero", 2);
    CHECK_EQ(render(t.complete("", 5)), std::string("[zero:2, one:1, alpha:0]"));
    CHECK(!t.contains("absent"));
    CHECK_EQ(t.weight("absent"), std::uint64_t{0});
}

TEST(Trie, TiesAreBrokenByKeyAscending) {
    Trie t(3);
    for (const char* key : {"pear", "peach", "pea", "apple", "peak"}) t.insert(key, 4);
    CHECK_EQ(render(t.complete("pea", 10)), std::string("[pea:4, peach:4, peak:4, pear:4]"));  // k > K
    CHECK_EQ(render(t.complete("pea", 3)), std::string("[pea:4, peach:4, peak:4]"));          // k == K
    CHECK_EQ(render(t.complete("pea", 2)), std::string("[pea:4, peach:4]"));                  // k < K
    CHECK_EQ(render(t.complete("", 10)), std::string("[apple:4, pea:4, peach:4, peak:4, pear:4]"));
}

TEST(Trie, KeyEvictedFromACacheComesBackThroughItsOwnInsert) {
    Trie t(2);
    t.insert("a", 10);
    t.insert("b", 9);
    t.insert("c", 1);
    CHECK_EQ(render(t.complete("", 2)), std::string("[a:10, b:9]"));  // c is not cached at the root
    t.insert("c", 20);                                                // c:21 pushes b out
    CHECK_EQ(render(t.complete("", 2)), std::string("[c:21, a:10]"));
    CHECK_EQ(render(t.complete("", 3)), std::string("[c:21, a:10, b:9]"));  // k > K: scan
    t.insert("b", 100);                                               // b:109 re-enters, pushes a out
    CHECK_EQ(render(t.complete("", 2)), std::string("[b:109, c:21]"));
    CHECK_EQ(render(t.complete("", 3)), std::string("[b:109, c:21, a:10]"));
}

TEST(Trie, InsertCopiesTheKeyBytes) {
    Trie t;
    std::string s = "hello";
    t.insert(s);
    s[0] = 'j';
    CHECK(t.contains("hello"));
    CHECK(!t.contains("jello"));
    t.insert(std::string_view("abcdef", 3));  // a view into a longer buffer: only "abc"
    CHECK(t.contains("abc"));
    CHECK(!t.contains("abcd"));
}

// ---- cache size versus k ----------------------------------------------------------

TEST(Trie, CachedKOneStillGivesExactAnswersForEveryK) {
    Trie t(1);
    Reference ref;
    const char* keys[] = {"car", "card", "care", "cart", "cat", "dog", "do", "d"};
    std::uint64_t w = 1;
    for (const char* key : keys) {
        t.insert(key, w);
        ref[key] += w;
        w = (w * 7) % 5 + 1;  // 1, 3, 2, 1... a few ties and a few distinct values
    }
    for (const std::string prefix : {"", "c", "ca", "car", "d", "do", "x"}) {
        for (std::size_t k = 0; k <= 10; ++k) expect_complete(t, ref, prefix, k, 0);
    }
}

TEST(Trie, CachedKLargerThanKeyCountReturnsEverythingFromTheCache) {
    Trie t(100);
    Reference ref;
    std::mt19937_64 rng(42);
    for (int i = 0; i < 12; ++i) {
        const std::string key = random_key(rng, "abc", 4);
        const std::uint64_t w = random_weight(rng);
        t.insert(key, w);
        ref[key] += w;
    }
    for (const std::string prefix : {"", "a", "b", "ab", "abc", "cc"}) {
        for (std::size_t k = 0; k <= 15; ++k) expect_complete(t, ref, prefix, k, 42);
    }
}

TEST(Trie, KAboveAndBelowCachedKOnTheSameTrie) {
    Trie t(3);
    Reference ref;
    // Twelve keys below "p" with distinct weights, so every rank is unambiguous.
    for (int i = 0; i < 12; ++i) {
        const std::string key = "p" + std::string(1, static_cast<char>('a' + i));
        const std::uint64_t w = static_cast<std::uint64_t>((i * 5) % 12) + 1;
        t.insert(key, w);
        ref[key] += w;
    }
    t.insert("q", 100);
    ref["q"] += 100;
    for (std::size_t k = 0; k <= 16; ++k) {
        expect_complete(t, ref, "p", k, 7);
        expect_complete(t, ref, "", k, 7);
    }
    CHECK_EQ(t.complete("p", 12).back().weight, std::uint64_t{1});
}

TEST(Trie, HugeCachedKIsClampedNotOverflowed) {
    Trie t(kAll);
    Reference ref;
    std::mt19937_64 rng(5);
    for (int i = 0; i < 100; ++i) {
        const std::string key = random_key(rng, "abcd", 5);
        const std::uint64_t w = random_weight(rng);
        t.insert(key, w);
        ref[key] += w;
    }
    for (const std::string prefix : {"", "a", "ab", "dd"}) {
        for (const std::size_t k : {std::size_t{1}, std::size_t{10}, std::size_t{200}, kAll}) {
            expect_complete(t, ref, prefix, k, 5);
        }
    }
    CHECK_EQ(t.cached_k(), kAll);
}

TEST(Trie, CachePathAndScanPathAgreeOnTheSameData) {
    // Same inserts into K=1 (answers any k >= 2 by DFS + heap) and K=5000 (answers every
    // query from the cache). They must be indistinguishable.
    Trie scan(1);
    Trie cached(5000);
    std::mt19937_64 rng(2024);
    std::vector<std::string> seen;
    for (int i = 0; i < 3000; ++i) {
        std::string key = random_key(rng, "abcde", 6);
        const std::uint64_t w = random_weight(rng);
        scan.insert(key, w);
        cached.insert(key, w);
        seen.push_back(std::move(key));
    }
    CHECK_EQ(scan.size(), cached.size());
    for (int q = 0; q < 300; ++q) {
        const std::string prefix = random_prefix(rng, seen, "abcde", 6);
        const std::size_t k = random_k(rng, 1) * (1 + below(rng, 20));
        const std::vector<Completion> a = scan.complete(prefix, k);
        const std::vector<Completion> b = cached.complete(prefix, k);
        expect_same(a, b, 2024, prefix, k);
    }
}

// ---- bytes ------------------------------------------------------------------------

TEST(Trie, KeysAreOrderedAndIndexedAsUnsignedBytes) {
    // Expected order with all weights equal: strictly by unsigned byte value, so 0x80 and
    // 0xff come AFTER 'z', and a key with an embedded NUL sorts right after its prefix.
    const std::vector<std::string> expected = {
        "a",
        bytes({'a', 0}),
        bytes({'a', 0, 'b'}),
        bytes({'a', 0x7f}),
        bytes({'a', 0x80}),
        "z",
        bytes({0x7f}),
        bytes({0x80}),
        bytes({0xc3, 0xa9}),
        bytes({0xff}),
    };
    for (const std::size_t cached_k : {std::size_t{1}, std::size_t{3}, std::size_t{100}}) {
        Trie t(cached_k);
        for (auto it = expected.rbegin(); it != expected.rend(); ++it) t.insert(*it, 1);  // reverse order in
        CHECK_EQ(t.size(), expected.size());
        const std::vector<Completion> all = t.complete("", 100);
        CHECK_EQ(all.size(), expected.size());
        for (std::size_t i = 0; i < expected.size(); ++i) CHECK(all[i].key == expected[i]);
        for (const std::string& key : expected) {
            CHECK(t.contains(key));
            CHECK_EQ(t.weight(key), std::uint64_t{1});
        }
    }
}

TEST(Trie, EmbeddedNulIsAnOrdinaryByteInKeysAndPrefixes) {
    Trie t(2);
    t.insert(bytes({'a'}), 1);
    t.insert(bytes({'a', 0}), 2);
    t.insert(bytes({'a', 0, 'b'}), 3);
    t.insert(bytes({'a', 'b'}), 4);
    CHECK_EQ(render(t.complete(bytes({'a', 0}), 10)), std::string("[a\\x00b:3, a\\x00:2]"));
    CHECK_EQ(render(t.complete(bytes({'a', 0, 'b'}), 10)), std::string("[a\\x00b:3]"));
    CHECK(t.complete(bytes({'a', 0, 'c'}), 10).empty());
    CHECK(t.complete(bytes({0}), 10).empty());
    CHECK(!t.contains(bytes({'a', 0, 'b', 0})));
    CHECK_EQ(t.complete("a", 10).size(), std::size_t{4});
    // std::string_view("a\0b") would stop at the NUL if built from a C string: size matters.
    CHECK_EQ(t.weight(std::string_view("a\0b", 3)), std::uint64_t{3});
    CHECK_EQ(t.weight(std::string_view("a\0b", 1)), std::uint64_t{1});
}

TEST(Trie, AllTwoHundredFiftySixSingleByteKeysSortNumerically) {
    std::vector<int> order;
    for (int b = 0; b < 256; ++b) order.push_back(b);
    std::mt19937_64 rng(99);
    for (std::size_t i = order.size() - 1; i > 0; --i) std::swap(order[i], order[below(rng, i + 1)]);

    Trie t(10);
    for (const int b : order) t.insert(std::string(1, static_cast<char>(b)), 1);
    CHECK_EQ(t.size(), std::size_t{256});

    const std::vector<Completion> all = t.complete("", 256);  // k > K: scan over a 256-way root
    CHECK_EQ(all.size(), std::size_t{256});
    for (std::size_t i = 0; i < all.size(); ++i) {
        CHECK_EQ(all[i].key.size(), std::size_t{1});
        CHECK_EQ(static_cast<unsigned>(static_cast<unsigned char>(all[i].key[0])), static_cast<unsigned>(i));
    }
    const std::vector<Completion> head = t.complete("", 10);  // straight from the root cache
    for (std::size_t i = 0; i < head.size(); ++i) {
        CHECK_EQ(static_cast<unsigned>(static_cast<unsigned char>(head[i].key[0])), static_cast<unsigned>(i));
    }
    for (int b = 0; b < 256; ++b) CHECK(t.contains(std::string(1, static_cast<char>(b))));
    CHECK(!t.contains(std::string(2, '\xff')));
}

// ---- randomized comparison against the brute-force reference -----------------------

TEST(Trie, RandomizedSmallAlphabetsMatchBruteForce) {
    for (std::uint64_t seed = 1; seed <= 70; ++seed) {
        const std::string alphabet = (seed % 2 == 0) ? "ab" : "abc";
        run_scenario(seed, kCachedKs[seed % 7], alphabet, 7, 40 + (seed * 7) % 160);
    }
}

TEST(Trie, RandomizedBinaryKeysWithNulsAndHighBytesMatchBruteForce) {
    for (std::uint64_t seed = 101; seed <= 150; ++seed) {
        const std::string alphabet = (seed % 2 == 0) ? bytes({'a', 0, 0x80, 0xff}) : bytes({0, 1, 0xfe, 0xff});
        run_scenario(seed, kCachedKs[seed % 7], alphabet, 6, 40 + (seed * 11) % 160);
    }
}

TEST(Trie, RandomizedWideFanOutMatchesBruteForce) {
    const std::string alphabet = full_alphabet();
    for (std::uint64_t seed = 201; seed <= 220; ++seed) {
        run_scenario(seed, kCachedKs[seed % 7], alphabet, 2, 300);  // up to 256 children per node
    }
}

TEST(Trie, LargeSkewedWorkloadMatchesBruteForce) {
    std::mt19937_64 rng(777);
    Trie t(10);
    Reference ref;
    const std::string alphabet = "abcdef";
    std::vector<std::string> seen;
    for (int i = 0; i < 20000; ++i) {
        // Zipf-ish: most inserts hit a small hot set, like log tokens do.
        const bool hot = below(rng, 4) != 0;
        std::string key = hot ? random_key(rng, "ab", 5) : random_key(rng, alphabet, 9);
        const std::uint64_t w = 1 + below(rng, hot ? 50 : 3);
        t.insert(key, w);
        ref[key] += w;
        if (i % 4 == 0) seen.push_back(std::move(key));
    }
    CHECK_EQ(t.size(), ref.size());
    for (int q = 0; q < 60; ++q) {
        const std::string prefix = q < 3 ? std::string() : random_prefix(rng, seen, alphabet, 9);
        for (const std::size_t k : {std::size_t{1}, std::size_t{10}, std::size_t{11}, std::size_t{300}}) {
            expect_complete(t, ref, prefix, k, 777);
        }
    }
}

TEST(Trie, ResultDoesNotDependOnInsertionOrderOrHowWeightIsSplit) {
    for (std::uint64_t seed = 300; seed < 320; ++seed) {
        std::mt19937_64 rng(seed);
        Reference ref;
        while (ref.size() < 60) ref[random_key(rng, "abc", 5)] = random_weight(rng);
        std::vector<std::pair<std::string, std::uint64_t>> items(ref.begin(), ref.end());

        Trie forward(3);
        for (const auto& item : items) forward.insert(item.first, item.second);

        std::vector<std::pair<std::string, std::uint64_t>> shuffled = items;
        for (std::size_t i = shuffled.size() - 1; i > 0; --i) std::swap(shuffled[i], shuffled[below(rng, i + 1)]);
        Trie reordered(3);
        for (const auto& item : shuffled) reordered.insert(item.first, item.second);

        // Every weight is delivered as two or three pieces, in shuffled order.
        std::vector<std::pair<std::string, std::uint64_t>> pieces;
        for (const auto& item : items) {
            const std::uint64_t first = item.second / 3;
            const std::uint64_t second = (item.second - first) / 2;
            pieces.emplace_back(item.first, first);
            pieces.emplace_back(item.first, second);
            pieces.emplace_back(item.first, item.second - first - second);
        }
        for (std::size_t i = pieces.size() - 1; i > 0; --i) std::swap(pieces[i], pieces[below(rng, i + 1)]);
        Trie split(3);
        for (const auto& piece : pieces) split.insert(piece.first, piece.second);

        std::set<std::string> prefixes{std::string()};
        for (const auto& item : items) {
            for (std::size_t len = 1; len <= item.first.size(); ++len) prefixes.insert(item.first.substr(0, len));
        }
        for (const std::string& prefix : prefixes) {
            for (const std::size_t k : {std::size_t{1}, std::size_t{3}, std::size_t{4}, std::size_t{100}}) {
                const std::vector<Completion> want = reference_complete(ref, prefix, k);
                expect_same(forward.complete(prefix, k), want, seed, prefix, k);
                expect_same(reordered.complete(prefix, k), want, seed, prefix, k);
                expect_same(split.complete(prefix, k), want, seed, prefix, k);
            }
        }
    }
}

// ---- long keys --------------------------------------------------------------------

TEST(Trie, MillionByteKeyNeitherOverflowsTheStackNorLosesAnything) {
    const std::size_t n = 1000000;
    std::string big(n, 'a');
    for (std::size_t i = 0; i < n; ++i) big[i] = static_cast<char>((i * 131 + 7) % 256);  // every byte value, NULs too

    Trie t(2);
    t.insert(big, 7);
    CHECK_EQ(t.size(), std::size_t{1});
    CHECK(t.contains(big));
    CHECK_EQ(t.weight(big), std::uint64_t{7});
    CHECK(!t.contains(std::string_view(big.data(), n - 1)));

    const std::string_view half(big.data(), n / 2);
    for (const std::size_t k : {std::size_t{1}, std::size_t{3}}) {  // k=3 > K=2: iterative DFS down a 500,000-node chain
        const std::vector<Completion> r = t.complete(half, k);
        CHECK_EQ(r.size(), std::size_t{1});
        CHECK(r[0].key == big);
        CHECK_EQ(r[0].weight, std::uint64_t{7});
    }
    CHECK_EQ(t.complete(big, 1).size(), std::size_t{1});
    CHECK(t.complete(big + "x", 1).empty());

    // A sibling that differs only in the last byte shares a 999,999-node path. Different
    // weights keep every tie-break O(1), so this stays linear.
    std::string sibling = big;
    sibling.back() = static_cast<char>(sibling.back() ^ 0x55);
    t.insert(sibling, 9);
    const std::string_view shared(big.data(), n - 1);
    CHECK_EQ(t.complete(shared, 5).size(), std::size_t{2});
    CHECK(t.complete(shared, 5)[0].key == sibling);
    CHECK(t.complete(shared, 5)[1].key == big);
    CHECK(t.complete("", 1)[0].key == sibling);

    // big: 12 now overtakes sibling: 9 along the whole path. No timing assertions in this
    // project, but this line is the regression guard for a real bug: when the updated key is
    // itself the worst cache entry, comparing it with itself byte by byte costs 1,000,000
    // bytes at each of 1,000,000 nodes (about 25 seconds); identity must short-circuit.
    t.insert(big, 5);
    CHECK_EQ(t.weight(big), std::uint64_t{12});
    CHECK(t.complete(shared, 5)[0].key == big);
    CHECK(t.complete("", 2)[1].key == sibling);

    const Trie copy = t;  // copying and destroying a million-node trie must not recurse either
    CHECK(copy.complete(shared, 5) == t.complete(shared, 5));
    t.clear();
    CHECK_EQ(t.size(), std::size_t{0});
    CHECK(t.complete(shared, 5).empty());
    CHECK_EQ(copy.size(), std::size_t{2});
}

TEST(Trie, DeepChainOfNestedKeysWorks) {
    // "a", "aa", "aaa", ... each key is a prefix of the next: a chain with a key at every node.
    Trie t(4);
    Reference ref;
    for (std::size_t len = 1; len <= 1000; ++len) {
        const std::string key(len, 'a');
        const std::uint64_t w = (len * 37) % 11;
        t.insert(key, w);
        ref[key] += w;
    }
    for (const std::size_t depth : {std::size_t{0}, std::size_t{1}, std::size_t{499}, std::size_t{999}, std::size_t{1000}}) {
        for (const std::size_t k : {std::size_t{1}, std::size_t{4}, std::size_t{5}, std::size_t{50}}) {
            expect_complete(t, ref, std::string(depth, 'a'), k, 0);
        }
    }
}

// ---- overflow, clear, copy, move --------------------------------------------------

TEST(Trie, OverflowThrowsAndLeavesTheTrieUnchanged) {
    const std::uint64_t max = std::numeric_limits<std::uint64_t>::max();
    Trie t(2);
    t.insert("k", max - 5);
    t.insert("ka", 3);
    t.insert("kb", 4);
    t.insert("kc", 1);

    const auto snapshot = [&t]() {
        return render(t.complete("", 100)) + " | " + render(t.complete("k", 1)) + " | " +
               render(t.complete("ka", 3)) + " | size=" + std::to_string(t.size());
    };
    const std::string before = snapshot();

    CHECK_THROWS(t.insert("k", 6), std::overflow_error);         // max - 5 + 6 would wrap
    CHECK_EQ(snapshot(), before);
    CHECK_THROWS(t.insert("k", max), std::overflow_error);
    CHECK_EQ(snapshot(), before);
    CHECK_EQ(t.weight("k"), max - 5);

    t.insert("k", 0);  // adding nothing never overflows
    CHECK_EQ(snapshot(), before);
    t.insert("k", 5);  // lands exactly on UINT64_MAX: allowed
    CHECK_EQ(t.weight("k"), max);
    CHECK_THROWS(t.insert("k", 1), std::overflow_error);
    CHECK_EQ(t.weight("k"), max);
    CHECK_EQ(render(t.complete("k", 1)), "[k:" + std::to_string(max) + "]");

    // Half + half wraps to exactly 0, the sneakiest case for a naive `a + b < a` check.
    Trie u(1);
    u.insert("h", std::uint64_t{1} << 63);
    CHECK_THROWS(u.insert("h", std::uint64_t{1} << 63), std::overflow_error);
    CHECK_EQ(u.weight("h"), std::uint64_t{1} << 63);
    u.insert("new", max);  // a brand-new key may have any weight, including the maximum
    CHECK_EQ(u.weight("new"), max);
    CHECK_THROWS(u.insert("new", 1), std::overflow_error);
    CHECK_EQ(render(u.complete("", 5)), "[new:" + std::to_string(max) + ", h:" + std::to_string(std::uint64_t{1} << 63) + "]");
}

TEST(Trie, ClearEmptiesTheTrieAndAllowsReuse) {
    Trie t(3);
    Reference ref;
    std::mt19937_64 rng(3);
    for (int i = 0; i < 500; ++i) t.insert(random_key(rng, "abc", 6), random_weight(rng));
    CHECK(t.size() > 0);
    t.clear();
    CHECK_EQ(t.size(), std::size_t{0});
    CHECK(!t.contains("a"));
    CHECK_EQ(t.weight("a"), std::uint64_t{0});
    CHECK(t.complete("", 10).empty());
    CHECK(t.complete("a", 10).empty());
    CHECK_EQ(t.cached_k(), std::size_t{3});

    // Reused trie behaves like a fresh one; weights restart from zero.
    for (int i = 0; i < 500; ++i) {
        const std::string key = random_key(rng, "abc", 6);
        const std::uint64_t w = random_weight(rng);
        t.insert(key, w);
        ref[key] += w;
    }
    CHECK_EQ(t.size(), ref.size());
    for (const std::string prefix : {"", "a", "ab", "c", "cc"}) {
        for (const std::size_t k : {std::size_t{1}, std::size_t{3}, std::size_t{4}, kAll}) {
            expect_complete(t, ref, prefix, k, 3);
        }
    }
    t.clear();
    t.clear();  // idempotent
    CHECK_EQ(t.size(), std::size_t{0});
}

TEST(Trie, CopyIsDeepAndIndependent) {
    Trie a(2);
    a.insert("alpha", 3);
    a.insert("alps", 5);

    Trie b = a;
    b.insert("alpha", 10);
    b.insert("beta", 1);
    CHECK_EQ(a.weight("alpha"), std::uint64_t{3});
    CHECK(!a.contains("beta"));
    CHECK_EQ(a.size(), std::size_t{2});
    CHECK_EQ(render(a.complete("al", 5)), std::string("[alps:5, alpha:3]"));
    CHECK_EQ(render(b.complete("al", 5)), std::string("[alpha:13, alps:5]"));
    CHECK_EQ(b.size(), std::size_t{3});

    Trie c(7);
    c.insert("junk", 1);
    c = a;  // copy assignment replaces everything, including cached_k
    CHECK_EQ(c.cached_k(), std::size_t{2});
    CHECK(!c.contains("junk"));
    CHECK_EQ(render(c.complete("", 5)), render(a.complete("", 5)));
    c.insert("alps", 100);
    CHECK_EQ(a.weight("alps"), std::uint64_t{5});

    Trie& alias = a;
    a = alias;  // self-assignment is harmless
    CHECK_EQ(a.size(), std::size_t{2});
    CHECK_EQ(render(a.complete("al", 5)), std::string("[alps:5, alpha:3]"));
}

TEST(Trie, MovedFromTrieIsEmptyAndReusable) {
    Trie src(3);
    src.insert("one", 1);
    src.insert("two", 2);

    Trie dst(std::move(src));
    CHECK_EQ(dst.size(), std::size_t{2});
    CHECK_EQ(render(dst.complete("", 5)), std::string("[two:2, one:1]"));
    CHECK_EQ(src.size(), std::size_t{0});
    CHECK(!src.contains("one"));
    CHECK_EQ(src.weight("two"), std::uint64_t{0});
    CHECK(src.complete("", 5).empty());
    CHECK_EQ(src.cached_k(), std::size_t{3});

    src.insert("fresh", 4);  // reusable, and independent of dst
    CHECK_EQ(render(src.complete("", 5)), std::string("[fresh:4]"));
    CHECK_EQ(dst.size(), std::size_t{2});
    CHECK(!dst.contains("fresh"));

    Trie other(5);
    other.insert("z", 9);
    other = std::move(dst);  // move assignment takes everything, cached_k included
    CHECK_EQ(other.cached_k(), std::size_t{3});
    CHECK_EQ(render(other.complete("", 5)), std::string("[two:2, one:1]"));
    CHECK(!other.contains("z"));
    CHECK_EQ(dst.size(), std::size_t{0});
    CHECK(dst.complete("", 5).empty());
    dst.insert("again", 1);
    CHECK(dst.contains("again"));

    Trie& alias = other;
    other = std::move(alias);  // self-move must not destroy the trie
    CHECK_EQ(other.size(), std::size_t{2});
}
