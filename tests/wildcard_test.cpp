#include <cstddef>
#include <random>
#include <string>
#include <string_view>

#include "loganalyzer/wildcard.hpp"
#include "testkit.hpp"

using loganalyzer::wildcard_match;

namespace {

// Obviously-correct recursive definition to compare the two-pointer version against.
bool reference_match(std::string_view pattern, std::string_view text) {
    if (pattern.empty()) return text.empty();
    if (pattern[0] == '*') {
        for (std::size_t skip = 0; skip <= text.size(); ++skip) {
            if (reference_match(pattern.substr(1), text.substr(skip))) return true;
        }
        return false;
    }
    if (text.empty()) return false;
    if (pattern[0] != '?' && pattern[0] != text[0]) return false;
    return reference_match(pattern.substr(1), text.substr(1));
}

}  // namespace

TEST(Wildcard, LiteralsMatchExactly) {
    CHECK(wildcard_match("", ""));
    CHECK(wildcard_match("abc", "abc"));
    CHECK(!wildcard_match("abc", "abd"));
    CHECK(!wildcard_match("abc", "ab"));
    CHECK(!wildcard_match("ab", "abc"));
    CHECK(!wildcard_match("", "a"));
    CHECK(!wildcard_match("a", ""));
}

TEST(Wildcard, QuestionMarkMatchesExactlyOneCharacter) {
    CHECK(wildcard_match("?", "x"));
    CHECK(!wildcard_match("?", ""));
    CHECK(!wildcard_match("?", "xy"));
    CHECK(wildcard_match("a?c", "abc"));
    CHECK(!wildcard_match("a?c", "ac"));
}

TEST(Wildcard, StarMatchesAnyRunIncludingNone) {
    CHECK(wildcard_match("*", ""));
    CHECK(wildcard_match("*", "anything at all"));
    CHECK(wildcard_match("*.log", "a.log"));
    CHECK(wildcard_match("*.log", ".log"));
    CHECK(!wildcard_match("*.log", "a.txt"));
    CHECK(!wildcard_match("*.log", "a.log.gz"));
    CHECK(wildcard_match("a*b", "ab"));
    CHECK(wildcard_match("a*b", "a-lots-of-stuff-b"));
    CHECK(!wildcard_match("a*b", "a-lots-of-stuff-c"));
    CHECK(wildcard_match("**", ""));
    CHECK(wildcard_match("a**b", "axxb"));
}

TEST(Wildcard, StarNeedsBacktrackingToFindTheRightSplit) {
    CHECK(wildcard_match("*ab", "aab"));
    CHECK(wildcard_match("*ab*cd", "xabxabcd"));
    CHECK(wildcard_match("*a*a*a", "banana"));
    CHECK(!wildcard_match("*a*a*a*", "bnn"));
    CHECK(wildcard_match("a*a*a", "aaa"));
    CHECK(!wildcard_match("a*a*a", "aa"));
}

TEST(Wildcard, IsCaseSensitive) {
    CHECK(!wildcard_match("*.LOG", "a.log"));
    CHECK(wildcard_match("*.LOG", "a.LOG"));
}

TEST(Wildcard, PathologicalPatternStaysFast) {
    // Classic exponential blow-up for naive recursion; the two-pointer scan is polynomial.
    const std::string text(5000, 'a');
    CHECK(!wildcard_match("*a*a*a*a*a*a*a*b", text));
    CHECK(wildcard_match("*a*a*a*a*a*a*a*", text));
}

TEST(Wildcard, MatchesAReferenceImplementationOnRandomInput) {
    std::mt19937 rng(2026);
    const char pattern_alphabet[] = {'a', 'b', '*', '?'};
    const char text_alphabet[] = {'a', 'b'};
    for (int round = 0; round < 20000; ++round) {
        std::string pattern;
        std::string text;
        for (unsigned i = rng() % 8; i > 0; --i) pattern += pattern_alphabet[rng() % 4];
        for (unsigned i = rng() % 9; i > 0; --i) text += text_alphabet[rng() % 2];
        const bool want = reference_match(pattern, text);
        const bool got = wildcard_match(pattern, text);
        if (want != got) {
            throw testkit::Failure{"mismatch for pattern '" + pattern + "' text '" + text + "': expected " +
                                   (want ? "match" : "no match")};
        }
    }
}
