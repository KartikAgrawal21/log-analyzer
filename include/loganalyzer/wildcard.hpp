#pragma once

#include <cstddef>
#include <string_view>

namespace loganalyzer {

/// Glob match: '*' matches any run of characters (including none), '?' exactly one, every
/// other character matches itself (case-sensitive). The whole text must match.
///
/// Two-pointer scan that remembers the most recent '*' and, on a mismatch, backtracks to it
/// letting that star swallow one more character. No recursion; O(|pattern| * |text|) worst
/// case (e.g. "*a*a*a*b" against "aaaa..."), O(|text|) when there is at most one star.
inline bool wildcard_match(std::string_view pattern, std::string_view text) {
    std::size_t p = 0, t = 0;
    std::size_t star = std::string_view::npos;  // pattern index of the last '*' seen
    std::size_t resume = 0;                     // text index that star currently covers up to
    while (t < text.size()) {
        if (p < pattern.size() && (pattern[p] == '?' || pattern[p] == text[t])) {
            ++p;
            ++t;
        } else if (p < pattern.size() && pattern[p] == '*') {
            star = p++;
            resume = t;
        } else if (star != std::string_view::npos) {
            p = star + 1;
            t = ++resume;
        } else {
            return false;
        }
    }
    while (p < pattern.size() && pattern[p] == '*') ++p;  // trailing stars match nothing
    return p == pattern.size();
}

}  // namespace loganalyzer
