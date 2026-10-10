#include "loganalyzer/error_signature.hpp"

#include <cstddef>

namespace loganalyzer {
namespace {

// Hand-rolled ASCII classifiers. std::isdigit/isxdigit take an int that must be an
// unsigned char value or EOF, so passing a plain (signed) char >= 128 is undefined
// behaviour; these comparisons are well-defined for every char value.
constexpr bool is_digit(char c) noexcept { return c >= '0' && c <= '9'; }
constexpr bool is_alpha(char c) noexcept { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }
constexpr bool is_alnum(char c) noexcept { return is_digit(c) || is_alpha(c); }
constexpr bool is_hex(char c) noexcept {
    return is_digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}
constexpr bool is_space(char c) noexcept {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f';
}

// Every matcher below returns the length of the token starting at `pos`, or 0 for
// "no match", and never reads past s.size().

// 8-4-4-4-12 hex digits; must not run straight into more alphanumerics.
std::size_t match_uuid(std::string_view s, std::size_t pos) noexcept {
    constexpr std::size_t kLen = 36;
    if (s.size() - pos < kLen) return 0;
    for (std::size_t k = 0; k < kLen; ++k) {
        const bool dash = k == 8 || k == 13 || k == 18 || k == 23;
        if (dash ? s[pos + k] != '-' : !is_hex(s[pos + k])) return 0;
    }
    if (pos + kLen < s.size() && is_alnum(s[pos + kLen])) return 0;
    return kLen;
}

// a.b.c.d with octets 0..255 (1-3 digits), optionally followed by ":port".
std::size_t match_ipv4(std::string_view s, std::size_t pos) noexcept {
    const std::size_t n = s.size();
    std::size_t p = pos;
    for (int octet = 0; octet < 4; ++octet) {
        if (octet > 0) {
            if (p >= n || s[p] != '.') return 0;
            ++p;
        }
        const std::size_t start = p;
        int value = 0;
        while (p < n && is_digit(s[p]) && p - start < 3) {
            value = value * 10 + (s[p] - '0');
            ++p;
        }
        if (p == start || value > 255) return 0;
        if (p < n && is_digit(s[p])) return 0;  // 4+ digits is not an octet
    }
    // "1.2.3.4.5" and "1.2.3.4abc" are not addresses.
    if (p < n && is_alnum(s[p])) return 0;
    if (p + 1 < n && s[p] == '.' && is_digit(s[p + 1])) return 0;

    if (p < n && s[p] == ':') {
        std::size_t q = p + 1;
        while (q < n && is_digit(s[q])) ++q;
        const std::size_t digits = q - (p + 1);
        // A port that is too long or glued to letters is left for the <N> rule.
        if (digits >= 1 && digits <= 5 && !(q < n && is_alnum(s[q]))) p = q;
    }
    return p - pos;
}

// 0x / 0X followed by at least one hex digit, then a non-alphanumeric (or the end).
std::size_t match_hex_literal(std::string_view s, std::size_t pos) noexcept {
    const std::size_t n = s.size();
    if (pos + 1 >= n || s[pos] != '0' || (s[pos + 1] != 'x' && s[pos + 1] != 'X')) return 0;
    std::size_t p = pos + 2;
    while (p < n && is_hex(s[p])) ++p;
    if (p == pos + 2) return 0;
    if (p < n && is_alnum(s[p])) return 0;
    return p - pos;
}

// Standalone run of >= 8 hex digits mixing decimal digits and a-f letters, which is what
// request ids, hashes and addresses look like. All-letter runs ("deadbeef") are
// ordinary words and all-digit runs are numbers, so both are left to other rules.
std::size_t match_hex_token(std::string_view s, std::size_t pos) noexcept {
    const std::size_t n = s.size();
    std::size_t p = pos;
    bool has_digit = false;
    bool has_letter = false;
    while (p < n && is_hex(s[p])) {
        if (is_digit(s[p])) {
            has_digit = true;
        } else {
            has_letter = true;
        }
        ++p;
    }
    if (p - pos < 8 || !has_digit || !has_letter) return 0;
    if (p < n && is_alnum(s[p])) return 0;
    return p - pos;
}

// Digits with an optional ".digits" fraction. A '.' not followed by a digit stays out.
std::size_t match_decimal(std::string_view s, std::size_t pos) noexcept {
    const std::size_t n = s.size();
    std::size_t p = pos;
    while (p < n && is_digit(s[p])) ++p;
    if (p + 1 < n && s[p] == '.' && is_digit(s[p + 1])) {
        ++p;
        while (p < n && is_digit(s[p])) ++p;
    }
    return p - pos;
}

}  // namespace

std::string normalize_signature(std::string_view s) {
    std::string out;
    out.reserve(s.size());

    // Whether the last thing written to `out` was an ASCII letter/digit. Judging
    // token starts from the output (not the input) is what makes the function
    // idempotent: the character after a placeholder is a token start in the first pass
    // and, since the placeholder ends in '>', in the second pass as well.
    bool prev_alnum = false;
    bool pending_space = false;

    const std::size_t n = s.size();
    std::size_t i = 0;
    while (i < n) {
        const char c = s[i];
        if (is_space(c)) {
            pending_space = !out.empty();  // leading whitespace is dropped
            prev_alnum = false;
            ++i;
            continue;
        }
        if (pending_space) {
            out.push_back(' ');  // trailing whitespace never reaches here
            pending_space = false;
        }

        // Every placeholder starts with a hex digit, so skip the matchers for the rest.
        std::size_t len = 0;
        const char* tag = nullptr;
        if (!prev_alnum && is_hex(c)) {
            if ((len = match_uuid(s, i)) != 0) {
                tag = "<UUID>";
            } else if (is_digit(c) && (len = match_ipv4(s, i)) != 0) {
                tag = "<IP>";
            } else if (c == '0' && (len = match_hex_literal(s, i)) != 0) {
                tag = "<HEX>";
            } else if ((len = match_hex_token(s, i)) != 0) {
                tag = "<HEX>";
            } else if (is_digit(c)) {
                len = match_decimal(s, i);
                tag = "<N>";
            }
        }

        if (tag != nullptr) {
            out.append(tag);
            i += len;
            prev_alnum = false;
        } else {
            out.push_back(c);
            prev_alnum = is_alnum(c);
            ++i;
        }
    }
    return out;
}

}  // namespace loganalyzer
