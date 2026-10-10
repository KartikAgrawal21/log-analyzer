#include <cstddef>
#include <random>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "loganalyzer/error_signature.hpp"
#include "testkit.hpp"

using loganalyzer::normalize_signature;

namespace {

using Cases = std::vector<std::pair<std::string, std::string>>;  // input, expected

void check_cases(const Cases& cases) {
    for (const auto& c : cases) {
        CHECK_EQ(normalize_signature(c.first), c.second);
    }
}

std::string repeat(const std::string& unit, std::size_t times) {
    std::string out;
    out.reserve(unit.size() * times);
    for (std::size_t i = 0; i < times; ++i) out += unit;
    return out;
}

bool contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

// Messages built from fragments that stress every rule boundary: numbers, hex-ish words,
// IPs, UUIDs, placeholders themselves, separators, whitespace and high bytes.
std::string random_fragment_message(std::mt19937& rng) {
    static const std::vector<std::string> pieces = {
        "0", "1", "7", "9", "42", "3000", "a", "b", "f", "e", "g", "z", "x", "X", "0x", "0X",
        "deadbeef", "DEADBEEF", "1a2b3c4d", "12345678", "1700000000", "abc1234", "3.5", "1.2.3",
        "550e8400-e29b-41d4-a716-446655440000", "550E8400-E29B-41D4-A716-446655440000",
        "10.0.0.1", "192.168.1.255:8080", "256.1.1.1", "1.2.3.4.5", ".", ":", "-", "_", "/",
        " ", "  ", "\t", "\n", "<", ">", "<N>", "<HEX>", "<IP>", "<UUID>", "N", "H", "ms", "KB",
        "http", "db", "\xC3\xA9", "\xFF", "\x80"};
    std::uniform_int_distribution<std::size_t> count(0, 24);
    std::uniform_int_distribution<std::size_t> pick(0, pieces.size() - 1);
    std::string s;
    for (std::size_t n = count(rng); n > 0; --n) s += pieces[pick(rng)];
    return s;
}

std::string random_alphabet_message(std::mt19937& rng, const std::string& alphabet,
                                    std::size_t max_len) {
    std::uniform_int_distribution<std::size_t> len(0, max_len);
    std::uniform_int_distribution<std::size_t> pick(0, alphabet.size() - 1);
    std::string s;
    for (std::size_t n = len(rng); n > 0; --n) s.push_back(alphabet[pick(rng)]);
    return s;
}

std::string random_bytes(std::mt19937& rng, std::size_t max_len) {
    std::uniform_int_distribution<std::size_t> len(0, max_len);
    std::uniform_int_distribution<int> byte(0, 255);
    std::string s;
    for (std::size_t n = len(rng); n > 0; --n) s.push_back(static_cast<char>(byte(rng)));
    return s;
}

bool is_ascii_digit(char c) { return c >= '0' && c <= '9'; }
bool is_ascii_alnum(char c) {
    return is_ascii_digit(c) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

}  // namespace

TEST(ErrorSignature, EmptyAndWhitespaceOnlyInputsGiveEmptySignature) {
    CHECK_EQ(normalize_signature(""), std::string());
    CHECK_EQ(normalize_signature(" "), std::string());
    CHECK_EQ(normalize_signature("\t\n  \r\v\f"), std::string());
}

TEST(ErrorSignature, CollapsesWhitespaceRunsAndTrims) {
    check_cases({
        {"a", "a"},
        {"  a \t b\n\nc  ", "a b c"},
        {"a\vb\fc", "a b c"},
        {"\r\nhello   world\r\n", "hello world"},
        {"Timeout   after \t 5 ms", "Timeout after <N> ms"},
    });
}

TEST(ErrorSignature, KeepsPlainTextVerbatimWithCasePreserved) {
    check_cases({
        {"Connection Refused: no route to host!", "Connection Refused: no route to host!"},
        {"NullPointerException in Foo.bar()", "NullPointerException in Foo.bar()"},
        {"key=value; other=\"quoted\" [tag] {x} <y>", "key=value; other=\"quoted\" [tag] {x} <y>"},
    });
}

TEST(ErrorSignature, ReplacesUuidsInAnyCase) {
    check_cases({
        {"550e8400-e29b-41d4-a716-446655440000", "<UUID>"},
        {"550E8400-E29B-41D4-A716-446655440000", "<UUID>"},
        {"550e8400-E29B-41d4-A716-44665544abcd", "<UUID>"},
        {"Order 550e8400-e29b-41d4-a716-446655440000 failed", "Order <UUID> failed"},
        {"id=550e8400-e29b-41d4-a716-446655440000;", "id=<UUID>;"},
        {"(550e8400-e29b-41d4-a716-446655440000)", "(<UUID>)"},
        {"a 550e8400-e29b-41d4-a716-446655440000 b 123e4567-e89b-12d3-a456-426614174000 c",
         "a <UUID> b <UUID> c"},
    });
}

TEST(ErrorSignature, MalformedUuidsAreNotReplacedAsUuids) {
    const std::vector<std::string> not_uuids = {
        "550e8400-e29b-41d4-a716-44665544000",     // last group too short
        "550e8400-e29b-41d4-a716-4466554400000",   // last group too long: 13 hex run
        "550e8400e29b41d4a716446655440000",        // no dashes
        "550e8400-e29b-41d4-a716-44665544000g",    // non-hex digit
        "x550e8400-e29b-41d4-a716-446655440000",   // glued to a preceding letter
        "550e8400-e29b-41d4-a716-446655440000x",   // glued to a following letter
        "50e8400-e29b-41d4-a716-446655440000",     // first group too short
    };
    for (const auto& s : not_uuids) {
        CHECK(!contains(normalize_signature(s), "<UUID>"));
    }
}

TEST(ErrorSignature, ReplacesIpv4AddressesWithOptionalPort) {
    check_cases({
        {"10.0.0.1", "<IP>"},
        {"0.0.0.0", "<IP>"},
        {"255.255.255.255", "<IP>"},
        {"010.001.002.003", "<IP>"},
        {"192.168.1.255:8080", "<IP>"},
        {"10.0.0.1:99999", "<IP>"},
        {"connect to 10.1.2.3:5432 refused", "connect to <IP> refused"},
        {"(10.0.0.1)", "(<IP>)"},
        {"from 10.0.0.1.", "from <IP>."},
        {"ip=10.0.0.1,port=80", "ip=<IP>,port=<N>"},
        {"a.1.2.3.4", "a.<IP>"},
        {"10.0.0.1 10.0.0.2", "<IP> <IP>"},
    });
}

TEST(ErrorSignature, IpPortThatIsTooLongOrGluedToLettersIsLeftToTheNumberRule) {
    check_cases({
        {"10.0.0.1:", "<IP>:"},
        {"10.0.0.1:123456", "<IP>:<N>"},
        {"10.0.0.1:80x", "<IP>:<N>x"},
        {"10.0.0.1:abc", "<IP>:abc"},
    });
}

TEST(ErrorSignature, NearMissIpv4AddressesFallBackToNumbers) {
    check_cases({
        {"256.1.1.1", "<N>.<N>"},
        {"1.2.3", "<N>.<N>"},
        {"1.2.3.4.5", "<N>.<N>.<N>"},
        {"1.2.3.4abc", "<N>.<N>abc"},
        {"v1.2.3.4", "v1.<N>.<N>"},
        {"1234.1.1.1", "<N>.<N>"},
    });
}

TEST(ErrorSignature, ReplacesHexLiterals) {
    check_cases({
        {"0xDEADBEEF", "<HEX>"},
        {"0x1f", "<HEX>"},
        {"0X7FFD", "<HEX>"},
        {"0x0", "<HEX>"},
        {"ptr=0x7ffd1234abcd,", "ptr=<HEX>,"},
        {"segfault at 0x00000000 ip 0x7f3a2b1c", "segfault at <HEX> ip <HEX>"},
    });
}

TEST(ErrorSignature, BrokenHexLiteralsFallBackToNumbersAndIdentifiers) {
    check_cases({
        {"0x", "<N>x"},
        {"0xg", "<N>xg"},
        {"0x1g", "<N>x1g"},
        {"a0x1f", "a0x1f"},  // glued to a letter: part of an identifier
    });
}

TEST(ErrorSignature, ReplacesStandaloneHexTokensOfEightOrMoreDigits) {
    check_cases({
        {"deadbeef12", "<HEX>"},
        {"DEADBEEF12", "<HEX>"},
        {"DeadBeef01", "<HEX>"},
        {"id=1a2b3c4d", "id=<HEX>"},
        {"req-1A2B3C4D5E6F done", "req-<HEX> done"},
        {"sha 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
         "sha <HEX>"},
        {"1a2b3c4d,", "<HEX>,"},
    });
}

TEST(ErrorSignature, HexLookingWordsNumbersAndShortTokensAreNotHex) {
    check_cases({
        {"deadbeef", "deadbeef"},      // no decimal digit: an ordinary word
        {"cafebabe", "cafebabe"},
        {"abc1234", "abc1234"},        // 7 chars and glued to a letter
        {"12345678", "<N>"},           // all digits: a number, never <HEX>
        {"1700000000", "<N>"},
        {"12345678ms", "<N>ms"},
        {"1a2b3c4", "<N>a2b3c4"},      // only 7 hex digits
        {"1a2b3c4dZ", "<N>a2b3c4dZ"},  // runs into a non-hex letter: not standalone
        {"x1a2b3c4d5e", "x1a2b3c4d5e"},  // glued to a preceding letter
    });
}

TEST(ErrorSignature, ReplacesDecimalNumbersAndKeepsTrailingUnits) {
    check_cases({
        {"Timeout calling bank gateway after 3000ms", "Timeout calling bank gateway after <N>ms"},
        {"took 2.5s", "took <N>s"},
        {"4KB", "<N>KB"},
        {"5xx", "<N>xx"},
        {"50%", "<N>%"},
        {"42", "<N>"},
        {"0", "<N>"},
        {"007", "<N>"},
        {"99999999999999999999999", "<N>"},
        {"-42", "-<N>"},
        {"+7", "+<N>"},
        {"1,000", "<N>,<N>"},
        {"3.", "<N>."},
        {".5", ".<N>"},
        {"version 1.2.3", "version <N>.<N>"},
        {"retry 3/5", "retry <N>/<N>"},
        {"[12:30:45]", "[<N>:<N>:<N>]"},
        {"1e5", "<N>e5"},
    });
}

TEST(ErrorSignature, DigitsInsideIdentifiersFollowTheDocumentedRule) {
    check_cases({
        // glued to a preceding letter or digit: part of the identifier, kept
        {"http2", "http2"},
        {"(http2)", "(http2)"},
        {"utf8", "utf8"},
        {"sha256 mismatch", "sha256 mismatch"},
        {"ipv6", "ipv6"},
        {"a1b2c3", "a1b2c3"},
        {"user42", "user42"},
        {"node7 down", "node7 down"},
        {"api/v2/users/42", "api/v2/users/<N>"},
        // after a separator: data, replaced
        {"db-3", "db-<N>"},
        {"db_3", "db_<N>"},
        {"worker-12 crashed", "worker-<N> crashed"},
        {"HTTP/2", "HTTP/<N>"},
        {"x86_64", "x86_<N>"},
        {"shard=7", "shard=<N>"},
    });
}

TEST(ErrorSignature, RewritesAMixedRealWorldMessage) {
    CHECK_EQ(normalize_signature("Request 550e8400-e29b-41d4-a716-446655440000 from 10.0.0.1:443 "
                                 "failed with code 0xDEADBEEF after 1500ms on db-3 (http2)"),
             std::string("Request <UUID> from <IP> failed with code <HEX> after <N>ms on db-<N> "
                         "(http2)"));
}

TEST(ErrorSignature, SameKindOfErrorGetsOneSignatureDifferentKindsDiffer) {
    const std::string a = normalize_signature("Timeout calling bank gateway after 3000ms");
    const std::string b = normalize_signature("Timeout  calling bank gateway after 25ms ");
    CHECK_EQ(a, b);

    CHECK_EQ(normalize_signature("User 17 not found"), normalize_signature("User 90210 not found"));
    CHECK_EQ(normalize_signature("conn from 10.0.0.1:80 reset"),
             normalize_signature("conn from 172.16.5.9:65535 reset"));

    CHECK(a != normalize_signature("Timeout calling bank gateway after 3000s"));  // unit kept
    CHECK(a != normalize_signature("timeout calling bank gateway after 3000ms"));  // case kept
    CHECK(normalize_signature("User 17 not found") != normalize_signature("Group 17 not found"));
}

TEST(ErrorSignature, SafeOnHighBytesAndEmbeddedNul) {
    check_cases({
        {"caf\xC3\xA9 5", "caf\xC3\xA9 <N>"},
        {"\xFF" "12", "\xFF<N>"},                // high byte never glues digits
        {"\xC3\xA9" "2", "\xC3\xA9<N>"},
        {"\x80\x81\x82", "\x80\x81\x82"},
        {"a\xC2\xA0" "b", "a\xC2\xA0" "b"},     // U+00A0 is not collapsed as whitespace
        {std::string("a\0" "b 5", 5), std::string("a\0" "b <N>", 7)},
    });

    // Every single byte value, alone and between digits, must neither crash nor change
    // under a second pass.
    for (int b = 0; b < 256; ++b) {
        const char c = static_cast<char>(b);
        for (const std::string& s : {std::string(1, c), std::string("1") + c + "2",
                                     std::string("deadbeef1") + c, c + std::string("0x1f")}) {
            const std::string once = normalize_signature(s);
            CHECK_EQ(normalize_signature(once), once);
        }
    }
}

TEST(ErrorSignature, PlaceholderLikeInputIsStableAndNotDoubleEscaped) {
    check_cases({
        {"<N>", "<N>"},
        {"<HEX> <IP> <UUID>", "<HEX> <IP> <UUID>"},
        {"<5>", "<<N>>"},
        {"<N>3", "<N><N>"},
    });
}

TEST(ErrorSignature, IsIdempotentOnExamples) {
    const std::vector<std::string> inputs = {
        "", " ", "Timeout calling bank gateway after 3000ms", "db-3 http2 x86_64 node7",
        "550e8400-e29b-41d4-a716-446655440000", "10.0.0.1:8080", "0xDEADBEEF", "deadbeef12",
        "1.5abcdef01", "0x1g", "1a2b3c4dZ", "12abcdef01", "1.2.3.4.5", "<5>", "<N>3",
        "  a \t\n b  ", "caf\xC3\xA9 5", "256.1.1.1", "1e5", "10.0.0.1:80x",
    };
    for (const auto& s : inputs) {
        const std::string once = normalize_signature(s);
        CHECK_EQ(normalize_signature(once), once);
    }
}

TEST(ErrorSignature, IsIdempotentOnRandomFragmentInputs) {
    for (unsigned seed = 1; seed <= 40; ++seed) {
        std::mt19937 rng(seed);
        for (int i = 0; i < 1500; ++i) {
            const std::string input = random_fragment_message(rng);
            const std::string once = normalize_signature(input);
            CHECK_EQ(normalize_signature(once), once);
        }
    }
}

TEST(ErrorSignature, IsIdempotentOnRandomDigitHeavyAndByteInputs) {
    const std::string alphabet = "0123456789abcdefABCDEFxX.:-_ \tgz/<>";
    for (unsigned seed = 1; seed <= 40; ++seed) {
        std::mt19937 rng(1000 + seed);
        for (int i = 0; i < 1500; ++i) {
            for (const std::string& input :
                 {random_alphabet_message(rng, alphabet, 80), random_bytes(rng, 64)}) {
                const std::string once = normalize_signature(input);
                CHECK_EQ(normalize_signature(once), once);
            }
        }
    }
}

TEST(ErrorSignature, OutputInvariantsHoldOnRandomInputs) {
    const std::string alphabet = "0123456789abcdefABCDEFxX.:-_ \t\ngz/<>";
    for (unsigned seed = 1; seed <= 30; ++seed) {
        std::mt19937 rng(5000 + seed);
        for (int i = 0; i < 1500; ++i) {
            for (const std::string& input :
                 {random_fragment_message(rng), random_alphabet_message(rng, alphabet, 80),
                  random_bytes(rng, 64)}) {
                const std::string out = normalize_signature(input);
                CHECK(out.empty() || (out.front() != ' ' && out.back() != ' '));
                for (std::size_t p = 0; p < out.size(); ++p) {
                    const char c = out[p];
                    // whitespace is only ever a single plain space
                    CHECK(!(c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'));
                    CHECK(!(c == ' ' && p + 1 < out.size() && out[p + 1] == ' '));
                    // a decimal digit survives only when glued to the alphanumeric before it
                    if (is_ascii_digit(c)) CHECK(p > 0 && is_ascii_alnum(out[p - 1]));
                }
                // worst case is a lone digit becoming "<N>"
                CHECK(out.size() <= 3 * input.size());
            }
        }
    }
}

TEST(ErrorSignature, AdversarialLongInputsRunInLinearTime) {
    // Each of these is quadratic for a scanner that re-reads a long run at every token
    // start; at this size that would take minutes, so merely finishing is the check.
    constexpr std::size_t kN = 300000;

    const std::string long_run = "1" + std::string(kN, 'a') + "g";
    CHECK_EQ(normalize_signature(long_run), "<N>" + std::string(kN, 'a') + "g");

    CHECK_EQ(normalize_signature(repeat("0x", kN)), "<N>x" + repeat("0x", kN - 1));

    CHECK_EQ(normalize_signature(repeat("a1", kN / 2)), std::string("<HEX>"));
    CHECK_EQ(normalize_signature(std::string(kN, ' ') + "a" + std::string(kN, ' ')),
             std::string("a"));

    const std::string dotted = repeat("1.1.1.1.", kN / 8);
    const std::string dotted_once = normalize_signature(dotted);
    CHECK_EQ(normalize_signature(dotted_once), dotted_once);

    const std::string ips = repeat("10.0.0.1:80 ", kN / 12);
    CHECK_EQ(normalize_signature(ips), repeat("<IP> ", kN / 12 - 1) + "<IP>");

    const std::string almost_uuids = repeat("550e8400-e29b-41d4-a716-44665544000 ", kN / 36);
    const std::string almost_once = normalize_signature(almost_uuids);
    CHECK(!contains(almost_once, "<UUID>"));
    CHECK_EQ(normalize_signature(almost_once), almost_once);
}
