#pragma once

#include <string>
#include <string_view>

namespace loganalyzer {

/// Collapses the variable parts of a log message so that "the same kind of error"
/// maps to ONE signature string. Hand-written single-pass scanner (no regex):
/// O(n) time, never throws except std::bad_alloc, safe on any bytes (including
/// >= 128 and NUL), locale independent.
///
/// Rewrites, tried most specific first at every token start:
///   <UUID>  8-4-4-4-12 hex digits, any case
///   <IP>    dotted-quad IPv4 (each octet 0..255) with an optional ":port" (1-5 digits)
///   <HEX>   "0x"/"0X" literal (any number of hex digits), or a standalone hex token
///           of >= 8 hex digits that has at least one decimal digit AND one a-f letter
///   <N>     any other run of decimal digits, with an optional ".digits" fraction
/// A trailing unit is left alone: "3000ms" -> "<N>ms", "2.5s" -> "<N>s", "4KB" -> "<N>KB".
/// Whitespace runs (space, \t, \n, \r, \v, \f) become one space; the ends are trimmed.
/// Everything else is copied verbatim, case preserved.
///
/// Token starts. Every rule above only fires at a token start, i.e. where the previous
/// character of the OUTPUT is not an ASCII letter or digit (a placeholder ends in '>',
/// so the character right after one is a token start too). A rule also needs its match
/// to end at a non-alphanumeric character ("standalone"), except <N>, which may be
/// followed by a unit. This is the documented answer for digits inside identifiers:
///   - digits glued directly to a preceding letter or digit belong to the identifier
///     and are kept: "http2", "utf8", "sha256", "ipv6", "x86", "node7", "user42";
///   - digits after any separator are data and are replaced: "db-3" -> "db-<N>",
///     "db_3" -> "db_<N>", "users/42" -> "users/<N>", "x86_64" -> "x86_<N>",
///     "HTTP/2" -> "HTTP/<N>", "-5" -> "-<N>", "1,000" -> "<N>,<N>".
/// Trade-off: "node1" and "node2" keep distinct signatures. Splitting the digits off
/// every letter would merge them, but would also turn "http2" into "http<N>".
/// A pure-digit run is always <N>, never <HEX>, however long ("1700000000" -> "<N>").
/// Bytes >= 128 are treated as non-alphanumeric (they never glue digits).
///
/// Idempotent: normalize_signature(normalize_signature(x)) == normalize_signature(x).
std::string normalize_signature(std::string_view message);

}  // namespace loganalyzer
