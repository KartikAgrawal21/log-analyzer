#pragma once

#include <cstddef>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "loganalyzer/alert_engine.hpp"
#include "loganalyzer/http_server.hpp"
#include "loganalyzer/log_entry.hpp"

namespace loganalyzer {

struct ServeOptions {
    /// Title of the HTML dashboard (HTML-escaped by the report, so any text is safe).
    std::string title = "Log dashboard";
    /// Rows in the report's top error signatures table (the report clamps it to [1, 1000]).
    /// It does NOT change the default of /api/top-errors, which is always k=10.
    std::size_t top_k = 10;
    /// Bars in the report's timeline chart (the report clamps it to [1, 400]).
    std::size_t time_buckets = 60;
};

/// The escaped CONTENT of a JSON string, WITHOUT the surrounding quotes. Total: every byte
/// sequence is accepted, and the result is always valid inside a JSON string (RFC 8259) and
/// valid UTF-8, whatever the input. O(|text|), no recursion, never reads outside `text`.
///
///  - '"' becomes \" and '\' becomes \\.
///  - The control characters 0x00-0x1F become \b \f \n \r \t (0x08, 0x0C, 0x0A, 0x0D, 0x09)
///    or \u00XX (lower-case hex) for the rest, e.g. NUL is \u0000 and ESC is \u001b.
///  - DEL (0x7F) becomes \u007f.
///  - '<', '>' and '&' become <, > and &. They are valid JSON either way; the
///    escapes exist so that the text can never contain "</script>", "<!--" or an entity. That
///    makes the result safe to embed in HTML text, in a <script> block and in a double-quoted
///    attribute. It is NOT a general HTML escaper: the single quote is not escaped (so it is not
///    safe in a single-quoted attribute), and U+2028 and U+2029 pass through (valid JSON, but
///    line terminators inside a JavaScript string literal before ES2019). Nothing in this module
///    embeds JSON in HTML; the API is consumed as JSON.
///  - Everything else in 0x20-0x7E passes through unchanged.
///  - Valid UTF-8 passes through unchanged (U+2028 and U+2029 and the noncharacters U+FFFE and
///    U+FFFF included, they are legal in JSON). "Valid" is the well-formed byte-sequence table
///    of the Unicode standard (Table 3-7), nothing looser:
///        00..7F
///        C2..DF  80..BF
///        E0      A0..BF  80..BF          (E0 80..9F would be an overlong form)
///        E1..EC  80..BF  80..BF
///        ED      80..9F  80..BF          (ED A0..BF would be a surrogate, U+D800-DFFF)
///        EE..EF  80..BF  80..BF
///        F0      90..BF  80..BF  80..BF  (F0 80..8F would be an overlong form)
///        F1..F3  80..BF  80..BF  80..BF
///        F4      80..8F  80..BF  80..BF  (F4 90.. would be above U+10FFFF)
///  - Every other byte sequence is replaced by U+FFFD (the three bytes EF BF BD), ONE
///    replacement per maximal invalid subpart: the longest prefix of a sequence that is still
///    the beginning of some valid sequence, or a single byte that cannot begin one (80..C1,
///    F5..FF). Scanning resumes at the byte that broke the sequence, so that byte is never
///    swallowed ("E2 82 41" gives U+FFFD then 'A'; "E0 80 80" gives three U+FFFD, the same
///    as Python's bytes.decode("utf-8", "replace")). A sequence cut off by the end of the
///    input gives one U+FFFD and nothing is read past the end.
std::string json_escape(std::string_view text);

namespace detail {

// Where DashboardService::handle() calls its test hook. Production passes NoServeFault, which
// compiles away; the tests inject exceptions to check how a failure is mapped to a response.
struct NoServeFault {
    void operator()(const HttpRequest&) const noexcept {}
};

}  // namespace detail

struct DashboardServiceTestAccess;

/// The request handler behind the "serve" command: a JSON API and the HTML dashboard over an
/// in-memory set of log entries. It is a plain object (no sockets, no threads), so it is tested
/// by calling handle() with HttpRequest values; the serve command wraps it in an HttpHandler:
///
///     auto service = std::make_shared<DashboardService>(std::move(entries), std::move(alerts), options);
///     server.start([service](const HttpRequest& request) { return service->handle(request); });
///
/// Move-only. A copy would clone every entry, the index and the report, so it is deleted
/// (capture a std::shared_ptr or a reference, as above). A moved-from service owns nothing:
/// entry_count() is 0 and handle() answers 500 (see below); it can be destroyed or assigned to.
///
/// CONSTRUCTION takes ownership of the entries and alerts and does all the work that does not
/// depend on a request, exactly once:
///  - indexes "service LEVEL message" of every entry in an InvertedIndex (the same text as the
///    `search` command), with DocId = the entry's position in the vector, so the entries may
///    come in ANY order (they are never sorted; "document order" below means vector order);
///  - renders the HTML report with render_html_report (title, top_k, time_buckets from the
///    options) so GET / only copies a string. Timestamps may be anything; one case is worked
///    around: when the earliest is exactly INT64_MIN and the latest exactly INT64_MAX (no
///    parsed log has such times) the report is rendered from a copy whose INT64_MIN entries are
///    1 ms later, because the report's timeline would otherwise index out of range. The API
///    routes always show the real timestamps;
///  - renders the /api/summary and /api/alerts bodies.
/// It may throw std::bad_alloc, and std::length_error when there are 2^32 entries or more (the
/// index's id space); nothing is leaked.
///
/// THREADING AND CACHES. handle() must be called from ONE thread at a time (HttpServer's serving
/// thread does exactly that). It builds caches lazily and mutates them without a lock, so the
/// object is NOT thread-safe. The caches are a TopKErrors per min-level (at most 4), a Trie per
/// (field, min-level) (at most 12) and a small memo of completion lists (see /api/complete).
/// Each is built on its first request, in one pass over the entries, and then kept (see
/// RESOURCE BOUNDS for what that costs and when a Trie is dropped again). They only speed things
/// up: an answer never depends on which caches exist, were evicted or are warm, and a build that
/// throws leaves no half-built cache behind and is not remembered, so the next request for it
/// starts the build over.
///
/// ROUTES. The path (percent-decoded once by parse_request_head) must match exactly: a trailing
/// slash or different letter case is a 404. The query string is ignored by routes that take no
/// parameters, and unknown parameters are always ignored. A parameter given twice uses the
/// LAST value (HttpRequest::query_value). HEAD is handled exactly like GET (same status and
/// headers; the server drops the body). Any other method gets 405 {"error":"method not
/// allowed"} with "Allow: GET, HEAD" (the server never lets one through; this is a guard).
///
///   GET /            200 text/html; charset=utf-8: the pre-rendered report. It carries two
///                    headers that no other response has: "Content-Security-Policy:
///                    default-src 'none'; style-src 'unsafe-inline'; base-uri 'none';
///                    form-action 'none'; frame-ancestors 'none'" and "Referrer-Policy:
///                    no-referrer". The report is inline CSS and SVG without scripts, images or
///                    links to anything, so the policy costs it nothing, and it would contain a
///                    future escaping mistake and keep the page from being framed.
///   GET /healthz     200 text/plain; charset=utf-8: "ok".
///   GET /api/summary 200 JSON {"entries":N,
///                              "levels":{"debug":n,"info":n,"warn":n,"error":n},
///                              "services":[{"name":S,"entries":n,"errors":n}, ...],
///                              "first":"<ISO>","last":"<ISO>","alerts":n}
///       services: busiest first (entries descending, then name ascending: a total order, so
///       the result never depends on a sort being stable), one row per distinct service
///       (bounded by the data, not by the request; an empty service name is a service like any
///       other; names are clipped, see STRINGS). "errors" counts ERROR entries. "first"/"last"
///       are the earliest and latest timestamp (format_iso8601_utc), JSON null when there are
///       no entries. "alerts" is the number of alerts given to the constructor.
///   GET /api/top-errors  parameters k (1..1000, default 10) and min-level (DEBUG, INFO, WARN
///       or ERROR in any letter case, default ERROR). 200 JSON {"total":T,"distinct":D,
///       "results":[{"service":S,"signature":S,"count":n,"first_seen":"<ISO>",
///       "last_seen":"<ISO>","example":S}, ...]}, computed with TopKErrors, so the rows,
///       their order and the totals are exactly what `loganalyzer top-errors` prints: best
///       first (count descending, then signature, then service), at most k rows, T = entries
///       at or above min-level, D = distinct (service, signature) groups. The strings are
///       clipped (STRINGS) and the list ends early when the rows reach 4 MiB (BODY): then
///       fewer than min(k, D) rows are returned, always a prefix of the full list.
///   GET /api/search  parameters q (REQUIRED: 400 if missing or empty after decoding) and limit
///       (1..1000, default 50). 200 JSON {"query":Q,"matches":N,"shown":n,"results":
///       [{"time":"<ISO>","level":"ERROR","service":S,"message":S}, ...]}: Q is q as decoded
///       (echoed in full: it is at most as long as the request target the server accepts),
///       N the total number of hits of InvertedIndex::search(q) (query language: see
///       inverted_index.hpp; a query without any usable word, such as "|" or "-", is valid and
///       matches nothing), results are the first `shown` hits in document order, where shown =
///       min(limit, N) unless the rows reach 4 MiB first (BODY); `shown` is always the number
///       of rows returned. Only the rows are limited; the count N is exact. The index sees
///       the whole message even where the response clips it (STRINGS).
///   GET /api/complete  parameters prefix (default "", may be empty), field (signature,
///       service or word, exactly this spelling, default signature), k (1..1000, default 10)
///       and min-level (default DEBUG). 200 JSON {"field":F,"prefix":P,"results":
///       [{"key":S,"count":n}, ...]}: the trie completions of `loganalyzer complete`, heaviest
///       first (count descending, then key ascending bytewise). Only entries at or above
///       min-level count. signature: normalize_signature(message) of each entry, empty
///       signatures skipped; service: the service name (empty names skipped); word: every
///       tokenize(message) token. A key longer than 256 bytes (MAX_KEY) is not a completion
///       and is skipped, so it does not count either. For field=word the prefix is lower-cased
///       (ASCII), because words are indexed in lower case, and P is that lower-cased prefix,
///       i.e. the prefix that was actually matched; for the other fields P is the prefix as
///       decoded. A prefix longer than 256 bytes matches nothing (no key is that long) and
///       is answered without touching the trie. With k above 10 the trie cannot answer from
///       its per-node caches and would scan everything below the prefix on every request, so
///       the top 1000 of a (field, min-level, prefix) are computed once and kept in a memo of
///       the 32 most recently used ones; any k from 11 to 1000 is then the first k of that
///       list (the order is total, so this is exact).
///   GET /api/alerts  200 JSON {"alerts":[{"rule":S,"service":S,"fired_at":"<ISO>","count":n,
///       "first_event":"<ISO>","suppressed":n}, ...]} in the order given to the constructor
///       (it is never sorted, whatever the timestamps say), every one of them (bounded by the
///       data, not by the request; strings are clipped, see STRINGS).
///   anything else    404 {"error":"not found"}.
///
/// BAD PARAMETERS give 400 {"error":"<message>"} whose message names the parameter ("k must be
/// a whole number from 1 to 1000", "min-level must be one of DEBUG, INFO, WARN, ERROR", "q is
/// required: ...", "field must be one of signature, service, word"). The message is a fixed
/// text: the offending value is never echoed. When several parameters are bad, the first in the
/// order of the lists above is reported (top-errors: k, min-level; search: q, limit; complete:
/// field, k, min-level). A number is a non-empty run of ASCII digits and nothing else: no sign,
/// no space, no decimal point, no exponent ("007" is 7, "+5", " 5", "5.0", "1e3", "" are 400);
/// anything above the range is 400, and a number too long for 64 bits is 400, never wrapped.
/// min-level is matched case-insensitively (like the CLI), field case-sensitively (like the CLI).
///
/// JSON. Every JSON response has content type "application/json; charset=utf-8" and no extra
/// headers. The text is always valid RFC 8259 JSON (and valid UTF-8) whatever bytes the log
/// text contains: every string goes through json_escape, numbers are plain unsigned integers,
/// there is no insignificant whitespace, and member order is as written above.
///
/// RESOURCE BOUNDS. Rows, bytes, CPU and memory are bounded separately, because a bound on one
/// is no bound on the others (1000 rows of a 1 MB message are a gigabyte of JSON).
///  - ROWS: a request gets at most 1000 result rows (k and limit are capped at 1000; search
///    results are copied only for the rows shown).
///  - STRINGS: every string that comes from the log (service names, messages, examples,
///    signatures, completion keys, alert rule and service names) is clipped to 4096 bytes
///    before it is escaped. The cut never splits a UTF-8 sequence: it backs up to the start of
///    the character that straddles the limit, so a clipped string is at most 4096 bytes of
///    the original, and it ends with U+2026 (the three bytes E2 80 A6, an ellipsis) to show
///    that it was clipped. A string of 4096 bytes or less is untouched. What the CLIENT sent
///    (q and prefix) is echoed in full, once. An escaped string is at most six times its
///    length (a control byte or '<' becomes \u00XX).
///  - BODY: search and top-errors stop adding rows once the text of the rows would pass 4 MiB
///    (4,194,304 bytes of JSON): the row that crosses the line is dropped and so are all after
///    it. (The first row is always kept; that cannot matter, a row is below 80 KB.) So the rows
///    of a response are at most 4 MiB whatever k asks for, and the response is that plus its
///    envelope and the echoed q. /api/complete has no such line: 1000 rows of at most
///    256-byte keys are below 2 MB. /api/summary and /api/alerts are rendered once from the
///    data and are bounded by it (one row per service, one per alert).
///  - MAX_KEY: a completion key (signature, service name or word) longer than 256 bytes is
///    skipped when the tries are built. Trie::insert breaks weight ties by comparing keys, which
///    costs the length of their common prefix, so near-identical keys of length L cost O(L^2)
///    each: 20 keys of 40,000 bytes took 1.8 s, 12 keys of 100,000 bytes 6 s per (field,
///    min-level) cache, all of it on the single serving thread. With the cap an insert costs a
///    bounded amount and a cold cache is one pass over the entries, linear in their text.
///    Messages and names longer than that stay searchable, countable and visible in the
///    other routes.
///  - CPU: besides the cold-cache pass (once per cache), a request costs O(query length) to
///    parse, O(N) for a search with N hits (the hits are counted), O(k) for a cached
///    completion, and for an uncached (field, min-level, prefix) with k above 10 one scan of
///    the trie below the prefix, after which the memo answers it (32 entries; each holds at
///    most 1000 rows of at most 256-byte keys). Nothing is done per byte of the query string
///    beyond parsing and echoing it. The report is never re-rendered.
///  - MEMORY: the caches are not free. A Trie costs about 35 bytes of memory per byte of
///    distinct key text (measured on 120-letter random keys with nothing in common: nodes,
///    edges and per-node top-10 lists), a TopKErrors about 6 bytes per byte of its groups'
///    text, and there can be 12 and 4 of them. The service therefore keeps an estimate of what
///    its tries hold (40 bytes per byte of key text) and drops the least recently used tries
///    while the estimate is above 256 MiB; a trie that has just been built is never dropped,
///    so a single large trie can exceed the budget, and a request for a dropped trie builds it
///    again. A log whose text is mostly distinct (ids, hashes) is the expensive case; the
///    repetitive text of real logs is far cheaper. The TopKErrors tables are not budgeted.
///    The constructor needs the entries, the index and the report; the caches come on top.
///
/// FAILURES. handle() never throws. Anything thrown while serving a request (std::bad_alloc
/// included, or any other exception, std::exception or not) is mapped to 500 with the JSON body
/// {"error":"internal error"}: nothing about the exception, not even what(), reaches the
/// client, and the service stays usable. The response for that case is prepared in advance, so
/// producing it allocates nothing and cannot fail for lack of memory; right after a failure
/// the service builds the next spare one, and if that allocation fails too, the following
/// failure is answered with status 500 and an EMPTY content type, which HttpServer replaces by
/// its own generic 500 (the spare is built again at the next failure).
class DashboardService {
public:
    DashboardService(std::vector<LogEntry> entries, std::vector<Alert> alerts, ServeOptions options = {});
    ~DashboardService();

    DashboardService(const DashboardService&) = delete;
    DashboardService& operator=(const DashboardService&) = delete;
    DashboardService(DashboardService&&) noexcept;
    DashboardService& operator=(DashboardService&&) noexcept;

    /// Serves one GET or HEAD request; see the class comment. Never throws.
    HttpResponse handle(const HttpRequest& request);

    /// Number of entries the service owns (0 once it has been moved from).
    std::size_t entry_count() const noexcept;

private:
    friend struct DashboardServiceTestAccess;

    struct Impl;

    // What the caches have done so far; only the tests look at it (through the friend), so that
    // "built once", "evicted" and "memoized" are checked by counting, not by timing.
    struct CacheStats {
        std::size_t trie_builds = 0;         // tries built, evicted ones built again included
        std::size_t top_errors_builds = 0;   // TopKErrors tables built
        std::size_t resident_tries = 0;      // tries alive now
        std::size_t memo_hits = 0;           // completion lists served from the memo
        std::size_t memo_misses = 0;         // completion lists computed (and then memoized)
        std::size_t resident_memo = 0;       // memo entries alive now (at most 32)
    };
    CacheStats cache_stats() const noexcept;
    // Replaces the 256 MiB estimate above which tries are dropped (tests use a tiny one).
    void set_trie_budget(std::size_t estimated_bytes) noexcept;

    // handle() with a hook that runs inside the guarded region before routing. Only the tests
    // pass anything but NoServeFault.
    template <class Fault>
    HttpResponse handle_with(const HttpRequest& request, Fault&& fault) {
        try {
            fault(request);
            return route(request);
        } catch (...) {
            return take_failure_response();
        }
    }

    HttpResponse route(const HttpRequest& request);
    HttpResponse take_failure_response() noexcept;

    std::unique_ptr<Impl> impl_;
    HttpResponse failure_response_;  // the prepared 500 (see FAILURES), moved out when used
};

}  // namespace loganalyzer
