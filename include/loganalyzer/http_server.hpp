#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace loganalyzer {

// A minimal, hardened HTTP/1.1 server for serving a live dashboard: raw BSD / Winsock sockets
// (no third-party code), IPv4 only, GET and HEAD only, one connection at a time, no keep-alive.
//
// What it is NOT: it has no TLS, no request bodies, no chunked encoding, no routing, no
// authentication. It binds to loopback by default; do not expose it to an untrusted network.

struct HttpHeader {
    std::string name;
    std::string value;
};

/// A parsed request. Only the pieces a handler needs are kept; header lines are validated and
/// then discarded.
struct HttpRequest {
    std::string method;  ///< "GET" or "HEAD"
    std::string target;  ///< the raw request target, exactly as received, e.g. "/api/top-errors?k=5"
    std::string path;    ///< percent-decoded path (decoded once), e.g. "/api/top-errors"; '+' stays '+'
    /// Percent-decoded key/value pairs in order of appearance; '+' decodes to a space. A pair
    /// without '=' has an empty value. Empty pairs ("a=1&&b=2") are skipped.
    std::vector<std::pair<std::string, std::string>> query;
    /// The value of the Host header with surrounding spaces trimmed, exactly as received
    /// ("localhost:8080"); empty when the request has no Host header.
    std::string host;

    /// Pointer to the value of the LAST pair whose key equals `key` (exact, case-sensitive
    /// comparison of the decoded key), or nullptr. The pointer is valid as long as this request
    /// is not modified or destroyed.
    const std::string* query_value(std::string_view key) const;
};

/// What a handler returns.
///
/// The server sends: "HTTP/1.1 <status> <reason>", Content-Type, Content-Length (the exact
/// body size, also for HEAD), "Connection: close", "Cache-Control: no-store",
/// "X-Content-Type-Options: nosniff", then `headers` in order, a blank line, and the body
/// (omitted for HEAD).
///
/// A response that is not safe to put on the wire is replaced by a generic 500 whose body is
/// "internal server error" (nothing about the offending response is revealed). A response is
/// rejected when
///  - status is outside 100..599;
///  - content_type is empty or contains a control character (CR, LF, NUL and the rest of
///    0x00-0x1F, and 0x7F);
///  - a header name is not a non-empty RFC 7230 token (so no ':', space, CR, LF, NUL);
///  - a header value contains a control character other than horizontal tab, or 0x7F;
///  - a header is named Content-Length, Content-Type, Connection or Transfer-Encoding (any
///    case): the server owns those; use the dedicated fields instead;
///  - the status cannot carry a body (1xx, 204, 304) and `body` is not empty. For those
///    statuses (with an empty body) the server omits Content-Type and Content-Length.
struct HttpResponse {
    int status = 200;
    std::string content_type = "text/plain; charset=utf-8";
    std::string body;
    std::vector<HttpHeader> headers;  ///< extra response headers, appended after the fixed ones
};

/// Called once per accepted request, only on the serving thread, never concurrently with itself.
/// May throw: any exception (std::exception or not) becomes a generic 500 and what() is never
/// sent to the client. It is called for HEAD too (the body is then computed and discarded, so
/// Content-Length matches GET).
using HttpHandler = std::function<HttpResponse(const HttpRequest&)>;

struct HttpServerOptions {
    std::string bind_address = "127.0.0.1";  ///< IPv4 dotted quad only (no host names, no IPv6)
    std::uint16_t port = 8080;               ///< 0 = let the OS pick a free port (see HttpServer::port())
    /// Per connection: the TOTAL time allowed to receive the whole request head, measured from
    /// accept. It is a deadline, not an idle timeout, so a client that trickles one byte at a
    /// time cannot hold the (sequential) server longer than this. On expiry the connection is
    /// closed without a response.
    int read_timeout_ms = 5000;
    /// Per connection: the TOTAL time allowed to send the response. A client that stops reading
    /// delays later clients by at most this long; the connection is then closed.
    int write_timeout_ms = 5000;
    /// The request head INCLUDING its terminating CRLF CRLF may be at most this many bytes;
    /// one more byte is answered with 431. The server never buffers more than this per request.
    std::size_t max_header_bytes = 16384;
    std::size_t max_target_bytes = 2048;  ///< longest accepted request target (414 beyond it)
    std::size_t max_query_params = 64;    ///< most key/value pairs in one query (400 beyond it)
    /// Defence against DNS rebinding. A web page the user visits can make their browser send
    /// requests to http://127.0.0.1:<port>/ after its own domain is re-pointed at loopback, and
    /// read the answers: the browser's same-origin rule no longer protects a local service. The
    /// request still carries the attacker's domain in its Host header, so when this list is not
    /// empty a request whose Host is not one of these names is answered 403 and never reaches the
    /// handler. Names are bare host names or IPv4 literals without a port ("localhost",
    /// "127.0.0.1"); matching is case-insensitive, and the request's Host may add a ":port"
    /// (1-5 digits). A request WITHOUT a Host header is refused too (it is mandatory in
    /// HTTP/1.1, and an attacker-controlled client can omit it). Empty (the default) switches
    /// the check off, which is right when the server is meant to be reached by name from other
    /// machines. parse_request_head() ignores this field: the check happens in the server.
    std::vector<std::string> allowed_hosts;
};

/// Single-threaded-accept HTTP/1.1 server.
///
/// Threading: start() launches ONE serving thread. It accepts a connection, reads the request,
/// calls the handler, writes the response and closes the connection, strictly one connection at
/// a time. The handler runs only on that thread. The accept loop and every wait for a client
/// wake up every ~100 ms (poll/select with a timeout; no socket is closed from another thread
/// while the serving thread is blocked on it) and look at the stop flag, so stop() returns
/// within about 100 ms plus the time the handler of a request already being served needs and
/// a lingering close of at most 250 ms. A client that is still sending its head, or not
/// reading its response, is abandoned when stop() is called. A slow client delays later
/// clients by at most read_timeout_ms (reading) or write_timeout_ms (writing). start(),
/// stop(), running(), port() and requests_served() may be called from any thread, except that
/// the handler must not call start() or destroy the server.
///
/// Connection handling, in order:
///  1. Sockets are non-blocking; the read and write timeouts are enforced as deadlines.
///  2. The request head is read up to the first CRLF CRLF (a bare LF LF does not end it; such a
///     client times out). More than max_header_bytes gives 431. EOF, a socket error or a
///     timeout before the head is complete closes the connection without a response.
///  3. parse_request_head() decides: Ok -> handler; BadRequest 400; MethodNotAllowed 405 (with
///     "Allow: GET, HEAD"); UriTooLong 414; VersionNotSupported 505. Request bodies are not
///     supported: a request with Content-Length > 0 or any Transfer-Encoding is a 400.
///  4. The response always carries "Connection: close". Bytes the client sent after the head
///     (a body, a pipelined request) are never interpreted: they are read and discarded for a
///     short, bounded time after the response so that closing does not reset the connection
///     and destroy the response in flight, then the connection is closed.
///  Server-generated error responses are text/plain with the lowercase reason as the body
///  ("bad request", "internal server error", ...).
///
/// Sockets are owned by RAII wrappers, so every exit path (exceptions included) closes them.
/// SIGPIPE is never raised (MSG_NOSIGNAL / SO_NOSIGPIPE); a client that vanishes mid-response
/// costs the server nothing but that connection. The process-wide SIGPIPE disposition is not
/// touched. Windows: WSAStartup/WSACleanup are reference-counted internally, so any number of
/// servers (and other Winsock users) can coexist.
///
/// Binding: only the address given in the options, IPv4. POSIX sets SO_REUSEADDR (restart
/// right after a stop works); Windows sets SO_EXCLUSIVEADDRUSE instead (SO_REUSEADDR there
/// lets another process hijack the port). Binding a port that is in use throws.
class HttpServer {
public:
    /// Validates the options and throws std::invalid_argument for a bind_address that is not a
    /// strict dotted quad ("a.b.c.d", each part 0-255 without leading zeros), a timeout < 1 ms, or
    /// a zero limit. Does NOT open a socket.
    explicit HttpServer(HttpServerOptions options = {});

    /// Calls stop(). Never throws. Must not be called from the handler.
    ~HttpServer();

    HttpServer(const HttpServer&) = delete;
    HttpServer& operator=(const HttpServer&) = delete;

    /// Binds, listens and starts the serving thread. The server is ready to accept connections
    /// when this returns (the kernel queues them even before the thread picks them up).
    /// Throws std::logic_error if already started (stop() first; a stopped server may be started
    /// again), std::invalid_argument (a std::logic_error) if `handler` is empty, and
    /// std::runtime_error if the socket cannot be created, bound or put into listening mode
    /// (the message includes the OS error text and number; "address in use" included). After a
    /// throw the server is not started and nothing is leaked.
    void start(HttpHandler handler);

    /// Stops accepting, lets a connection that is being served finish (bounded by the
    /// timeouts), joins the serving thread and closes the listening socket, so the port is free
    /// again when this returns. Idempotent, thread-safe, never throws; a stop() that races
    /// another stop() waits for it. Called from inside the handler it cannot join itself: it
    /// only requests the shutdown (running() becomes false at once, the serving thread leaves
    /// its loop when the handler returns) and a later stop() or the destructor does the join.
    void stop() noexcept;

    /// True from a successful start() until stop() begins (or the accept loop dies from an
    /// unrecoverable socket error).
    bool running() const noexcept;

    /// The port actually bound (useful with options.port == 0). Throws std::logic_error unless
    /// the server is started (never started, or stopped).
    std::uint16_t port() const;

    /// Request/response exchanges completed so far, whatever the status (200, 404, 400, 431,
    /// 500, ...): counted once the whole response has been written to the socket, before the
    /// connection is closed, so a client that reads until EOF is guaranteed to observe its own
    /// exchange in this counter. Connections closed without a response (timeout, EOF) and
    /// responses that could not be fully written are not counted. Thread-safe (atomic).
    std::uint64_t requests_served() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// ---------------------------------------------------------------------------------------------
// Pure helpers, exposed so they can be tested without sockets.

enum class ParseStatus {
    Ok,
    BadRequest,           ///< -> 400
    MethodNotAllowed,     ///< -> 405 with "Allow: GET, HEAD"
    UriTooLong,           ///< -> 414
    VersionNotSupported,  ///< -> 505
};

/// Parses a request head: the request line and header lines separated by CRLF, everything up to
/// (not including) the blank line that ends the head. `out` is assigned only when the result is
/// Ok; on any other result it is left untouched. Only limits.max_target_bytes and
/// limits.max_query_params are used. Never throws except std::bad_alloc.
///
/// Rules, checked in this order (the first violated one decides the status):
///  1. BadRequest: an empty head; any control byte (< 0x20 or 0x7F) other than the CR LF
///     pairs that separate lines (so NUL, tab, a bare CR and a bare LF are all rejected, in the
///     request line and in header values alike).
///  2. Request line `METHOD SP TARGET SP HTTP/d.d`: exactly two single spaces (no leading,
///     trailing, doubled or missing ones; HTTP/0.9's "GET /" is therefore a 400);
///     METHOD must be 1-32 RFC 7230 token characters containing no lowercase letter
///     (empty or "get" -> BadRequest); the version must be literally "HTTP/" digit "." digit.
///     All violations -> BadRequest.
///  3. UriTooLong: the target is longer than limits.max_target_bytes (exactly the limit is fine).
///  4. VersionNotSupported: a well-formed version other than HTTP/1.0 and HTTP/1.1.
///  5. MethodNotAllowed: any method other than GET and HEAD (HEAD is served like GET).
///  6. Target, BadRequest unless it is origin-form: it starts with '/' (so "http://host/x",
///     "host:443" and "*" are rejected), contains no '#', and its path and query percent-decode
///     (see percent_decode(); the path decodes without '+' handling, so '%00' in a path is a
///     400). Bytes >= 0x80 are accepted as raw bytes, UTF-8 is never validated; "//" and "/.."
///     are ordinary paths (the server has no filesystem). The query is everything after the
///     FIRST '?'. It is split on '&' (empty pairs skipped, more than limits.max_query_params
///     pairs -> BadRequest), each pair split at its FIRST '=', key and value decoded with '+' as
///     space.
///  7. Header lines (at most 100, else BadRequest): `name ":" value` where the name is a
///     non-empty token (so a space before the colon, a leading space and obs-fold continuation
///     lines are rejected) and a colon is present; the value, with surrounding spaces trimmed,
///     is otherwise ignored (the Host value is kept in HttpRequest::host), with these
///     exceptions: a second Host header, a second
///     Content-Length header, a Content-Length that is not all digits or is not zero, and any
///     Transfer-Encoding header are BadRequest (request-smuggling hardening; bodies are not
///     supported). A missing Host header is accepted.
ParseStatus parse_request_head(std::string_view head, const HttpServerOptions& limits, HttpRequest& out);

/// Replaces %XX (hex digits in either case) by the byte it names; with `plus_is_space` a '+'
/// becomes a space (query strings; a '%2B' is always a literal '+'). Decoding happens exactly
/// once ("%2541" gives "%41"). Bytes >= 0x80 pass through untouched. Returns false, with `out`
/// cleared, on a malformed or truncated escape ("%", "%4", "%zz") and when the decoded text
/// would contain a NUL (a literal NUL byte or "%00"). `out` is replaced, not appended to.
bool percent_decode(std::string_view in, bool plus_is_space, std::string& out);

/// The standard reason phrase ("OK", "Not Found", "Request Header Fields Too Large", ...) of
/// the statuses this server and a dashboard normally use, "Unknown" for anything else.
std::string_view status_reason(int status) noexcept;

}  // namespace loganalyzer
