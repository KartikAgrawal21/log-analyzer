#include "loganalyzer/http_server.hpp"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <system_error>
#include <thread>

// ---- platform socket API ------------------------------------------------------------------
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace loganalyzer {
namespace {

// ---- thin platform layer --------------------------------------------------------------------
// Everything that differs between Winsock and BSD sockets lives in this block; the rest of the
// file is portable C++17.

#ifdef _WIN32

using socket_t = SOCKET;
constexpr socket_t kInvalidSocket = INVALID_SOCKET;
using SockLen = int;
constexpr int kShutdownSend = SD_SEND;

inline int last_error() noexcept { return ::WSAGetLastError(); }
inline bool err_would_block(int e) noexcept { return e == WSAEWOULDBLOCK; }
inline bool err_interrupted(int e) noexcept { return e == WSAEINTR; }
inline void close_native(socket_t s) noexcept { ::closesocket(s); }

inline bool set_nonblocking(socket_t s) noexcept {
    u_long mode = 1;
    return ::ioctlsocket(s, FIONBIO, &mode) == 0;
}

inline std::ptrdiff_t sock_recv(socket_t s, char* buffer, std::size_t length) noexcept {
    return ::recv(s, buffer, static_cast<int>(length), 0);
}

inline std::ptrdiff_t sock_send(socket_t s, const char* data, std::size_t length) noexcept {
    return ::send(s, data, static_cast<int>(length), 0);
}

#else  // POSIX

using socket_t = int;
constexpr socket_t kInvalidSocket = -1;
using SockLen = socklen_t;
constexpr int kShutdownSend = SHUT_WR;

#ifdef MSG_NOSIGNAL
constexpr int kSendFlags = MSG_NOSIGNAL;  // Linux: never raise SIGPIPE for this send
#else
constexpr int kSendFlags = 0;  // macOS/BSD: SO_NOSIGPIPE is set on every accepted socket instead
#endif

inline int last_error() noexcept { return errno; }
inline bool err_would_block(int e) noexcept { return e == EAGAIN || e == EWOULDBLOCK; }
inline bool err_interrupted(int e) noexcept { return e == EINTR; }
inline void close_native(socket_t s) noexcept { ::close(s); }

inline bool set_nonblocking(socket_t s) noexcept {
    const int flags = ::fcntl(s, F_GETFL, 0);
    return flags != -1 && ::fcntl(s, F_SETFL, flags | O_NONBLOCK) != -1;
}

inline std::ptrdiff_t sock_recv(socket_t s, char* buffer, std::size_t length) noexcept {
    return ::recv(s, buffer, length, 0);
}

inline std::ptrdiff_t sock_send(socket_t s, const char* data, std::size_t length) noexcept {
    return ::send(s, data, length, kSendFlags);
}

#endif

/// "what: <OS message> (os error N)".
std::string os_error(std::string what, int code) {
    std::string message = std::system_category().message(code);
    while (!message.empty() &&
           (message.back() == '\r' || message.back() == '\n' || message.back() == ' ' || message.back() == '.')) {
        message.pop_back();
    }
    what += ": ";
    what += message;
    what += " (os error ";
    what += std::to_string(code);
    what += ')';
    return what;
}

/// Reference-counted WSAStartup / WSACleanup (a no-op elsewhere): the first holder starts
/// Winsock, the last one to let go cleans it up, so servers (and tests) can come and go freely.
#ifdef _WIN32
class WinsockSession {
public:
    WinsockSession() = default;
    WinsockSession(const WinsockSession&) = delete;
    WinsockSession& operator=(const WinsockSession&) = delete;
    ~WinsockSession() { release(); }

    void acquire() {
        if (held_) return;
        std::lock_guard<std::mutex> lock(mutex());
        if (count() == 0) {
            WSADATA data;
            const int rc = ::WSAStartup(MAKEWORD(2, 2), &data);
            if (rc != 0) throw std::runtime_error(os_error("HttpServer: WSAStartup failed", rc));
        }
        ++count();
        held_ = true;
    }

    void release() noexcept {
        if (!held_) return;
        held_ = false;
        try {
            std::lock_guard<std::mutex> lock(mutex());
            if (--count() == 0) ::WSACleanup();
        } catch (...) {
        }
    }

private:
    static std::mutex& mutex() {
        static std::mutex m;
        return m;
    }
    static int& count() {
        static int c = 0;
        return c;
    }
    bool held_ = false;
};
#else
class WinsockSession {
public:
    void acquire() noexcept {}
    void release() noexcept {}
};
#endif

/// Owns one socket handle; every exit path closes it.
class OwnedSocket {
public:
    OwnedSocket() noexcept = default;
    explicit OwnedSocket(socket_t s) noexcept : s_(s) {}
    OwnedSocket(const OwnedSocket&) = delete;
    OwnedSocket& operator=(const OwnedSocket&) = delete;
    OwnedSocket(OwnedSocket&& other) noexcept : s_(other.release()) {}
    OwnedSocket& operator=(OwnedSocket&& other) noexcept {
        if (this != &other) reset(other.release());
        return *this;
    }
    ~OwnedSocket() { reset(); }

    socket_t get() const noexcept { return s_; }
    bool valid() const noexcept { return s_ != kInvalidSocket; }
    socket_t release() noexcept {
        const socket_t s = s_;
        s_ = kInvalidSocket;
        return s;
    }
    void reset(socket_t s = kInvalidSocket) noexcept {
        if (s_ != kInvalidSocket) close_native(s_);
        s_ = s;
    }

private:
    socket_t s_ = kInvalidSocket;
};

enum class Wait { Ready, Timeout, Interrupted, Error };

/// Waits until `s` is readable (or writable) or `timeout_ms` has passed. Ready also covers
/// "hung up / errored": the following recv()/send() reports the details.
Wait wait_for(socket_t s, bool for_write, int timeout_ms) noexcept {
    if (timeout_ms < 0) timeout_ms = 0;
#ifdef _WIN32
    fd_set set;
    FD_ZERO(&set);
    FD_SET(s, &set);
    timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    const int rc = ::select(0, for_write ? nullptr : &set, for_write ? &set : nullptr, nullptr, &tv);
    if (rc > 0) return Wait::Ready;
    if (rc == 0) return Wait::Timeout;
    return err_interrupted(last_error()) ? Wait::Interrupted : Wait::Error;
#else
    pollfd p;
    p.fd = s;
    p.events = static_cast<short>(for_write ? POLLOUT : POLLIN);
    p.revents = 0;
    const int rc = ::poll(&p, 1, timeout_ms);
    if (rc > 0) return (p.revents & POLLNVAL) != 0 ? Wait::Error : Wait::Ready;
    if (rc == 0) return Wait::Timeout;
    return err_interrupted(last_error()) ? Wait::Interrupted : Wait::Error;
#endif
}

// ---- small text helpers ----------------------------------------------------------------------

using Clock = std::chrono::steady_clock;

constexpr int kAcceptPollMs = 100;           // how often the accept loop looks at the stop flag
constexpr int kMaxLingerMs = 250;            // longest lingering close after a response
constexpr std::size_t kMaxDrainBytes = 1u << 20;
constexpr std::size_t kRecvChunk = 4096;
constexpr std::size_t kSendChunk = 1u << 20;
constexpr std::size_t kMaxMethodLength = 32;
constexpr std::size_t kMaxHeaderLines = 100;

/// Milliseconds left until `deadline`, rounded up, never negative.
int ms_until(Clock::time_point deadline) noexcept {
    const auto now = Clock::now();
    if (now >= deadline) return 0;
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count() + 1;
    return ms > std::numeric_limits<int>::max() ? std::numeric_limits<int>::max() : static_cast<int>(ms);
}

/// wait_for() in slices of at most kAcceptPollMs, so a stop request is noticed promptly even
/// while a client is stalling a read or not draining a write. Returns Ready, Timeout (the
/// deadline passed) or Error (socket error, or `cancel` was set: callers treat it as "give up").
Wait wait_until_ready(socket_t s, bool for_write, Clock::time_point deadline, const std::atomic<bool>& cancel) noexcept {
    for (;;) {
        if (cancel.load()) return Wait::Error;
        const int left = ms_until(deadline);
        const int slice = std::min(left, kAcceptPollMs);
        const Wait w = wait_for(s, for_write, slice);
        if (w == Wait::Ready || w == Wait::Error) return w;
        if (w == Wait::Timeout && left <= slice) return Wait::Timeout;  // this slice reached the deadline
    }
}

bool is_digit(char c) noexcept { return c >= '0' && c <= '9'; }

int hex_value(char c) noexcept {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/// RFC 7230 tchar.
bool is_tchar(char c) noexcept {
    if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) return true;
    switch (c) {
        case '!': case '#': case '$': case '%': case '&': case '\'': case '*': case '+':
        case '-': case '.': case '^': case '_': case '`': case '|': case '~':
            return true;
        default:
            return false;
    }
}

bool is_token(std::string_view s) noexcept {
    if (s.empty()) return false;
    for (const char c : s) {
        if (!is_tchar(c)) return false;
    }
    return true;
}

char lower_ascii(char c) noexcept { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c; }

bool iequals(std::string_view a, std::string_view lower_b) noexcept {
    if (a.size() != lower_b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (lower_ascii(a[i]) != lower_b[i]) return false;
    }
    return true;
}

std::string_view trim_spaces(std::string_view s) noexcept {
    while (!s.empty() && s.front() == ' ') s.remove_prefix(1);
    while (!s.empty() && s.back() == ' ') s.remove_suffix(1);
    return s;
}

/// Any control character (NUL, CR, LF, ... 0x1F, 0x7F); horizontal tab is allowed on request.
bool has_control(std::string_view s, bool allow_tab) noexcept {
    for (const char ch : s) {
        const unsigned char c = static_cast<unsigned char>(ch);
        if (c == 0x7F) return true;
        if (c < 0x20 && !(allow_tab && c == '\t')) return true;
    }
    return false;
}

/// Strict dotted quad: four decimal parts of 1-3 digits, each 0-255, no leading zeros.
bool parse_dotted_quad(std::string_view text, std::uint32_t& out) noexcept {
    std::uint32_t value = 0;
    int parts = 0;
    std::size_t i = 0;
    for (;;) {
        const std::size_t start = i;
        unsigned part = 0;
        while (i < text.size() && is_digit(text[i])) {
            part = part * 10 + static_cast<unsigned>(text[i] - '0');
            ++i;
            if (i - start > 3) return false;
        }
        const std::size_t length = i - start;
        if (length == 0 || part > 255 || (length > 1 && text[start] == '0')) return false;
        value = (value << 8) | part;
        ++parts;
        if (i == text.size()) break;
        if (text[i] != '.') return false;
        ++i;
    }
    if (parts != 4) return false;
    out = value;
    return true;
}

// ---- request head parsing ---------------------------------------------------------------------

bool valid_method(std::string_view m) noexcept {
    if (m.empty() || m.size() > kMaxMethodLength) return false;
    for (const char c : m) {
        if (!is_tchar(c) || (c >= 'a' && c <= 'z')) return false;
    }
    return true;
}

bool well_formed_version(std::string_view v) noexcept {
    return v.size() == 8 && v.substr(0, 5) == "HTTP/" && is_digit(v[5]) && v[6] == '.' && is_digit(v[7]);
}

/// Fills req.path and req.query from an origin-form target. False = BadRequest.
bool parse_target(std::string_view target, const HttpServerOptions& limits, HttpRequest& req) {
    if (target.empty() || target.front() != '/') return false;           // absolute-form, authority-form, "*"
    if (target.find('#') != std::string_view::npos) return false;        // browsers never send a fragment
    const std::size_t question = target.find('?');
    const std::string_view raw_path = target.substr(0, question);
    if (!percent_decode(raw_path, false, req.path)) return false;
    if (question == std::string_view::npos) return true;

    std::string_view query = target.substr(question + 1);
    while (!query.empty()) {
        const std::size_t amp = query.find('&');
        const std::string_view pair = query.substr(0, amp);
        query = amp == std::string_view::npos ? std::string_view() : query.substr(amp + 1);
        if (pair.empty()) continue;
        if (req.query.size() >= limits.max_query_params) return false;
        const std::size_t eq = pair.find('=');
        const std::string_view raw_key = pair.substr(0, eq);
        const std::string_view raw_value = eq == std::string_view::npos ? std::string_view() : pair.substr(eq + 1);
        std::string key;
        std::string value;
        if (!percent_decode(raw_key, true, key) || !percent_decode(raw_value, true, value)) return false;
        req.query.emplace_back(std::move(key), std::move(value));
    }
    return true;
}

/// Validates one header line. `seen_host` / `seen_length` carry the duplicate checks; the
/// (trimmed) value of the Host header is stored in `host` (a view into the line).
bool check_header_line(std::string_view line, bool& seen_host, bool& seen_length, std::string_view& host) noexcept {
    const std::size_t colon = line.find(':');
    if (colon == std::string_view::npos) return false;
    const std::string_view name = line.substr(0, colon);
    if (!is_token(name)) return false;  // also rejects "Name : v", " Name: v" and obs-fold lines
    const std::string_view value = trim_spaces(line.substr(colon + 1));
    if (iequals(name, "host")) {
        if (seen_host) return false;
        seen_host = true;
        host = value;
    } else if (iequals(name, "content-length")) {
        if (seen_length) return false;
        seen_length = true;
        // Bodies are not supported: the only acceptable length is zero ("0", "00", ...).
        if (value.empty()) return false;
        for (const char c : value) {
            if (c != '0') return false;
        }
    } else if (iequals(name, "transfer-encoding")) {
        return false;
    }
    return true;
}

// ---- response building ----------------------------------------------------------------------

bool status_has_no_body(int status) noexcept { return status < 200 || status == 204 || status == 304; }

/// True if `r` is safe to put on the wire (see HttpResponse in the header).
bool response_is_valid(const HttpResponse& r) noexcept {
    if (r.status < 100 || r.status > 599) return false;
    if (status_has_no_body(r.status)) {
        if (!r.body.empty()) return false;
    } else if (r.content_type.empty() || has_control(r.content_type, false)) {
        return false;
    }
    for (const HttpHeader& h : r.headers) {
        if (!is_token(h.name) || has_control(h.value, true)) return false;
        if (iequals(h.name, "content-length") || iequals(h.name, "content-type") || iequals(h.name, "connection") ||
            iequals(h.name, "transfer-encoding")) {
            return false;
        }
    }
    return true;
}

/// The complete bytes of a response. `r` must be valid. `head_only` omits the body (HEAD).
std::string build_wire(const HttpResponse& r, bool head_only) {
    const bool no_body = status_has_no_body(r.status);
    std::string wire;
    wire.reserve(256 + (head_only ? 0 : r.body.size()));
    wire += "HTTP/1.1 ";
    wire += std::to_string(r.status);
    wire += ' ';
    wire += status_reason(r.status);
    wire += "\r\n";
    if (!no_body) {
        wire += "Content-Type: ";
        wire += r.content_type;
        wire += "\r\nContent-Length: ";
        wire += std::to_string(r.body.size());
        wire += "\r\n";
    }
    wire += "Connection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n";
    for (const HttpHeader& h : r.headers) {
        wire += h.name;
        wire += ": ";
        wire += h.value;
        wire += "\r\n";
    }
    wire += "\r\n";
    if (!no_body && !head_only) wire += r.body;
    return wire;
}

/// A server-generated error response: the lowercase reason phrase as a text/plain body.
std::string error_wire(int status, bool head_only) {
    HttpResponse r;
    r.status = status;
    r.body = std::string(status_reason(status));
    for (char& c : r.body) c = lower_ascii(c);
    if (status == 405) r.headers.push_back(HttpHeader{"Allow", "GET, HEAD"});
    return build_wire(r, head_only);
}

bool looks_like_head_request(std::string_view head) noexcept { return head.substr(0, 5) == "HEAD "; }

/// Is `host` (a Host header value) one of `allowed`, optionally followed by ":port"? Case-insensitive
/// on the name; the port, when present, must be 1-5 digits. An empty value never matches.
bool host_allowed(const std::vector<std::string>& allowed, std::string_view host) noexcept {
    if (host.empty()) return false;
    std::string_view name = host;
    const std::size_t colon = host.rfind(':');
    if (colon != std::string_view::npos) {
        const std::string_view port = host.substr(colon + 1);
        if (port.empty() || port.size() > 5) return false;
        for (const char c : port) {
            if (c < '0' || c > '9') return false;
        }
        name = host.substr(0, colon);
    }
    for (const std::string& candidate : allowed) {
        if (iequals(name, candidate)) return true;
    }
    return false;
}

/// The wire bytes answering the complete request head `head`.
std::string make_reply(const HttpServerOptions& options, const HttpHandler& handler, std::string_view head) {
    HttpRequest request;
    switch (parse_request_head(head, options, request)) {
        case ParseStatus::Ok: break;
        case ParseStatus::BadRequest: return error_wire(400, looks_like_head_request(head));
        case ParseStatus::MethodNotAllowed: return error_wire(405, looks_like_head_request(head));
        case ParseStatus::UriTooLong: return error_wire(414, looks_like_head_request(head));
        case ParseStatus::VersionNotSupported: return error_wire(505, looks_like_head_request(head));
    }
    const bool head_only = request.method == "HEAD";
    // DNS-rebinding defence: refuse a Host we were not told to answer to, before any handler runs.
    if (!options.allowed_hosts.empty() && !host_allowed(options.allowed_hosts, request.host)) {
        return error_wire(403, head_only);
    }
    HttpResponse response;
    try {
        response = handler(request);
    } catch (...) {
        return error_wire(500, head_only);  // never reveal what() or the exception type
    }
    if (!response_is_valid(response)) return error_wire(500, head_only);
    return build_wire(response, head_only);
}

// ---- connection I/O -----------------------------------------------------------------------------

enum class HeadResult { Complete, TooLarge, Closed };

/// Reads until the first CRLF CRLF. On Complete, `head` is everything before it. Never reads
/// more than `max_bytes` in total (head plus terminator), so a pipelined request or a body is
/// left in the kernel buffer and never interpreted.
HeadResult read_head(socket_t s, std::size_t max_bytes, Clock::time_point deadline, const std::atomic<bool>& cancel,
                     std::string& head) {
    head.clear();
    char chunk[kRecvChunk];
    std::size_t scan_from = 0;
    for (;;) {
        const Wait w = wait_until_ready(s, false, deadline, cancel);
        if (w != Wait::Ready) return HeadResult::Closed;  // timeout, socket error or shutdown

        const std::size_t room = max_bytes - head.size();  // > 0: we return as soon as head fills up
        const std::ptrdiff_t n = sock_recv(s, chunk, std::min(room, sizeof chunk));
        if (n == 0) return HeadResult::Closed;  // EOF before the head was complete
        if (n < 0) {
            const int e = last_error();
            if (err_would_block(e) || err_interrupted(e)) continue;
            return HeadResult::Closed;
        }
        head.append(chunk, static_cast<std::size_t>(n));

        const std::size_t end = head.find("\r\n\r\n", scan_from);
        if (end != std::string::npos) {
            head.resize(end);  // drop the terminator (and anything that followed it within the limit)
            return HeadResult::Complete;
        }
        if (head.size() >= max_bytes) return HeadResult::TooLarge;
        scan_from = head.size() >= 3 ? head.size() - 3 : 0;
    }
}

/// Writes all of data[0, length) before `deadline`; handles partial sends, EINTR and
/// would-block. False if the peer went away or the deadline passed.
bool send_all(socket_t s, const char* data, std::size_t length, Clock::time_point deadline,
              const std::atomic<bool>& cancel) {
    std::size_t sent = 0;
    while (sent < length) {
        const std::ptrdiff_t n = sock_send(s, data + sent, std::min(length - sent, kSendChunk));
        if (n > 0) {
            sent += static_cast<std::size_t>(n);
            continue;
        }
        const int e = n < 0 ? last_error() : 0;
        if (n < 0 && err_interrupted(e)) continue;
        if (n == 0 || err_would_block(e)) {
            const Wait w = wait_until_ready(s, true, deadline, cancel);
            if (w == Wait::Ready) continue;
            return false;  // timed out (a client that does not read), shutting down, or the socket is broken
        }
        return false;  // EPIPE / ECONNRESET / WSAECONNABORTED ...
    }
    return true;
}

/// Half-close, then read and discard what the client still sends (bounded in bytes and time)
/// before the socket is closed. Closing a socket whose receive buffer is not empty makes the
/// OS send a RST, which can destroy a response the client has not read yet; this is how an
/// oversized head or a request body still gets its 431 / 400.
void graceful_close(OwnedSocket& client, int linger_ms) noexcept {
    ::shutdown(client.get(), kShutdownSend);
    const auto deadline = Clock::now() + std::chrono::milliseconds(linger_ms);
    char chunk[kRecvChunk];
    std::size_t drained = 0;
    while (drained < kMaxDrainBytes) {
        const Wait w = wait_for(client.get(), false, ms_until(deadline));
        if (w == Wait::Interrupted) continue;
        if (w != Wait::Ready) break;
        const std::ptrdiff_t n = sock_recv(client.get(), chunk, sizeof chunk);
        if (n > 0) {
            drained += static_cast<std::size_t>(n);
        } else if (n == 0) {
            break;  // the client closed its side too
        } else {
            const int e = last_error();
            if (err_would_block(e) || err_interrupted(e)) continue;
            break;
        }
    }
    client.reset();
}

/// Non-blocking mode and no SIGPIPE for a freshly accepted connection. False = drop it.
bool prepare_client(socket_t s) noexcept {
#ifdef SO_NOSIGPIPE
    const int one = 1;
    ::setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, reinterpret_cast<const char*>(&one), sizeof one);
#endif
#ifndef _WIN32
    ::fcntl(s, F_SETFD, FD_CLOEXEC);
#endif
    return set_nonblocking(s);
}

/// Creates, configures, binds and starts listening on a non-blocking IPv4 socket.
/// Throws std::runtime_error (message includes the OS error); the socket is closed by RAII.
OwnedSocket create_listener(const HttpServerOptions& options, std::uint32_t address, std::uint16_t& bound_port) {
    const std::string where = options.bind_address + ":" + std::to_string(options.port);

    OwnedSocket sock(::socket(AF_INET, SOCK_STREAM, 0));
    if (!sock.valid()) throw std::runtime_error(os_error("HttpServer: cannot create a socket", last_error()));

#ifdef _WIN32
    // SO_REUSEADDR on Windows lets another process bind the same port (port hijacking);
    // SO_EXCLUSIVEADDRUSE is the safe equivalent.
    const BOOL exclusive = TRUE;
    if (::setsockopt(sock.get(), SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&exclusive),
                     sizeof exclusive) != 0) {
        throw std::runtime_error(os_error("HttpServer: cannot set SO_EXCLUSIVEADDRUSE", last_error()));
    }
#else
    const int reuse = 1;
    if (::setsockopt(sock.get(), SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof reuse) != 0) {
        throw std::runtime_error(os_error("HttpServer: cannot set SO_REUSEADDR", last_error()));
    }
    ::fcntl(sock.get(), F_SETFD, FD_CLOEXEC);
#endif
    if (!set_nonblocking(sock.get())) {
        throw std::runtime_error(os_error("HttpServer: cannot make the listening socket non-blocking", last_error()));
    }

    sockaddr_in addr;
    std::memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(options.port);
    addr.sin_addr.s_addr = htonl(address);
    if (::bind(sock.get(), reinterpret_cast<const sockaddr*>(&addr), static_cast<SockLen>(sizeof addr)) != 0) {
        throw std::runtime_error(os_error("HttpServer: cannot bind " + where, last_error()));
    }
    if (::listen(sock.get(), SOMAXCONN) != 0) {
        throw std::runtime_error(os_error("HttpServer: cannot listen on " + where, last_error()));
    }

    sockaddr_in actual;
    std::memset(&actual, 0, sizeof actual);
    SockLen length = static_cast<SockLen>(sizeof actual);
    if (::getsockname(sock.get(), reinterpret_cast<sockaddr*>(&actual), &length) != 0) {
        throw std::runtime_error(os_error("HttpServer: cannot read the bound port of " + where, last_error()));
    }
    bound_port = ntohs(actual.sin_port);
    return sock;
}

void validate_options(const HttpServerOptions& o, std::uint32_t& address) {
    if (!parse_dotted_quad(o.bind_address, address)) {
        throw std::invalid_argument("HttpServerOptions: bind_address must be an IPv4 dotted quad like 127.0.0.1, got '" +
                                    o.bind_address + "'");
    }
    if (o.read_timeout_ms < 1) throw std::invalid_argument("HttpServerOptions: read_timeout_ms must be >= 1");
    if (o.write_timeout_ms < 1) throw std::invalid_argument("HttpServerOptions: write_timeout_ms must be >= 1");
    if (o.max_header_bytes < 1) throw std::invalid_argument("HttpServerOptions: max_header_bytes must be >= 1");
    if (o.max_target_bytes < 1) throw std::invalid_argument("HttpServerOptions: max_target_bytes must be >= 1");
    if (o.max_query_params < 1) throw std::invalid_argument("HttpServerOptions: max_query_params must be >= 1");
    for (const std::string& host : o.allowed_hosts) {
        // Bare names only: a request's ":port" is stripped before comparing, so an entry such as
        // "localhost:8080" could never match and would lock every client out without a word.
        bool ok = !host.empty();
        for (const char c : host) {
            const bool name_char = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                                   c == '-' || c == '.' || c == '_';
            if (!name_char) ok = false;
        }
        if (!ok) {
            throw std::invalid_argument("HttpServerOptions: allowed_hosts entries must be bare host names or IPv4 "
                                        "literals (letters, digits, '-', '_' and '.', no port), got '" + host + "'");
        }
    }
}

}  // namespace

// ---- public helpers ---------------------------------------------------------------------------

const std::string* HttpRequest::query_value(std::string_view key) const {
    for (auto it = query.rbegin(); it != query.rend(); ++it) {
        if (it->first == key) return &it->second;
    }
    return nullptr;
}

bool percent_decode(std::string_view in, bool plus_is_space, std::string& out) {
    std::string result;
    result.reserve(in.size());
    for (std::size_t i = 0; i < in.size(); ++i) {
        char c = in[i];
        if (c == '%') {
            if (i + 2 >= in.size()) {  // needs two more characters
                out.clear();
                return false;
            }
            const int hi = hex_value(in[i + 1]);
            const int lo = hex_value(in[i + 2]);
            if (hi < 0 || lo < 0) {
                out.clear();
                return false;
            }
            c = static_cast<char>(hi * 16 + lo);
            i += 2;
        } else if (c == '+' && plus_is_space) {
            c = ' ';
        }
        if (c == '\0') {
            out.clear();
            return false;
        }
        result.push_back(c);
    }
    out = std::move(result);
    return true;
}

std::string_view status_reason(int status) noexcept {
    switch (status) {
        case 100: return "Continue";
        case 101: return "Switching Protocols";
        case 200: return "OK";
        case 201: return "Created";
        case 202: return "Accepted";
        case 204: return "No Content";
        case 206: return "Partial Content";
        case 301: return "Moved Permanently";
        case 302: return "Found";
        case 303: return "See Other";
        case 304: return "Not Modified";
        case 307: return "Temporary Redirect";
        case 308: return "Permanent Redirect";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 406: return "Not Acceptable";
        case 408: return "Request Timeout";
        case 409: return "Conflict";
        case 410: return "Gone";
        case 411: return "Length Required";
        case 412: return "Precondition Failed";
        case 413: return "Payload Too Large";
        case 414: return "URI Too Long";
        case 415: return "Unsupported Media Type";
        case 416: return "Range Not Satisfiable";
        case 422: return "Unprocessable Entity";
        case 429: return "Too Many Requests";
        case 431: return "Request Header Fields Too Large";
        case 500: return "Internal Server Error";
        case 501: return "Not Implemented";
        case 502: return "Bad Gateway";
        case 503: return "Service Unavailable";
        case 504: return "Gateway Timeout";
        case 505: return "HTTP Version Not Supported";
        default: return "Unknown";
    }
}

ParseStatus parse_request_head(std::string_view head, const HttpServerOptions& limits, HttpRequest& out) {
    // 1. Control bytes: only the CR LF pairs between lines may appear.
    if (head.empty()) return ParseStatus::BadRequest;
    for (std::size_t i = 0; i < head.size(); ++i) {
        const unsigned char c = static_cast<unsigned char>(head[i]);
        if (c == '\r') {
            if (i + 1 < head.size() && head[i + 1] == '\n') {
                ++i;
                continue;
            }
            return ParseStatus::BadRequest;  // bare CR
        }
        if (c < 0x20 || c == 0x7F) return ParseStatus::BadRequest;  // includes a bare LF, NUL and tab
    }

    // 2. Request line: METHOD SP TARGET SP VERSION.
    const std::size_t line_end = head.find("\r\n");
    const std::string_view request_line = head.substr(0, line_end);
    const std::size_t sp1 = request_line.find(' ');
    if (sp1 == std::string_view::npos) return ParseStatus::BadRequest;
    const std::size_t sp2 = request_line.find(' ', sp1 + 1);
    if (sp2 == std::string_view::npos) return ParseStatus::BadRequest;
    const std::string_view method = request_line.substr(0, sp1);
    const std::string_view target = request_line.substr(sp1 + 1, sp2 - sp1 - 1);
    const std::string_view version = request_line.substr(sp2 + 1);  // may still contain a space: then malformed
    if (!valid_method(method) || target.empty() || !well_formed_version(version)) return ParseStatus::BadRequest;

    // 3.-5. Length, version, method.
    if (target.size() > limits.max_target_bytes) return ParseStatus::UriTooLong;
    if (version != "HTTP/1.1" && version != "HTTP/1.0") return ParseStatus::VersionNotSupported;
    if (method != "GET" && method != "HEAD") return ParseStatus::MethodNotAllowed;

    // 6. Target.
    HttpRequest request;
    request.method = std::string(method);
    request.target = std::string(target);
    if (!parse_target(target, limits, request)) return ParseStatus::BadRequest;

    // 7. Header lines.
    std::size_t header_lines = 0;
    bool seen_host = false;
    bool seen_length = false;
    std::string_view host;
    bool more = line_end != std::string_view::npos;
    std::string_view rest = more ? head.substr(line_end + 2) : std::string_view();
    while (more) {
        const std::size_t end = rest.find("\r\n");
        const std::string_view line = rest.substr(0, end);
        more = end != std::string_view::npos;
        rest = more ? rest.substr(end + 2) : std::string_view();
        if (++header_lines > kMaxHeaderLines) return ParseStatus::BadRequest;
        if (!check_header_line(line, seen_host, seen_length, host)) return ParseStatus::BadRequest;
    }
    request.host = std::string(host);

    out = std::move(request);
    return ParseStatus::Ok;
}

// ---- HttpServer ---------------------------------------------------------------------------------

struct HttpServer::Impl {
    Impl(HttpServerOptions o, std::uint32_t address) : options(std::move(o)), bind_ip(address) {}

    void run();
    void serve_connection(OwnedSocket& client);

    const HttpServerOptions options;
    const std::uint32_t bind_ip;  // host byte order

    std::mutex lifecycle_mutex;  // serializes start() and stop()
    std::thread thread;          // guarded by lifecycle_mutex
    OwnedSocket listener;        // set before the thread starts, closed after it is joined
    HttpHandler handler;         // likewise
    WinsockSession winsock;      // held while the listener exists

    std::atomic<bool> stop_requested{false};
    std::atomic<bool> running{false};
    std::atomic<int> bound_port{-1};  // -1 = not started
    std::atomic<std::uint64_t> served{0};
    std::atomic<std::thread::id> serving_id{std::thread::id()};  // the serving thread, once it runs
};

void HttpServer::Impl::serve_connection(OwnedSocket& client) {
    if (!prepare_client(client.get())) return;

    const auto read_deadline = Clock::now() + std::chrono::milliseconds(options.read_timeout_ms);
    std::string head;
    const HeadResult read = read_head(client.get(), options.max_header_bytes, read_deadline, stop_requested, head);
    if (read == HeadResult::Closed) return;  // slow, vanished or broken client: no response

    const std::string wire = read == HeadResult::TooLarge ? error_wire(431, looks_like_head_request(head))
                                                          : make_reply(options, handler, head);

    const auto write_deadline = Clock::now() + std::chrono::milliseconds(options.write_timeout_ms);
    if (!send_all(client.get(), wire.data(), wire.size(), write_deadline, stop_requested)) return;
    served.fetch_add(1);  // before the FIN: a client that reads to EOF sees its own exchange counted
    graceful_close(client, std::min(options.read_timeout_ms, kMaxLingerMs));
}

void HttpServer::Impl::run() {
    serving_id.store(std::this_thread::get_id());
    while (!stop_requested.load()) {
        const Wait w = wait_for(listener.get(), false, kAcceptPollMs);
        if (w == Wait::Timeout || w == Wait::Interrupted) continue;
        if (w == Wait::Error) break;  // the listening socket is broken: nothing left to serve

        OwnedSocket client(::accept(listener.get(), nullptr, nullptr));
        if (!client.valid()) {
            const int e = last_error();
            // A connection that vanished between select() and accept() is routine. Anything
            // else (EMFILE, ENOBUFS, ...) may persist, so do not spin on it.
            if (!err_would_block(e) && !err_interrupted(e)) std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }
        try {
            serve_connection(client);
        } catch (...) {
            // bad_alloc and friends: drop this connection (RAII closes it), keep serving.
        }
    }
    running.store(false);
}

HttpServer::HttpServer(HttpServerOptions options) {
    std::uint32_t address = 0;
    validate_options(options, address);
    impl_ = std::make_unique<Impl>(std::move(options), address);
}

HttpServer::~HttpServer() { stop(); }

void HttpServer::start(HttpHandler handler) {
    Impl& s = *impl_;
    std::lock_guard<std::mutex> lock(s.lifecycle_mutex);
    if (s.thread.joinable()) throw std::logic_error("HttpServer::start: the server is already started");
    if (!handler) throw std::invalid_argument("HttpServer::start: the handler is empty");

    s.winsock.acquire();
    try {
        std::uint16_t bound = 0;
        s.listener = create_listener(s.options, s.bind_ip, bound);
        s.handler = std::move(handler);
        s.stop_requested.store(false);
        s.running.store(true);  // before the thread exists, so a thread that dies at once wins
        s.bound_port.store(bound);
        s.thread = std::thread([&s] { s.run(); });
    } catch (...) {
        s.running.store(false);
        s.bound_port.store(-1);
        s.listener.reset();
        s.handler = nullptr;
        s.winsock.release();
        throw;
    }
}

void HttpServer::stop() noexcept {
    Impl& s = *impl_;
    try {
        if (s.serving_id.load() == std::this_thread::get_id()) {
            // Called from the handler: this thread cannot join itself. Ask it to leave the
            // loop; a later stop() / the destructor joins it.
            s.stop_requested.store(true);
            s.running.store(false);
            return;
        }
        std::lock_guard<std::mutex> lock(s.lifecycle_mutex);
        if (!s.thread.joinable()) return;
        s.stop_requested.store(true);
        s.running.store(false);
        s.thread.join();
        s.listener.reset();  // the port is free again once stop() returns
        s.handler = nullptr;
        s.winsock.release();
        s.serving_id.store(std::thread::id());
        s.bound_port.store(-1);
    } catch (...) {
        // Unreachable in practice: join() can only throw for a non-joinable or self-joining
        // thread, and both were excluded above. stop() promises not to throw.
    }
}

bool HttpServer::running() const noexcept { return impl_->running.load(); }

std::uint16_t HttpServer::port() const {
    const int p = impl_->bound_port.load();
    if (p < 0) throw std::logic_error("HttpServer::port: the server is not started");
    return static_cast<std::uint16_t>(p);
}

std::uint64_t HttpServer::requests_served() const noexcept { return impl_->served.load(); }

}  // namespace loganalyzer
