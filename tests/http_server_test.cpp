#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <windows.h>
#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif
#else
#include <arpa/inet.h>
#include <dirent.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <cerrno>
#endif

#include "loganalyzer/http_server.hpp"
#include "testkit.hpp"

using loganalyzer::HttpHandler;
using loganalyzer::HttpHeader;
using loganalyzer::HttpRequest;
using loganalyzer::HttpResponse;
using loganalyzer::HttpServer;
using loganalyzer::HttpServerOptions;
using loganalyzer::ParseStatus;
using loganalyzer::parse_request_head;
using loganalyzer::percent_decode;
using loganalyzer::status_reason;
using namespace std::string_literals;

namespace {

// =============================================================================================
// A tiny blocking test client (the platform differences are confined to this block)
// =============================================================================================

#ifdef _WIN32

using sock_t = SOCKET;
const sock_t kNoSock = INVALID_SOCKET;
using NetLen = int;

struct WinsockInit {
    WinsockInit() {
        WSADATA data;
        WSAStartup(MAKEWORD(2, 2), &data);
    }
    ~WinsockInit() { WSACleanup(); }
};
void net_init() { static const WinsockInit init; (void)init; }

int net_errno() { return WSAGetLastError(); }
void net_close(sock_t s) { closesocket(s); }
bool net_timed_out(int e) { return e == WSAETIMEDOUT || e == WSAEWOULDBLOCK; }
std::ptrdiff_t net_send(sock_t s, const char* data, std::size_t n) { return ::send(s, data, static_cast<int>(n), 0); }
std::ptrdiff_t net_recv(sock_t s, char* buf, std::size_t n) { return ::recv(s, buf, static_cast<int>(n), 0); }
void net_set_timeouts(sock_t s, int ms) {
    const DWORD t = static_cast<DWORD>(ms);
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&t), sizeof t);
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&t), sizeof t);
}
void net_no_sigpipe(sock_t) {}
/// True if `s` is readable within 0 ms (data, EOF or error).
bool net_readable_now(sock_t s) {
    fd_set set;
    FD_ZERO(&set);
    FD_SET(s, &set);
    timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    return ::select(0, &set, nullptr, nullptr, &tv) > 0;
}
long open_handle_count() {
    DWORD n = 0;
    if (!GetProcessHandleCount(GetCurrentProcess(), &n)) return -1;
    return static_cast<long>(n);
}

#else  // POSIX

using sock_t = int;
const sock_t kNoSock = -1;
using NetLen = socklen_t;

void net_init() {}
int net_errno() { return errno; }
void net_close(sock_t s) { ::close(s); }
bool net_timed_out(int e) { return e == EAGAIN || e == EWOULDBLOCK || e == ETIMEDOUT; }
#ifdef MSG_NOSIGNAL
const int kClientSendFlags = MSG_NOSIGNAL;
#else
const int kClientSendFlags = 0;
#endif
std::ptrdiff_t net_send(sock_t s, const char* data, std::size_t n) { return ::send(s, data, n, kClientSendFlags); }
std::ptrdiff_t net_recv(sock_t s, char* buf, std::size_t n) { return ::recv(s, buf, n, 0); }
void net_set_timeouts(sock_t s, int ms) {
    timeval tv;
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
}
void net_no_sigpipe(sock_t s) {
#ifdef SO_NOSIGPIPE
    const int one = 1;
    setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#else
    (void)s;
#endif
}
bool net_readable_now(sock_t s) {
    pollfd p;
    p.fd = s;
    p.events = POLLIN;
    p.revents = 0;
    return ::poll(&p, 1, 0) > 0;
}
long open_handle_count() {
    DIR* dir = opendir("/proc/self/fd");
    if (dir == nullptr) return -1;
    long count = 0;
    while (readdir(dir) != nullptr) ++count;
    closedir(dir);
    return count;
}

#endif

enum class End { Eof, Reset, Timeout };

sock_t net_connect(std::uint16_t port, int* error) {
    net_init();
    const sock_t s = ::socket(AF_INET, SOCK_STREAM, 0);
    if (s == kNoSock) {
        *error = net_errno();
        return kNoSock;
    }
    net_no_sigpipe(s);
    sockaddr_in addr;
    std::memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::connect(s, reinterpret_cast<const sockaddr*>(&addr), static_cast<NetLen>(sizeof addr)) != 0) {
        *error = net_errno();
        net_close(s);
        return kNoSock;
    }
    return s;
}

/// True if something accepts connections on 127.0.0.1:port.
bool can_connect(std::uint16_t port) {
    int error = 0;
    const sock_t s = net_connect(port, &error);
    if (s == kNoSock) return false;
    net_close(s);
    return true;
}

class Conn {
public:
    explicit Conn(std::uint16_t port, int timeout_ms = 10000) {
        int error = 0;
        s_ = net_connect(port, &error);
        if (s_ == kNoSock) {
            throw testkit::Failure{"test client: cannot connect to 127.0.0.1:" + std::to_string(port) +
                                   " (os error " + std::to_string(error) + ")"};
        }
        net_set_timeouts(s_, timeout_ms);
    }
    Conn(const Conn&) = delete;
    Conn& operator=(const Conn&) = delete;
    ~Conn() {
        if (s_ != kNoSock) net_close(s_);
    }

    /// False if the data could not be sent in full (e.g. the server already closed).
    bool send(std::string_view data) {
        std::size_t sent = 0;
        while (sent < data.size()) {
            const std::ptrdiff_t n = net_send(s_, data.data() + sent, data.size() - sent);
            if (n <= 0) return false;
            sent += static_cast<std::size_t>(n);
        }
        return true;
    }

    /// Appends everything the server sends to `out` until it closes (or resets, or the
    /// client-side timeout expires).
    End read_all(std::string& out) {
        char buf[8192];
        for (;;) {
            const std::ptrdiff_t n = net_recv(s_, buf, sizeof buf);
            if (n > 0) {
                out.append(buf, static_cast<std::size_t>(n));
                continue;
            }
            if (n == 0) return End::Eof;
            return net_timed_out(net_errno()) ? End::Timeout : End::Reset;
        }
    }

    /// True once the server has closed (or reset) its side. Consumes nothing but an EOF.
    bool peer_closed() {
        if (!net_readable_now(s_)) return false;
        char c;
        const std::ptrdiff_t n = net_recv(s_, &c, 1);
        return n <= 0;
    }

    /// Close with a RST instead of a FIN (SO_LINGER {on, 0}).
    void abort() {
        linger l;
        l.l_onoff = 1;
        l.l_linger = 0;
        setsockopt(s_, SOL_SOCKET, SO_LINGER, reinterpret_cast<const char*>(&l), sizeof l);
        net_close(s_);
        s_ = kNoSock;
    }

    void close() {
        if (s_ != kNoSock) net_close(s_);
        s_ = kNoSock;
    }

private:
    sock_t s_ = kNoSock;
};

struct Reply {
    std::string raw;
    End end = End::Eof;
    bool has_head = false;    // a CRLF CRLF was received
    int status = 0;           // 0 if there is no parsable status line
    std::string status_line;
    std::string head;         // everything before the blank line
    std::string body;         // everything after it
    std::vector<std::pair<std::string, std::string>> headers;

    const std::string* header(std::string_view name) const {
        for (const auto& h : headers) {
            if (h.first == name) return &h.second;
        }
        return nullptr;
    }
};

Reply parse_reply(std::string raw, End end) {
    Reply r;
    r.raw = std::move(raw);
    r.end = end;
    const std::size_t split = r.raw.find("\r\n\r\n");
    if (split == std::string::npos) return r;
    r.has_head = true;
    r.head = r.raw.substr(0, split);
    r.body = r.raw.substr(split + 4);
    std::size_t pos = 0;
    bool first = true;
    while (pos <= r.head.size()) {
        std::size_t eol = r.head.find("\r\n", pos);
        if (eol == std::string::npos) eol = r.head.size();
        const std::string line = r.head.substr(pos, eol - pos);
        pos = eol + 2;
        if (first) {
            first = false;
            r.status_line = line;
            const std::size_t sp = line.find(' ');
            if (sp != std::string::npos) r.status = std::atoi(line.c_str() + sp + 1);
            continue;
        }
        const std::size_t colon = line.find(": ");
        if (colon == std::string::npos) continue;
        r.headers.emplace_back(line.substr(0, colon), line.substr(colon + 2));
    }
    return r;
}

Reply fetch(std::uint16_t port, std::string_view request, int timeout_ms = 10000) {
    Conn c(port, timeout_ms);
    c.send(request);  // a failed send is not an error here: the server may already have answered and closed
    std::string raw;
    const End end = c.read_all(raw);
    return parse_reply(std::move(raw), end);
}

Reply http_get(std::uint16_t port, const std::string& target) {
    return fetch(port, "GET " + target + " HTTP/1.1\r\nHost: localhost\r\n\r\n");
}

template <class Pred>
bool wait_until(Pred pred, int timeout_ms = 10000) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (!pred()) {
        if (std::chrono::steady_clock::now() > deadline) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return true;
}

// =============================================================================================
// Server-side helpers
// =============================================================================================

HttpServerOptions test_options() {
    HttpServerOptions o;
    o.bind_address = "127.0.0.1";
    o.port = 0;
    o.read_timeout_ms = 5000;  // generous: only the stall tests shorten it
    o.write_timeout_ms = 5000;
    return o;
}

HttpResponse text(std::string body, int status = 200) {
    HttpResponse r;
    r.status = status;
    r.body = std::move(body);
    return r;
}

std::string describe(const HttpRequest& r) {
    std::string s = r.method + " " + r.path;
    for (const auto& kv : r.query) s += " [" + kv.first + "=" + kv.second + "]";
    return s;
}

HttpHandler echo_handler() {
    return [](const HttpRequest& r) { return text(describe(r)); };
}

/// Records what the handler saw (the handler runs on the serving thread, the test reads).
struct Seen {
    std::mutex m;
    std::vector<HttpRequest> requests;
    std::set<std::thread::id> threads;

    void add(const HttpRequest& r) {
        std::lock_guard<std::mutex> lock(m);
        requests.push_back(r);
        threads.insert(std::this_thread::get_id());
    }
    std::size_t count() {
        std::lock_guard<std::mutex> lock(m);
        return requests.size();
    }
    HttpRequest at(std::size_t i) {
        std::lock_guard<std::mutex> lock(m);
        return requests.at(i);
    }
    std::size_t thread_count() {
        std::lock_guard<std::mutex> lock(m);
        return threads.size();
    }
    bool ran_on(std::thread::id id) {
        std::lock_guard<std::mutex> lock(m);
        return threads.count(id) != 0;
    }
};

HttpHandler recording(Seen& seen) {
    return [&seen](const HttpRequest& r) {
        seen.add(r);
        return text(describe(r));
    };
}

bool contains(const std::string& haystack, std::string_view needle) { return haystack.find(needle) != std::string::npos; }

// =============================================================================================
// Pure parsing helpers
// =============================================================================================

const char* status_name(ParseStatus s) {
    switch (s) {
        case ParseStatus::Ok: return "Ok";
        case ParseStatus::BadRequest: return "BadRequest";
        case ParseStatus::MethodNotAllowed: return "MethodNotAllowed";
        case ParseStatus::UriTooLong: return "UriTooLong";
        case ParseStatus::VersionNotSupported: return "VersionNotSupported";
    }
    return "?";
}

std::string escape(const std::string& s) {
    std::string out;
    const std::size_t shown = std::min<std::size_t>(s.size(), 80);
    for (std::size_t i = 0; i < shown; ++i) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        if (c == '\r') out += "\\r";
        else if (c == '\n') out += "\\n";
        else if (c == '\t') out += "\\t";
        else if (c < 0x20 || c >= 0x7F) {
            static const char* hex = "0123456789abcdef";
            out += "\\x";
            out += hex[c >> 4];
            out += hex[c & 15];
        } else out += static_cast<char>(c);
    }
    if (shown < s.size()) out += "...(" + std::to_string(s.size()) + " bytes)";
    return out;
}

ParseStatus parse(const std::string& head, HttpRequest* out = nullptr, const HttpServerOptions& limits = {}) {
    HttpRequest scratch;
    return parse_request_head(head, limits, out != nullptr ? *out : scratch);
}

HttpRequest parse_ok(const std::string& head, const HttpServerOptions& limits = {}) {
    HttpRequest r;
    const ParseStatus st = parse_request_head(head, limits, r);
    if (st != ParseStatus::Ok) {
        throw testkit::Failure{"expected Ok for '" + escape(head) + "' but got " + status_name(st)};
    }
    return r;
}

std::string decode(const std::string& in, bool plus_is_space, bool* ok = nullptr) {
    std::string out = "stale";
    const bool result = percent_decode(in, plus_is_space, out);
    if (ok != nullptr) *ok = result;
    return out;
}

/// "/" followed by `n - 1` letters: a target of exactly n bytes.
std::string target_of_size(std::size_t n) { return "/" + std::string(n - 1, 'a'); }

std::string head_with_header_lines(std::size_t n) {
    std::string h = "GET / HTTP/1.1";
    for (std::size_t i = 0; i < n; ++i) h += "\r\nX-H" + std::to_string(i) + ": v";
    return h;
}

std::string head_with_query_params(std::size_t n) {
    std::string h = "GET /?";
    for (std::size_t i = 0; i < n; ++i) {
        if (i != 0) h += '&';
        h += "p" + std::to_string(i) + "=v";
    }
    return h + " HTTP/1.1";
}

struct ParseCase {
    std::string label;
    std::string head;
    ParseStatus want;
};

std::vector<ParseCase> parse_cases() {
    const ParseStatus kOk = ParseStatus::Ok;
    const ParseStatus kBad = ParseStatus::BadRequest;
    const ParseStatus k405 = ParseStatus::MethodNotAllowed;
    const ParseStatus kLong = ParseStatus::UriTooLong;
    const ParseStatus k505 = ParseStatus::VersionNotSupported;

    std::vector<ParseCase> c;
    auto add = [&c](const char* label, std::string head, ParseStatus want) {
        c.push_back(ParseCase{label, std::move(head), want});
    };

    // ---- accepted -----------------------------------------------------------------------
    add("minimal GET", "GET / HTTP/1.1", kOk);
    add("HTTP/1.0", "GET / HTTP/1.0", kOk);
    add("HEAD", "HEAD / HTTP/1.1", kOk);
    add("HEAD 1.0", "HEAD /x HTTP/1.0", kOk);
    add("no Host header is fine", "GET /index.html HTTP/1.1", kOk);
    add("simple path", "GET /api/top-errors HTTP/1.1", kOk);
    add("path and query", "GET /api/top-errors?k=5 HTTP/1.1", kOk);
    add("one Host header", "GET / HTTP/1.1\r\nHost: localhost:8080", kOk);
    add("several headers", "GET / HTTP/1.1\r\nHost: a\r\nAccept: */*\r\nUser-Agent: curl/8.0\r\nConnection: close", kOk);
    add("mixed-case header name", "GET / HTTP/1.1\r\nhOsT: x", kOk);
    add("empty header value", "GET / HTTP/1.1\r\nX-Empty:", kOk);
    add("header value with padding", "GET / HTTP/1.1\r\nX-A:    spaced   ", kOk);
    add("colon inside a value", "GET / HTTP/1.1\r\nX-Time: 12:30:45", kOk);
    add("odd but legal name characters", "GET / HTTP/1.1\r\nX-Weird_Name.1~: v", kOk);
    add("quotes in value", "GET / HTTP/1.1\r\nX-Q: \"hi\"", kOk);
    add("high bytes in a header value", "GET / HTTP/1.1\r\nX-N: caf\xC3\xA9", kOk);
    add("different names containing host are not duplicates", "GET / HTTP/1.1\r\nHost: a\r\nX-Host: b\r\nHost-Other: c", kOk);
    add("Content-Length 0", "GET / HTTP/1.1\r\nContent-Length: 0", kOk);
    add("Content-Length 000", "GET / HTTP/1.1\r\nContent-Length: 000", kOk);
    add("very long header value is the socket layer's business", "GET / HTTP/1.1\r\nX-Long: " + std::string(8000, 'a'), kOk);
    add("double slash path", "GET // HTTP/1.1", kOk);
    add("double slash inside", "GET //a//b HTTP/1.1", kOk);
    add("dot-dot path (no filesystem)", "GET /.. HTTP/1.1", kOk);
    add("dot-dot traversal", "GET /../../etc/passwd HTTP/1.1", kOk);
    add("dot-dot in the middle", "GET /a/../b HTTP/1.1", kOk);
    add("encoded dot-dot", "GET /%2e%2e/secret HTTP/1.1", kOk);
    add("encoded slashes", "GET /%2F%2f HTTP/1.1", kOk);
    add("encoded space", "GET /a%20b HTTP/1.1", kOk);
    add("encoded UTF-8", "GET /caf%C3%A9 HTTP/1.1", kOk);
    add("raw UTF-8 in the target", "GET /caf\xC3\xA9 HTTP/1.1", kOk);
    add("invalid UTF-8 is not validated", "GET /%FF%FE HTTP/1.1", kOk);
    add("raw invalid UTF-8", "GET /\xFF\xFE HTTP/1.1", kOk);
    add("encoded CRLF in the path is just data", "GET /%0d%0aInjected:%20x HTTP/1.1", kOk);
    add("plus in a path", "GET /a+b HTTP/1.1", kOk);
    add("semicolon and colon in a path", "GET /a;b/c:d HTTP/1.1", kOk);
    add("encoded letter", "GET /%41 HTTP/1.1", kOk);
    add("empty query", "GET /? HTTP/1.1", kOk);
    add("only empty pairs", "GET /?&&& HTTP/1.1", kOk);
    add("key without value", "GET /?a HTTP/1.1", kOk);
    add("key with empty value", "GET /?a= HTTP/1.1", kOk);
    add("empty key", "GET /?=x HTTP/1.1", kOk);
    add("value containing '='", "GET /?a=b=c HTTP/1.1", kOk);
    add("repeated key", "GET /?a=1&a=2 HTTP/1.1", kOk);
    add("plus and encoded plus in a query", "GET /?q=a+b%2Bc HTTP/1.1", kOk);
    add("second '?' belongs to the query", "GET /?k=5?x HTTP/1.1", kOk);
    add("64 query pairs (the limit)", head_with_query_params(64), kOk);
    add("target exactly at the limit", "GET " + target_of_size(2048) + " HTTP/1.1", kOk);
    add("100 header lines (the limit)", head_with_header_lines(100), kOk);

    // ---- BadRequest: request line ----------------------------------------------------------
    add("empty head", "", kBad);
    add("method only", "GET", kBad);
    add("HTTP/0.9 style request", "GET /", kBad);
    add("HTTP/0.9 with trailing space", "GET / ", kBad);
    add("target only", "/ HTTP/1.1", kBad);
    add("double space after method", "GET  / HTTP/1.1", kBad);
    add("double space before version", "GET /  HTTP/1.1", kBad);
    add("trailing space", "GET / HTTP/1.1 ", kBad);
    add("leading space", " GET / HTTP/1.1", kBad);
    add("space inside the target", "GET /a b HTTP/1.1", kBad);
    add("spaces in the method", "G E T / HTTP/1.1", kBad);
    add("tab instead of a space", "GET\t/ HTTP/1.1", kBad);
    add("tab inside the target", "GET /a\tb HTTP/1.1", kBad);
    add("tab before the version", "GET /\tHTTP/1.1", kBad);
    add("tab at the end of the line", "GET / HTTP/1.1\t", kBad);
    add("lowercase method", "get / HTTP/1.1", kBad);
    add("mixed-case method", "Get / HTTP/1.1", kBad);
    add("method with a symbol", "G@T / HTTP/1.1", kBad);
    add("method of 33 characters", std::string(33, 'A') + " / HTTP/1.1", kBad);
    add("empty method (leading space)", " / HTTP/1.1", kBad);
    add("lowercase protocol name", "GET / http/1.1", kBad);
    add("version without minor", "GET / HTTP/1", kBad);
    add("two-digit minor version", "GET / HTTP/1.10", kBad);
    add("letter in the version", "GET / HTTP/1.x", kBad);
    add("missing slash in the version", "GET / HTTP1.1", kBad);
    add("extra version component", "GET / HTTP/1.1.1", kBad);
    add("wrong protocol", "GET / FOO/1.1", kBad);
    add("no spaces at all", "GET/HTTP/1.1", kBad);

    // ---- BadRequest: control characters ----------------------------------------------------
    add("NUL in the target", "GET /\0 HTTP/1.1"s, kBad);
    add("NUL in a header value", "GET / HTTP/1.1\r\nX: a\0b"s, kBad);
    add("DEL in the target", "GET /\x7f HTTP/1.1", kBad);
    add("0x01 in a header value", "GET / HTTP/1.1\r\nX: a\x01" "b", kBad);
    add("0x1f in a header name", "GET / HTTP/1.1\r\nX\x1f: b", kBad);
    add("bare LF between lines", "GET / HTTP/1.1\nHost: x", kBad);
    add("bare LF in the request line", "GET /\n HTTP/1.1", kBad);
    add("bare CR between lines", "GET / HTTP/1.1\rHost: x", kBad);
    add("bare CR inside a value", "GET / HTTP/1.1\r\nX: a\rb", kBad);
    add("tab inside a header value", "GET / HTTP/1.1\r\nX: a\tb", kBad);

    // ---- BadRequest: target forms ----------------------------------------------------------
    add("absolute-form", "GET http://example.com/ HTTP/1.1", kBad);
    add("absolute-form upper case", "GET HTTP://example.com/ HTTP/1.1", kBad);
    add("authority-form with GET", "GET example.com:443 HTTP/1.1", kBad);
    add("asterisk-form with GET", "GET * HTTP/1.1", kBad);
    add("relative target", "GET a/b HTTP/1.1", kBad);
    add("fragment", "GET /#frag HTTP/1.1", kBad);
    add("fragment after a query", "GET /?a=1#x HTTP/1.1", kBad);
    add("empty fragment", "GET /# HTTP/1.1", kBad);
    add("%00 in the path", "GET /%00 HTTP/1.1", kBad);
    add("%00 in the middle of the path", "GET /a%00b HTTP/1.1", kBad);
    add("truncated escape at the end of the path", "GET /% HTTP/1.1", kBad);
    add("truncated escape with one digit", "GET /%2 HTTP/1.1", kBad);
    add("non-hex escape", "GET /%zz HTTP/1.1", kBad);
    add("half-hex escape", "GET /%4g HTTP/1.1", kBad);
    add("percent followed by percent", "GET /%%41 HTTP/1.1", kBad);
    add("malformed escape in a query value", "GET /?a=%GG HTTP/1.1", kBad);
    add("truncated escape in a query value", "GET /?a=% HTTP/1.1", kBad);
    add("%00 in a query key", "GET /?%00=1 HTTP/1.1", kBad);
    add("%00 in a query value", "GET /?a=%00 HTTP/1.1", kBad);
    add("65 query pairs", head_with_query_params(65), kBad);
    add("101 header lines", head_with_header_lines(101), kBad);

    // ---- BadRequest: header lines (smuggling-style oddities) -------------------------------
    add("header without a colon", "GET / HTTP/1.1\r\nHost", kBad);
    add("space before the colon", "GET / HTTP/1.1\r\nHost : example.com", kBad);
    add("space before the colon (length)", "GET / HTTP/1.1\r\nContent-Length : 0", kBad);
    add("leading space on a header line", "GET / HTTP/1.1\r\n Host: example.com", kBad);
    add("obs-fold continuation without a colon", "GET / HTTP/1.1\r\nX-A: b\r\n folded", kBad);
    add("obs-fold continuation with a tab", "GET / HTTP/1.1\r\nX-A: b\r\n\tfolded", kBad);
    add("obs-fold continuation containing a colon", "GET / HTTP/1.1\r\nX-A: b\r\n  more: stuff", kBad);
    add("empty header name", "GET / HTTP/1.1\r\n: value", kBad);
    add("space in a header name", "GET / HTTP/1.1\r\nBad Name: v", kBad);
    add("bracket in a header name", "GET / HTTP/1.1\r\nX[1]: v", kBad);
    add("empty line inside the head", "GET / HTTP/1.1\r\n\r\nX: y", kBad);
    add("trailing CRLF (empty last line)", "GET / HTTP/1.1\r\n", kBad);
    add("duplicate Host", "GET / HTTP/1.1\r\nHost: a\r\nHost: b", kBad);
    add("duplicate Host, different case", "GET / HTTP/1.1\r\nHost: a\r\nhost: a", kBad);
    add("Content-Length 5", "GET / HTTP/1.1\r\nContent-Length: 5", kBad);
    add("Content-Length not a number", "GET / HTTP/1.1\r\nContent-Length: abc", kBad);
    add("Content-Length negative", "GET / HTTP/1.1\r\nContent-Length: -1", kBad);
    add("Content-Length list", "GET / HTTP/1.1\r\nContent-Length: 0, 0", kBad);
    add("Content-Length with plus", "GET / HTTP/1.1\r\nContent-Length: +0", kBad);
    add("Content-Length empty", "GET / HTTP/1.1\r\nContent-Length:", kBad);
    add("duplicate Content-Length 0", "GET / HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 0", kBad);
    add("conflicting Content-Length", "GET / HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 5", kBad);
    add("Transfer-Encoding", "GET / HTTP/1.1\r\nTransfer-Encoding: chunked", kBad);
    add("Transfer-Encoding identity", "GET / HTTP/1.1\r\ntransfer-encoding: identity", kBad);
    add("Content-Length and Transfer-Encoding", "GET / HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: chunked", kBad);
    add("Transfer-Encoding with an empty value", "GET / HTTP/1.1\r\nTransfer-Encoding:", kBad);

    // ---- UriTooLong ----------------------------------------------------------------------
    add("target one over the limit", "GET " + target_of_size(2049) + " HTTP/1.1", kLong);
    add("very long target", "GET " + target_of_size(100000) + " HTTP/1.1", kLong);
    add("long target inside a query", "GET /?q=" + std::string(2100, 'a') + " HTTP/1.1", kLong);
    add("length wins over a fragment", "GET " + target_of_size(2049) + "#frag HTTP/1.1", kLong);
    add("length wins over an unsupported method", "POST " + target_of_size(2049) + " HTTP/1.1", kLong);

    // ---- VersionNotSupported -------------------------------------------------------------
    add("HTTP/0.9 as a version token", "GET / HTTP/0.9", k505);
    add("HTTP/2.0", "GET / HTTP/2.0", k505);
    add("HTTP/1.2", "GET / HTTP/1.2", k505);
    add("HTTP/3.0 HEAD", "HEAD / HTTP/3.0", k505);
    add("version wins over an unsupported method", "POST / HTTP/2.0", k505);

    // ---- MethodNotAllowed ----------------------------------------------------------------
    add("POST", "POST / HTTP/1.1", k405);
    add("POST with a body announced", "POST /x HTTP/1.1\r\nContent-Length: 5", k405);
    add("PUT", "PUT /x HTTP/1.1", k405);
    add("DELETE", "DELETE /x HTTP/1.1", k405);
    add("OPTIONS", "OPTIONS /x HTTP/1.1", k405);
    add("OPTIONS *", "OPTIONS * HTTP/1.1", k405);
    add("PATCH", "PATCH /x HTTP/1.1", k405);
    add("TRACE", "TRACE / HTTP/1.1", k405);
    add("CONNECT", "CONNECT example.com:443 HTTP/1.1", k405);
    add("hyphenated token method", "M-SEARCH * HTTP/1.1", k405);
    add("WebDAV method", "PROPFIND / HTTP/1.1", k405);
    add("method with digits", "GET1 / HTTP/1.1", k405);
    add("method longest allowed (32)", std::string(32, 'A') + " / HTTP/1.1", k405);

    return c;
}

}  // namespace

// =============================================================================================
// percent_decode
// =============================================================================================

TEST(HttpPercentDecode, DecodesValidEscapes) {
    bool ok = false;
    CHECK_EQ(decode("", false, &ok), std::string());
    CHECK(ok);
    CHECK_EQ(decode("plain-text_123", false, &ok), "plain-text_123"s);
    CHECK(ok);
    CHECK_EQ(decode("%41%42%43", false, &ok), "ABC"s);
    CHECK(ok);
    CHECK_EQ(decode("a%20b", false, &ok), "a b"s);
    CHECK(ok);
    CHECK_EQ(decode("%2f%2F", false, &ok), "//"s);
    CHECK(ok);
    CHECK_EQ(decode("%7E%7e", false, &ok), "~~"s);
    CHECK(ok);
}

TEST(HttpPercentDecode, HexDigitsAreCaseInsensitive) {
    bool ok = false;
    CHECK_EQ(decode("%aF", false, &ok), "\xAF"s);
    CHECK(ok);
    CHECK_EQ(decode("%Af", false, &ok), "\xAF"s);
    CHECK(ok);
    CHECK_EQ(decode("%AF", false, &ok), "\xAF"s);
    CHECK(ok);
    CHECK_EQ(decode("%af", false, &ok), "\xAF"s);
    CHECK(ok);
}

TEST(HttpPercentDecode, DecodesExactlyOnce) {
    bool ok = false;
    CHECK_EQ(decode("%2541", false, &ok), "%41"s);
    CHECK(ok);
    CHECK_EQ(decode("%25", false, &ok), "%"s);
    CHECK(ok);
    CHECK_EQ(decode("100%25", false, &ok), "100%"s);
    CHECK(ok);
}

TEST(HttpPercentDecode, PlusIsASpaceOnlyWhenAsked) {
    bool ok = false;
    CHECK_EQ(decode("a+b", false, &ok), "a+b"s);
    CHECK(ok);
    CHECK_EQ(decode("a+b", true, &ok), "a b"s);
    CHECK(ok);
    CHECK_EQ(decode("a%2Bb", true, &ok), "a+b"s);  // an encoded plus is always a plus
    CHECK(ok);
    CHECK_EQ(decode("a%2Bb", false, &ok), "a+b"s);
    CHECK(ok);
    CHECK_EQ(decode("++%20+", true, &ok), "    "s);
    CHECK(ok);
}

TEST(HttpPercentDecode, HighBytesPassThrough) {
    bool ok = false;
    CHECK_EQ(decode("\xC3\xA9", false, &ok), "\xC3\xA9"s);  // raw bytes are not validated
    CHECK(ok);
    CHECK_EQ(decode("%C3%A9", false, &ok), "\xC3\xA9"s);
    CHECK(ok);
    CHECK_EQ(decode("%FF%FE", false, &ok), "\xFF\xFE"s);  // invalid UTF-8 is fine
    CHECK(ok);
    CHECK_EQ(decode("\xFF" "a%80", false, &ok), "\xFF" "a\x80"s);
    CHECK(ok);
}

TEST(HttpPercentDecode, RejectsMalformedAndTruncatedEscapes) {
    const char* bad[] = {"%", "%4", "%zz", "%4g", "%g4", "a%", "a%2", "%%41", "% 41", "%-1", "abc%4", "%G0"};
    for (const char* in : bad) {
        bool ok = true;
        const std::string out = decode(in, false, &ok);
        if (ok) throw testkit::Failure{std::string("expected failure for '") + in + "'"};
        CHECK(out.empty());  // out is cleared on failure
        ok = true;
        decode(in, true, &ok);
        CHECK(!ok);
    }
}

TEST(HttpPercentDecode, RejectsADecodedNul) {
    bool ok = true;
    decode("%00", false, &ok);
    CHECK(!ok);
    ok = true;
    decode("a%00b", true, &ok);
    CHECK(!ok);
    ok = true;
    decode("abc%00", false, &ok);
    CHECK(!ok);
    ok = true;
    decode("a\0b"s, false, &ok);  // a literal NUL byte as well
    CHECK(!ok);
    ok = true;
    decode("%0", false, &ok);
    CHECK(!ok);
    ok = false;
    decode("%01", false, &ok);  // other control bytes are data
    CHECK(ok);
}

TEST(HttpPercentDecode, OutIsReplacedNotAppendedAndClearedOnFailure) {
    std::string out = "previous";
    CHECK(percent_decode("x%20y", false, out));
    CHECK_EQ(out, "x y"s);
    out = "previous";
    CHECK(!percent_decode("%zz", false, out));
    CHECK(out.empty());
}

// =============================================================================================
// status_reason
// =============================================================================================

TEST(HttpStatusReason, KnownAndUnknownStatuses) {
    CHECK_EQ(std::string(status_reason(200)), "OK"s);
    CHECK_EQ(std::string(status_reason(204)), "No Content"s);
    CHECK_EQ(std::string(status_reason(400)), "Bad Request"s);
    CHECK_EQ(std::string(status_reason(404)), "Not Found"s);
    CHECK_EQ(std::string(status_reason(405)), "Method Not Allowed"s);
    CHECK_EQ(std::string(status_reason(414)), "URI Too Long"s);
    CHECK_EQ(std::string(status_reason(431)), "Request Header Fields Too Large"s);
    CHECK_EQ(std::string(status_reason(500)), "Internal Server Error"s);
    CHECK_EQ(std::string(status_reason(505)), "HTTP Version Not Supported"s);
    CHECK_EQ(std::string(status_reason(599)), "Unknown"s);
    CHECK_EQ(std::string(status_reason(0)), "Unknown"s);
    CHECK_EQ(std::string(status_reason(-1)), "Unknown"s);
    CHECK_EQ(std::string(status_reason(999)), "Unknown"s);
}

// =============================================================================================
// parse_request_head
// =============================================================================================

TEST(HttpParse, TableOfAcceptedAndRejectedHeads) {
    const std::vector<ParseCase> cases = parse_cases();
    CHECK(cases.size() >= 60);
    std::string failures;
    for (const ParseCase& c : cases) {
        const ParseStatus got = parse(c.head);
        if (got != c.want) {
            failures += "  [" + c.label + "] '" + escape(c.head) + "': expected " + status_name(c.want) + ", got " +
                        status_name(got) + "\n";
        }
    }
    if (!failures.empty()) throw testkit::Failure{"parse table mismatches:\n" + failures};
}

TEST(HttpParse, EveryRejectedHeadLeavesTheOutputUntouched) {
    for (const ParseCase& c : parse_cases()) {
        if (c.want == ParseStatus::Ok) continue;
        HttpRequest out;
        out.method = "KEEP";
        out.target = "keep";
        out.path = "/keep";
        out.query.emplace_back("k", "v");
        parse(c.head, &out);
        if (out.method != "KEEP" || out.target != "keep" || out.path != "/keep" || out.query.size() != 1) {
            throw testkit::Failure{"output modified for rejected head [" + c.label + "]"};
        }
    }
}

TEST(HttpParse, AcceptedHeadReplacesTheWholeOutput) {
    HttpRequest out;
    out.query.emplace_back("old", "1");
    out.path = "/old";
    CHECK_EQ(parse("GET /new HTTP/1.1", &out), ParseStatus::Ok);
    CHECK(out.query.empty());
    CHECK_EQ(out.path, "/new"s);
}

TEST(HttpParse, FieldsOfASimpleRequest) {
    const HttpRequest r = parse_ok("GET /api/top-errors?k=5 HTTP/1.1\r\nHost: localhost");
    CHECK_EQ(r.method, "GET"s);
    CHECK_EQ(r.target, "/api/top-errors?k=5"s);
    CHECK_EQ(r.path, "/api/top-errors"s);
    CHECK_EQ(r.query.size(), std::size_t(1));
    CHECK_EQ(r.query[0].first, "k"s);
    CHECK_EQ(r.query[0].second, "5"s);

    const HttpRequest h = parse_ok("HEAD / HTTP/1.0");
    CHECK_EQ(h.method, "HEAD"s);
    CHECK_EQ(h.path, "/"s);
    CHECK(h.query.empty());
}

TEST(HttpParse, PathIsPercentDecodedOnce) {
    CHECK_EQ(parse_ok("GET /a%20b/c%2Fd HTTP/1.1").path, "/a b/c/d"s);
    CHECK_EQ(parse_ok("GET /%2541 HTTP/1.1").path, "/%41"s);
    CHECK_EQ(parse_ok("GET /a+b HTTP/1.1").path, "/a+b"s);  // '+' is only a space in the query
    CHECK_EQ(parse_ok("GET /%C3%A9 HTTP/1.1").path, "/\xC3\xA9"s);
    CHECK_EQ(parse_ok("GET /\xFF HTTP/1.1").path, "/\xFF"s);
    CHECK_EQ(parse_ok("GET /%0d%0aInjected:%20x HTTP/1.1").path, "/\r\nInjected: x"s);
    CHECK_EQ(parse_ok("GET //a//b HTTP/1.1").path, "//a//b"s);
    CHECK_EQ(parse_ok("GET /../../etc/passwd HTTP/1.1").path, "/../../etc/passwd"s);
    CHECK_EQ(parse_ok("GET /%2e%2e/x HTTP/1.1").path, "/../x"s);
    CHECK_EQ(parse_ok("GET /?a=1 HTTP/1.1").path, "/"s);
    // The raw target is kept as received.
    CHECK_EQ(parse_ok("GET /a%20b?x=%41 HTTP/1.1").target, "/a%20b?x=%41"s);
}

TEST(HttpParse, QueryKeepsOrderAndSplitsAtTheFirstEquals) {
    const HttpRequest r = parse_ok("GET /s?a=1&b=2&a=3&c&d=&=e&f=g=h&&i=%41+%2B HTTP/1.1");
    const std::vector<std::pair<std::string, std::string>> want = {
        {"a", "1"}, {"b", "2"}, {"a", "3"}, {"c", ""}, {"d", ""}, {"", "e"}, {"f", "g=h"}, {"i", "A +"}};
    CHECK(r.query == want);
}

TEST(HttpParse, QueryKeysAndValuesAreDecodedWithPlusAsSpace) {
    const HttpRequest r = parse_ok("GET /s?k%20ey=v+w&%C3%A9=%C3%A9&a%2Bb=c%26d HTTP/1.1");
    CHECK_EQ(r.query.size(), std::size_t(3));
    CHECK_EQ(r.query[0].first, "k ey"s);
    CHECK_EQ(r.query[0].second, "v w"s);
    CHECK_EQ(r.query[1].first, "\xC3\xA9"s);
    CHECK_EQ(r.query[1].second, "\xC3\xA9"s);
    CHECK_EQ(r.query[2].first, "a+b"s);
    CHECK_EQ(r.query[2].second, "c&d"s);  // an encoded '&' does not split
}

TEST(HttpParse, QueryStartsAtTheFirstQuestionMark) {
    const HttpRequest r = parse_ok("GET /p?a=1?b=2&c=?d HTTP/1.1");
    CHECK_EQ(r.path, "/p"s);
    CHECK_EQ(r.query.size(), std::size_t(2));
    CHECK_EQ(r.query[0].first, "a"s);
    CHECK_EQ(r.query[0].second, "1?b=2"s);
    CHECK_EQ(r.query[1].first, "c"s);
    CHECK_EQ(r.query[1].second, "?d"s);
}

TEST(HttpQueryValue, LastValueWins) {
    const HttpRequest r = parse_ok("GET /s?a=1&b=2&a=3&c&a= HTTP/1.1");
    const std::string* a = r.query_value("a");
    CHECK(a != nullptr);
    CHECK_EQ(*a, ""s);                    // the LAST a is the empty one
    CHECK(a == &r.query[4].second);       // and the pointer really points into the request
    const std::string* b = r.query_value("b");
    CHECK(b != nullptr);
    CHECK_EQ(*b, "2"s);
    const std::string* c = r.query_value("c");
    CHECK(c != nullptr);
    CHECK_EQ(*c, ""s);                    // present without '='
    CHECK(r.query_value("d") == nullptr);
    CHECK(r.query_value("A") == nullptr);  // keys are case-sensitive
    CHECK(r.query_value("") == nullptr);

    const HttpRequest two = parse_ok("GET /s?x=first&x=second HTTP/1.1");
    CHECK_EQ(*two.query_value("x"), "second"s);

    const HttpRequest none = parse_ok("GET /s HTTP/1.1");
    CHECK(none.query_value("x") == nullptr);

    const HttpRequest decoded = parse_ok("GET /s?k%20ey=v+w HTTP/1.1");
    CHECK(decoded.query_value("k ey") != nullptr);
    CHECK_EQ(*decoded.query_value("k ey"), "v w"s);
    CHECK(decoded.query_value("k%20ey") == nullptr);  // lookups use the decoded key
}

TEST(HttpParse, TargetLengthLimitIsInclusive) {
    HttpServerOptions limits;
    limits.max_target_bytes = 10;
    CHECK_EQ(parse("GET " + target_of_size(9) + " HTTP/1.1", nullptr, limits), ParseStatus::Ok);
    CHECK_EQ(parse("GET " + target_of_size(10) + " HTTP/1.1", nullptr, limits), ParseStatus::Ok);
    CHECK_EQ(parse("GET " + target_of_size(11) + " HTTP/1.1", nullptr, limits), ParseStatus::UriTooLong);
    CHECK_EQ(parse("GET /?a=12345678 HTTP/1.1", nullptr, limits), ParseStatus::UriTooLong);  // the query counts
    limits.max_target_bytes = 1;
    CHECK_EQ(parse("GET / HTTP/1.1", nullptr, limits), ParseStatus::Ok);
    CHECK_EQ(parse("GET /a HTTP/1.1", nullptr, limits), ParseStatus::UriTooLong);

    // The default limit is 2048.
    CHECK_EQ(parse("GET " + target_of_size(2048) + " HTTP/1.1"), ParseStatus::Ok);
    CHECK_EQ(parse("GET " + target_of_size(2049) + " HTTP/1.1"), ParseStatus::UriTooLong);
}

TEST(HttpParse, QueryParameterLimitCountsNonEmptyPairs) {
    HttpServerOptions limits;
    limits.max_query_params = 2;
    CHECK_EQ(parse("GET /?a&b HTTP/1.1", nullptr, limits), ParseStatus::Ok);
    CHECK_EQ(parse("GET /?a&&&b& HTTP/1.1", nullptr, limits), ParseStatus::Ok);  // empty pairs are free
    CHECK_EQ(parse("GET /?a&b&c HTTP/1.1", nullptr, limits), ParseStatus::BadRequest);
    CHECK_EQ(parse("GET /?a=1&a=2&a=3 HTTP/1.1", nullptr, limits), ParseStatus::BadRequest);  // repeats count
    CHECK_EQ(parse(head_with_query_params(64)), ParseStatus::Ok);
    CHECK_EQ(parse(head_with_query_params(65)), ParseStatus::BadRequest);
}

TEST(HttpParse, HeaderLineLimitIsOneHundred) {
    CHECK_EQ(parse(head_with_header_lines(0)), ParseStatus::Ok);
    CHECK_EQ(parse(head_with_header_lines(100)), ParseStatus::Ok);
    CHECK_EQ(parse(head_with_header_lines(101)), ParseStatus::BadRequest);
}

TEST(HttpParse, TableHasAtLeastSixtyCasesInEveryCategory) {
    int counts[5] = {0, 0, 0, 0, 0};
    for (const ParseCase& c : parse_cases()) ++counts[static_cast<int>(c.want)];
    CHECK(counts[static_cast<int>(ParseStatus::Ok)] >= 10);
    CHECK(counts[static_cast<int>(ParseStatus::BadRequest)] >= 40);
    CHECK(counts[static_cast<int>(ParseStatus::MethodNotAllowed)] >= 5);
    CHECK(counts[static_cast<int>(ParseStatus::UriTooLong)] >= 3);
    CHECK(counts[static_cast<int>(ParseStatus::VersionNotSupported)] >= 3);
    CHECK(parse_cases().size() >= 100);
}

// =============================================================================================
// Construction and lifecycle
// =============================================================================================

TEST(HttpServerLifecycle, InvalidOptionsThrowInvalidArgument) {
    const char* bad_addresses[] = {"",          "localhost",  "256.0.0.1",     "1.2.3",       "1.2.3.4.5", "::1",
                                   "127.0.0.1 ", " 127.0.0.1", "127.0.0.01",   "127.0.0.",    ".1.2.3",    "1..2.3",
                                   "1.2.3.4/8", "0x7f.0.0.1", "-1.0.0.0",     "1000.1.1.1",  "a.b.c.d",   "127.0.0.1:80",
                                   "1.2.3.+4",  "1 .2.3.4"};
    for (const char* address : bad_addresses) {
        HttpServerOptions o = test_options();
        o.bind_address = address;
        bool threw = false;
        try {
            HttpServer server(o);
        } catch (const std::invalid_argument&) {
            threw = true;
        }
        if (!threw) throw testkit::Failure{std::string("bind address accepted: '") + address + "'"};
    }

    HttpServerOptions o = test_options();
    o.read_timeout_ms = 0;
    CHECK_THROWS(HttpServer(o), std::invalid_argument);
    o = test_options();
    o.read_timeout_ms = -5;
    CHECK_THROWS(HttpServer(o), std::invalid_argument);
    o = test_options();
    o.write_timeout_ms = 0;
    CHECK_THROWS(HttpServer(o), std::invalid_argument);
    o = test_options();
    o.write_timeout_ms = -1;
    CHECK_THROWS(HttpServer(o), std::invalid_argument);
    o = test_options();
    o.max_header_bytes = 0;
    CHECK_THROWS(HttpServer(o), std::invalid_argument);
    o = test_options();
    o.max_target_bytes = 0;
    CHECK_THROWS(HttpServer(o), std::invalid_argument);
    o = test_options();
    o.max_query_params = 0;
    CHECK_THROWS(HttpServer(o), std::invalid_argument);
}

TEST(HttpServerLifecycle, ValidOptionsConstructWithoutOpeningASocket) {
    const char* good[] = {"127.0.0.1", "0.0.0.0", "255.255.255.255", "10.0.0.1", "192.168.1.200", "1.2.3.4"};
    for (const char* address : good) {
        HttpServerOptions o = test_options();
        o.bind_address = address;
        HttpServer server(o);  // constructing never touches the network
        CHECK(!server.running());
        CHECK_EQ(server.requests_served(), std::uint64_t(0));
    }
    HttpServer defaults;  // default options (port 8080) are valid and not bound until start()
    CHECK(!defaults.running());
    CHECK_THROWS(defaults.port(), std::logic_error);
}

TEST(HttpServerLifecycle, PortBeforeStartThrowsLogicError) {
    HttpServer server(test_options());
    CHECK_THROWS(server.port(), std::logic_error);
    CHECK(!server.running());
    server.stop();  // stopping a server that never started is a no-op
    CHECK_THROWS(server.port(), std::logic_error);
}

TEST(HttpServerLifecycle, PortZeroPicksAUsableEphemeralPort) {
    HttpServer server(test_options());
    server.start(echo_handler());
    CHECK(server.running());
    const std::uint16_t port = server.port();
    CHECK(port != 0);
    const Reply r = http_get(port, "/hello");
    CHECK_EQ(r.status, 200);
    CHECK_EQ(r.body, "GET /hello"s);
    server.stop();
}

TEST(HttpServerLifecycle, StartingTwiceThrowsLogicError) {
    HttpServer server(test_options());
    server.start(echo_handler());
    const std::uint16_t port = server.port();
    CHECK_THROWS(server.start(echo_handler()), std::logic_error);
    CHECK(server.running());
    CHECK_EQ(server.port(), port);               // unchanged
    CHECK_EQ(http_get(port, "/still").status, 200);   // and still serving
    server.stop();
}

TEST(HttpServerLifecycle, EmptyHandlerIsRejected) {
    HttpServer server(test_options());
    CHECK_THROWS(server.start(HttpHandler()), std::invalid_argument);
    CHECK(!server.running());
    CHECK_THROWS(server.port(), std::logic_error);
    server.start(echo_handler());  // and the server is still usable afterwards
    CHECK_EQ(http_get(server.port(), "/").status, 200);
}

TEST(HttpServerLifecycle, StartingASecondServerOnTheSamePortThrowsRuntimeError) {
    HttpServer first(test_options());
    first.start(echo_handler());
    HttpServerOptions o = test_options();
    o.port = first.port();
    HttpServer second(o);
    bool threw = false;
    try {
        second.start(echo_handler());
    } catch (const std::runtime_error& e) {
        threw = true;
        const std::string what = e.what();
        CHECK(contains(what, "bind"));
        CHECK(contains(what, "os error"));  // the OS error is part of the message
        CHECK(contains(what, std::to_string(o.port)));
    }
    CHECK(threw);
    CHECK(!second.running());
    CHECK_THROWS(second.port(), std::logic_error);
    CHECK_EQ(http_get(first.port(), "/ok").status, 200);  // the first one is unharmed
    second.stop();                                   // and stopping the failed one is harmless
}

TEST(HttpServerLifecycle, FailedBindLeavesNothingBehind) {
    HttpServerOptions o = test_options();
    o.bind_address = "203.0.113.77";  // TEST-NET-3: not an address of this machine
    HttpServer server(o);
    CHECK_THROWS(server.start(echo_handler()), std::runtime_error);
    CHECK(!server.running());
    CHECK_THROWS(server.port(), std::logic_error);
    CHECK_THROWS(server.start(echo_handler()), std::runtime_error);  // retrying behaves the same
    server.stop();
}

TEST(HttpServerLifecycle, StopIsIdempotentAndClosesTheListener) {
    HttpServer server(test_options());
    server.start(echo_handler());
    const std::uint16_t port = server.port();
    CHECK(server.running());
    CHECK_EQ(http_get(port, "/x").status, 200);

    server.stop();
    CHECK(!server.running());
    server.stop();
    server.stop();
    CHECK(!server.running());
    CHECK_THROWS(server.port(), std::logic_error);
    CHECK(!can_connect(port));  // nothing listens any more
}

TEST(HttpServerLifecycle, DestructorStopsARunningServer) {
    std::uint16_t port = 0;
    {
        HttpServer server(test_options());
        server.start(echo_handler());
        port = server.port();
        CHECK_EQ(http_get(port, "/in-scope").status, 200);
    }  // destructor runs here
    CHECK(!can_connect(port));

    // The port is genuinely free: a new server can take it.
    HttpServerOptions o = test_options();
    o.port = port;
    HttpServer again(o);
    again.start(echo_handler());
    CHECK_EQ(again.port(), port);
    CHECK_EQ(http_get(port, "/again").status, 200);
}

TEST(HttpServerLifecycle, StopThenNewServerOnTheSamePortWorks) {
    HttpServer first(test_options());
    first.start(echo_handler());
    const std::uint16_t port = first.port();
    for (int i = 0; i < 5; ++i) CHECK_EQ(http_get(port, "/n" + std::to_string(i)).status, 200);
    first.stop();

    HttpServerOptions o = test_options();
    o.port = port;
    HttpServer second(o);
    second.start([](const HttpRequest&) { return text("second"); });
    CHECK_EQ(second.port(), port);
    const Reply r = http_get(port, "/");
    CHECK_EQ(r.status, 200);
    CHECK_EQ(r.body, "second"s);
}

TEST(HttpServerLifecycle, AStoppedServerCanBeStartedAgain) {
    HttpServer server(test_options());
    server.start([](const HttpRequest&) { return text("one"); });
    CHECK_EQ(http_get(server.port(), "/").body, "one"s);
    server.stop();
    CHECK(!server.running());

    server.start([](const HttpRequest&) { return text("two"); });
    CHECK(server.running());
    CHECK_EQ(http_get(server.port(), "/").body, "two"s);
    server.stop();
    server.stop();
    CHECK(!server.running());
}

TEST(HttpServerLifecycle, TwoServersCoexistAndStopIndependently) {
    HttpServer a(test_options());
    HttpServer b(test_options());
    a.start([](const HttpRequest&) { return text("A"); });
    b.start([](const HttpRequest&) { return text("B"); });
    CHECK(a.port() != b.port());
    CHECK_EQ(http_get(a.port(), "/").body, "A"s);
    CHECK_EQ(http_get(b.port(), "/").body, "B"s);
    const std::uint16_t a_port = a.port();
    a.stop();
    CHECK(!can_connect(a_port));
    CHECK_EQ(http_get(b.port(), "/").body, "B"s);  // the other one is unaffected (Winsock stays initialised)
    b.stop();
}

TEST(HttpServerLifecycle, StopFromTheHandlerDoesNotDeadlock) {
    HttpServer server(test_options());
    server.start([&server](const HttpRequest&) {
        server.stop();  // cannot join itself: only requests the shutdown
        return text("bye");
    });
    const std::uint16_t port = server.port();
    const Reply r = http_get(port, "/");
    CHECK_EQ(r.status, 200);
    CHECK_EQ(r.body, "bye"s);
    CHECK(wait_until([&] { return !server.running(); }));
    server.stop();  // this one joins the serving thread
    CHECK_THROWS(server.port(), std::logic_error);
    CHECK(!can_connect(port));
}

TEST(HttpServerLifecycle, StopAbandonsAClientThatIsStillSendingItsHead) {
    HttpServerOptions o = test_options();
    o.read_timeout_ms = 30000;  // far longer than the bound asserted below
    HttpServer server(o);
    server.start(echo_handler());
    Conn stalled(server.port());
    CHECK(stalled.send("GET /slo"));  // half a head, then silence

    const auto begin = std::chrono::steady_clock::now();
    server.stop();
    const auto elapsed = std::chrono::steady_clock::now() - begin;
    CHECK(elapsed < std::chrono::seconds(10));  // would be ~30 s if stop() waited for the read timeout
    CHECK(!server.running());

    std::string rest;
    const End end = stalled.read_all(rest);  // the client sees the connection closed, not a timeout
    CHECK(end != End::Timeout);
    CHECK(rest.empty());
}

// =============================================================================================
// Requests over real sockets
// =============================================================================================

TEST(HttpServer, GetReturnsTheHandlerBodyAndExactHeaders) {
    HttpServer server(test_options());
    server.start([](const HttpRequest&) {
        HttpResponse r;
        r.body = "hello";
        r.headers.push_back(HttpHeader{"X-Test", "1"});
        r.headers.push_back(HttpHeader{"Set-Cookie", "a=b; HttpOnly"});
        return r;
    });
    const Reply r = fetch(server.port(), "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    CHECK(r.end == End::Eof);  // the server closes the connection after the response
    const std::string expected =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "Content-Length: 5\r\n"
        "Connection: close\r\n"
        "Cache-Control: no-store\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "X-Test: 1\r\n"
        "Set-Cookie: a=b; HttpOnly\r\n"
        "\r\n"
        "hello";
    CHECK_EQ(r.raw, expected);
}

TEST(HttpServer, HeadReturnsTheSameHeadersAndNoBody) {
    HttpServer server(test_options());
    server.start([](const HttpRequest&) {
        HttpResponse r = text("hello world, this body is not sent for HEAD");
        r.content_type = "text/html; charset=utf-8";
        r.headers.push_back(HttpHeader{"X-Test", "1"});
        return r;
    });
    const Reply get_reply = fetch(server.port(), "GET /p HTTP/1.1\r\n\r\n");
    const Reply head_reply = fetch(server.port(), "HEAD /p HTTP/1.1\r\n\r\n");
    CHECK_EQ(get_reply.status, 200);
    CHECK_EQ(head_reply.status, 200);
    CHECK(head_reply.end == End::Eof);
    CHECK_EQ(head_reply.head, get_reply.head);  // identical status line and headers, Content-Length included
    CHECK(head_reply.body.empty());
    CHECK_EQ(get_reply.body, "hello world, this body is not sent for HEAD"s);
    const std::string* length = head_reply.header("Content-Length");
    CHECK(length != nullptr);
    CHECK_EQ(*length, std::to_string(get_reply.body.size()));
    CHECK_EQ(head_reply.raw.size(), head_reply.head.size() + 4);  // nothing after the blank line
}

TEST(HttpServer, CustomStatusAndContentType) {
    HttpServer server(test_options());
    server.start([](const HttpRequest&) {
        HttpResponse r;
        r.status = 404;
        r.content_type = "text/html; charset=utf-8";
        r.body = "<h1>nope</h1>";
        return r;
    });
    const Reply r = http_get(server.port(), "/missing");
    CHECK_EQ(r.status, 404);
    CHECK_EQ(r.status_line, "HTTP/1.1 404 Not Found"s);
    CHECK_EQ(*r.header("Content-Type"), "text/html; charset=utf-8"s);
    CHECK_EQ(*r.header("Content-Length"), "13"s);
    CHECK_EQ(r.body, "<h1>nope</h1>"s);
}

TEST(HttpServer, EmptyBodyHasContentLengthZero) {
    HttpServer server(test_options());
    server.start([](const HttpRequest&) { return HttpResponse{}; });
    const Reply r = http_get(server.port(), "/");
    CHECK_EQ(r.status, 200);
    CHECK_EQ(*r.header("Content-Length"), "0"s);
    CHECK(r.body.empty());
}

TEST(HttpServer, ResponsesThatCannotCarryABodyOmitItAndItsHeaders) {
    HttpServer server(test_options());
    server.start([](const HttpRequest& req) {
        HttpResponse r;
        r.status = req.path == "/304" ? 304 : 204;
        return r;
    });
    const std::string expected_tail =
        "\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\r\n";
    CHECK_EQ(http_get(server.port(), "/204").raw, "HTTP/1.1 204 No Content" + expected_tail);
    CHECK_EQ(http_get(server.port(), "/304").raw, "HTTP/1.1 304 Not Modified" + expected_tail);
}

TEST(HttpServer, UnknownButValidStatusIsSentWithTheUnknownReason) {
    HttpServer server(test_options());
    server.start([](const HttpRequest&) { return text("teapot-ish", 599); });
    const Reply r = http_get(server.port(), "/");
    CHECK_EQ(r.status_line, "HTTP/1.1 599 Unknown"s);
    CHECK_EQ(r.body, "teapot-ish"s);
}

TEST(HttpServer, HandlerSeesTheParsedRequestOnOneServingThread) {
    Seen seen;
    HttpServer server(test_options());
    server.start(recording(seen));
    const Reply r = http_get(server.port(), "/a%20b/c?x=1&y=%2B+z&x=2&flag");
    CHECK_EQ(r.status, 200);
    CHECK_EQ(seen.count(), std::size_t(1));
    const HttpRequest req = seen.at(0);
    CHECK_EQ(req.method, "GET"s);
    CHECK_EQ(req.target, "/a%20b/c?x=1&y=%2B+z&x=2&flag"s);
    CHECK_EQ(req.path, "/a b/c"s);
    CHECK_EQ(req.query.size(), std::size_t(4));
    CHECK_EQ(*req.query_value("x"), "2"s);
    CHECK_EQ(*req.query_value("y"), "+ z"s);
    CHECK_EQ(*req.query_value("flag"), ""s);
    CHECK_EQ(r.body, "GET /a b/c [x=1] [y=+ z] [x=2] [flag=]"s);

    for (int i = 0; i < 20; ++i) CHECK_EQ(http_get(server.port(), "/n").status, 200);
    CHECK_EQ(seen.count(), std::size_t(21));
    CHECK_EQ(seen.thread_count(), std::size_t(1));       // one serving thread ran every handler call
    CHECK(!seen.ran_on(std::this_thread::get_id()));     // and it is not the test's thread
}

TEST(HttpServer, HeadRequestsReachTheHandlerAsHead) {
    Seen seen;
    HttpServer server(test_options());
    server.start(recording(seen));
    CHECK_EQ(fetch(server.port(), "HEAD /h HTTP/1.1\r\n\r\n").status, 200);
    CHECK_EQ(seen.count(), std::size_t(1));
    CHECK_EQ(seen.at(0).method, "HEAD"s);
}

TEST(HttpServer, Http10ClientsAreServedAndClosed) {
    HttpServer server(test_options());
    server.start(echo_handler());
    const Reply r = fetch(server.port(), "GET /old HTTP/1.0\r\n\r\n");
    CHECK_EQ(r.status, 200);
    CHECK(r.end == End::Eof);
    CHECK_EQ(r.body, "GET /old"s);
    CHECK_EQ(*r.header("Connection"), "close"s);
}

TEST(HttpServer, UnsupportedMethodsGet405WithAnAllowHeader) {
    Seen seen;
    HttpServer server(test_options());
    server.start(recording(seen));
    const char* requests[] = {"POST /x HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
                              "PUT /x HTTP/1.1\r\n\r\n",
                              "DELETE /x HTTP/1.1\r\n\r\n",
                              "OPTIONS * HTTP/1.1\r\n\r\n",
                              "PATCH /x HTTP/1.1\r\n\r\n",
                              "TRACE / HTTP/1.1\r\n\r\n"};
    for (const char* request : requests) {
        const Reply r = fetch(server.port(), request);
        if (r.status != 405) throw testkit::Failure{std::string("expected 405 for ") + escape(request) + ", got " + r.raw};
        CHECK_EQ(r.status_line, "HTTP/1.1 405 Method Not Allowed"s);
        CHECK(r.header("Allow") != nullptr);
        CHECK_EQ(*r.header("Allow"), "GET, HEAD"s);
        CHECK_EQ(*r.header("Connection"), "close"s);
        CHECK_EQ(r.body, "method not allowed"s);
        CHECK_EQ(*r.header("Content-Length"), std::to_string(r.body.size()));
    }
    CHECK_EQ(seen.count(), std::size_t(0));  // the handler never saw any of them
}

TEST(HttpServer, MalformedRequestsGet400AndNeverReachTheHandler) {
    Seen seen;
    HttpServer server(test_options());
    server.start(recording(seen));
    const std::string requests[] = {
        "garbage\r\n\r\n",
        "\x01\x02garbage\r\n\r\n"s,
        "NOT HTTP AT ALL\r\n\r\n",
        "GET / HTTP/1.1\r\nHost : x\r\n\r\n",
        "GET http://example.com/ HTTP/1.1\r\n\r\n",
        "get / HTTP/1.1\r\n\r\n",
        "GET /\r\n\r\n",
        "GET /%zz HTTP/1.1\r\n\r\n",
        "GET /#frag HTTP/1.1\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
        "GET / HTTP/1.1\r\nX: a\0b\r\n\r\n"s,
        // request bodies are not supported
        "GET / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello",
        "GET / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
    };
    for (const std::string& request : requests) {
        const Reply r = fetch(server.port(), request);
        if (r.status != 400) throw testkit::Failure{"expected 400 for '" + escape(request) + "', got '" + escape(r.raw) + "'"};
        CHECK_EQ(r.status_line, "HTTP/1.1 400 Bad Request"s);
        CHECK_EQ(r.body, "bad request"s);
        CHECK(r.end == End::Eof);
    }
    CHECK_EQ(seen.count(), std::size_t(0));
}

TEST(HttpServer, TooLongTargetsGet414AndUnknownVersionsGet505) {
    HttpServerOptions o = test_options();
    o.max_target_bytes = 64;
    Seen seen;
    HttpServer server(o);
    server.start(recording(seen));

    const Reply at_limit = http_get(server.port(), target_of_size(64));
    CHECK_EQ(at_limit.status, 200);
    const Reply over = http_get(server.port(), target_of_size(65));
    CHECK_EQ(over.status, 414);
    CHECK_EQ(over.status_line, "HTTP/1.1 414 URI Too Long"s);
    CHECK_EQ(over.body, "uri too long"s);

    const Reply v2 = fetch(server.port(), "GET / HTTP/2.0\r\n\r\n");
    CHECK_EQ(v2.status, 505);
    CHECK_EQ(v2.status_line, "HTTP/1.1 505 HTTP Version Not Supported"s);
    CHECK_EQ(v2.body, "http version not supported"s);
    CHECK_EQ(fetch(server.port(), "GET / HTTP/0.9\r\n\r\n").status, 505);
    CHECK_EQ(seen.count(), std::size_t(1));  // only the request at the limit
}

TEST(HttpServer, ErrorResponsesToHeadRequestsHaveNoBody) {
    HttpServer server(test_options());
    server.start(echo_handler());
    const Reply r = fetch(server.port(), "HEAD / HTTP/2.0\r\n\r\n");
    CHECK_EQ(r.status, 505);
    CHECK(r.body.empty());
    CHECK_EQ(*r.header("Content-Length"), std::to_string(std::string("http version not supported").size()));
    CHECK_EQ(r.raw.size(), r.head.size() + 4);
}

TEST(HttpServer, OversizedHeadGets431) {
    HttpServerOptions o = test_options();
    o.max_header_bytes = 1024;
    Seen seen;
    HttpServer server(o);
    server.start(recording(seen));

    // Far over the limit, terminator present.
    const Reply big = fetch(server.port(), "GET / HTTP/1.1\r\nX-Pad: " + std::string(20000, 'a') + "\r\n\r\n");
    CHECK_EQ(big.status, 431);
    CHECK_EQ(big.status_line, "HTTP/1.1 431 Request Header Fields Too Large"s);
    CHECK_EQ(big.body, "request header fields too large"s);
    CHECK(big.end == End::Eof);

    // 100 kB of junk that never contains a CRLF CRLF at all.
    const Reply junk = fetch(server.port(), std::string(100000, 'a'));
    CHECK_EQ(junk.status, 431);

    // Many small header lines adding up.
    std::string many = "GET / HTTP/1.1\r\n";
    for (int i = 0; i < 200; ++i) many += "X-H" + std::to_string(i) + ": value\r\n";
    many += "\r\n";
    CHECK_EQ(fetch(server.port(), many).status, 431);

    CHECK_EQ(seen.count(), std::size_t(0));
    CHECK_EQ(http_get(server.port(), "/fine").status, 200);  // and the server carries on
}

TEST(HttpServer, HeadLimitIsInclusiveOfTheTerminator) {
    HttpServerOptions o = test_options();
    o.max_header_bytes = 300;
    HttpServer server(o);
    server.start(echo_handler());
    const std::string prefix = "GET / HTTP/1.1\r\nX-Pad: ";
    const std::string suffix = "\r\n\r\n";
    auto request_of_size = [&](std::size_t total) {
        return prefix + std::string(total - prefix.size() - suffix.size(), 'a') + suffix;
    };
    CHECK_EQ(request_of_size(300).size(), std::size_t(300));
    CHECK_EQ(fetch(server.port(), request_of_size(299)).status, 200);
    CHECK_EQ(fetch(server.port(), request_of_size(300)).status, 200);  // exactly max_header_bytes
    CHECK_EQ(fetch(server.port(), request_of_size(301)).status, 431);  // one byte more
    CHECK_EQ(fetch(server.port(), request_of_size(302)).status, 431);
}

TEST(HttpServer, ABareLfDoesNotEndTheHead) {
    HttpServerOptions o = test_options();
    o.read_timeout_ms = 150;
    Seen seen;
    HttpServer server(o);
    server.start(recording(seen));
    const Reply r = fetch(server.port(), "GET / HTTP/1.1\n\n");
    CHECK(r.raw.empty());           // no response: the head never completed, the client was timed out
    CHECK(r.end != End::Timeout);   // the server closed the connection by itself
    CHECK_EQ(seen.count(), std::size_t(0));
    CHECK_EQ(http_get(server.port(), "/after").status, 200);
}

TEST(HttpServer, BytesAfterTheHeadAreIgnored) {
    Seen seen;
    HttpServer server(test_options());
    server.start(recording(seen));
    // Two pipelined requests: only the first one is answered, then the connection is closed.
    const Reply r = fetch(server.port(), "GET /one HTTP/1.1\r\n\r\nGET /two HTTP/1.1\r\n\r\n");
    CHECK_EQ(r.status, 200);
    CHECK_EQ(r.body, "GET /one"s);
    CHECK(r.end == End::Eof);
    std::size_t responses = 0;
    for (std::size_t at = r.raw.find("HTTP/1.1 "); at != std::string::npos; at = r.raw.find("HTTP/1.1 ", at + 1)) ++responses;
    CHECK_EQ(responses, std::size_t(1));

    CHECK_EQ(http_get(server.port(), "/three").status, 200);
    CHECK_EQ(seen.count(), std::size_t(2));  // /one and /three; /two was never interpreted
    CHECK_EQ(seen.at(0).path, "/one"s);
    CHECK_EQ(seen.at(1).path, "/three"s);
}

// ---- slow, stalled and vanishing clients --------------------------------------------------------

TEST(HttpServer, AStalledClientDoesNotStopTheNextClientFromBeingServed) {
    HttpServerOptions o = test_options();
    o.read_timeout_ms = 150;
    HttpServer server(o);
    server.start(echo_handler());

    Conn stalled(server.port());  // connects and never sends a byte
    const Reply r = http_get(server.port(), "/queued-behind-the-stalled-client");
    CHECK_EQ(r.status, 200);
    CHECK_EQ(r.body, "GET /queued-behind-the-stalled-client"s);

    std::string rest;
    const End end = stalled.read_all(rest);  // the server gave up on it: closed, no response
    CHECK(end != End::Timeout);
    CHECK(rest.empty());
}

TEST(HttpServer, AClientThatSendsHalfAHeadAndGoesSilentLikewiseDoesNotBlock) {
    HttpServerOptions o = test_options();
    o.read_timeout_ms = 150;
    Seen seen;
    HttpServer server(o);
    server.start(recording(seen));

    Conn half(server.port());
    CHECK(half.send("GET /half-a-he"));
    const Reply r = http_get(server.port(), "/next");
    CHECK_EQ(r.status, 200);
    std::string rest;
    CHECK(half.read_all(rest) != End::Timeout);
    CHECK(rest.empty());
    CHECK_EQ(seen.count(), std::size_t(1));  // only /next ever reached the handler
}

TEST(HttpServer, ATricklingClientIsCutOffByTheTotalReadDeadline) {
    HttpServerOptions o = test_options();
    o.read_timeout_ms = 200;  // a deadline for the whole head, not an idle timeout
    Seen seen;
    HttpServer server(o);
    server.start(recording(seen));

    Conn slow(server.port());
    const std::string request = "GET /trickle HTTP/1.1\r\nX-Pad: " + std::string(2000, 'a') + "\r\n\r\n";
    bool closed = false;
    // One byte every 20 ms never goes idle for long, yet the head cannot complete within 200 ms.
    for (std::size_t i = 0; i < request.size() - 4 && !closed; ++i) {
        if (!slow.send(std::string_view(request).substr(i, 1))) closed = true;
        else {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
            closed = slow.peer_closed();
        }
    }
    CHECK(closed);  // the server hung up on us before we could finish the head
    CHECK_EQ(http_get(server.port(), "/after-the-trickle").status, 200);
    CHECK_EQ(seen.count(), std::size_t(1));
}

TEST(HttpServer, AClientThatClosesBeforeCompletingItsHeadDoesNotBreakTheServer) {
    Seen seen;
    HttpServer server(test_options());
    server.start(recording(seen));
    for (int i = 0; i < 10; ++i) {
        {
            Conn c(server.port());
            CHECK(c.send("GET /never-fini"));
            c.close();  // FIN before the head is complete
        }
        {
            Conn c(server.port());
            CHECK(c.send("GET /never-finished"));
            c.abort();  // RST before the head is complete
        }
        {
            Conn c(server.port());
            c.close();  // connects and leaves without a byte
        }
    }
    CHECK_EQ(http_get(server.port(), "/alive").status, 200);
    CHECK_EQ(seen.count(), std::size_t(1));
}

TEST(HttpServer, AClientThatDisconnectsWithoutReadingTheResponseDoesNotBreakTheServer) {
    HttpServer server(test_options());
    server.start([](const HttpRequest& r) {
        if (r.path == "/big") return text(std::string(4u << 20, 'x'));  // far more than a socket buffer
        return text("small");
    });
    for (int i = 0; i < 10; ++i) {
        {
            Conn c(server.port());
            CHECK(c.send("GET /big HTTP/1.1\r\n\r\n"));
            c.abort();  // RST while the server is (or is about to start) writing 4 MiB
        }
        {
            Conn c(server.port());
            CHECK(c.send("GET /big HTTP/1.1\r\n\r\n"));
            c.close();  // plain close without reading anything
        }
        {
            Conn c(server.port());
            CHECK(c.send("GET /small HTTP/1.1\r\n\r\n"));
            c.abort();  // and a tiny response to a client that is already gone
        }
    }
    const Reply r = http_get(server.port(), "/small");
    CHECK_EQ(r.status, 200);
    CHECK_EQ(r.body, "small"s);
    CHECK(server.running());
}

TEST(HttpServer, AClientThatReadsOnlyAPartOfAHugeResponseDoesNotStallTheServerForever) {
    HttpServerOptions o = test_options();
    o.write_timeout_ms = 200;
    HttpServer server(o);
    server.start([](const HttpRequest& r) {
        if (r.path == "/huge") return text(std::string(16u << 20, 'y'));
        return text("small");
    });
    Conn lazy(server.port());
    CHECK(lazy.send("GET /huge HTTP/1.1\r\n\r\n"));
    // `lazy` never reads: if the kernel cannot buffer 16 MiB the server gives up after the 200 ms
    // write timeout; if it can, the response is simply done. Either way the next client is served.
    const Reply r = http_get(server.port(), "/small");
    CHECK_EQ(r.status, 200);
    CHECK_EQ(r.body, "small"s);
}

// ---- handler failures --------------------------------------------------------------------------------

TEST(HttpServer, AThrowingHandlerGivesAGeneric500WithoutLeakingTheMessage) {
    HttpServer server(test_options());
    server.start([](const HttpRequest& r) -> HttpResponse {
        if (r.path == "/std") throw std::runtime_error("secret-database-password");
        if (r.path == "/logic") throw std::logic_error("another-secret");
        if (r.path == "/int") throw 42;
        if (r.path == "/string") throw std::string("string-secret");
        return text("fine");
    });
    for (const char* path : {"/std", "/logic", "/int", "/string"}) {
        const Reply r = http_get(server.port(), path);
        CHECK_EQ(r.status, 500);
        CHECK_EQ(r.status_line, "HTTP/1.1 500 Internal Server Error"s);
        CHECK_EQ(r.body, "internal server error"s);
        CHECK(!contains(r.raw, "secret"));
        CHECK(!contains(r.raw, "runtime_error"));
        CHECK(!contains(r.raw, "42"s + "\r\n\r\n"));
        CHECK_EQ(*r.header("Content-Length"), "21"s);
    }
    CHECK_EQ(http_get(server.port(), "/ok").body, "fine"s);  // the server survives
    CHECK_EQ(fetch(server.port(), "HEAD /std HTTP/1.1\r\n\r\n").body, ""s);  // HEAD: headers only
}

TEST(HttpServer, UnsafeHandlerResponsesAreReplacedByAGeneric500) {
    // Each case builds a response that must never reach the wire.
    struct Bad {
        const char* label;
        HttpResponse response;
    };
    std::vector<Bad> bad;
    auto with_header = [](std::string name, std::string value) {
        HttpResponse r = text("body");
        r.headers.push_back(HttpHeader{std::move(name), std::move(value)});
        return r;
    };
    bad.push_back({"CRLF in a header value", with_header("X-A", "ok\r\nInjected: yes")});
    bad.push_back({"LF in a header value", with_header("X-A", "ok\nInjected: yes")});
    bad.push_back({"CR in a header value", with_header("X-A", "ok\rInjected: yes")});
    bad.push_back({"NUL in a header value", with_header("X-A", "a\0b"s)});
    bad.push_back({"DEL in a header value", with_header("X-A", "a\x7f" "b")});
    bad.push_back({"0x01 in a header value", with_header("X-A", "a\x01" "b")});
    bad.push_back({"CRLF in a header name", with_header("X-Bad\r\nInjected", "v")});
    bad.push_back({"LF in a header name", with_header("X-Bad\nInjected: yes\nX", "v")});
    bad.push_back({"space in a header name", with_header("X Bad", "v")});
    bad.push_back({"colon in a header name", with_header("X:Bad", "v")});
    bad.push_back({"empty header name", with_header("", "v")});
    bad.push_back({"NUL in a header name", with_header("X-\0-A"s, "v")});
    bad.push_back({"Content-Length override", with_header("Content-Length", "5")});
    bad.push_back({"content-length override (lower case)", with_header("content-length", "5")});
    bad.push_back({"Transfer-Encoding", with_header("Transfer-Encoding", "chunked")});
    bad.push_back({"Connection override", with_header("Connection", "keep-alive")});
    bad.push_back({"second Content-Type", with_header("Content-Type", "text/html")});
    {
        HttpResponse r = text("body");
        r.content_type = "text/html\r\nInjected: yes";
        bad.push_back({"CRLF in the content type", r});
        r.content_type = "text/html\nInjected: yes";
        bad.push_back({"LF in the content type", r});
        r.content_type = "text/plain\0x"s;
        bad.push_back({"NUL in the content type", r});
        r.content_type = "";
        bad.push_back({"empty content type", r});
        r.content_type = "text/plain\t";
        bad.push_back({"tab in the content type", r});
    }
    for (const int status : {0, 1, 99, 600, 999, -200}) {
        HttpResponse r = text("body");
        r.status = status;
        bad.push_back({"status out of range", r});
    }
    {
        HttpResponse r = text("not allowed here", 204);
        bad.push_back({"204 with a body", r});
        r.status = 304;
        bad.push_back({"304 with a body", r});
        r.status = 101;
        bad.push_back({"101 with a body", r});
    }

    std::size_t next = 0;
    std::mutex m;
    HttpServer server(test_options());
    server.start([&](const HttpRequest&) {
        std::lock_guard<std::mutex> lock(m);
        return bad.at(next).response;
    });
    for (std::size_t i = 0; i < bad.size(); ++i) {
        {
            std::lock_guard<std::mutex> lock(m);
            next = i;
        }
        const Reply r = http_get(server.port(), "/");
        if (r.status != 500 || r.body != "internal server error" || contains(r.raw, "Injected") ||
            contains(r.raw, "keep-alive") || contains(r.raw, "chunked") || contains(r.raw, "text/html")) {
            throw testkit::Failure{std::string("unsafe response was not replaced by a generic 500: ") + bad[i].label +
                                   " -> '" + escape(r.raw) + "'"};
        }
        CHECK_EQ(*r.header("Content-Length"), "21"s);
        // Exactly one header block: the blank line is where the server put it.
        CHECK_EQ(r.raw.find("\r\n\r\n"), r.head.size());
        CHECK(r.header("Injected") == nullptr);
    }
    CHECK(bad.size() >= 30);
}

TEST(HttpServer, UnusualButSafeHandlerResponsesArePassedThrough) {
    HttpServer server(test_options());
    server.start([](const HttpRequest&) {
        HttpResponse r = text("{\"ok\":true}");
        r.content_type = "application/json";
        r.headers.push_back(HttpHeader{"X-Tab", "a\tb"});
        r.headers.push_back(HttpHeader{"X-High", "caf\xC3\xA9"});
        r.headers.push_back(HttpHeader{"X-Empty", ""});
        r.headers.push_back(HttpHeader{"Cache-Control", "max-age=60"});  // allowed: appended after ours
        return r;
    });
    const Reply r = http_get(server.port(), "/");
    CHECK_EQ(r.status, 200);
    CHECK_EQ(*r.header("Content-Type"), "application/json"s);
    CHECK_EQ(*r.header("X-Tab"), "a\tb"s);
    CHECK_EQ(*r.header("X-High"), "caf\xC3\xA9"s);
    CHECK(r.head.find("X-Empty:") != std::string::npos);
    CHECK(r.head.find("Cache-Control: max-age=60") != std::string::npos);
    CHECK_EQ(r.body, "{\"ok\":true}"s);
}

TEST(HttpServer, ABinaryBodyIsSentByteForByte) {
    std::string body;
    for (int i = 0; i < 4096; ++i) body.push_back(static_cast<char>(i * 7 + 3));
    body += "\r\n\r\n\0end"s;
    HttpServer server(test_options());
    server.start([&](const HttpRequest&) {
        HttpResponse r = text(body);
        r.content_type = "application/octet-stream";
        return r;
    });
    const Reply r = http_get(server.port(), "/");
    CHECK_EQ(r.status, 200);
    CHECK(r.body == body);
    CHECK_EQ(*r.header("Content-Length"), std::to_string(body.size()));
}

TEST(HttpServer, ALargeResponseIsSentInFull) {
    const std::string body(6u << 20, 'z');  // 6 MiB: several partial sends
    HttpServer server(test_options());
    server.start([&](const HttpRequest&) { return text(body); });
    const Reply r = http_get(server.port(), "/");
    CHECK_EQ(r.status, 200);
    CHECK_EQ(r.body.size(), body.size());
    CHECK(r.body == body);
}

// ---- counting and volume ---------------------------------------------------------------------------------

TEST(HttpServer, TwoHundredSequentialRequestsAreServedAndCounted) {
    HttpServer server(test_options());
    server.start(echo_handler());
    CHECK_EQ(server.requests_served(), std::uint64_t(0));
    for (int i = 0; i < 200; ++i) {
        const Reply r = http_get(server.port(), "/n" + std::to_string(i));
        if (r.status != 200 || r.body != "GET /n" + std::to_string(i)) {
            throw testkit::Failure{"request " + std::to_string(i) + " failed: '" + escape(r.raw) + "'"};
        }
    }
    // The client read to EOF, which the server only sends after counting the exchange.
    CHECK(wait_until([&] { return server.requests_served() >= 200; }));
    CHECK_EQ(server.requests_served(), std::uint64_t(200));
}

TEST(HttpServer, RequestsServedCountsEveryCompletedExchangeButNotDroppedConnections) {
    HttpServer server(test_options());
    server.start([](const HttpRequest& r) -> HttpResponse {
        if (r.path == "/boom") throw std::runtime_error("boom");
        if (r.path == "/missing") return text("nope", 404);
        return text("ok");
    });
    CHECK_EQ(http_get(server.port(), "/ok").status, 200);
    CHECK_EQ(http_get(server.port(), "/missing").status, 404);
    CHECK_EQ(http_get(server.port(), "/boom").status, 500);
    CHECK_EQ(fetch(server.port(), "POST / HTTP/1.1\r\n\r\n").status, 405);
    CHECK_EQ(fetch(server.port(), "garbage\r\n\r\n").status, 400);
    CHECK_EQ(fetch(server.port(), "GET / HTTP/9.9\r\n\r\n").status, 505);
    CHECK_EQ(server.requests_served(), std::uint64_t(6));

    // A connection that is closed without a response is not an exchange.
    {
        Conn silent(server.port());
        silent.close();  // connects and leaves without a byte
        Conn partial(server.port());
        CHECK(partial.send("GET /par"));
        partial.close();  // EOF before the head is complete
    }
    CHECK_EQ(http_get(server.port(), "/ok").status, 200);
    CHECK(wait_until([&] { return server.requests_served() >= 7; }));
    CHECK_EQ(server.requests_served(), std::uint64_t(7));
}

TEST(HttpServer, ThousandSequentialRequestsLeakNothing) {
    HttpServer server(test_options());
    server.start(echo_handler());
    const std::uint16_t port = server.port();
    for (int i = 0; i < 20; ++i) CHECK_EQ(http_get(port, "/warmup").status, 200);
    const long handles_before = open_handle_count();

    for (int i = 0; i < 1000; ++i) {
        const Reply r = http_get(port, "/n");
        if (r.status != 200) throw testkit::Failure{"request " + std::to_string(i) + " failed: '" + escape(r.raw) + "'"};
    }
    CHECK(wait_until([&] { return server.requests_served() >= 1020; }));
    CHECK_EQ(server.requests_served(), std::uint64_t(1020));

    const long handles_after = open_handle_count();
    if (handles_before >= 0 && handles_after >= 0) {
        // A leaked socket per request would add ~1000 handles.
        CHECK(handles_after - handles_before < 25);
    }
    CHECK_EQ(http_get(port, "/still-accepting").status, 200);

    // stop() followed by a new server on the SAME port works.
    server.stop();
    HttpServerOptions o = test_options();
    o.port = port;
    HttpServer second(o);
    second.start(echo_handler());
    CHECK_EQ(second.port(), port);
    CHECK_EQ(http_get(port, "/second").body, "GET /second"s);
}

TEST(HttpServer, ManyConnectionsQueuedAtOnceAreAllServed) {
    HttpServer server(test_options());
    server.start(echo_handler());
    // Open 40 connections before the server has handled any of them, then talk on each.
    std::vector<std::unique_ptr<Conn>> conns;
    for (int i = 0; i < 40; ++i) conns.push_back(std::make_unique<Conn>(server.port()));
    for (std::size_t i = 0; i < conns.size(); ++i) {
        CHECK(conns[i]->send("GET /q" + std::to_string(i) + " HTTP/1.1\r\n\r\n"));
    }
    for (std::size_t i = 0; i < conns.size(); ++i) {
        std::string raw;
        conns[i]->read_all(raw);
        const Reply r = parse_reply(std::move(raw), End::Eof);
        if (r.status != 200 || r.body != "GET /q" + std::to_string(i)) {
            throw testkit::Failure{"queued connection " + std::to_string(i) + " got '" + escape(r.raw) + "'"};
        }
    }
    CHECK(wait_until([&] { return server.requests_served() >= 40; }));
}
