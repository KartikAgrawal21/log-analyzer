#include "loganalyzer/log_generator.hpp"

#include <initializer_list>
#include <stdexcept>
#include <utility>

namespace loganalyzer {
namespace {

// ===========================================================================
// Message template catalog
//
// One catalog per service archetype, five in total. A service uses the catalog whose name
// equals its own; any other service name falls back to catalog (index % 5). Templates are
// listed most frequent first: rank k of a pool is chosen with weight 1/(k+1) (Zipf).
//
// Placeholders (see log_generator.hpp): {ms} {n} {id} {ip} {hex} {uuid}.
// Literal text contains no digits, so a normalizer that maps every number / ip:port /
// 0x-hex / uuid to a token must turn all messages of one template into one signature.
// Per catalog: 10 ERROR, 4 WARN, 5 INFO, 4 DEBUG templates.
// ===========================================================================

enum class Param { None, Ms, Count, Id, Ip, Hex, Uuid };

struct Segment {
    std::string_view literal;  // only for Param::None
    Param param = Param::None;
};

struct Template {
    std::string_view text;
    std::vector<Segment> segments;
    std::size_t max_length = 0;  // upper bound of the rendered size: one reserve, no regrowth
};

struct Pool {
    std::vector<Template> templates;
    std::vector<std::uint32_t> cumulative;  // cumulative[k] = weight(0) + ... + weight(k)
};

struct Catalog {
    std::string_view service;
    Pool pools[4];  // indexed by static_cast<size_t>(Level)
};

// lcm(1..12): 27720 / (k + 1) is an exact integer weight for every rank k < 12, so the
// Zipf weights need no floating point.
constexpr std::uint32_t kZipfScale = 27720;
constexpr std::size_t kMaxPoolSize = 12;

std::size_t max_width(Param p) noexcept {
    switch (p) {
        case Param::None:  return 0;
        case Param::Ms:    return 5;   // 30000
        case Param::Count: return 3;   // 999
        case Param::Id:    return 9;   // 999999999
        case Param::Ip:    return 20;  // 10.255.255.254:27017
        case Param::Hex:   return 10;  // 0x + 8
        case Param::Uuid:  return 36;
    }
    return 0;
}

Param param_from_name(std::string_view name) {
    if (name == "ms") return Param::Ms;
    if (name == "n") return Param::Count;
    if (name == "id") return Param::Id;
    if (name == "ip") return Param::Ip;
    if (name == "hex") return Param::Hex;
    if (name == "uuid") return Param::Uuid;
    throw std::logic_error("log_generator: unknown template placeholder");
}

Template compile_template(std::string_view text) {
    Template t;
    t.text = text;
    std::size_t pos = 0;
    while (pos < text.size()) {
        const std::size_t open = text.find('{', pos);
        if (open == std::string_view::npos) {
            t.segments.push_back({text.substr(pos), Param::None});
            break;
        }
        if (open > pos) t.segments.push_back({text.substr(pos, open - pos), Param::None});
        const std::size_t close = text.find('}', open);
        if (close == std::string_view::npos) throw std::logic_error("log_generator: unterminated placeholder");
        t.segments.push_back({std::string_view(), param_from_name(text.substr(open + 1, close - open - 1))});
        pos = close + 1;
    }
    for (const Segment& s : t.segments) {
        t.max_length += s.param == Param::None ? s.literal.size() : max_width(s.param);
    }
    return t;
}

Pool compile_pool(std::initializer_list<std::string_view> texts) {
    if (texts.size() == 0 || texts.size() > kMaxPoolSize) {
        throw std::logic_error("log_generator: bad template pool size");
    }
    Pool pool;
    std::uint32_t running = 0;
    std::uint32_t rank = 0;
    for (std::string_view text : texts) {
        pool.templates.push_back(compile_template(text));
        running += kZipfScale / (rank + 1);
        pool.cumulative.push_back(running);
        ++rank;
    }
    return pool;
}

Catalog make_catalog(std::string_view service, std::initializer_list<std::string_view> debug,
                     std::initializer_list<std::string_view> info,
                     std::initializer_list<std::string_view> warn,
                     std::initializer_list<std::string_view> error) {
    Catalog c;
    c.service = service;
    c.pools[static_cast<std::size_t>(Level::Debug)] = compile_pool(debug);
    c.pools[static_cast<std::size_t>(Level::Info)] = compile_pool(info);
    c.pools[static_cast<std::size_t>(Level::Warn)] = compile_pool(warn);
    c.pools[static_cast<std::size_t>(Level::Error)] = compile_pool(error);
    return c;
}

std::vector<Catalog> build_catalogs() {
    std::vector<Catalog> v;
    v.reserve(5);

    v.push_back(make_catalog(
        "auth-service",
        {  // DEBUG
            "Cache lookup for session {uuid} took {ms}ms",
            "Loaded {n} permissions for user {id}",
            "Connecting to identity store at {ip}",
            "JWT header parsed, key id {hex}",
        },
        {  // INFO
            "User {id} logged in from {ip}",
            "Issued access token {hex} for user {id}",
            "Session {uuid} created",
            "User {id} logged out",
            "Refreshed token for user {id} in {ms}ms",
        },
        {  // WARN
            "Slow token validation for user {id}: {ms}ms",
            "Login retry limit approaching for account {id}: {n} failed attempts",
            "Token for session {uuid} expires in {ms}ms",
            "Deprecated auth API called by client {ip}",
        },
        {  // ERROR
            "Failed to validate token for user {id}: signature mismatch",
            "Database connection to {ip} timed out after {ms}ms",
            "Rate limit exceeded for client {ip}: {n} requests in the last minute",
            "Session store unavailable, request {uuid} rejected",
            "LDAP bind failed against {ip} with error code {n}",
            "Password hash verification failed for account {id} after {n} attempts",
            "Unhandled exception in AuthFilter at {hex}: null principal",
            "OAuth provider callback failed for session {uuid} with status {n}",
            "Signing key rotation failed: unable to load key {hex}",
            "Redis node {ip} unreachable, {n} sessions lost",
        }));

    v.push_back(make_catalog(
        "payment-service",
        {  // DEBUG
            "Serialized charge request for order {id} in {ms}ms",
            "Selected gateway route {n} via {ip}",
            "Idempotency key {uuid} registered",
            "Ledger entry {hex} staged",
        },
        {  // INFO
            "Payment {uuid} authorized for order {id}",
            "Captured payment {uuid} in {ms}ms",
            "Refund issued for order {id}",
            "Settlement batch {hex} completed with {n} transactions",
            "Webhook acknowledged by {ip}",
        },
        {  // WARN
            "Bank gateway {ip} latency high: {ms}ms",
            "Retrying charge for order {id}, attempt {n}",
            "Payment {uuid} pending longer than expected",
            "Fraud score elevated for order {id}: {n}",
        },
        {  // ERROR
            "Timeout calling bank gateway {ip} after {ms}ms",
            "Card declined for order {id}: issuer code {n}",
            "Payment {uuid} failed: insufficient funds",
            "Fraud check service at {ip} returned status {n}",
            "Ledger write failed for transaction {hex}: deadlock detected",
            "Refund {uuid} rejected by processor with code {n}",
            "Currency conversion failed for order {id}: stale rate {n}",
            "Webhook delivery to {ip} failed after {n} retries",
            "Idempotency key {uuid} conflict on order {id}",
            "Settlement batch {hex} aborted: {n} transactions unreconciled",
        }));

    v.push_back(make_catalog(
        "order-service",
        {  // DEBUG
            "Fetched cart {uuid} with {n} items",
            "Calling inventory at {ip} for order {id}",
            "Order state machine transition {n} for order {id}",
            "Event {hex} appended to outbox",
        },
        {  // INFO
            "Order {id} created for customer {id}",
            "Order {uuid} confirmed",
            "Order {id} shipped, tracking {hex}",
            "Order {id} cancelled by customer",
            "Processed {n} orders in {ms}ms",
        },
        {  // WARN
            "Order {id} took {ms}ms to validate",
            "Cart for customer {id} contains {n} unavailable items",
            "Retrying publish of event {hex} to {ip}",
            "Order {uuid} awaiting payment longer than expected",
        },
        {  // ERROR
            "Failed to reserve inventory for order {id}: upstream {ip} returned status {n}",
            "Order {uuid} could not be persisted: database error {n}",
            "Timeout waiting for payment confirmation on order {id} after {ms}ms",
            "Message broker {ip} refused publish of event {hex}",
            "Order {id} stuck in state {n} for {ms}ms",
            "Shipping quote request to {ip} failed with status {n}",
            "Inconsistent cart total for order {id}: delta {n}",
            "Duplicate order submission {uuid} for customer {id}",
            "Saga rollback failed at step {n} for order {id}",
            "Outbox relay {hex} crashed while processing {n} events",
        }));

    v.push_back(make_catalog(
        "inventory-service",
        {  // DEBUG
            "Looking up sku {id} in shard {hex}",
            "Cache hit for sku {id} in {ms}ms",
            "Opened connection to warehouse database {ip}",
            "Reservation {uuid} registered with {n} units",
        },
        {  // INFO
            "Reserved {n} units of sku {id}",
            "Stock updated for sku {id}: {n} units",
            "Reservation {uuid} committed",
            "Cycle count finished for aisle {n} in {ms}ms",
            "Synced with supplier API at {ip}",
        },
        {  // WARN
            "Low stock for sku {id}: {n} units remaining",
            "Warehouse query took {ms}ms for sku {id}",
            "Reservation {uuid} close to expiry",
            "Supplier API {ip} responded slowly: {ms}ms",
        },
        {  // ERROR
            "Stock level negative for sku {id}: {n} units",
            "Warehouse database {ip} connection reset after {ms}ms",
            "Reservation {uuid} failed: optimistic lock conflict on sku {id}",
            "Failed to sync stock with supplier API at {ip}: status {n}",
            "Index corruption detected in shard {hex}",
            "Cache invalidation failed for sku {id} on node {ip}",
            "Reservation {uuid} expired before commit, {n} units released",
            "Barcode scan rejected for item {hex}: unknown sku {id}",
            "Replication lag {ms}ms exceeds limit on replica {ip}",
            "Batch import aborted at row {n}: malformed record {hex}",
        }));

    v.push_back(make_catalog(
        "notification-service",
        {  // DEBUG
            "Rendered template for message {uuid} in {ms}ms",
            "Dequeued {n} messages from queue {hex}",
            "Resolved user {id} contact preferences",
            "Opened connection to push gateway {ip}",
        },
        {  // INFO
            "Sent email {uuid} to user {id}",
            "Push notification delivered to device {hex} in {ms}ms",
            "Batch of {n} notifications dispatched",
            "User {id} unsubscribed from newsletter",
            "Connected to SMTP relay at {ip}",
        },
        {  // WARN
            "Delivery of message {uuid} delayed by {ms}ms",
            "Retrying SMTP delivery to {ip}, attempt {n}",
            "Recipient {id} has {n} unread notifications",
            "Push token {hex} is about to expire",
        },
        {  // ERROR
            "SMTP delivery to {ip} failed with code {n}",
            "Push gateway timeout after {ms}ms for device {hex}",
            "Template rendering failed for message {uuid}: missing field {n}",
            "SMS provider at {ip} rejected message for user {id}: status {n}",
            "Message queue {hex} overflowed, dropped {n} notifications",
            "Bounce limit exceeded for recipient {id}: {n} hard bounces",
            "Webhook subscriber {ip} unreachable for event {uuid}",
            "Failed to persist delivery receipt {hex} after {ms}ms",
            "Unsubscribe lookup failed for user {id}: database error {n}",
            "Dead letter queue write failed for message {uuid}",
        }));

    return v;
}

const std::vector<Catalog>& catalogs() {
    static const std::vector<Catalog> kCatalogs = build_catalogs();  // built once, thread-safe
    return kCatalogs;
}

std::size_t catalog_for(std::string_view service, std::size_t service_index) {
    const std::vector<Catalog>& all = catalogs();
    for (std::size_t i = 0; i < all.size(); ++i) {
        if (all[i].service == service) return i;
    }
    return service_index % all.size();
}

// ===========================================================================
// Parameter rendering. Every function draws from the PRNG in separate statements: the order
// in which C++ evaluates function arguments is unspecified, and two next() calls inside one
// expression would make the output depend on the compiler.
// ===========================================================================

constexpr char kHexDigits[] = "0123456789abcdef";
constexpr std::uint32_t kPorts[8] = {80, 443, 3306, 5432, 6379, 8080, 9092, 27017};

std::size_t write_uint(char* out, std::uint64_t value) noexcept {
    char reversed[20];
    std::size_t n = 0;
    do {
        reversed[n++] = static_cast<char>('0' + value % 10);
        value /= 10;
    } while (value != 0);
    for (std::size_t i = 0; i < n; ++i) out[i] = reversed[n - 1 - i];
    return n;
}

std::size_t write_ip(char* out, Xoshiro256& rng) noexcept {
    const std::uint64_t bits = rng.next();
    const std::uint32_t last_octet = 1 + rng.below(254);
    char* p = out;
    *p++ = '1';
    *p++ = '0';
    *p++ = '.';
    p += write_uint(p, bits & 0xFF);
    *p++ = '.';
    p += write_uint(p, (bits >> 8) & 0xFF);
    *p++ = '.';
    p += write_uint(p, last_octet);
    *p++ = ':';
    p += write_uint(p, kPorts[(bits >> 16) & 7]);
    return static_cast<std::size_t>(p - out);
}

std::size_t write_hex(char* out, Xoshiro256& rng) noexcept {
    const std::uint64_t word = rng.next() >> 32;
    out[0] = '0';
    out[1] = 'x';
    for (int i = 0; i < 8; ++i) out[2 + i] = kHexDigits[(word >> (28 - 4 * i)) & 0xF];
    return 10;
}

// RFC 4122 version 4: 122 random bits, version nibble 4, variant nibble in [89ab].
std::size_t write_uuid(char* out, Xoshiro256& rng) noexcept {
    const std::uint64_t high = rng.next();
    const std::uint64_t low = rng.next();
    unsigned nibble[32];
    for (int i = 0; i < 16; ++i) {
        nibble[i] = static_cast<unsigned>((high >> (60 - 4 * i)) & 0xF);
        nibble[16 + i] = static_cast<unsigned>((low >> (60 - 4 * i)) & 0xF);
    }
    nibble[12] = 4;
    nibble[16] = 8 | (nibble[16] & 3);
    char* p = out;
    for (int i = 0; i < 32; ++i) {
        if (i == 8 || i == 12 || i == 16 || i == 20) *p++ = '-';
        *p++ = kHexDigits[nibble[i]];
    }
    return 36;
}

std::size_t write_param(Param param, Xoshiro256& rng, char* out) noexcept {
    switch (param) {
        case Param::Ms:    return write_uint(out, 1u + rng.below(30000));
        case Param::Count: return write_uint(out, 1u + rng.below(999));
        case Param::Id:    return write_uint(out, 1000u + rng.below(999'999'000));
        case Param::Ip:    return write_ip(out, rng);
        case Param::Hex:   return write_hex(out, rng);
        case Param::Uuid:  return write_uuid(out, rng);
        case Param::None:  break;
    }
    return 0;
}

std::string render(const Template& tmpl, Xoshiro256& rng) {
    std::string message;
    message.reserve(tmpl.max_length);
    char buffer[40];
    for (const Segment& segment : tmpl.segments) {
        if (segment.param == Param::None) {
            message.append(segment.literal.data(), segment.literal.size());
        } else {
            const std::size_t n = write_param(segment.param, rng, buffer);
            message.append(buffer, n);
        }
    }
    return message;
}

// Weighted pick = first index whose cumulative weight exceeds the draw (binary search).
std::size_t pick_template(const Pool& pool, Xoshiro256& rng) {
    const std::uint32_t draw = rng.below(pool.cumulative.back());
    std::size_t lo = 0;
    std::size_t hi = pool.cumulative.size() - 1;
    while (lo < hi) {
        const std::size_t mid = lo + (hi - lo) / 2;
        if (pool.cumulative[mid] > draw) {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    return lo;
}

// ===========================================================================
// Config handling
// ===========================================================================

constexpr std::uint64_t kUnit53 = std::uint64_t{1} << 53;
constexpr std::int64_t kMaxMeanGapMs = 1'000'000'000;
// 9999-12-31T23:59:59.999Z: the last instant format_entry / parse_line can represent. Every
// generated timestamp must stay within [0, kMaxTimestampMs] so a generated log can always be
// written out and read back.
constexpr std::int64_t kMaxTimestampMs = 253402300799999LL;

bool has_whitespace(const std::string& s) noexcept {
    for (char c : s) {
        if (c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r') return true;
    }
    return false;
}

void validate(const GeneratorConfig& c) {
    if (c.services.empty()) throw std::invalid_argument("GeneratorConfig: no services");
    for (const std::string& name : c.services) {
        if (name.empty() || has_whitespace(name)) {
            throw std::invalid_argument("GeneratorConfig: service names must be non-empty without whitespace");
        }
    }
    // Written as !(x >= 0) so that NaN is rejected too.
    if (!(c.error_rate >= 0.0) || !(c.warn_rate >= 0.0) || !(c.debug_rate >= 0.0)) {
        throw std::invalid_argument("GeneratorConfig: rates must be >= 0");
    }
    if (!(c.error_rate + c.warn_rate + c.debug_rate <= 1.0 + 1e-9)) {
        throw std::invalid_argument("GeneratorConfig: rates sum to more than 1");
    }
    if (c.mean_gap_ms < 0 || c.mean_gap_ms > kMaxMeanGapMs) {
        throw std::invalid_argument("GeneratorConfig: mean_gap_ms must be in [0, 1e9]");
    }
    if (c.start_ms < 0 || c.start_ms > kMaxTimestampMs) {
        throw std::invalid_argument("GeneratorConfig: start_ms must be in [0, 9999-12-31T23:59:59.999Z]");
    }
}

// rate * 2^53 is an exact scaling of the double, so truncating it is exact and portable.
std::uint64_t to_threshold(double rate) noexcept {
    const double scaled = rate * static_cast<double>(kUnit53);
    return scaled >= static_cast<double>(kUnit53) ? kUnit53 : static_cast<std::uint64_t>(scaled);
}

std::uint64_t stream_seed(std::uint64_t seed, std::size_t index) noexcept {
    SplitMix64 base(seed);
    SplitMix64 mixed(base.next() + static_cast<std::uint64_t>(index) * 0xD1B54A32D192ED03ULL);
    return mixed.next();
}

}  // namespace

LogGenerator::LogGenerator(GeneratorConfig config) : config_(std::move(config)) {
    validate(config_);
    error_cut_ = to_threshold(config_.error_rate);
    warn_cut_ = error_cut_ + to_threshold(config_.warn_rate);
    debug_cut_ = warn_cut_ + to_threshold(config_.debug_rate);
    if (debug_cut_ > kUnit53) debug_cut_ = kUnit53;  // rates summed to 1 within tolerance
    if (warn_cut_ > debug_cut_) warn_cut_ = debug_cut_;
    if (error_cut_ > warn_cut_) error_cut_ = warn_cut_;

    streams_.reserve(config_.services.size());
    for (std::size_t i = 0; i < config_.services.size(); ++i) {
        streams_.push_back(Stream{Xoshiro256(stream_seed(config_.seed, i)), config_.start_ms,
                                  catalog_for(config_.services[i], i)});
    }
}

std::vector<LogEntry> LogGenerator::generate_service(std::size_t service_index, std::size_t count) {
    if (service_index >= streams_.size()) {
        throw std::out_of_range("LogGenerator::generate_service: bad service index");
    }
    Stream& stream = streams_[service_index];
    const Catalog& catalog = catalogs()[stream.catalog_index];
    const std::string& service = config_.services[service_index];
    const std::uint32_t gap_choices = static_cast<std::uint32_t>(2 * config_.mean_gap_ms + 1);

    // Refuse, before touching any state, a request whose WORST case (every gap at its maximum)
    // would carry a timestamp past what the log format can represent. The check is
    // conservative near the end of the range and exact everywhere else; it keeps the stream
    // untouched when it throws, so the call is all-or-nothing.
    if (count > 0) {
        if (stream.next_timestamp_ms > kMaxTimestampMs) {
            throw std::length_error("LogGenerator: this service's stream has reached the end of the log time range");
        }
        const std::uint64_t worst_gap = 2 * static_cast<std::uint64_t>(config_.mean_gap_ms);
        const std::uint64_t room = static_cast<std::uint64_t>(kMaxTimestampMs - stream.next_timestamp_ms);
        if (worst_gap != 0 && static_cast<std::uint64_t>(count - 1) > room / worst_gap) {
            throw std::length_error("LogGenerator: the requested entries could run past 9999-12-31T23:59:59.999Z");
        }
    }

    std::vector<LogEntry> entries;
    entries.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        LogEntry& entry = entries.emplace_back();
        entry.timestamp_ms = stream.next_timestamp_ms;

        // Draw order per entry is fixed: level, template, parameters, gap.
        const std::uint64_t level_draw = stream.rng.next53();
        if (level_draw < error_cut_) {
            entry.level = Level::Error;
        } else if (level_draw < warn_cut_) {
            entry.level = Level::Warn;
        } else if (level_draw < debug_cut_) {
            entry.level = Level::Debug;
        } else {
            entry.level = Level::Info;
        }
        const Pool& pool = catalog.pools[static_cast<std::size_t>(entry.level)];
        const std::size_t rank = pick_template(pool, stream.rng);
        entry.message = render(pool.templates[rank], stream.rng);
        entry.service = service;

        stream.next_timestamp_ms += stream.rng.below(gap_choices);
    }
    return entries;
}

std::vector<std::vector<LogEntry>> LogGenerator::generate_all(std::size_t count_per_service) {
    std::vector<std::vector<LogEntry>> all;
    all.reserve(streams_.size());
    for (std::size_t i = 0; i < streams_.size(); ++i) {
        all.push_back(generate_service(i, count_per_service));
    }
    return all;
}

std::vector<std::string_view> LogGenerator::message_templates(std::size_t service_index,
                                                              Level level) const {
    if (service_index >= streams_.size()) {
        throw std::out_of_range("LogGenerator::message_templates: bad service index");
    }
    const std::size_t pool_index = static_cast<std::size_t>(level);
    if (pool_index >= 4) throw std::invalid_argument("LogGenerator::message_templates: bad level");
    const Pool& pool = catalogs()[streams_[service_index].catalog_index].pools[pool_index];
    std::vector<std::string_view> texts;
    texts.reserve(pool.templates.size());
    for (const Template& t : pool.templates) texts.push_back(t.text);
    return texts;
}

}  // namespace loganalyzer
