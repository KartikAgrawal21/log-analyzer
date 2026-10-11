#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "loganalyzer/min_heap.hpp"

namespace loganalyzer {

/// One autocomplete suggestion: a stored key and its accumulated weight.
struct Completion {
    std::string key;
    std::uint64_t weight = 0;

    friend bool operator==(const Completion& a, const Completion& b) {
        return a.weight == b.weight && a.key == b.key;
    }
    friend bool operator!=(const Completion& a, const Completion& b) { return !(a == b); }
};

/// Prefix-autocomplete trie with a cached top-k list at every node, written from scratch.
/// Each key carries a weight (think "how often was this query / token / service seen");
/// complete(prefix, k) returns the k heaviest keys that start with the prefix.
///
/// KEYS
///   Keys are arbitrary byte strings, compared and indexed as UNSIGNED bytes: bytes >= 128
///   and embedded NULs are ordinary key bytes (a NUL never terminates anything). The empty
///   key is not allowed. Whether text is UTF-8 is irrelevant: ordering is by byte value.
///
/// WEIGHTS
///   insert(key, w) ADDS w to the key's weight and creates the key (at weight w) if it is
///   new, so feeding one log token a million times is a million cheap calls, not a million
///   keys. Weight 0 is allowed: it creates a key that ranks after every key with weight > 0.
///   Weights never decrease and keys are never removed (clear() empties the whole trie);
///   that is what makes the per-node caches cheap to maintain, see the invariant below.
///
/// RESULT ORDER
///   complete() orders by weight DESCENDING, then by key ASCENDING (bytewise, unsigned).
///   That is a strict total order over distinct keys, so results are fully deterministic and
///   never depend on insertion order. A key is a "completion" of itself: complete("app", k)
///   includes the key "app".
///
/// COMPLEXITY (n = |key| or |prefix|, sigma <= 256 = branching, K = cached_k)
///   insert    O(n * (log sigma + K)) worst case: one child lookup and one cache update per
///             byte; the O(K) scan of a cache is skipped as soon as the new weight cannot
///             beat the cache's worst entry. Adding a brand-new edge shifts at most sigma
///             edges. Ties on weight are broken by comparing keys, which costs the length
///             of their common prefix, so inserting many near-identical multi-megabyte
///             keys with EQUAL weights is quadratic in the key length (distinct weights are
///             decided in O(1)).
///   complete  k <= K: O(n log sigma + k) straight from the cache of the prefix node (plus
///             copying the k result strings).
///             k >  K: O(n log sigma + N + m log k) where N = nodes below the prefix and
///             m = keys below it: an iterative DFS offers each key to a bounded MinHeap of
///             size k. Subtrees whose best key cannot beat the heap's current worst are
///             skipped, so this is usually far cheaper than the bound.
///   contains / weight   O(n log sigma).
///
/// REPRESENTATION
///   * All nodes live in ONE contiguous std::vector and refer to each other by 32-bit index;
///     there is no per-node heap allocation and no pointer to fix up on copy, so copying a
///     Trie is a plain deep copy of a few vectors.
///   * A node's children are a byte-sorted block of (byte, child index) edges inside one
///     shared edge pool, looked up with binary search. A block starts at 1 slot and doubles
///     (up to 256) by moving to the end of the pool; the abandoned block stays as dead space
///     (at most as much as the live data, geometric series) until clear(). The alternative,
///     a 256-entry child array per node, gives O(1) lookup but costs 1 KiB per node: a
///     single 1,000,000-byte key would take a gigabyte, while the sorted block costs 8 bytes
///     per edge. Below the first couple of levels most nodes are chain links or have a
///     handful of children, where binary search over 1-4 entries is as fast as indexing;
///     only the few wide nodes near the root pay the full log2(256) = 8 probes.
///   * Each node caches its best K keys as indices into a key table (the key strings are
///     stored once, in the table, never copied into nodes), best first, in another shared
///     pool with the same grow-by-relocation blocks (capacity min(K, keys below)).
///     Worst-case cache memory is 4 bytes * K per node, plus at most as much again in
///     abandoned blocks.
///   * Nothing recurses: insert, lookup and the DFS are loops, so key length is limited by
///     memory only (a 1,000,000-byte key is fine; the stack never grows with it).
///   * Indices are 32-bit; exceeding 2^32 - 2 nodes, keys or pool slots throws
///     std::length_error long before that much memory exists in practice.
///
/// EXCEPTIONS
///   insert throws std::invalid_argument for the empty key and std::overflow_error when the
///   accumulated weight would exceed UINT64_MAX; both are thrown BEFORE anything is changed
///   (strong guarantee). If an allocation fails (std::bad_alloc) the trie is observably
///   unchanged too: the only leftover is possibly a few key-less empty branches, which no
///   query can see and clear() reclaims. contains / weight / size never throw.
///
/// THREADING
///   const members keep no scratch state, so any number of threads may call them
///   concurrently as long as nobody calls a non-const member at the same time.
///
/// COPY / MOVE
///   Copyable (deep copy, strong guarantee on assignment) and movable. A moved-from Trie is
///   empty and fully reusable and keeps its cached_k.
class Trie {
public:
    /// cached_k is the per-node cache size K: complete() is fastest for k <= K, and larger
    /// K costs memory (up to 4 bytes per node per slot) and insert time. Throws
    /// std::invalid_argument if cached_k == 0.
    explicit Trie(std::size_t cached_k = 10)
        : cached_k_(cached_k),
          cache_limit_(static_cast<std::uint32_t>(std::min<std::size_t>(cached_k, kNone - 1))) {
        if (cached_k == 0) throw std::invalid_argument("Trie: cached_k must be at least 1");
    }

    Trie(const Trie&) = default;

    Trie& operator=(const Trie& other) {
        if (this != &other) {
            Trie copy(other);  // copy-and-swap: a failed copy leaves *this untouched
            *this = std::move(copy);
        }
        return *this;
    }

    Trie(Trie&& other) noexcept
        : nodes_(std::move(other.nodes_)),
          edges_(std::move(other.edges_)),
          cache_(std::move(other.cache_)),
          keys_(std::move(other.keys_)),
          cached_k_(other.cached_k_),
          cache_limit_(other.cache_limit_) {
        other.clear();  // a moved-from vector is only "valid but unspecified"; make it empty
    }

    Trie& operator=(Trie&& other) noexcept {
        if (this != &other) {
            nodes_ = std::move(other.nodes_);
            edges_ = std::move(other.edges_);
            cache_ = std::move(other.cache_);
            keys_ = std::move(other.keys_);
            cached_k_ = other.cached_k_;
            cache_limit_ = other.cache_limit_;
            other.clear();
        }
        return *this;
    }

    /// The K given to the constructor.
    std::size_t cached_k() const noexcept { return cached_k_; }

    /// Number of distinct keys (a key inserted ten times counts once).
    std::size_t size() const noexcept { return keys_.size(); }

    /// Adds `amount` to the weight of `key`, creating the key if it is new (weight 0 is
    /// allowed and creates a key of weight 0). The key bytes are copied.
    /// Throws std::invalid_argument if key is empty and std::overflow_error if the
    /// resulting weight would exceed UINT64_MAX; in both cases the trie is unchanged.
    void insert(std::string_view key, std::uint64_t amount = 1) {
        if (key.empty()) throw std::invalid_argument("Trie::insert: empty key");

        const std::uint32_t existing = find_key(key);
        if (existing != kNone) {
            KeyRecord& record = keys_[existing];
            if (amount > std::numeric_limits<std::uint64_t>::max() - record.weight) {
                throw std::overflow_error("Trie::insert: weight overflows uint64");
            }
            if (amount == 0) return;
            record.weight += amount;
            // Cannot fail: every node on the path already contains this key, and a key
            // that is already below a node never needs a new cache slot there (see the
            // invariant on touch()).
            refresh_path(key, existing);
            return;
        }

        if (keys_.size() >= kNone) throw std::length_error("Trie: too many keys");
        // Everything that can throw (node, edge, cache-slot and key-table allocation) happens
        // before the first visible change; keys_.push_back is deliberately the last of them.
        // After it, only noexcept steps remain.
        const std::uint32_t terminal = ensure_path(key);
        keys_.push_back(KeyRecord{std::string(key), amount});
        const auto index = static_cast<std::uint32_t>(keys_.size() - 1);
        nodes_[terminal].terminal = index;
        refresh_path(key, index);
    }

    /// True if exactly this key has been inserted (a mere prefix of a key is not enough).
    bool contains(std::string_view key) const noexcept { return find_key(key) != kNone; }

    /// Accumulated weight of the key, or 0 if it is absent (so a present key of weight 0 and
    /// an absent key look the same here; use contains() to tell them apart).
    std::uint64_t weight(std::string_view key) const noexcept {
        const std::uint32_t index = find_key(key);
        return index == kNone ? 0 : keys_[index].weight;
    }

    /// The k best keys that start with `prefix`, ordered by weight descending then key
    /// ascending (bytewise, unsigned). `prefix` may be empty (global top-k). k == 0, an
    /// unknown prefix, or an empty trie give an empty vector; a k larger than the number of
    /// matches returns all matches (any k up to SIZE_MAX is fine, memory is bounded by the
    /// number of matches, not by k).
    std::vector<Completion> complete(std::string_view prefix, std::size_t k) const {
        std::vector<Completion> result;
        if (k == 0) return result;
        const std::uint32_t node = find_node(prefix);
        if (node == kNone) return result;
        const Node& n = nodes_[node];
        if (n.cache_count == 0) return result;  // only possible for a leftover empty branch

        // The cache is authoritative when it is long enough (k <= K) or when it is not
        // full: a cache with room left holds EVERY key below the node.
        if (k <= cached_k_ || n.cache_count < cache_limit_) {
            const std::size_t take = std::min<std::size_t>(k, n.cache_count);
            const std::uint32_t* cached = cache_.data() + n.cache_off;
            result.reserve(take);
            for (std::size_t i = 0; i < take; ++i) result.push_back(to_completion(cached[i]));
            return result;
        }
        return complete_by_scan(node, k);
    }

    /// Removes every key. Allocated memory is kept for reuse, like std::vector::clear().
    void clear() noexcept {
        nodes_.clear();
        edges_.clear();
        cache_.clear();
        keys_.clear();
    }

private:
    static constexpr std::uint32_t kNone = 0xFFFFFFFFu;  // "no index"; real indices are < kNone

    struct Edge {
        std::uint32_t child;
        unsigned char byte;
    };

    struct Node {
        std::uint32_t terminal = kNone;  // key-table index of the key ending here, or kNone
        std::uint32_t edge_off = 0;      // block [edge_off, edge_off + edge_cap) in edges_
        std::uint32_t cache_off = 0;     // block [cache_off, cache_off + cache_cap) in cache_
        std::uint32_t cache_count = 0;   // used slots of the cache block: min(K, keys below)
        std::uint32_t cache_cap = 0;
        std::uint16_t edge_count = 0;    // sorted by byte; at most 256 distinct bytes
        std::uint16_t edge_cap = 0;
    };

    struct KeyRecord {
        std::string key;
        std::uint64_t weight;
    };

    // Comparator for the bounded scan heap. MinHeap keeps its "smallest" element on top; by
    // declaring "a < b" to mean "a is the WORSE key" the top is the worst of the kept k,
    // which is exactly the one to evict.
    struct WorseFirst {
        const Trie* trie;
        bool operator()(std::uint32_t a, std::uint32_t b) const noexcept { return trie->better(b, a); }
    };

    // ---- ordering -----------------------------------------------------------------

    // Strict total order on distinct key indices: weight descending, then key ascending.
    // std::char_traits<char>::compare orders as unsigned char (the standard defines lt that
    // way), so bytes >= 128 sort after ASCII and embedded NULs compare as ordinary bytes.
    bool better(std::uint32_t a, std::uint32_t b) const noexcept {
        if (a == b) return false;  // irreflexive, and O(1) instead of comparing a key with itself
        const KeyRecord& x = keys_[a];
        const KeyRecord& y = keys_[b];
        if (x.weight != y.weight) return x.weight > y.weight;
        return std::string_view(x.key).compare(std::string_view(y.key)) < 0;
    }

    Completion to_completion(std::uint32_t index) const {
        return Completion{keys_[index].key, keys_[index].weight};
    }

    // ---- lookup -------------------------------------------------------------------

    // First edge whose byte is >= `byte` (binary search over the node's sorted block).
    static std::size_t lower_bound_edge(const Edge* edges, std::size_t count, unsigned char byte) noexcept {
        std::size_t lo = 0;
        std::size_t hi = count;
        while (lo < hi) {
            const std::size_t mid = lo + (hi - lo) / 2;
            if (edges[mid].byte < byte) lo = mid + 1;
            else hi = mid;
        }
        return lo;
    }

    std::uint32_t child(std::uint32_t node, unsigned char byte) const noexcept {
        const Node& n = nodes_[node];
        const Edge* edges = edges_.data() + n.edge_off;
        const std::size_t i = lower_bound_edge(edges, n.edge_count, byte);
        return (i < n.edge_count && edges[i].byte == byte) ? edges[i].child : kNone;
    }

    // Node reached by following `text` from the root, or kNone. Iterative on purpose.
    std::uint32_t find_node(std::string_view text) const noexcept {
        if (nodes_.empty()) return kNone;
        std::uint32_t node = 0;
        for (const char c : text) {
            node = child(node, static_cast<unsigned char>(c));  // never index with a signed char
            if (node == kNone) return kNone;
        }
        return node;
    }

    std::uint32_t find_key(std::string_view key) const noexcept {
        const std::uint32_t node = find_node(key);
        return node == kNone ? kNone : nodes_[node].terminal;
    }

    // ---- growth (the only code that allocates; see insert) ---------------------------

    // Moves a block into fresh space at the end of `pool` with room for new_cap items and
    // returns the new offset. Strong guarantee: if it throws, `pool` is unchanged. Capacity
    // is grown explicitly by doubling so amortization does not depend on how a particular
    // standard library implements resize().
    template <class T>
    static std::uint32_t relocate(std::vector<T>& pool, std::uint32_t old_off, std::size_t used,
                                  std::size_t new_cap) {
        const std::size_t new_off = pool.size();
        if (new_cap > static_cast<std::size_t>(kNone) - new_off) {
            throw std::length_error("Trie: index space exhausted");
        }
        const std::size_t needed = new_off + new_cap;
        if (needed > pool.capacity()) {
            const std::size_t doubled =
                pool.capacity() > pool.max_size() / 2 ? pool.max_size() : pool.capacity() * 2;
            pool.reserve(std::max(needed, doubled));
        }
        pool.resize(needed);  // cannot reallocate now, so it cannot throw
        T* base = pool.data();
        std::copy(base + old_off, base + old_off + used, base + new_off);
        return static_cast<std::uint32_t>(new_off);
    }

    // Makes sure the node's cache block has a free slot if its cache is not already full.
    void reserve_cache_slot(std::uint32_t node_index) {
        Node& n = nodes_[node_index];
        if (n.cache_count < cache_limit_ && n.cache_count == n.cache_cap) {
            const std::uint64_t doubled = n.cache_cap == 0 ? 1 : std::uint64_t{n.cache_cap} * 2;
            const auto new_cap = static_cast<std::uint32_t>(std::min<std::uint64_t>(doubled, cache_limit_));
            n.cache_off = relocate(cache_, n.cache_off, n.cache_count, new_cap);
            n.cache_cap = new_cap;
        }
    }

    // Appends a new child node for `byte` under `parent` and links the sorted edge.
    // The edge block is grown and the node is allocated BEFORE the edge is linked, so a
    // failure leaves no half-linked edge.
    std::uint32_t add_child(std::uint32_t parent, unsigned char byte) {
        {
            Node& p = nodes_[parent];
            if (p.edge_count == p.edge_cap) {
                const std::size_t new_cap = p.edge_cap == 0 ? 1 : std::size_t{p.edge_cap} * 2;
                p.edge_off = relocate(edges_, p.edge_off, p.edge_count, new_cap);
                p.edge_cap = static_cast<std::uint16_t>(new_cap);
            }
        }
        if (nodes_.size() >= kNone) throw std::length_error("Trie: too many nodes");
        nodes_.emplace_back();  // may reallocate nodes_: take references only afterwards
        const auto created = static_cast<std::uint32_t>(nodes_.size() - 1);

        Node& p = nodes_[parent];
        Edge* edges = edges_.data() + p.edge_off;
        const std::size_t pos = lower_bound_edge(edges, p.edge_count, byte);
        for (std::size_t i = p.edge_count; i > pos; --i) edges[i] = edges[i - 1];
        edges[pos] = Edge{created, byte};
        ++p.edge_count;
        return created;
    }

    // Walks (creating nodes as needed) to the node where `key` ends, and reserves one cache
    // slot in every node on the way, root included. Returns the terminal node.
    std::uint32_t ensure_path(std::string_view key) {
        if (nodes_.empty()) nodes_.emplace_back();  // the root is created lazily
        std::uint32_t node = 0;
        reserve_cache_slot(node);
        for (const char c : key) {
            const auto byte = static_cast<unsigned char>(c);
            std::uint32_t next = child(node, byte);
            if (next == kNone) next = add_child(node, byte);
            node = next;
            reserve_cache_slot(node);
        }
        return node;
    }

    // ---- cache maintenance (noexcept: all capacity was reserved beforehand) ----------

    // Re-walks the (now complete) path of `key` and updates the cache of every node on it,
    // root included. Nodes off the path do not contain the key and are untouched.
    void refresh_path(std::string_view key, std::uint32_t key_index) noexcept {
        std::uint32_t node = 0;
        touch(node, key_index);
        for (const char c : key) {
            node = child(node, static_cast<unsigned char>(c));
            touch(node, key_index);
        }
    }

    // Cache invariant: for every node n, cache(n) lists min(K, |S(n)|) keys of S(n), best
    // first, where S(n) is the set of keys in n's subtree (including a key ending at n) and
    // "best" is the order of better().
    //
    // touch() restores it after ONE key x became better (new, or its weight went up).
    // That is all an insert ever does, and it is why one pass over the path suffices and
    // nothing ever has to be refilled:
    //   * every other key keeps its position relative to the others; only x can move, and
    //     only upwards;
    //   * x already cached: it stays cached and nobody outside can enter, because each
    //     outsider was already worse than the worst cached key and x only got better. Just
    //     bubble x up to its new place;
    //   * x not cached, cache full: x gets in iff it now beats the worst cached key, which
    //     is the only entry that can be pushed out;
    //   * x not cached, cache not full: the cache holds all of S(n), so x is a brand-new key
    //     (an existing one would be cached). Append and bubble up.
    // A key evicted from a cache never needs to come back by itself: that would take some
    // cached key getting worse than it, i.e. a weight decrease or a deletion, and neither
    // exists. It returns only through its own next insert, which is the "x" case above.
    void touch(std::uint32_t node_index, std::uint32_t x) noexcept {
        Node& n = nodes_[node_index];
        std::uint32_t* cached = cache_.data() + n.cache_off;
        const std::uint32_t count = n.cache_count;

        // x only moved up, so if it is still worse than the worst entry of a full cache it
        // was outside before and stays outside. O(1) exit for the common case.
        if (count == cache_limit_ && better(cached[count - 1], x)) return;

        std::uint32_t pos = 0;
        while (pos < count && cached[pos] != x) ++pos;
        if (pos == count) {  // not cached yet
            if (count < cache_limit_) ++n.cache_count;  // take the reserved free slot
            else --pos;                                 // full: overwrite the worst entry
        }
        while (pos > 0 && better(x, cached[pos - 1])) {
            cached[pos] = cached[pos - 1];
            --pos;
        }
        cached[pos] = x;
    }

    // ---- fallback for k > K --------------------------------------------------------

    // Best k keys below `root` by an iterative DFS and a bounded heap of the k best seen
    // so far (top = worst of them). A key enters only while the heap has room or when it
    // beats the top, which is then evicted: O(log k) per offered key.
    std::vector<Completion> complete_by_scan(std::uint32_t root, std::size_t k) const {
        MinHeap<std::uint32_t, WorseFirst> best{WorseFirst{this}};
        std::vector<std::uint32_t> pending{root};
        while (!pending.empty()) {
            const std::uint32_t node = pending.back();
            pending.pop_back();
            const Node& n = nodes_[node];
            if (n.cache_count == 0) continue;  // leftover empty branch: no keys below
            // cache[0] is the best key of the whole subtree; if even that cannot beat the
            // worst kept key, nothing below can, so skip it (branch and bound).
            if (best.size() == k && better(best.top(), cache_[n.cache_off])) continue;

            if (n.terminal != kNone) {
                if (best.size() < k) {
                    best.push(n.terminal);
                } else if (better(n.terminal, best.top())) {
                    best.pop();
                    best.push(n.terminal);
                }
            }
            const Edge* edges = edges_.data() + n.edge_off;
            for (std::size_t i = 0; i < n.edge_count; ++i) pending.push_back(edges[i].child);
        }

        std::vector<Completion> result(best.size());
        for (std::size_t i = result.size(); i-- > 0;) result[i] = to_completion(best.pop());  // worst first
        return result;
    }

    std::vector<Node> nodes_;       // nodes_[0] is the root once the first key is inserted
    std::vector<Edge> edges_;       // shared pool of child blocks
    std::vector<std::uint32_t> cache_;  // shared pool of top-K blocks (indices into keys_)
    std::vector<KeyRecord> keys_;   // the key table: each key string is stored exactly once
    std::size_t cached_k_;          // K as configured
    std::uint32_t cache_limit_;     // K clamped to what a 32-bit index can address
};

}  // namespace loganalyzer
