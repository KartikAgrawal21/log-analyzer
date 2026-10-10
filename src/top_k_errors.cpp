#include "loganalyzer/top_k_errors.hpp"

#include <algorithm>
#include <string_view>
#include <utility>

#include "loganalyzer/error_signature.hpp"
#include "loganalyzer/min_heap.hpp"

namespace loganalyzer {
namespace {

// 64-bit FNV-1a: byte-wise, so it is independent of char signedness.
std::uint64_t fnv1a(std::string_view s) noexcept {
    std::uint64_t h = 14695981039346656037ULL;
    for (char c : s) {
        h ^= static_cast<unsigned char>(c);
        h *= 1099511628211ULL;
    }
    return h;
}

// boost::hash_combine widened to 64 bits. Order-sensitive, so (service, signature)
// and (signature, service) hash differently.
std::uint64_t hash_combine(std::uint64_t seed, std::uint64_t h) noexcept {
    return seed ^ (h + 0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2));
}

// MurmurHash3 finalizer: unordered_map implementations that mask the low bits
// (MSVC) would otherwise see FNV's weakest bits.
std::uint64_t avalanche(std::uint64_t x) noexcept {
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    return x;
}

// `a` ranks strictly before `b`: higher count first, then signature, then service
// ascending. (service, signature) is unique per group, so this is a strict total order.
bool ranks_before(const SignatureCount& a, const SignatureCount& b) noexcept {
    if (a.count != b.count) return a.count > b.count;
    if (a.signature != b.signature) return a.signature < b.signature;
    return a.service < b.service;
}

// MinHeap keeps its "smallest" element on top. Ordering by "ranks after" makes that the
// WORST retained group, which is the one to evict when a better group shows up.
struct RanksAfter {
    bool operator()(const SignatureCount* a, const SignatureCount* b) const noexcept {
        return ranks_before(*b, *a);
    }
};

}  // namespace

std::size_t TopKErrors::GroupKeyHash::operator()(const GroupKey& key) const noexcept {
    const std::uint64_t h = hash_combine(fnv1a(key.service), fnv1a(key.signature));
    return static_cast<std::size_t>(avalanche(h));
}

TopKErrors::TopKErrors(Level min_level) : min_level_(min_level) {}

void TopKErrors::add(const LogEntry& entry) {
    if (entry.level < min_level_) return;

    GroupKey key{entry.service, normalize_signature(entry.message)};
    auto it = index_.find(key);
    if (it != index_.end()) {
        SignatureCount& group = groups_[it->second];
        ++group.count;
        group.first_seen_ms = std::min(group.first_seen_ms, entry.timestamp_ms);
        group.last_seen_ms = std::max(group.last_seen_ms, entry.timestamp_ms);
        ++total_;
        return;
    }

    SignatureCount group;
    group.service = key.service;
    group.signature = key.signature;
    group.count = 1;
    group.first_seen_ms = entry.timestamp_ms;
    group.last_seen_ms = entry.timestamp_ms;
    group.example = entry.message;

    // Keep groups_ and index_ in step even if an allocation fails halfway.
    groups_.push_back(std::move(group));
    try {
        index_.emplace(std::move(key), groups_.size() - 1);
    } catch (...) {
        groups_.pop_back();
        throw;
    }
    ++total_;
}

std::vector<SignatureCount> TopKErrors::top_k(std::size_t k) const {
    if (k == 0 || groups_.empty()) return {};

    MinHeap<const SignatureCount*, RanksAfter> best;  // at most k entries, worst on top
    for (const SignatureCount& group : groups_) {
        if (best.size() < k) {
            best.push(&group);
        } else if (ranks_before(group, *best.top())) {
            best.pop();
            best.push(&group);
        }
    }

    // The heap yields worst first, so fill the result from the back.
    std::vector<SignatureCount> result(best.size());
    for (std::size_t i = result.size(); i-- > 0;) result[i] = *best.pop();
    return result;
}

}  // namespace loganalyzer
