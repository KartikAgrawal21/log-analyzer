#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "loganalyzer/level.hpp"
#include "loganalyzer/log_entry.hpp"

namespace loganalyzer {

/// One group of "the same kind of error" in one service.
struct SignatureCount {
    std::string service;
    std::string signature;  ///< normalize_signature() of the message
    std::uint64_t count = 0;
    std::int64_t first_seen_ms = 0;  ///< smallest timestamp seen (entries may arrive out of order)
    std::int64_t last_seen_ms = 0;   ///< largest timestamp seen
    std::string example;             ///< raw message of the first entry added to the group
};

/// Counts log entries per (service, normalized message) and reports the most frequent.
///
/// add() is O(m) in the message length (normalization) plus an expected O(1) hash
/// lookup. top_k() keeps a bounded MinHeap of the k best groups seen so far and evicts
/// the worst when it is full: O(n log k) for n groups instead of the O(n log n) of
/// sorting everything, and only O(k) extra memory.
class TopKErrors {
public:
    /// Entries with a level below `min_level` are ignored entirely.
    explicit TopKErrors(Level min_level = Level::Error);

    void add(const LogEntry& entry);

    /// The k best groups, best first: count descending, then signature ascending, then
    /// service ascending. That is a total order over groups, so the result is fully
    /// deterministic. k == 0 gives an empty vector; k >= distinct() gives every group.
    std::vector<SignatureCount> top_k(std::size_t k) const;

    /// Number of distinct (service, signature) groups.
    std::size_t distinct() const noexcept { return groups_.size(); }

    /// Number of entries counted (those at or above min_level).
    std::uint64_t total() const noexcept { return total_; }

private:
    // Why a struct of two strings and not `service + signature` as the map key:
    // concatenation is ambiguous. ("ab", "c") and ("a", "bc") would both become "abc"
    // and silently merge two groups; any separator character would just move the
    // problem, because signatures are arbitrary message text. Comparing the two fields
    // separately has no such ambiguity.
    struct GroupKey {
        std::string service;
        std::string signature;
        bool operator==(const GroupKey& other) const {
            return service == other.service && signature == other.signature;
        }
    };
    struct GroupKeyHash {
        std::size_t operator()(const GroupKey& key) const noexcept;
    };

    Level min_level_;
    std::uint64_t total_ = 0;
    std::vector<SignatureCount> groups_;                             // insertion order
    std::unordered_map<GroupKey, std::size_t, GroupKeyHash> index_;  // key -> groups_ slot
};

}  // namespace loganalyzer
