#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "loganalyzer/log_entry.hpp"
#include "loganalyzer/min_heap.hpp"

namespace loganalyzer {

/// Streaming k-way merge of per-service logs into one stream ordered by timestamp.
///
/// Every source must already be sorted by timestamp_ms (non-decreasing). The output
/// order is total and deterministic:
///   1. timestamp_ms ascending,
///   2. equal timestamps: source index ascending,
///   3. equal timestamps within one source: original position (the merge is stable).
/// That is exactly what a stable sort of the concatenated sources keyed by
/// (timestamp_ms, source index) would produce.
///
/// The heap holds one small cursor {source, position, cached timestamp} per source that
/// still has entries, never LogEntry copies, and entries are moved out of the owned
/// sources, never copied. Producing all N entries costs O(N log k) time in the worst case
/// (a pop and a push on a heap of at most k cursors per entry); the extra space is O(k).
/// Construction adds an O(N) sortedness check and O(k log k) to seed the heap.
///
/// When the source that just produced an entry also holds the next-smallest one (a run:
/// non-overlapping segments, bursts of equal timestamps, one huge source among tiny ones),
/// its advanced cursor stays out of the heap in `leader_` and that entry costs a single
/// comparison with the heap top instead of a full-depth sift_down plus sift_up.
///
/// Movable, not copyable: a copy would clone every entry. A moved-from merger is empty
/// (has_next() false, remaining() 0).
class KWayMerger {
public:
    /// Takes ownership of the sources. Throws std::invalid_argument naming the first
    /// source that is not sorted by timestamp_ms.
    explicit KWayMerger(std::vector<std::vector<LogEntry>> sources)
        : sources_(std::move(sources)) {
        for (std::size_t s = 0; s < sources_.size(); ++s) {
            const std::vector<LogEntry>& source = sources_[s];
            // Only < is used on timestamps (never a subtraction), so INT64_MIN/MAX are safe.
            for (std::size_t p = 1; p < source.size(); ++p) {
                if (source[p].timestamp_ms < source[p - 1].timestamp_ms) {
                    throw std::invalid_argument(
                        "KWayMerger: source " + std::to_string(s) +
                        " is not sorted by timestamp_ms (position " + std::to_string(p) +
                        " is earlier than position " + std::to_string(p - 1) + ")");
                }
            }
            remaining_ += source.size();
            if (!source.empty()) heap_.push(Cursor{s, 0, source.front().timestamp_ms});
        }
    }

    // Copying would clone every entry, so it is deleted. Moves are explicit (rather than
    // defaulted) so the moved-from merger is reset to empty instead of keeping a stale
    // remaining() or a leader cursor into sources it no longer owns.
    KWayMerger(const KWayMerger&) = delete;
    KWayMerger& operator=(const KWayMerger&) = delete;

    KWayMerger(KWayMerger&& other) noexcept
        : sources_(std::move(other.sources_)),
          heap_(std::move(other.heap_)),
          leader_(other.leader_),
          remaining_(other.remaining_) {
        other.reset();
    }

    KWayMerger& operator=(KWayMerger&& other) noexcept {
        if (this != &other) {
            sources_ = std::move(other.sources_);
            heap_ = std::move(other.heap_);
            leader_ = other.leader_;
            remaining_ = other.remaining_;
            other.reset();
        }
        return *this;
    }

    bool has_next() const noexcept { return leader_.has_value() || !heap_.empty(); }

    /// Entries not yet returned by next(), summed over all sources. O(1).
    std::size_t remaining() const noexcept { return remaining_; }

    /// Moves the earliest remaining entry out. Throws std::out_of_range when exhausted.
    /// O(log k) worst case, O(1) when the same source also holds the next entry.
    LogEntry next() {
        if (!has_next()) throw std::out_of_range("KWayMerger::next on exhausted merger");
        // Invariant: a present leader_ is strictly smaller than heap_.top(), so it is the
        // global minimum; otherwise heap_.top() is.
        Cursor cursor{};
        if (leader_) {
            cursor = *leader_;
            leader_.reset();
        } else {
            cursor = heap_.pop();
        }
        std::vector<LogEntry>& source = sources_[cursor.source];
        LogEntry result = std::move(source[cursor.position]);
        --remaining_;
        // At most one cursor per source is live (in the heap or as leader_), and a
        // source's next entry only becomes live after the previous one left, so ties
        // within a source resolve by position without position taking part in the
        // comparison. CursorLess is a strict total order over live cursors (their source
        // indices differ), so "less than the top" is exact, never a tie.
        if (++cursor.position < source.size()) {
            cursor.timestamp_ms = source[cursor.position].timestamp_ms;
            if (heap_.empty() || CursorLess()(cursor, heap_.top())) {
                leader_ = cursor;
            } else {
                heap_.push(cursor);
            }
        }
        return result;
    }

private:
    struct Cursor {
        std::size_t source;
        std::size_t position;
        std::int64_t timestamp_ms;  // cached so heap comparisons never touch the sources
    };

    struct CursorLess {
        bool operator()(const Cursor& a, const Cursor& b) const noexcept {
            if (a.timestamp_ms != b.timestamp_ms) return a.timestamp_ms < b.timestamp_ms;
            return a.source < b.source;
        }
    };

    void reset() noexcept {
        sources_.clear();
        heap_.clear();
        leader_.reset();
        remaining_ = 0;
    }

    std::vector<std::vector<LogEntry>> sources_;
    MinHeap<Cursor, CursorLess> heap_;
    std::optional<Cursor> leader_;  // smallest live cursor when it was kept out of heap_
    std::size_t remaining_ = 0;
};

/// Merges the sources into one vector ordered as described on KWayMerger.
/// O(N log k) time for N entries in k sources; throws std::invalid_argument if a
/// source is not sorted.
inline std::vector<LogEntry> merge_sorted(std::vector<std::vector<LogEntry>> sources) {
    KWayMerger merger(std::move(sources));
    std::vector<LogEntry> merged;
    merged.reserve(merger.remaining());
    while (merger.has_next()) merged.push_back(merger.next());
    return merged;
}

}  // namespace loganalyzer
