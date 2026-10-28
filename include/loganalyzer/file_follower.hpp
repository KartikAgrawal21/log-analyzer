#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "loganalyzer/log_entry.hpp"

namespace loganalyzer {

/// Knobs of a FileFollower. The constructor rejects a 0 for either size.
struct FollowerOptions {
    /// true: the first poll() delivers what each file already contains. false: the first poll()
    /// only records where each existing file ends (like `tail -f -n 0`), so only later appends
    /// are delivered. Files that do not exist yet at that first poll are read from their first
    /// byte when they appear, whatever this says.
    bool from_start = true;

    /// Longest line kept in memory, measured in the bytes between two newlines, not counting ONE
    /// trailing '\r': that byte belongs to a CRLF line ending, as for parse_line, so a line is kept
    /// or discarded the same way whether it ends in "\n" or "\r\n". Must be >= 1. A longer line is
    /// discarded; see "Over-long lines" below.
    std::size_t max_line_bytes = std::size_t{1} << 20;

    /// Most bytes consumed from ONE file by one poll(). Must be >= 1. The rest of the file is left
    /// for the next poll() and backlog() says so; see "Bounded polls" below. This bounds the INPUT
    /// of a poll, not the memory it needs: poll() returns every entry it parsed, from every file,
    /// and an entry (with its strings) is several times larger than the line it came from. A caller
    /// that follows many files, or files written by someone it does not trust, should choose it
    /// with that in mind (a few hundred KiB per poll is plenty for a loop that polls every second).
    std::size_t max_bytes_per_poll = std::size_t{16} << 20;
};

/// Running totals since construction (copied along with the follower).
struct FollowStats {
    std::uint64_t entries = 0;    ///< lines parsed into entries so far
    std::uint64_t malformed = 0;  ///< non-blank lines that did not parse, plus every discarded over-long line
    std::uint64_t bytes = 0;      ///< bytes consumed so far, over all files (not the ones from_start == false skipped)
    std::uint64_t rotations = 0;  ///< times a file was detected as truncated, replaced, or deleted and recreated
};

/// A "tail -f" for log files, for the live alerting and dashboard modes: the caller calls poll()
/// whenever it likes and gets the entries that were appended since the previous call.
///
/// The follower never blocks and never sleeps (how often to poll is the caller's decision), does
/// not expand wildcards (paths are used as given, relative ones against the working directory of
/// each poll), and keeps no file handle between polls: every poll() opens each file with a fresh
/// binary std::ifstream, seeks to the remembered offset, reads what is new and closes it again.
/// So between two polls other programs can append to, rename, truncate or delete a followed file,
/// also on Windows, where an open handle would block a delete or rename. DURING a poll the file is
/// open, and on Windows the standard library opens it without FILE_SHARE_DELETE: a rename or
/// delete by another program that lands in that window (the time to read at most
/// max_bytes_per_poll bytes) fails with a sharing violation, so a writer that rotates its own log
/// may have to retry. A smaller max_bytes_per_poll shortens the window.
///
/// Only regular files are followed. Before opening a path the follower asks the file system what
/// it is, and a directory, a FIFO (named pipe), a socket or a device is treated as present but
/// unreadable and never opened: opening a FIFO for reading would block until a writer shows up,
/// which would break "never blocks". (A path that is swapped for a FIFO between that check and the
/// open is not guarded against.) The stream is imbued with the classic locale, so a program-wide
/// locale with an exotic narrow-character codecvt cannot change the bytes that are read.
///
/// Lines. What counts as a line, a blank line, a malformed line and an entry is exactly what
/// parse_stream() decides, because each complete line is handed to parse_line(): one trailing
/// '\r' (CRLF) is accepted as parse_line accepts it, lines that are empty or hold only spaces,
/// tabs and '\r' are skipped silently, every other line that does not parse is skipped and counted
/// in stats().malformed. A UTF-8 byte-order mark at the very start of a file (or of the new
/// content after a rotation) is skipped, also when the writer produced its three bytes in
/// separate pieces; one anywhere else, also at the start of a second line that follows a blank
/// or an over-long first line, stays part of its line. Feeding a file to the follower in any
/// number of pieces, split at any byte, gives the same entries as parse_stream over the whole
/// file (the tests check this on randomly split generated logs).
///
/// A line is complete only once its terminating '\n' has been seen. A trailing fragment without a
/// newline stays buffered, per file, and is completed by a later poll, even when the writer
/// produced the line in many pieces. Consequence, unlike parse_stream: a FINAL line that is never
/// newline-terminated is never delivered (it is indistinguishable from a line that is still being
/// written). Do not follow files whose writer omits the last newline.
///
/// Over-long lines. A line longer than max_line_bytes is never held in memory: as soon as the
/// bytes seen so far of a line exceed the limit, the buffered part is dropped and the follower
/// discards everything up to and including the next '\n', counting ONE malformed line for it (at
/// the moment the limit is crossed, so it is also counted exactly once when the line only becomes
/// complete in a later poll, or never completes). A line of exactly max_line_bytes is kept, with
/// an LF or a CRLF ending alike. Lengths are measured before the blank-line test, so a
/// longer-than-limit line of only blanks is counted malformed too.
///
/// Memory. The partial line buffered per file (buffered_bytes()) never exceeds max_line_bytes,
/// plus one '\r' that may turn out to be half of a CRLF; the capacity of the string that holds it
/// can be up to about twice that, as strings grow geometrically. While poll() runs it also needs
/// one read chunk (64 KiB). A file that merely grows by more of an unfinished line costs only
/// the new bytes; a buffered partial line that finally completes is assembled into one copy to
/// be parsed, so for that one file the transient peak is about twice max_line_bytes plus the
/// chunk. Nothing else is proportional to the file size: the entries a poll returns are, of
/// course, proportional to the bytes it consumed (see max_bytes_per_poll).
///
/// Bounded polls. At most max_bytes_per_poll bytes are consumed from one file per poll(); the
/// remainder stays in the file for the next poll. backlog() is true when the last poll stopped
/// because of that limit with bytes still unread in some file, so polling again returns more
/// without waiting for the writer. Nothing is split or lost at the boundary: a line cut in the
/// middle by the limit is buffered and completed by the next poll. The limit is per file, so a
/// huge file cannot starve the others.
///
/// Rotation and truncation. Per file the follower remembers the offset it has consumed up to and
/// a fingerprint: the first up to 256 bytes of the file (as many as it has read so far; the
/// fingerprint grows with the file until it holds 256). Every poll compares the file with them.
/// The file is treated as NEW (offset 0, buffered fragment and any over-long discard dropped,
/// stats().rotations incremented, all of its content delivered) when
///   * it is now shorter than the remembered offset (truncated, or replaced by a shorter file), or
///   * its first fingerprint-length bytes differ from the remembered ones (replaced, also by a
///     LONGER or equally long file), or
///   * it was deleted (a poll found no file at the path) and has been created again; this is
///     counted when the new file is first read.
/// Limitation, stated honestly: a file replaced or truncated and regrown to at least the old
/// offset, whose first 256 bytes (or whole old content, when that was shorter) are byte-identical
/// to the old ones, cannot be told from an append. Only the part beyond the old offset is
/// delivered and no rotation is counted. Log lines begin with a timestamp, so in practice only a
/// writer that rewrites identical headers can trigger this.
///
/// Missing and unreadable files are not errors. A file that does not exist, or cannot be opened,
/// sized or read right now contributes nothing to that poll and is retried on the next. A file
/// that appears later, or reappears after deletion, is read from offset 0 whatever from_start
/// says. A path that exists but cannot be opened (permissions, a sharing violation, a directory)
/// keeps its position, because it may be back to normal next time; a path that does not exist at
/// all is forgotten.
///
/// from_start == false. The first poll() records, for each file that exists, its size, its
/// fingerprint and whether it ends in a complete line, and returns nothing for it. A file that
/// exists but cannot be opened or read at that moment (a virus scanner or a writer holding it
/// exclusively, permissions) still counts as existing: the follower remembers the size the file
/// system reports for it (std::filesystem::file_size, which for a file that is being written can
/// lag a little behind the true size), takes the rest of the snapshot at the first poll that can
/// read the file, and delivers what lies beyond that size. The history is never delivered. If the
/// file system cannot report a size either, the snapshot is taken at the first poll that can read
/// the file, and whatever was appended in between is skipped. A file that is seen to be missing in
/// between counts as one that appears later (read from offset 0), and one that has become shorter
/// than it was is treated as replaced (a rotation); the fingerprint of such a file is taken
/// when it can first be read, so a same-size replacement in between goes unnoticed. A line that
/// was only partly written when the follower recorded its position (the file did not end with
/// '\n') is skipped as a whole: its remainder is discarded up to and including the next '\n', and
/// not counted as malformed, because delivering half a line would only produce a bogus malformed
/// count.
///
/// Errors. The stream cannot tell the end of a file from a failed read, so a read that returns
/// fewer bytes than the file's size promised simply ends that file's work for this poll: the bytes
/// that did arrive are consumed (the offset only ever moves past bytes that were processed), and
/// the rest is retried next time. A read that fails before delivering anything consumes nothing:
/// the offset stays where it was (a file that was found replaced is positioned at its start, as
/// described above). Only std::bad_alloc can escape poll(), and when it does the object is
/// observably unchanged (all new state is computed on the side and committed at the end, after
/// reserving the memory the commit needs), so the next poll re-reads the same bytes: no entry is
/// lost or delivered twice.
///
/// Complexity. A poll costs one file-system status query and one open per file, O(256) bytes for
/// the fingerprint comparison, and O(bytes read) for the rest; old content is never re-read and
/// the buffered partial line is not copied when the file just grows (appending to it is amortized
/// O(appended bytes)). parse_line runs only for complete lines, and a line is assembled with at
/// most one copy (only when it straddles two reads or two polls).
///
/// A plain value type: copyable and movable (a copy continues independently from the same
/// position; a moved-from follower may only be destroyed or assigned to). Not thread-safe.
class FileFollower {
public:
    /// Follows `paths` in this order. Throws std::invalid_argument for an empty list, an empty
    /// path, or an option that is 0 (max_line_bytes, max_bytes_per_poll). Does not touch the files:
    /// they need not exist yet. The same path listed twice is followed twice and delivers its
    /// entries twice.
    explicit FileFollower(std::vector<std::string> paths, FollowerOptions options = {});

    /// The entries parsed from the complete lines appended since the previous poll (on the first
    /// poll with from_start, everything the files hold): files in constructor order, each file's
    /// entries in file order. Never blocks. See the class comment for every case.
    std::vector<LogEntry> poll();

    /// True if the last poll() stopped early on max_bytes_per_poll for some file, so calling poll()
    /// again returns more at once. False before the first poll.
    bool backlog() const noexcept { return backlog_; }

    const FollowStats& stats() const noexcept { return stats_; }

    std::size_t file_count() const noexcept { return sources_.size(); }

    /// Bytes of incomplete lines currently held in memory, summed over the files. Never more than
    /// max_line_bytes (plus a '\r') per file; this is the follower's whole memory footprint apart
    /// from a transient read chunk, which makes the over-long-line guarantee observable.
    std::size_t buffered_bytes() const noexcept {
        std::size_t total = 0;
        for (const Source& source : sources_) total += source.fragment.size();
        return total;
    }

private:
    // What is remembered about one file, except its partial line. Invariant for a known file:
    // fingerprint.size() == min(256, offset).
    struct Cursor {
        bool known = false;             // offset and fingerprint describe a file we have looked at
        bool lost = false;              // the file was known and then found deleted: its return is a rotation
        bool snapshot_pending = false;  // from_start == false: the file existed at the first poll but could not be read
        bool discarding = false;        // inside an over-long (or half-seen) line: skip up to the next '\n'
        bool first_line = true;         // no line of this file has ended yet: a BOM may still precede the text
        std::uint64_t offset = 0;       // bytes of the file consumed so far, discarded ones included
        std::string fingerprint;        // the first min(256, offset) bytes of the file
        std::optional<std::uint64_t> pending_size;  // snapshot_pending: the size the file had at the first poll, if known
    };

    struct Source {
        std::string path;
        Cursor cursor;
        std::string fragment;  // partial line: bytes after the last '\n' that was consumed
    };

    // What one poll found out about one file; committed to its Source at the end of poll().
    struct Update {
        Cursor cursor;
        // The new partial line. When extends_fragment, it is only the bytes to ADD to the committed
        // fragment (which is left untouched until the commit, and never copied).
        std::string fragment;
        bool extends_fragment = false;
    };

    // The partial line while a file is being read: the committed fragment, as long as no line has
    // ended in this poll, followed by the bytes appended since.
    struct Partial {
        const std::string* base = nullptr;
        std::string tail;
        std::size_t size() const noexcept { return (base ? base->size() : 0) + tail.size(); }
        char back() const noexcept { return tail.empty() ? base->back() : tail.back(); }  // size() > 0
        void clear() noexcept;
    };

    // Polls one file. Returns its new state if anything about it changed; entries and counters go
    // to `out` / `delta`, and `backlog` is set when the byte limit stopped the read early. Does not
    // modify *this, so poll() can commit all files at once.
    std::optional<Update> poll_source(const Source& source, bool first_poll_from_end, std::vector<LogEntry>& out,
                                      FollowStats& delta, bool& backlog) const;

    // Splits `data` (the next bytes of the file) into lines and handles them.
    void feed(Cursor& cursor, Partial& partial, std::string_view data, std::vector<LogEntry>& out,
              FollowStats& delta) const;

    std::vector<Source> sources_;
    FollowerOptions options_;
    FollowStats stats_;
    bool started_ = false;  // poll() has completed at least once
    bool backlog_ = false;
};

}  // namespace loganalyzer
