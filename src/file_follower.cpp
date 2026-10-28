#include "loganalyzer/file_follower.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <ios>
#include <limits>
#include <locale>
#include <memory>
#include <stdexcept>
#include <system_error>
#include <utility>

#include "loganalyzer/log_parser.hpp"

namespace loganalyzer {
namespace {

constexpr std::size_t kFingerprintBytes = 256;
// One read, and the most buffer capacity a quiet file keeps after a long partial line.
constexpr std::size_t kChunkBytes = 64 * 1024;
constexpr std::string_view kBom("\xEF\xBB\xBF", 3);

// parse_stream's own definition of "blank" (it is private to log_parser.cpp): the follower must
// skip and count exactly what parse_stream does.
bool is_blank(std::string_view s) noexcept {
    for (char c : s) {
        if (c != ' ' && c != '\t' && c != '\r') return false;
    }
    return true;
}

// After a line ends, a big buffer is given back instead of being kept for a quiet file.
void release(std::string& s) noexcept {
    if (s.capacity() > kChunkBytes) {
        std::string().swap(s);
    } else {
        s.clear();
    }
}

// Room for `extra` more bytes in `s`. Geometric, so a file that grows by a byte per poll does not
// move its partial line every time, but never beyond `cap`.
void make_room(std::string& s, std::size_t extra, std::size_t cap) {
    const std::size_t need = s.size() + extra;
    if (need <= s.capacity()) return;
    s.reserve(std::max(need, std::min(s.capacity() * 2, cap)));
}

void handle_line(std::string_view line, bool& first_line, std::vector<LogEntry>& out, FollowStats& delta) {
    if (first_line) {
        first_line = false;
        if (line.substr(0, kBom.size()) == kBom) line.remove_prefix(kBom.size());
    }
    if (is_blank(line)) return;
    std::optional<LogEntry> entry = parse_line(line);
    if (entry) {
        out.push_back(std::move(*entry));
        ++delta.entries;
    } else {
        ++delta.malformed;
    }
}

// Size of the file behind an open stream.
bool stream_size(std::ifstream& in, std::uint64_t& size) {
    in.clear();
    in.seekg(0, std::ios::end);
    const std::streamoff end = in.tellg();  // -1 on failure
    if (!in || end < 0) return false;
    size = static_cast<std::uint64_t>(end);
    return true;
}

// Reads exactly `count` bytes at `position`.
bool read_exact(std::ifstream& in, std::uint64_t position, char* out, std::size_t count) {
    in.clear();
    in.seekg(static_cast<std::streamoff>(position));
    if (!in) return false;
    if (count == 0) return true;
    in.read(out, static_cast<std::streamsize>(count));
    return in.gcount() == static_cast<std::streamsize>(count);
}

enum class PathKind {
    missing,  // nothing there
    regular,  // a file, or something we cannot classify: opening it is the only way to find out
    other,    // a directory, FIFO, socket or device: there, but nothing to follow
};

// Asked before every open, because opening a FIFO for reading blocks until someone writes to it.
// std::filesystem::status follows symbolic links.
PathKind classify(const std::string& path) {
    std::error_code ec;
    switch (std::filesystem::status(path, ec).type()) {
        case std::filesystem::file_type::not_found:
            return PathKind::missing;
        case std::filesystem::file_type::directory:
        case std::filesystem::file_type::block:
        case std::filesystem::file_type::character:
        case std::filesystem::file_type::fifo:
        case std::filesystem::file_type::socket:
            return PathKind::other;
        default:  // regular, unknown, or an error from the status call itself
            return PathKind::regular;
    }
}

}  // namespace

void FileFollower::Partial::clear() noexcept {
    base = nullptr;
    release(tail);
}

FileFollower::FileFollower(std::vector<std::string> paths, FollowerOptions options) : options_(options) {
    if (paths.empty()) throw std::invalid_argument("FileFollower: no files to follow");
    if (options.max_line_bytes == 0) throw std::invalid_argument("FileFollower: max_line_bytes must be >= 1");
    if (options.max_bytes_per_poll == 0) {
        throw std::invalid_argument("FileFollower: max_bytes_per_poll must be >= 1");
    }
    for (std::size_t i = 0; i < paths.size(); ++i) {
        if (paths[i].empty()) {
            throw std::invalid_argument("FileFollower: path " + std::to_string(i + 1) + " is empty");
        }
    }
    sources_.reserve(paths.size());
    for (std::string& path : paths) {
        Source source;
        source.path = std::move(path);
        sources_.push_back(std::move(source));
    }
}

std::vector<LogEntry> FileFollower::poll() {
    std::vector<LogEntry> out;
    // New per-file state is computed on the side and only committed once every file has been
    // handled, so a std::bad_alloc anywhere leaves *this untouched: the next poll re-reads the same
    // bytes instead of losing the entries this one was building.
    std::vector<std::optional<Update>> updates;
    updates.reserve(sources_.size());
    FollowStats delta;
    bool backlog = false;
    const bool first_poll_from_end = !started_ && !options_.from_start;

    for (const Source& source : sources_) {
        updates.push_back(poll_source(source, first_poll_from_end, out, delta, backlog));
    }

    // The commit appends to buffered partial lines in place. Reserve the room first: the last step
    // that can throw, and it changes a capacity, not a value.
    const std::size_t line_cap = options_.max_line_bytes < std::numeric_limits<std::size_t>::max()
                                     ? options_.max_line_bytes + 1  // a '\r' that may be half a CRLF
                                     : options_.max_line_bytes;
    for (std::size_t i = 0; i < sources_.size(); ++i) {
        if (updates[i] && updates[i]->extends_fragment && !updates[i]->fragment.empty()) {
            make_room(sources_[i].fragment, updates[i]->fragment.size(), line_cap);
        }
    }

    // Commit: nothing below can throw.
    for (std::size_t i = 0; i < sources_.size(); ++i) {
        if (!updates[i]) continue;
        Update& update = *updates[i];
        Source& source = sources_[i];
        if (update.extends_fragment) {
            source.fragment.append(update.fragment);
        } else {
            source.fragment = std::move(update.fragment);
        }
        source.cursor = std::move(update.cursor);
    }
    stats_.entries += delta.entries;
    stats_.malformed += delta.malformed;
    stats_.bytes += delta.bytes;
    stats_.rotations += delta.rotations;
    backlog_ = backlog;
    started_ = true;
    return out;
}

auto FileFollower::poll_source(const Source& source, bool first_poll_from_end, std::vector<LogEntry>& out,
                               FollowStats& delta, bool& backlog) const -> std::optional<Update> {
    const Cursor& cur = source.cursor;
    // from_start == false: a file we have not looked at yet is recorded, not read. That also holds
    // for one that existed at the first poll but could not be looked at then.
    const bool snapshot = !cur.known && (first_poll_from_end || cur.snapshot_pending);

    switch (classify(source.path)) {
        case PathKind::missing: {
            // Deleted or renamed away: forget the position, so whatever shows up under this name is
            // read from its first byte. (A file that was never read has no position to lose, so its
            // arrival later is not a rotation.)
            if (!cur.known && !cur.snapshot_pending) return std::nullopt;
            Update forgotten;
            forgotten.cursor.lost = cur.known;
            return forgotten;
        }
        case PathKind::other:
            return std::nullopt;  // keep everything: it may be a file again next time
        case PathKind::regular:
            break;
    }

    // The file exists but cannot be looked at (a sharing violation, permissions). Present but not
    // openable keeps the position of a known file, because it may be fine next time. A file whose
    // snapshot was due is not allowed to become "a file that appears later", which would deliver
    // its whole history: it stays pending, with the size the file system can still tell us.
    auto cannot_look = [&]() -> std::optional<Update> {
        if (!snapshot || cur.snapshot_pending) return std::nullopt;
        Update pending;
        pending.cursor.snapshot_pending = true;
        std::error_code ec;
        const std::uintmax_t length = std::filesystem::file_size(source.path, ec);
        if (!ec) pending.cursor.pending_size = static_cast<std::uint64_t>(length);
        return pending;
    };

    std::ifstream in;
    in.imbue(std::locale::classic());  // a global narrow codecvt must not change the bytes we read
    in.open(source.path, std::ios::binary);
    std::uint64_t size = 0;
    if (!in || !stream_size(in, size)) return cannot_look();

    // Where does reading resume? `start` is the state of the file at that point.
    Cursor start;
    const std::string* base = nullptr;  // the committed partial line, when `start` continues it
    bool replaced = false;              // truncated, or replaced by another file
    if (cur.known) {
        replaced = size < cur.offset;
        if (!replaced && !cur.fingerprint.empty()) {
            char head[kFingerprintBytes];
            const std::size_t length = cur.fingerprint.size();  // <= kFingerprintBytes by the invariant
            if (!read_exact(in, 0, head, length)) return std::nullopt;  // cannot be read right now: leave it all as it was
            replaced = std::string_view(head, length) != std::string_view(cur.fingerprint);
        }
        if (!replaced) {
            start = cur;
            base = &source.fragment;
        }
    } else if (snapshot) {
        // Note where the snapshot ends and deliver none of what is before it: the end of the file
        // now, or, for a file that could not be looked at before, the size it had at the first poll.
        const std::uint64_t at = cur.pending_size ? *cur.pending_size : size;
        if (at > size) {
            replaced = true;  // shorter than when we first saw it
        } else {
            char head[kFingerprintBytes];
            const std::size_t keep = static_cast<std::size_t>(std::min<std::uint64_t>(at, kFingerprintBytes));
            if (!read_exact(in, 0, head, keep)) return cannot_look();
            char last = '\n';
            if (at > 0) {
                if (at <= kFingerprintBytes) {
                    last = head[keep - 1];
                } else if (!read_exact(in, at - 1, &last, 1)) {
                    return cannot_look();
                }
            }
            start.known = true;
            start.offset = at;
            start.fingerprint.assign(head, keep);
            start.first_line = at == 0;
            // The last line is only half there: its rest, whenever it arrives, is not a line of its own.
            start.discarding = last != '\n';
            if (at == kBom.size() && std::string_view(start.fingerprint) == kBom) {
                // A file that holds nothing but a byte-order mark is an empty file: the next line is whole.
                start.first_line = true;
                start.discarding = false;
            }
        }
    }

    if (!start.known) {
        start.known = true;  // a new file: offset 0, no fragment, no fingerprint yet
        if (replaced || cur.lost) ++delta.rotations;
    } else if (base && size == start.offset) {
        return std::nullopt;  // nothing new: the common, cheap case
    }

    Update update;
    update.cursor = std::move(start);
    Cursor& c = update.cursor;
    Partial partial;
    if (base && !base->empty()) partial.base = base;  // an empty fragment needs no special care

    const std::uint64_t budget = std::min<std::uint64_t>(size - c.offset, options_.max_bytes_per_poll);
    if (budget == 0) return update;  // a new, empty file, or a snapshot at the very end

    const std::size_t chunk = static_cast<std::size_t>(std::min<std::uint64_t>(budget, kChunkBytes));
    const std::unique_ptr<char[]> buffer(new char[chunk]);
    in.clear();
    in.seekg(static_cast<std::streamoff>(c.offset));
    std::uint64_t consumed = 0;
    while (in && consumed < budget) {
        const std::size_t want = static_cast<std::size_t>(std::min<std::uint64_t>(budget - consumed, chunk));
        in.read(buffer.get(), static_cast<std::streamsize>(want));
        const std::size_t got = static_cast<std::size_t>(in.gcount());
        if (got == 0) break;
        // Bytes at the very start of the file extend the fingerprint until it holds 256.
        if (c.fingerprint.size() < kFingerprintBytes && c.fingerprint.size() == c.offset) {
            c.fingerprint.append(buffer.get(), std::min(kFingerprintBytes - c.fingerprint.size(), got));
        }
        feed(c, partial, std::string_view(buffer.get(), got), out, delta);
        c.offset += got;
        consumed += got;
        if (got < want) break;  // the file ended (or failed) earlier than its size promised
    }
    delta.bytes += consumed;
    // Only the limit counts as a reason to come back at once, never a failed read: a caller that
    // loops `while (backlog()) poll();` must not spin on a file that cannot be read.
    if (consumed == options_.max_bytes_per_poll && c.offset < size) backlog = true;

    update.fragment = std::move(partial.tail);
    update.extends_fragment = partial.base != nullptr;
    return update;
}

void FileFollower::feed(Cursor& c, Partial& partial, std::string_view data, std::vector<LogEntry>& out,
                        FollowStats& delta) const {
    const std::size_t limit = options_.max_line_bytes;
    while (!data.empty()) {
        const std::size_t newline = data.find('\n');

        if (c.discarding) {
            if (newline == std::string_view::npos) return;  // all of it belongs to the discarded line
            data.remove_prefix(newline + 1);
            c.discarding = false;
            continue;
        }

        // The length of a line does not count one trailing '\r': it is half of the line ending.
        // Invariant: partial.size() <= limit + 1, so the arithmetic below cannot wrap.
        if (newline == std::string_view::npos) {
            const std::size_t length = partial.size() + data.size() - (data.back() == '\r' ? 1 : 0);
            if (length > limit) {
                // Longer than the limit whatever follows: stop buffering, count it once now.
                partial.clear();
                c.discarding = true;
                c.first_line = false;
                ++delta.malformed;
            } else {
                partial.tail.append(data.data(), data.size());
            }
            return;
        }

        const bool ends_in_cr =
            newline > 0 ? data[newline - 1] == '\r' : (partial.size() > 0 && partial.back() == '\r');
        const std::size_t length = partial.size() + newline - (ends_in_cr ? 1 : 0);
        if (length > limit) {
            ++delta.malformed;  // complete, but too long to keep
            partial.clear();
            c.first_line = false;
        } else if (partial.size() == 0) {
            handle_line(data.substr(0, newline), c.first_line, out, delta);  // the common case: no copy
        } else if (partial.base == nullptr) {
            partial.tail.append(data.data(), newline);
            handle_line(partial.tail, c.first_line, out, delta);
            partial.clear();
        } else {
            // The line starts in the committed fragment, which stays untouched until the commit:
            // assemble a copy of it.
            std::string line;
            line.reserve(partial.size() + newline);
            line.append(*partial.base);
            line.append(partial.tail);
            line.append(data.data(), newline);
            handle_line(line, c.first_line, out, delta);
            partial.clear();
        }
        data.remove_prefix(newline + 1);
    }
}

}  // namespace loganalyzer
