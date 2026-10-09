#pragma once

#include <cstdint>
#include <iosfwd>
#include <string>

#include "loganalyzer/level.hpp"

namespace loganalyzer {

/// One parsed log line.
///
/// Wire format (one entry per line, single spaces between the first three fields):
///   {ISO-8601 UTC instant} {LEVEL} {service} {message...}
/// e.g.
///   2026-10-10T12:00:00.123Z ERROR payment-service Timeout calling bank gateway after 3000ms
struct LogEntry {
    std::int64_t timestamp_ms = 0;  ///< milliseconds since the Unix epoch (UTC)
    Level level = Level::Info;
    std::string service;
    std::string message;

    friend bool operator==(const LogEntry& a, const LogEntry& b) {
        return a.timestamp_ms == b.timestamp_ms && a.level == b.level &&
               a.service == b.service && a.message == b.message;
    }
    friend bool operator!=(const LogEntry& a, const LogEntry& b) { return !(a == b); }
};

/// Debug printer (not the wire format): used by test failure messages.
std::ostream& operator<<(std::ostream& os, const LogEntry& entry);

}  // namespace loganalyzer
