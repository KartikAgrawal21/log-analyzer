#include "loganalyzer/log_entry.hpp"

#include <ostream>

namespace loganalyzer {

std::ostream& operator<<(std::ostream& os, const LogEntry& entry) {
    return os << "LogEntry{ts=" << entry.timestamp_ms << ", " << to_string(entry.level)
              << ", " << entry.service << ", \"" << entry.message << "\"}";
}

}  // namespace loganalyzer
