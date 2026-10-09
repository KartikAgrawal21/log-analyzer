#pragma once

#include <cctype>
#include <optional>
#include <string_view>

namespace loganalyzer {

/// Severity of a log line, ordered from least to most severe.
enum class Level { Debug = 0, Info = 1, Warn = 2, Error = 3 };

/// Upper-case wire name: "DEBUG", "INFO", "WARN", "ERROR".
constexpr std::string_view to_string(Level level) noexcept {
    switch (level) {
        case Level::Debug: return "DEBUG";
        case Level::Info:  return "INFO";
        case Level::Warn:  return "WARN";
        case Level::Error: return "ERROR";
    }
    return "UNKNOWN";
}

/// Case-insensitive parse; std::nullopt when the text is not a known level.
inline std::optional<Level> level_from_string(std::string_view text) noexcept {
    auto equals_ignore_case = [](std::string_view a, std::string_view b) {
        if (a.size() != b.size()) return false;
        for (std::size_t i = 0; i < a.size(); ++i) {
            if (std::toupper(static_cast<unsigned char>(a[i])) !=
                std::toupper(static_cast<unsigned char>(b[i]))) {
                return false;
            }
        }
        return true;
    };
    for (Level l : {Level::Debug, Level::Info, Level::Warn, Level::Error}) {
        if (equals_ignore_case(text, to_string(l))) return l;
    }
    return std::nullopt;
}

}  // namespace loganalyzer
