#pragma once

#include <iosfwd>
#include <string>
#include <vector>

namespace loganalyzer {

/// The `loganalyzer` command line as a plain function so it can be tested without spawning
/// a process. `args` excludes the program name. Normal output goes to `out`, diagnostics
/// and summaries to `err`.
///
/// Returns 0 on success, 1 on a runtime failure (missing/unreadable file, unsorted input,
/// ...), 2 on a usage error (unknown command or option, bad value).
///
/// Commands: generate, merge, top-errors, bench, help. See `loganalyzer help`.
int run_cli(const std::vector<std::string>& args, std::ostream& out, std::ostream& err);

}  // namespace loganalyzer
