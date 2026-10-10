# log-analyzer

A real-time log analytics and alerting engine in modern C++17 — a tiny Datadog/Splunk.
Every data structure and algorithm is implemented from scratch (no `std::priority_queue`,
no `std::regex`, no search libraries) because the point of this project is DSA practice
on a problem every backend team actually has.

## What it does (roadmap)

| Week | Milestone | DSA |
|------|-----------|-----|
| 1 ✅ | Log generator + parser, k-way merge of per-service logs by timestamp, Top-K error signatures | min-heap, hash map, k-way merge |
| 2 | Real-time alert rules ("more than N errors in W seconds"), cooldowns | sliding window (deque), per-rule hash map |
| 3 | Search: prefix autocomplete, keyword search, multi-keyword queries | trie, KMP, inverted index |
| 4 | CLI polish, dashboard / HTTP API | — |
| 5 | Probabilistic structures + benchmarks on 1M logs | Count-Min Sketch, HyperLogLog |

## Log format

```
{ISO-8601 UTC instant} {LEVEL} {service} {message...}
2026-10-10T12:00:00.123Z ERROR payment-service Timeout calling bank gateway after 3000ms
```

## Build & test

Requires CMake >= 3.16 and a C++17 compiler (developed with MSVC 2019 Build Tools).

```powershell
./build.ps1                  # Release build + run all tests (Windows)
./build.ps1 -Filter MinHeap  # only tests whose name contains "MinHeap"
```

Anywhere else:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
./build/loganalyzer_tests
```

## Usage

```
loganalyzer generate --out-dir DIR [--count N] [--seed S] [--services a,b,c]
loganalyzer merge FILE... [--out FILE]
loganalyzer top-errors FILE... [--k N] [--min-level LEVEL]
loganalyzer bench [--count N]
```

```
$ loganalyzer generate --out-dir logs --count 20000
wrote 20000 entries to logs\auth-service.log
... (one file per service)

$ loganalyzer merge logs\*.log --out merged.log
merged 100000 entries from 5 files (0 malformed skipped)

$ loganalyzer top-errors merged.log --k 2
Top 2 of 50 signature groups (level >= ERROR, 4995 entries, 0 malformed lines skipped)

RANK  COUNT  SERVICE               SIGNATURE
   1    352  order-service         Failed to reserve inventory for order <N>: upstream <IP> returned status <N>
             first 2026-10-10T00:00:01.001Z  last 2026-10-10T00:16:34.621Z
             e.g. Failed to reserve inventory for order 366441198: upstream 10.34.149.91:443 returned status 523
   2    352  notification-service  SMTP delivery to <IP> failed with code <N>
   ...
```

Thousands of distinct concrete messages (different order ids, IPs, status codes) collapse into
50 signature groups: 10 error templates x 5 services, exactly what the generator emits.

## Benchmark

`loganalyzer bench --count 1000000` (single run, MSVC 2019 Release, 94 MiB of log text, the
output of every stage is checked for correctness before the numbers are printed):

| stage    |     ms | M entries/sec |
|----------|-------:|--------------:|
| generate |  235.7 |          4.24 |
| format   |  261.9 |          3.82 |
| parse    |  338.8 |          2.95 |
| merge    |   86.3 |         11.59 |
| top-k    |   46.8 |         21.37 |

## What each module uses

| Module | Files | DSA |
|--------|-------|-----|
| Min-heap | `min_heap.hpp` | array-backed binary heap, hole-based sift |
| K-way merge | `log_merger.hpp` | heap of small cursors, O(N log k), stable (timestamp, source, position) order, run fast-path |
| Top-K errors | `top_k_errors.hpp`, `error_signature.hpp` | hash map keyed by (service, signature), bounded size-k heap for O(n log k) selection, single-pass scanner for normalization |
| Parser | `log_parser.hpp` | Hinnant days-from-civil calendar math, string_view slicing, block-based stream reading |
| Generator | `log_generator.hpp` | xoshiro256** PRNG, Zipf-weighted template choice, exact-integer level thresholds |

## Known limitations (follow-ups from review)

- `GeneratorConfig::start_ms` accepts values (up to +/-2^62) whose timestamps cannot be formatted back; sane dates are fine.
- `parse_stream` treats a leading UTF-8 BOM as part of the first line (that line is counted malformed).
- `parse_stream` on a stream with `exceptions(failbit)` enabled throws at EOF instead of returning the entries read.

## Layout

```
include/loganalyzer/   public headers (header-only data structures live here)
src/                   library implementation (globbed by CMake)
app/main.cpp           the `loganalyzer` executable (thin wrapper over run_cli)
tests/                 dependency-free tests (tests/testkit.hpp), globbed by CMake
tools/quick.ps1        compile + run a subset of tests in an isolated temp dir (optional -Asan)
```
