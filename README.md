# log-analyzer

A real-time log analytics and alerting engine in modern C++17 — a tiny Datadog/Splunk.
Every data structure and algorithm is implemented from scratch (no `std::priority_queue`,
no `std::regex`, no search libraries) because the point of this project is DSA practice
on a problem every backend team actually has.

## What it does (roadmap)

| Week | Milestone | DSA |
|------|-----------|-----|
| 1 | Log generator + parser, k-way merge of per-service logs by timestamp, Top-K error signatures | min-heap, hash map, k-way merge |
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

## Layout

```
include/loganalyzer/   public headers (header-only data structures live here)
src/                   library implementation (globbed by CMake)
app/main.cpp           the `loganalyzer` CLI
tests/                 dependency-free tests (tests/testkit.hpp), globbed by CMake
```
