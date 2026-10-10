# log-analyzer

A real-time log analytics and alerting engine in modern C++17 — a tiny Datadog/Splunk.
Every data structure and algorithm is implemented from scratch (no `std::priority_queue`,
no `std::regex`, no search libraries) because the point of this project is DSA practice
on a problem every backend team actually has.

## What it does (roadmap)

| Week | Milestone | DSA |
|------|-----------|-----|
| 1 ✅ | Log generator + parser, k-way merge of per-service logs by timestamp, Top-K error signatures | min-heap, hash map, k-way merge |
| 2 ✅ | Real-time alert rules ("more than N errors in W seconds"), cooldowns | sliding window (ring buffer), per-rule hash map |
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

Wall-clock performance assertions are opt-in because timing ratios are flaky on a busy
machine: set `LOGANALYZER_PERF_TESTS=1` to include them. `tools/quick.ps1 ... -Asan` runs a
subset under AddressSanitizer.

## Usage

```
loganalyzer generate --out-dir DIR [--count N] [--seed S] [--services a,b,c]
loganalyzer merge FILE... [--out FILE]
loganalyzer top-errors FILE... [--k N] [--min-level LEVEL]
loganalyzer alerts FILE... --rule SPEC [--rule SPEC ...] [--rules-file FILE]
loganalyzer bench [--count N]
```

### Alert rules

A rule fires when at least `threshold` matching entries fall inside a sliding time window
(the half-open interval `(t - window, t]`). "More than 50 errors in a minute" is `threshold=51,window=60s`.

```
name=NAME,threshold=N,window=60s[,service=S][,level=ERROR][,cooldown=5m][,per-service=true]
```

| field | meaning |
|-------|---------|
| `service` | only this service counts (default: all services) |
| `level` | minimum level that counts (default `ERROR`) |
| `cooldown` | after firing, repeats are suppressed until this much event time has passed; the next alert reports how many were swallowed |
| `per-service` | `true`: each service gets its own window and cooldown; `false`: one window shared by all services |

```
$ cat rules.txt
# error bursts anywhere in the system
name=error-burst,threshold=12,window=10s,cooldown=2m
name=payment-errors,service=payment-service,threshold=6,window=10s,cooldown=1m
name=warn-pileup,level=WARN,threshold=60,window=10s,cooldown=5m,per-service=true

$ loganalyzer alerts logs\*.log --rules-file rules.txt
2026-10-10T00:00:02.638Z ALERT rule=error-burst service=* count=12 since=2026-10-10T00:00:00.179Z suppressed=0
2026-10-10T00:00:09.681Z ALERT rule=payment-errors service=payment-service count=6 since=2026-10-10T00:00:00.179Z suppressed=0
2026-10-10T00:01:10.307Z ALERT rule=payment-errors service=payment-service count=11 since=2026-10-10T00:01:01.611Z suppressed=54
2026-10-10T00:02:02.798Z ALERT rule=error-burst service=* count=51 since=2026-10-10T00:01:53.800Z suppressed=608
...
processed 100000 entries with 3 rules: 26 alerts (0 malformed lines skipped, 176 suppressed crossings after the last alert)
```

The input files are k-way merged first, so rules always see one time-ordered stream
(100k entries through 3 rules, including loading the files, takes about 165 ms). Crossings
swallowed by a cooldown are counted in the *next* alert's `suppressed=`; the ones after the
final alert are reported in the summary line so a last burst is never silently lost.

Neither `cmd.exe` nor PowerShell expands wildcards for native programs, so the tool does it: any FILE
argument may contain `*` and `?` in the file-name part (`logs\*.log`); matches are sorted by name.
Rules files may be ASCII or UTF-8 (a BOM is fine); UTF-16 is rejected with a clear message.

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
| Ring buffer | `ring_buffer.hpp` | growable circular buffer (power-of-two capacity, mask indexing), amortized O(1) push/pop, written instead of using `std::deque` |
| Alert engine | `alert_engine.hpp` | sliding window over a ring buffer (each timestamp enters and leaves once: amortized O(1) per entry), rules indexed by service in a hash map, overflow-safe unsigned time arithmetic |
| Glob matcher | `wildcard.hpp` | two-pointer `*` / `?` matching with last-star backtracking (no recursion, no exponential blow-up) |
| Parser | `log_parser.hpp` | Hinnant days-from-civil calendar math, string_view slicing, block-based stream reading |
| Generator | `log_generator.hpp` | xoshiro256** PRNG, Zipf-weighted template choice, exact-integer level thresholds |

## Known limitations (follow-ups from review)

- `GeneratorConfig::start_ms` accepts values (up to +/-2^62) whose timestamps cannot be formatted back; sane dates are fine.
- `parse_stream` treats a leading UTF-8 BOM as part of the first line (that line is counted malformed).
- `parse_stream` on a stream with `exceptions(failbit)` enabled throws at EOF instead of returning the entries read.
- The alert engine keeps one window per (rule, service) for the engine's lifetime and one timestamp per entry inside a
  window, so a stream with an unbounded number of distinct services grows without bound. An idle-window eviction pass is a
  natural follow-up. Service filters are case-sensitive, and a rule that matches nothing is silent.
- `alerts` loads all input before replaying it (it needs the k-way merge), so it is a batch tool, not a tail-follower yet.

## Layout

```
include/loganalyzer/   public headers (header-only data structures live here)
src/                   library implementation (globbed by CMake)
app/main.cpp           the `loganalyzer` executable (thin wrapper over run_cli)
tests/                 dependency-free tests (tests/testkit.hpp), globbed by CMake
tools/quick.ps1        compile + run a subset of tests in an isolated temp dir (optional -Asan)
```
