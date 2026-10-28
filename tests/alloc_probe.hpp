#pragma once

#include <atomic>
#include <cstddef>

// Allocation probe shared by the tests. A program has exactly one global operator new and CMake
// links every tests/*.cpp into one executable, so the replacement lives in alloc_probe.cpp and
// every test that wants to count or fail allocations uses this header.
//
// With nothing armed the replacement behaves like malloc/free and costs a few counter bumps.
//
// A test file that reads these counters should compile with GCC's
// `#pragma GCC optimize("no-assume-sane-operators-new-delete")` (see kmp_test.cpp): GCC 15
// otherwise assumes a replaced operator new touches no program state and may move allocations
// across the reads of the counters.

namespace alloc_probe {

// Per-thread: only allocations made by the thread that reads them are counted or failed, so a
// background thread can neither perturb a measurement nor receive an injected std::bad_alloc.
// Constant-initialised thread_locals need no guard, which makes them safe to touch from operator
// new at any time.
//
// succeed_before_failing >= 0: that many further allocations of this thread succeed, then every
// one throws std::bad_alloc.
inline thread_local long succeed_before_failing = -1;
inline thread_local std::size_t allocations = 0;  // calls to operator new on this thread so far

// Arms the per-thread failure injection for the lifetime of the object; always disarms.
struct FailAfter {
    explicit FailAfter(long successes) { succeed_before_failing = successes; }
    ~FailAfter() { succeed_before_failing = -1; }
    FailAfter(const FailAfter&) = delete;
    FailAfter& operator=(const FailAfter&) = delete;
};

// Process-wide byte accounting, in bytes requested from operator new.
inline std::atomic<long long> live{0};   // currently allocated
inline std::atomic<long long> peak{0};   // the highest `live` since a test last reset it
inline std::atomic<long long> total{0};  // ever requested
// N > 0: the Nth next allocation, by any thread, throws std::bad_alloc.
inline std::atomic<long> fail_in{0};

}  // namespace alloc_probe
