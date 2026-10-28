// The one replacement of the global operator new/delete for the test program. See alloc_probe.hpp.
#include <cstdlib>
#include <limits>
#include <new>

#include "alloc_probe.hpp"

namespace {

// The block's size is kept in front of it so operator delete can keep `live` right; the header is
// as large as the strictest fundamental alignment, which keeps the returned pointer aligned.
constexpr std::size_t kHeader = alignof(std::max_align_t);

void* allocate(std::size_t size) {
    ++alloc_probe::allocations;
    if (alloc_probe::succeed_before_failing == 0) throw std::bad_alloc();
    if (alloc_probe::succeed_before_failing > 0) --alloc_probe::succeed_before_failing;

    const long armed = alloc_probe::fail_in.load(std::memory_order_relaxed);
    if (armed > 0) {
        alloc_probe::fail_in.store(armed - 1, std::memory_order_relaxed);
        if (armed == 1) throw std::bad_alloc();
    }

    if (size > std::numeric_limits<std::size_t>::max() - kHeader) throw std::bad_alloc();
    void* raw = std::malloc(size + kHeader);
    if (raw == nullptr) throw std::bad_alloc();
    *static_cast<std::size_t*>(raw) = size;

    const long long bytes = static_cast<long long>(size);
    const long long now = alloc_probe::live.fetch_add(bytes) + bytes;
    alloc_probe::total.fetch_add(bytes);
    long long seen = alloc_probe::peak.load();
    while (now > seen && !alloc_probe::peak.compare_exchange_weak(seen, now)) {
    }
    return static_cast<char*>(raw) + kHeader;
}

void* allocate_nothrow(std::size_t size) noexcept {
    try {
        return allocate(size);
    } catch (...) {
        return nullptr;
    }
}

void deallocate(void* p) noexcept {
    if (p == nullptr) return;
    void* raw = static_cast<char*>(p) - kHeader;
    alloc_probe::live.fetch_sub(static_cast<long long>(*static_cast<std::size_t*>(raw)));
    std::free(raw);
}

}  // namespace

// The complete family, not just the plain pair. Replacing only some leaves the others on the
// library's own allocator, and memory from one family is then freed by the other: under
// AddressSanitizer std::stable_sort's temporary buffer (operator new(size, nothrow), served by
// ASan) reached a free() and aborted the run as an alloc-dealloc mismatch. (Over-aligned variants
// are not replaced: nothing in these tests allocates over-aligned types.)
void* operator new(std::size_t size) { return allocate(size); }
void* operator new[](std::size_t size) { return allocate(size); }
void* operator new(std::size_t size, const std::nothrow_t&) noexcept { return allocate_nothrow(size); }
void* operator new[](std::size_t size, const std::nothrow_t&) noexcept { return allocate_nothrow(size); }

void operator delete(void* p) noexcept { deallocate(p); }
void operator delete[](void* p) noexcept { deallocate(p); }
void operator delete(void* p, std::size_t) noexcept { deallocate(p); }
void operator delete[](void* p, std::size_t) noexcept { deallocate(p); }
void operator delete(void* p, const std::nothrow_t&) noexcept { deallocate(p); }
void operator delete[](void* p, const std::nothrow_t&) noexcept { deallocate(p); }
