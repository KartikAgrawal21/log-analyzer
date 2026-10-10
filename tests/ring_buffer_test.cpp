#include <cstddef>
#include <cstdint>
#include <deque>
#include <random>
#include <stdexcept>
#include <string>
#include <utility>

#include "loganalyzer/ring_buffer.hpp"
#include "testkit.hpp"

using loganalyzer::RingBuffer;

TEST(RingBuffer, StartsEmptyAndThrowsOnAccess) {
    RingBuffer<int> r;
    CHECK(r.empty());
    CHECK_EQ(r.size(), std::size_t{0});
    CHECK_THROWS(r.front(), std::out_of_range);
    CHECK_THROWS(r.back(), std::out_of_range);
    CHECK_THROWS(r.pop_front(), std::out_of_range);
    CHECK_THROWS(r.at(0), std::out_of_range);
}

TEST(RingBuffer, IsFifo) {
    RingBuffer<int> r;
    for (int i = 1; i <= 5; ++i) r.push_back(i);
    CHECK_EQ(r.front(), 1);
    CHECK_EQ(r.back(), 5);
    for (int i = 1; i <= 5; ++i) {
        CHECK_EQ(r.front(), i);
        r.pop_front();
    }
    CHECK(r.empty());
}

TEST(RingBuffer, WrapsAroundWithoutGrowing) {
    RingBuffer<int> r;
    for (int i = 0; i < 8; ++i) r.push_back(i);
    const std::size_t cap = r.capacity();
    CHECK_EQ(cap, std::size_t{8});
    // Slide a window of 8 across 100 values: the head wraps many times, capacity stays put.
    for (int i = 8; i < 108; ++i) {
        r.pop_front();
        r.push_back(i);
        CHECK_EQ(r.size(), std::size_t{8});
        CHECK_EQ(r.front(), i - 7);
        CHECK_EQ(r.back(), i);
    }
    CHECK_EQ(r.capacity(), cap);
}

TEST(RingBuffer, GrowthPreservesOrderWhenHeadIsNotAtZero) {
    RingBuffer<int> r;
    for (int i = 0; i < 8; ++i) r.push_back(i);
    for (int i = 0; i < 5; ++i) r.pop_front();      // head now at slot 5
    for (int i = 8; i < 40; ++i) r.push_back(i);    // wraps, then forces several growths
    CHECK_EQ(r.size(), std::size_t{35});
    for (std::size_t i = 0; i < r.size(); ++i) CHECK_EQ(r.at(i), static_cast<int>(i) + 5);
    CHECK_EQ(r.capacity(), std::size_t{64});
}

TEST(RingBuffer, ClearResetsAndIsReusable) {
    RingBuffer<std::string> r;
    r.push_back("a");
    r.push_back("b");
    r.clear();
    CHECK(r.empty());
    r.push_back("c");
    CHECK_EQ(r.front(), std::string("c"));
    CHECK_EQ(r.size(), std::size_t{1});
}

TEST(RingBuffer, MovedFromBufferIsEmptyAndReusable) {
    RingBuffer<int> a;
    for (int i = 0; i < 20; ++i) a.push_back(i);
    RingBuffer<int> b(std::move(a));
    CHECK_EQ(b.size(), std::size_t{20});
    CHECK(a.empty());
    CHECK_EQ(a.capacity(), std::size_t{0});
    a.push_back(7);
    CHECK_EQ(a.front(), 7);
    RingBuffer<int> c;
    c = std::move(b);
    CHECK_EQ(c.size(), std::size_t{20});
    CHECK(b.empty());
}

TEST(RingBuffer, CopyIsIndependent) {
    RingBuffer<int> a;
    for (int i = 0; i < 10; ++i) a.push_back(i);
    RingBuffer<int> b = a;
    a.pop_front();
    a.push_back(99);
    CHECK_EQ(b.size(), std::size_t{10});
    CHECK_EQ(b.front(), 0);
    CHECK_EQ(b.back(), 9);
}

TEST(RingBuffer, MatchesStdDequeOnRandomOperations) {
    for (std::uint32_t seed = 1; seed <= 20; ++seed) {
        std::mt19937 rng(seed);
        RingBuffer<std::int64_t> r;
        std::deque<std::int64_t> reference;
        for (int step = 0; step < 5000; ++step) {
            const unsigned op = rng() % 10;
            if (op < 5) {  // push-heavy early, drain-heavy later, to cross many capacities
                const std::int64_t v = static_cast<std::int64_t>(rng());
                r.push_back(v);
                reference.push_back(v);
            } else if (op < 9) {
                if (!reference.empty()) {
                    r.pop_front();
                    reference.pop_front();
                }
            } else if (rng() % 50 == 0) {
                r.clear();
                reference.clear();
            }
            CHECK_EQ(r.size(), reference.size());
            if (!reference.empty()) {
                CHECK_EQ(r.front(), reference.front());
                CHECK_EQ(r.back(), reference.back());
            }
        }
        for (std::size_t i = 0; i < reference.size(); ++i) CHECK_EQ(r.at(i), reference[i]);
    }
}

// ---- added after review -----------------------------------------------------------------

TEST(RingBuffer, SelfCopyAndSelfMoveAssignmentAreSafe) {
    RingBuffer<int> r;
    for (int i = 0; i < 20; ++i) r.push_back(i);
    RingBuffer<int>& alias = r;  // an alias keeps compilers from warning about self-assignment
    r = alias;
    CHECK_EQ(r.size(), std::size_t{20});
    r = std::move(alias);
    CHECK_EQ(r.size(), std::size_t{20});
    CHECK_EQ(r.front(), 0);
    CHECK_EQ(r.back(), 19);
}

TEST(RingBuffer, CopyAssignmentReplacesContentsAndIsIndependent) {
    RingBuffer<int> a;
    RingBuffer<int> b;
    for (int i = 0; i < 12; ++i) a.push_back(i);
    for (int i = 100; i < 105; ++i) b.push_back(i);
    b = a;
    CHECK_EQ(b.size(), std::size_t{12});
    CHECK_EQ(b.front(), 0);
    a.pop_front();
    CHECK_EQ(b.front(), 0);
}

TEST(RingBuffer, AtIsLogicalAcrossTheWrapPoint) {
    RingBuffer<int> r;
    for (int i = 0; i < 8; ++i) r.push_back(i);
    for (int i = 0; i < 5; ++i) r.pop_front();   // logical contents: 5 6 7
    for (int i = 8; i < 13; ++i) r.push_back(i); // wraps around the end of the array: 5..12
    CHECK_EQ(r.capacity(), std::size_t{8});
    for (std::size_t i = 0; i < r.size(); ++i) CHECK_EQ(r.at(i), static_cast<int>(i) + 5);
    CHECK_THROWS(r.at(8), std::out_of_range);
}

TEST(RingBuffer, EmptyAfterClearThrowsAgain) {
    RingBuffer<std::string> r;
    r.push_back("x");
    r.clear();
    CHECK_THROWS(r.front(), std::out_of_range);
    CHECK_THROWS(r.back(), std::out_of_range);
    CHECK_THROWS(r.pop_front(), std::out_of_range);
}

TEST(RingBuffer, GrowsToAMillionElementsAndDrainsInOrder) {
    RingBuffer<std::int64_t> r;
    const std::int64_t n = 1'000'000;
    for (std::int64_t i = 0; i < n; ++i) r.push_back(i);
    CHECK_EQ(r.size(), static_cast<std::size_t>(n));
    CHECK_EQ(r.capacity(), std::size_t{1} << 20);  // next power of two >= n
    CHECK_EQ(r.front(), std::int64_t{0});
    CHECK_EQ(r.back(), n - 1);
    for (std::int64_t i = 0; i < n; ++i) {
        if (r.front() != i) throw testkit::Failure{"order broke at " + std::to_string(i)};
        r.pop_front();
    }
    CHECK(r.empty());
}
