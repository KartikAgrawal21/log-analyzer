#include <algorithm>
#include <functional>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

#include "loganalyzer/min_heap.hpp"
#include "testkit.hpp"

using loganalyzer::MinHeap;

TEST(MinHeap, EmptyHeapThrowsOnTopAndPop) {
    MinHeap<int> h;
    CHECK(h.empty());
    CHECK_EQ(h.size(), std::size_t{0});
    CHECK_THROWS(h.top(), std::out_of_range);
    CHECK_THROWS(h.pop(), std::out_of_range);
}

TEST(MinHeap, PopsInAscendingOrder) {
    MinHeap<int> h;
    for (int v : {5, 3, 8, 1, 9, 2, 7}) h.push(v);
    CHECK_EQ(h.size(), std::size_t{7});
    CHECK_EQ(h.top(), 1);
    std::vector<int> out;
    while (!h.empty()) out.push_back(h.pop());
    CHECK((out == std::vector<int>{1, 2, 3, 5, 7, 8, 9}));
}

TEST(MinHeap, HandlesDuplicatesAndSingleElement) {
    MinHeap<int> h;
    h.push(4);
    CHECK_EQ(h.pop(), 4);
    CHECK(h.empty());
    for (int v : {2, 2, 2, 1, 1}) h.push(v);
    std::vector<int> out;
    while (!h.empty()) out.push_back(h.pop());
    CHECK((out == std::vector<int>{1, 1, 2, 2, 2}));
}

TEST(MinHeap, CustomComparatorGivesMaxHeap) {
    MinHeap<int, std::greater<int>> h;
    for (int v : {5, 3, 8, 1}) h.push(v);
    CHECK_EQ(h.pop(), 8);
    CHECK_EQ(h.pop(), 5);
}

TEST(MinHeap, WorksWithMoveOnlyFriendlyTypes) {
    MinHeap<std::string> h;
    for (const char* s : {"pear", "apple", "fig"}) h.push(s);
    CHECK_EQ(h.pop(), std::string("apple"));
    CHECK_EQ(h.pop(), std::string("fig"));
    CHECK_EQ(h.pop(), std::string("pear"));
}

TEST(MinHeap, ClearEmptiesTheHeap) {
    MinHeap<int> h;
    h.push(1);
    h.push(2);
    h.clear();
    CHECK(h.empty());
    h.push(7);
    CHECK_EQ(h.top(), 7);
}

TEST(MinHeap, MatchesStdSortOnRandomData) {
    std::mt19937 rng(12345);
    std::uniform_int_distribution<int> dist(-1000, 1000);
    MinHeap<int> h;
    std::vector<int> reference;
    for (int i = 0; i < 20000; ++i) {
        int v = dist(rng);
        h.push(v);
        reference.push_back(v);
    }
    std::sort(reference.begin(), reference.end());
    for (int expected : reference) CHECK_EQ(h.pop(), expected);
    CHECK(h.empty());
}
