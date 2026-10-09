#pragma once

#include <cstddef>
#include <functional>
#include <stdexcept>
#include <utility>
#include <vector>

namespace loganalyzer {

/// Array-backed binary min-heap, written from scratch (no std::priority_queue,
/// no std::push_heap). With the default comparator the smallest element is on top;
/// pass std::greater<T> (or any comparator) to change the order.
///
/// push / pop are O(log n); top / size / empty are O(1).
template <class T, class Compare = std::less<T>>
class MinHeap {
public:
    explicit MinHeap(Compare cmp = Compare()) : cmp_(std::move(cmp)) {}

    std::size_t size() const noexcept { return data_.size(); }
    bool empty() const noexcept { return data_.empty(); }
    void clear() noexcept { data_.clear(); }

    void push(T value) {
        data_.push_back(std::move(value));
        sift_up(data_.size() - 1);
    }

    /// Smallest element. Throws std::out_of_range when empty.
    const T& top() const {
        if (empty()) throw std::out_of_range("MinHeap::top on empty heap");
        return data_.front();
    }

    /// Removes and returns the smallest element. Throws std::out_of_range when empty.
    T pop() {
        if (empty()) throw std::out_of_range("MinHeap::pop on empty heap");
        T result = std::move(data_.front());
        if (data_.size() > 1) {
            data_.front() = std::move(data_.back());
            data_.pop_back();
            sift_down(0);
        } else {
            data_.pop_back();
        }
        return result;
    }

private:
    // "Hole" based sifting: move the value once instead of swapping at every level.
    void sift_up(std::size_t i) {
        T value = std::move(data_[i]);
        while (i > 0) {
            std::size_t parent = (i - 1) / 2;
            if (!cmp_(value, data_[parent])) break;
            data_[i] = std::move(data_[parent]);
            i = parent;
        }
        data_[i] = std::move(value);
    }

    void sift_down(std::size_t i) {
        const std::size_t n = data_.size();
        T value = std::move(data_[i]);
        while (true) {
            std::size_t child = 2 * i + 1;
            if (child >= n) break;
            if (child + 1 < n && cmp_(data_[child + 1], data_[child])) ++child;
            if (!cmp_(data_[child], value)) break;
            data_[i] = std::move(data_[child]);
            i = child;
        }
        data_[i] = std::move(value);
    }

    std::vector<T> data_;
    Compare cmp_;
};

}  // namespace loganalyzer
