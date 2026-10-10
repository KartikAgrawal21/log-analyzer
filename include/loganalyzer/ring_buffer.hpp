#pragma once

#include <cstddef>
#include <stdexcept>
#include <utility>
#include <vector>

namespace loganalyzer {

/// Growable circular buffer used as a FIFO queue / sliding window, written from scratch
/// (no std::deque). Storage is one contiguous array whose capacity is a power of two, so
/// the physical slot of logical index i is (head + i) & mask: no modulo, no per-element
/// allocation, and push_back / pop_front are amortized O(1).
///
/// T must be default-constructible and movable. A moved-from RingBuffer is empty.
template <class T>
class RingBuffer {
public:
    RingBuffer() = default;

    RingBuffer(const RingBuffer&) = default;
    RingBuffer& operator=(const RingBuffer&) = default;

    RingBuffer(RingBuffer&& other) noexcept
        : data_(std::move(other.data_)),
          head_(std::exchange(other.head_, 0)),
          size_(std::exchange(other.size_, 0)) {
        other.data_.clear();
    }

    RingBuffer& operator=(RingBuffer&& other) noexcept {
        if (this != &other) {
            data_ = std::move(other.data_);
            head_ = std::exchange(other.head_, 0);
            size_ = std::exchange(other.size_, 0);
            other.data_.clear();
        }
        return *this;
    }

    std::size_t size() const noexcept { return size_; }
    bool empty() const noexcept { return size_ == 0; }
    std::size_t capacity() const noexcept { return data_.size(); }

    void push_back(T value) {
        if (size_ == data_.size()) grow();
        data_[slot(size_)] = std::move(value);
        ++size_;
    }

    /// Oldest element. Throws std::out_of_range when empty.
    const T& front() const {
        if (empty()) throw std::out_of_range("RingBuffer::front on empty buffer");
        return data_[head_];
    }

    /// Newest element. Throws std::out_of_range when empty.
    const T& back() const {
        if (empty()) throw std::out_of_range("RingBuffer::back on empty buffer");
        return data_[slot(size_ - 1)];
    }

    /// Removes the oldest element. Throws std::out_of_range when empty.
    void pop_front() {
        if (empty()) throw std::out_of_range("RingBuffer::pop_front on empty buffer");
        data_[head_] = T();  // don't keep a stale value alive in the vacated slot
        head_ = (head_ + 1) & (data_.size() - 1);
        --size_;
    }

    /// i-th oldest element (0 = front). Throws std::out_of_range if i >= size().
    const T& at(std::size_t i) const {
        if (i >= size_) throw std::out_of_range("RingBuffer::at index out of range");
        return data_[slot(i)];
    }

    void clear() noexcept {
        for (std::size_t i = 0; i < size_; ++i) data_[slot(i)] = T();
        head_ = 0;
        size_ = 0;
    }

private:
    std::size_t slot(std::size_t logical) const noexcept { return (head_ + logical) & (data_.size() - 1); }

    // Doubling keeps capacity a power of two. Elements are re-laid out starting at slot 0.
    void grow() {
        const std::size_t new_capacity = data_.empty() ? kInitialCapacity : data_.size() * 2;
        std::vector<T> bigger(new_capacity);
        for (std::size_t i = 0; i < size_; ++i) bigger[i] = std::move(data_[slot(i)]);
        data_ = std::move(bigger);
        head_ = 0;
    }

    static constexpr std::size_t kInitialCapacity = 8;

    std::vector<T> data_;  // size() is the capacity, always 0 or a power of two
    std::size_t head_ = 0;
    std::size_t size_ = 0;
};

}  // namespace loganalyzer
