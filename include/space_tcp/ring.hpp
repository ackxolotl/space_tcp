#ifndef SPACE_TCP_RING_HPP
#define SPACE_TCP_RING_HPP

#include <cstdint>

namespace space_tcp {

class RingBuffer {
public:
    /// Creates a new ring buffer.
    static auto create(uint8_t *buffer, size_t len) -> RingBuffer {
        return {buffer, len};
    }

    /// Returns the number of free bytes in the buffer.
    [[nodiscard]] auto free_space() const -> size_t {
        return (tail == head && !full) ? len : (tail - head) % len;
    }

    /// Returns the number of used bytes in the buffer.
    [[nodiscard]] auto used_space() const -> size_t {
        return len - free_space();
    }

    /// Returns whether the ring buffer is empty.
    [[nodiscard]] auto empty() const -> bool {
        return free_space() == len;
    }

    /// Pushes data to the ring buffer.
    auto push_back(const uint8_t *data, size_t len, size_t offset = 0) -> ssize_t {
        if (!data || free_space() == 0) {
            // nullptr or no free space
            return -1;
        }

        if (len + offset > free_space()) {
            len = free_space() - offset;
        }

        // ring buffer location to put data
        auto cur_head = (head + offset) % this->len;

        // copy data to into ring buffer
        for (size_t i = 0; i < len; i++) {
            buffer[cur_head] = data[i];
            cur_head = (cur_head + 1) % this->len;
        }

        // update head if data was put into the front
        if (offset == 0) {
            head = cur_head;

            // is the buffer full now?
            if (len > 0 && head == tail) {
                full = true;
            }
        }

        return len;
    }

    /// Pops data from the ring buffer.
    auto pop_front(uint8_t *data, size_t len) -> ssize_t {
        if (len > used_space()) {
            len = used_space();
        }

        if (data) {
            for (size_t i = 0; i < len; i++) {
                data[i] = buffer[tail];
                tail = (tail + 1) % this->len;
            }
        } else {
            tail = (tail + len) % this->len;
        }

        if (full && len > 0) {
            full = false;
        }

        return len;
    }

    /// Advances the head index of the ring buffer.
    auto advance_head(size_t bytes) -> bool {
        if (bytes > free_space()) {
            return false;
        }

        head = (head + bytes) % len;

        return true;
    }

    /// Copies data from the ring buffer to `buffer`.
    auto copy(uint8_t *buffer, size_t len, size_t offset = 0) -> size_t {
        len = (len + offset > used_space()) ? used_space() : len;

        auto index = (tail + offset) % this->len;

        for (size_t i = 0; i < len; i++) {
            buffer[i] = this->buffer[index];
            index = (index + 1) % this->len;
        }

        return len;
    }

private:
    RingBuffer(uint8_t *buffer, size_t len) : buffer{buffer}, len{len} {};

    uint8_t *buffer;
    size_t len;

    size_t head{}; // producer index
    size_t tail{}; // consumer index

    bool full{false};
};

}  // namespace space_tcp

#endif //SPACE_TCP_RING_HPP
