#ifndef SPACE_TCP_RING_HPP
#define SPACE_TCP_RING_HPP

#include <cstdint>

namespace space_tcp {

/// Class with functions to generate random numbers. FIXME
class RingBuffer {
public:
    /// Creates a new ring buffer.
    static auto create(uint8_t *buffer, size_t len) -> RingBuffer {
        return {buffer, len};
    }

    [[nodiscard]] auto free_space() const -> size_t {
        return (tail == head && !full) ? len : (tail - head) % len;
    }

    [[nodiscard]] auto used_space() const -> size_t {
        return len - free_space();
    }

    auto push_back(const uint8_t *data, size_t len, size_t offset = 0) -> ssize_t {
        if (!data || free_space() == 0) {
            // amount of data or offset exceeds free space for producer or nullptr
            return -1;
        }

        if (len + offset > free_space()) {
            len = free_space() - offset;
        }

        // ring buffer location to put data
        auto cur_head = (head + offset) % this->len;

        // copy data to into ring buffer
        for (auto i = 0; i < len; i++) {
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

    auto pop_front(uint8_t *data, size_t len) -> ssize_t {
        if (len > used_space()) {
            len = used_space();
        }

        if (data) {
            for (auto i = 0; i < len; i++) {
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

    auto advance_head(size_t bytes) -> bool {
        if (bytes > free_space()) {
            return false;
        }

        head = (head + bytes) % len;

        return true;
    }

    // FIXME(hal): DELETE
    auto data(size_t offset = 0) -> const uint8_t * {
        auto index = (tail + offset) % len;
        return (buffer + index);
    }

    [[nodiscard]] auto get_buffer() const -> uint8_t * {
        return buffer;
    }

    [[nodiscard]] auto get_len() const -> size_t {
        return len;
    }

    /// Generate a random number in range [from, to].
    //static auto generate_random_number(uint16_t from, uint16_t to) -> uint16_t;

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
