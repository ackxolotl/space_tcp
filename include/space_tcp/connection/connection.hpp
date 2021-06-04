#ifndef SPACE_TCP_CONNECTION_HPP
#define SPACE_TCP_CONNECTION_HPP

#include "space_tcp/log.hpp"
#include "space_tcp/rand.hpp"
#include "space_tcp/time.hpp"
#include "space_tcp/ring.hpp"
#include "space_tcp/segment.hpp"

#include <unistd.h>

#define WINDOWSIZE 32
#define RETRANSMISSION_TIMEOUT 1000


namespace space_tcp {

class TcpEndpoint;

/// Connection states.
enum class State {
    /// Uninitialized connection.
    Closed,
    /// Listening connection.
    Listen,
    /// Open connection request from this host.
    SynSent,
    /// Half-open connection waiting for ACK from remote host.
    SynReceived,
    /// Established connection.
    Established,
    /// Closed connection on this host.
    Closing,
    FinWait,
    /// Closing was acknowledged by remote host.
    TimeWait,
    /// Remote host closed the connection.
    CloseWait,
    /// Connection closed after remote host closed it already.
    LastAck,
};

/// A S3TP connection.
class Connection {
    template<typename std::size_t S>
    friend
    class Connections;

    friend class TcpEndpoint;

public:
    ~Connection() = default;

    /// Receive method of connection. Copies previously received data from the
    /// connection receive buffer to `buffer`.
    template<typename std::size_t T>
    auto receive(uint8_t (&buffer)[T], size_t len = 0, ssize_t timeout = -1) -> ssize_t {
        if (len > T) {
            warn("requested receive size exceeds buffer size");
            len = T;
        }

        auto available_data = receive_buffer.used_space();

        len = (len) ? len : T;
        len = (len < available_data) ? len : available_data;

        return receive_buffer.pop_front(buffer, len);
    }

    /// Send method of connection. Copies data to be sent to the connection
    /// transmit buffer.
    template<typename std::size_t T>
    auto send(const uint8_t (&buffer)[T], size_t len = 0) -> ssize_t {
        if (len > T) {
            warn("requested transmit size exceeds buffer size");
            len = T;
        }

        len = (len) ? len : T;

        return transmit_buffer.push_back(buffer, len);
    }

    /// Sets the state of the connection to `Listen` such that incoming data is
    /// stored in the receive buffer of the connection.
    auto listen() {
        state = State::Listen;
    }

    /// Sets the state of the connection to `FinWait` such that the connection
    /// will be closed by the endpoint.
    auto close() {
        state = State::Closing;
    }

    /// Returns the state of the connection.
    auto get_state() -> State {
        return state;
    }

    [[nodiscard]] auto transmitted_data() const -> size_t {
        return sent_bytes;
    }

    [[nodiscard]] auto received_data() const -> size_t {
        return received_bytes;
    }

    auto tx_queue_empty() -> bool {
        return transmit_buffer.empty();
    }

private:
    Connection(uint8_t *buffer, size_t len, uint16_t src_port, uint16_t dst_port, TcpEndpoint &endpoint) : src_port{src_port}, dst_port{dst_port}, endpoint{endpoint} {
        if (len < 512 * 4) {
            error("connection buffer size must be at least 4 S3TP packet payload size, i.e., 2048 B");
        }

        receive_buffer = RingBuffer::create(buffer, len/2);
        transmit_buffer = RingBuffer::create(buffer + len/2, len/2);

        auto tx = Rng::generate_random_number(0, 0xffff);
        tx_next_seq_num = tx;
        tx_initial_seq_num = tx;
        tx_unacked = tx;
    };

    /// Returns whether the TX timer for this connection has expired, i.e.,
    /// data has to be re-sent.
    [[nodiscard]] auto tx_timer_expired(size_t time) const -> bool {
        return (tx_unacked != tx_next_seq_num) && (tx_last_time + RETRANSMISSION_TIMEOUT) < time;
    }

    /// Returns the amount of data that has not been acknowledged yet.
    [[nodiscard]] auto tx_data_in_flight() const -> size_t {
        auto syn_fin = (state == State::SynSent || state == State::FinWait);
        return tx_next_seq_num - tx_unacked - syn_fin;
    }

    /// Returns whether the connection shall be closed.
    [[nodiscard]] auto to_be_closed() -> bool {
        return state == State::Closing;
    }

    /// Returns whether the TX buffer contains unsent data.
    auto tx_data_to_send() -> bool {
        return tx_data_in_flight() < transmit_buffer.used_space();
    }

    // connection properties
    uint16_t src_port;
    uint16_t dst_port;

    // connection state
    State state{State::Closed};

    RingBuffer receive_buffer = RingBuffer::create(nullptr, 0);
    RingBuffer transmit_buffer = RingBuffer::create(nullptr, 0);

    // TX connection information
    uint16_t tx_next_seq_num;
    uint16_t tx_initial_seq_num;
    uint16_t tx_unacked;                // oldest unacknowledged sequence number of transmitted packets
    uint64_t tx_last_time{};
    size_t sent_bytes{};                // unacknowledged data ?

    // RX connection information
    uint16_t rx_next_seq_num{};         // next expected sequence number for incoming packets
    uint16_t rx_initial_seq_num{};
    uint16_t rx_acked{};                // actually acknowledged sequence number
    uint64_t rx_last_time{};
    uint16_t received_bytes{};

    // out of order received segments
    Segments<WINDOWSIZE - 1> ooo_segments;

    TcpEndpoint &endpoint;
};

}  // namespace space_tcp

#endif //SPACE_TCP_CONNECTION_HPP
