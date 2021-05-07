#ifndef SPACE_TCP_CONNECTION_HPP
#define SPACE_TCP_CONNECTION_HPP

#include "space_tcp/log.hpp"

#define DEFAULT_TIMEOUT 1000

namespace space_tcp {

class TcpEndpoint;

template<typename std::size_t S>
class Connections;

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
    FinWait,
    Closing,
    /// Closing was acknowledged by remote host.
    TimeWait,
    /// Remote host closed the connection.
    CloseWait,
    /// Connection closed after remote host closed it already.
    LastAck,
};

/// A connection.
class Connection {
    template<typename std::size_t S>
    friend class Connections;
    friend class TcpEndpoint;

public:
    ~Connection() {
        debug("connection destructed");
    }

    // buffer should have the (maximum) size of one S3TP packet
    /*
    static auto
    create(uint8_t *buffer, size_t len, uint8_t src_port, uint8_t dst_port, TcpEndpoint &endpoint) -> Connection {
        // TODO: register new connection at S3TP endpoint, i.e. add reference to ourselves (if possible ?!)

        return Connection(buffer, len, src_port, dst_port, endpoint);
    }
    */

    /// Receive method of connection. Calls receive on the endpoint.
    template<typename std::size_t T>
    auto receive(uint8_t (&buffer)[T], size_t len = 0, size_t timeout = DEFAULT_TIMEOUT) -> ssize_t {
        // repeatedly call receive on endpoint until timeout
        auto data = endpoint.receive(this);

        if (data == -1) {
            // did not receive any data
            return -1;
        }

        len = (len == 0) ? T : len;
        len = (len < T) ? len : T;
        data = (len < data) ? len : data;

        for (auto i = 0; i < data; i++) {
            buffer[i] = con_buffer[i];
        }

        return len;
    }

    /// Send method of connection. Calls send on the endpoint.
    template<typename std::size_t T>
    auto send(const uint8_t (&buffer)[T], size_t len = 0, size_t timeout = DEFAULT_TIMEOUT) -> ssize_t {
        if (len > T) {
            warn("requested transmit size exceeds buffer size");
            len = T;
        }

        len = (len) ? len : T;

        return endpoint.send(this, buffer, len, timeout);
    }

private:
    Connection(uint8_t *buffer, size_t len, uint8_t src_port, uint8_t dst_port, TcpEndpoint &endpoint) : con_buffer{
            buffer}, buffer_len{len}, src_port{src_port}, dst_port{dst_port}, endpoint{endpoint} {};

    uint8_t *con_buffer;
    size_t buffer_len;

    // connection properties
    uint8_t src_port;
    uint8_t dst_port;

    uint16_t seq_num{0x1337}; // TODO(hal): guess we need multiple seq numbers, one for sending and one for receiving

    size_t received_data{};

    // some enum for connection state etc.
    // information about receive window, which segments are missing, etc.
    State state; // TODO(hal): guess we need two states, one for sending and one for receiving?

    TcpEndpoint &endpoint;
};

}  // namespace space_tcp

#endif //SPACE_TCP_CONNECTION_HPP
