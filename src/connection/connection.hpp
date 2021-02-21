#ifndef SPACE_TCP_CONNECTION_HPP
#define SPACE_TCP_CONNECTION_HPP

#include <new>

#define DEFAULT_TIMEOUT 1000

namespace space_tcp {

class TcpEndpoint;

template<typename std::size_t S>
class Connections;

class Connection {
    template<typename std::size_t S>
    friend class Connections;

public:
    ~Connection() {
        std::cout << "connection destructed" << std::endl;
    }

    // buffer should have the (maximum) size of one S3TP packet
    /*
    static auto
    create(uint8_t *buffer, size_t len, uint8_t rx_port, uint8_t tx_port, TcpEndpoint &endpoint) -> Connection {
        // TODO: register new connection at S3TP endpoint, i.e. add reference to ourselves (if possible ?!)

        return Connection(buffer, len, rx_port, tx_port, endpoint);
    }
    */

    template<typename std::size_t T>
    auto receive(uint8_t (&buffer)[T], size_t len = 0, size_t timeout = DEFAULT_TIMEOUT) -> ssize_t {
        std::cout << "tcp connection receive" << std::endl;

        // receive some data from S3TP endpoint
        if (endpoint.receive() == -1) {
            // could not receive data
            return -1;
        }

        // parse and store received data appropriately in receive window, send reply if needed

        // return amount of received data

        return 1;
    }

    template<typename std::size_t T>
    auto send(const uint8_t (&buffer)[T], size_t len = 0, size_t timeout = DEFAULT_TIMEOUT) -> ssize_t {
        return sizeof(buffer) + len + timeout;
    }

private:
    Connection(uint8_t *buffer, size_t len, uint8_t rx_port, uint8_t tx_port, TcpEndpoint &endpoint) : con_buffer{
            buffer}, buffer_len{len}, rx_port{rx_port}, tx_port{tx_port}, endpoint{endpoint} {
        std::cout << "connection created" << std::endl;
    };

    uint8_t *con_buffer{};
    size_t buffer_len;
    uint8_t rx_port{};
    uint8_t tx_port{};

    // some enum for connection state etc.
    // information about receive window, which segments are missing, etc.

    TcpEndpoint &endpoint;
};

} // namespace space_tcp

#endif //SPACE_TCP_CONNECTION_HPP
