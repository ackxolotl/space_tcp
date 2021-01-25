#ifndef SPACE_TCP_CONNECTION_HPP
#define SPACE_TCP_CONNECTION_HPP

#include <new>

#define DEFAULT_TIMEOUT 1000

namespace space_tcp {

class TcpEndpoint;

class Connection {
public:
    Connection(uint8_t *buffer, size_t len, uint8_t rx_port, uint8_t tx_port, TcpEndpoint &endpoint) : con_buffer{
            buffer}, buffer_len{len}, rx_port{rx_port}, tx_port{tx_port}, endpoint{endpoint} {
        std::cout << "connection created" << std::endl;
    };

    ~Connection() {
        std::cout << "connection destructed" << std::endl;
    }

    // buffer should have the (maximum) size of one S3TP packet
    static auto
    create(uint8_t *buffer, size_t len, uint8_t rx_port, uint8_t tx_port, TcpEndpoint &endpoint) -> Connection {
        // TODO: register new connection at S3TP endpoint, i.e. add reference to ourselves (if possible ?!)

        return Connection(buffer, len, rx_port, tx_port, endpoint);
    }

    template<typename std::size_t T>
    auto receive(uint8_t (&buffer)[T], size_t len = 0, size_t timeout = DEFAULT_TIMEOUT) -> ssize_t {
        std::cout << "tcp connection receive" << std::endl;

        // receive some data from S3TP endpoint
        if (endpoint.receive(con_buffer, 5, timeout / 10) == -1) {
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

    auto say_something() {
        std::cout << "hello: " << buffer_len << std::endl;
    }

private:
    uint8_t *con_buffer{};
    size_t buffer_len;
    uint8_t rx_port{};
    uint8_t tx_port{};

    // some enum for connection state etc.
    // information about receive window, which segments are missing, etc.

    TcpEndpoint &endpoint;
};

class ConnectionManager {
public:
    virtual auto get_connection(size_t i) -> Connection * = 0;

    virtual auto create_connection(uint8_t *buffer, size_t len, uint8_t rx_port, uint8_t tx_port,
                                   TcpEndpoint &endpoint) -> Connection * = 0;
};

template<typename std::size_t S>
class alignas(Connection) Connections : public ConnectionManager {
public:
    Connections() = default;

    ~Connections() {
        for (size_t i = 0; i < num_connections; i++) {
            (reinterpret_cast<Connection *>(connections) + i)->~Connection();
        }
    }

    auto get_connection(size_t i) -> Connection * override {
        if (num_connections <= i) {
            return nullptr;
        }

        return reinterpret_cast<Connection *>(connections) + i;
    }

    auto create_connection(uint8_t *buffer, size_t len, uint8_t rx_port, uint8_t tx_port,
                           TcpEndpoint &endpoint) -> Connection * override {
        if (num_connections >= S) {
            return nullptr;
        }

        return new(reinterpret_cast<Connection *>(connections) + num_connections++) Connection(buffer, len, rx_port,
                                                                                               tx_port, endpoint);
    }

private:
    uint8_t connections[S * sizeof(Connection)]{};
    size_t num_connections{};
};

} // namespace space_tcp

#endif //SPACE_TCP_CONNECTION_HPP
