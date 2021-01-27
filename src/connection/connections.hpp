#ifndef SPACE_TCP_CONNECTIONS_HPP
#define SPACE_TCP_CONNECTIONS_HPP

namespace space_tcp {

class ConnectionManager {
public:
    virtual ~ConnectionManager() = default;

    virtual auto get_connection(size_t i) -> Connection * = 0;

    virtual auto create_connection(uint8_t *buffer, size_t len, uint8_t rx_port, uint8_t tx_port,
                                   TcpEndpoint &endpoint) -> Connection * = 0;
};

template<typename std::size_t S>
class alignas(Connection) Connections : public ConnectionManager {
public:
    ~Connections() override {
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

}

#endif //SPACE_TCP_CONNECTIONS_HPP
