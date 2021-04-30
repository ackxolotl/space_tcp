#ifndef SPACE_TCP_CONNECTION_MANAGER_HPP
#define SPACE_TCP_CONNECTION_MANAGER_HPP

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
            error("cannot access connection " << i + 1 << " out of " << num_connections << " connections");
        }

        return reinterpret_cast<Connection *>(connections) + i;
    }

    auto create_connection(uint8_t *buffer, size_t len, uint8_t rx_port, uint8_t tx_port,
                           TcpEndpoint &endpoint) -> Connection * override {
        if (num_connections >= S) {
            error("cannot create new connection: maximum number of specified connections was already created");
        }

        return new(reinterpret_cast<Connection *>(connections) + num_connections++) Connection(buffer, len, rx_port,
                                                                                               tx_port, endpoint);
    }

private:
    uint8_t connections[S * sizeof(Connection)]{};
    size_t num_connections{};
};

}  // namespace space_tcp

#endif //SPACE_TCP_CONNECTION_MANAGER_HPP
