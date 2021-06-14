#ifndef SPACE_TCP_CONNECTION_MANAGER_HPP
#define SPACE_TCP_CONNECTION_MANAGER_HPP

namespace space_tcp {

/// Interface for a connection storage.
class ConnectionManager {
public:
    virtual ~ConnectionManager() = default;

    /// Returns the number of stored connections.
    virtual auto stored_connections() -> size_t = 0;

    /// Returns the specified connection.
    virtual auto get_connection(size_t i) -> Connection * = 0;

    /// Returns a pointer to a connection depending on source and destination
    /// port. Returns `nullptr` if no such connection exists.
    virtual auto find_connection(uint16_t src_port, uint16_t dst_port) -> Connection * = 0;

    /// Creates a connection in the connection storage.
    virtual auto create_connection(uint8_t *buffer, size_t len, uint8_t rx_port, uint8_t tx_port, TcpEndpoint &endpoint) -> Connection * = 0;
};

/// Concrete implementation of connection storage. Stores `S` connections in its memory.
template<typename std::size_t S>
class alignas(Connection) Connections : public ConnectionManager {
public:
    ~Connections() override {
        for (size_t i = 0; i < num_connections; i++) {
            (reinterpret_cast<Connection *>(connections) + i)->~Connection();
        }
    }

    auto stored_connections() -> size_t override {
        return num_connections;
    }

    auto get_connection(size_t i) -> Connection * override {
        if (num_connections <= i) {
            error("cannot access connection " << i + 1 << " out of " << num_connections << " connections");
        }

        return reinterpret_cast<Connection *>(connections) + i;
    }

    auto find_connection(uint16_t src_port, uint16_t dst_port) -> Connection * override {
        for (size_t i = 0; i < num_connections; i++) {
            auto connection = get_connection(i);

            if (connection->src_port == src_port && connection->dst_port == dst_port) {
                return connection;
            }
        }

        return nullptr;
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
