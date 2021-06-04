#include <gtest/gtest.h>

#include <space_tcp/space_tcp.hpp>
#include "space_tcp/endpoint.hpp"

class TestNetwork : public space_tcp::NetworkInterface {
public:
    auto receive(uint8_t *buffer, size_t len, ssize_t timeout) -> ssize_t override {
        len = (len > data) ? data : len;

        if (len == 0) {
            return -1;
        }

        for (int i = 0; i < len; i++) {
            buffer[i] = this->buffer[i];
        }

        return len;
    }

    auto send(const uint8_t *buffer, size_t len, ssize_t timeout) -> ssize_t override {
        for (int i = 0; i < len; i++) {
            this->buffer[i] = buffer[i];
        }

        data = len;

        return data;
    }

private:
    uint8_t buffer[1 << 12]{};
    size_t data{};
};

class TcpEndpointTest : public ::testing::Test {
public:
    TcpEndpointTest() {
        auto endpoint_obj_a = space_tcp::TcpEndpoint::create(space_tcp_buffer_a, sizeof(space_tcp_buffer_a), connections_a,
                                                           network);

        auto endpoint_mem_a = malloc(sizeof(space_tcp::TcpEndpoint));
        memcpy(endpoint_mem_a, &endpoint_obj_a, sizeof(space_tcp::TcpEndpoint));

        endpoint_a = static_cast<space_tcp::TcpEndpoint *>(endpoint_mem_a);

        connection_a = space_tcp::create_connection(connection_buffer_a, 13, 17, *endpoint_a);

        auto endpoint_obj_b = space_tcp::TcpEndpoint::create(space_tcp_buffer_b, sizeof(space_tcp_buffer_b), connections_b,
                                                           network);

        auto endpoint_mem_b = malloc(sizeof(space_tcp::TcpEndpoint));
        memcpy(endpoint_mem_b, &endpoint_obj_b, sizeof(space_tcp::TcpEndpoint));

        endpoint_b = static_cast<space_tcp::TcpEndpoint *>(endpoint_mem_b);

        connection_b = space_tcp::create_connection(connection_buffer_b, 17, 13, *endpoint_b);
    };

protected:
    uint8_t space_tcp_buffer_a[1 << 12]{};
    uint8_t connection_buffer_a[1 << 12]{};
    space_tcp::Connections<1> connections_a;
    TestNetwork network{};
    space_tcp::TcpEndpoint *endpoint_a;
    space_tcp::Connection *connection_a;

    uint8_t space_tcp_buffer_b[1 << 12]{};
    uint8_t connection_buffer_b[1 << 12]{};
    space_tcp::Connections<1> connections_b;
    space_tcp::TcpEndpoint *endpoint_b;
    space_tcp::Connection *connection_b;
};

TEST_F(TcpEndpointTest, ConnectionTest) {
    uint8_t data[] = "hallo";

    connection_b->listen();
    connection_a->send(data);

    EXPECT_EQ(space_tcp::State::Closed, connection_a->get_state());
    endpoint_a->tx();
    EXPECT_EQ(space_tcp::State::SynSent, connection_a->get_state());

    EXPECT_EQ(space_tcp::State::Listen, connection_b->get_state());
    endpoint_b->rx();
    EXPECT_EQ(space_tcp::State::SynReceived, connection_b->get_state());

    endpoint_a->rx();
    EXPECT_EQ(space_tcp::State::Established, connection_a->get_state());

    endpoint_b->rx();
    EXPECT_EQ(space_tcp::State::Established, connection_b->get_state());
}