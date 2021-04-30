////////////////////////////////////////////////////////////
/// \mainpage
///
/// \section welcome Welcome
/// Welcome to the official S3TP documentation. Here you will find a detailed
/// view of all the S3TP classes and functions. <br/>
///
/// \section example Short example
/// Here is a short example, to show you how simple it is to use S3TP:
///
/// \code
///
/// #include "space_tcp/space_tcp.hpp"
///
/// // memory for TUN interface and space TCP endpoint for internal operations
/// uint8_t tun_buffer[1u << 11u];
/// uint8_t tcp_buffer[1u << 11u];
///
/// // memory for receive/transmit window of connections
/// uint8_t connection_buffer[1u << 12u];
///
/// // connections managed by space TCP endpoint
/// space_tcp::Connections<1> connections;
///
/// auto main() -> int {
///     auto tun_config = space_tcp::tun_config{
///             .dev_name = "tun1",
///             .source_addr = "10.9.8.7",
///             .dest_addr = "10.1.2.3"
///     };
///
///     // create TUN interface and space TCP endpoint
///     auto tun_interface = space_tcp::create_tun_interface(tun_buffer, tun_config);
///     auto tcp_endpoint = space_tcp::create_tcp_endpoint(tcp_buffer, tun_interface, connections);
///
///     // create a connection
///     auto connection = space_tcp::create_connection(connection_buffer, 117, 105, tcp_endpoint);
///
///     uint8_t message_1[] = "some message";
///     uint8_t message_2[] = "another message";
///     uint8_t message_3[] = "yet another message";
///
///     for (auto i = 0; i < 120; i++) {
///         // transmit messages
///         connection->send(message_1);
///         sleep(1);
///
///         connection->send(message_2);
///         sleep(1);
///
///         // send third buffer only partially
///         connection->send(message_3, 3);
///         sleep(1);
///     }
///
///     return 0;
/// }
///
/// \endcode
////////////////////////////////////////////////////////////
