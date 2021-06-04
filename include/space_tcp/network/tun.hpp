#ifndef SPACE_TCP_TUN_HPP
#define SPACE_TCP_TUN_HPP

#include "network.hpp"

#include <cstring>
#include <iostream>
#include <utility>

#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <arpa/inet.h>

namespace space_tcp {

/// Config struct for TUN interface.
struct tun_config {
    const std::string &dev_name{};
    const std::string &source_addr{"10.0.6.1"};
    const std::string &dest_addr{"10.0.7.1"};
};

/// IPv4 + Linux TUN interface which implements the NetworkInterface.
class TunInterface : public NetworkInterface {
public:
    // buffer should have the (maximum) size of one S3TP packet + header of the network protocol
    static auto create(uint8_t *buffer, size_t len, const tun_config &config = {}) -> TunInterface;

    auto receive(uint8_t *buffer, size_t len, ssize_t timeout) -> ssize_t override;

    auto send(const uint8_t *buffer, size_t len, ssize_t timeout) -> ssize_t override;

private:
    TunInterface(std::string name, int fd, uint8_t *const buffer, size_t len, uint32_t source_addr, uint32_t dest_addr)
            : name{std::move(name)},
              fd{fd},
              tun_buffer{buffer},
              buffer_len{len},
              src_addr{source_addr},
              dst_addr{dest_addr} {};

    // TUN device
    const std::string name;
    const int fd;

    // transmit/receive buffer
    uint8_t *const tun_buffer;
    const size_t buffer_len;

    // configuration
    uint32_t src_addr;
    uint32_t dst_addr;

    // IPv4 identification number
    uint16_t identification{0x1337};
};

}  // namespace space_tcp

#endif //SPACE_TCP_TUN_HPP
