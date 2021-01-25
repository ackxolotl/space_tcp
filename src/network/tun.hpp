#ifndef SPACE_TCP_TUN_HPP
#define SPACE_TCP_TUN_HPP

#include <cstring>
#include <iostream>
#include <utility>

#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "network.hpp"
#include "protocol/ip.hpp"

namespace space_tcp {

class TunInterface : public NetworkInterface {
public:
    // buffer should have the (maximum) size of one S3TP packet + header of the network protocol
    static auto create(uint8_t *buffer, size_t len, const std::string &dev_name = {}) -> TunInterface {
        struct ifreq ifr{};
        int fd;

        // open the clone device
        if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
            std::cerr << "failed to open /dev/net/tun" << std::endl;
            exit(-1);
        }

        // we want a tun device and no protocol information
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

        // request a specific name for our tun device
        if (!dev_name.empty()) {
            strncpy(ifr.ifr_name, dev_name.c_str(), IFNAMSIZ);
        }

        // try to create the device
        if (ioctl(fd, TUNSETIFF, reinterpret_cast<void *>(&ifr)) < 0) {
            close(fd);
            std::cerr << "failed to ioctl(" << fd << ", TUNSETIFF, &ifr)" << std::endl;
            exit(-1);
        }

        return {ifr.ifr_name, fd, buffer, len};
    }

    auto receive(uint8_t *buffer, size_t len, size_t timeout) -> ssize_t override {
        if (fd < 0) {
            std::cerr << "file descriptor invalid" << std::endl;
            exit(1);
        }

        // buffer should be at least the MTU size of the interface, eg 1500 bytes
        auto bytes = read(fd, tun_buffer, len);
        if (bytes < 0) {
            std::cerr << "could not read from tun interface" << std::endl;
            close(fd);
            exit(1);
        }

        std::cout << "read " << std::dec << bytes << " bytes from device " << name << std::endl;

        auto ipv4_packet = Ipv4::create_unchecked(tun_buffer, bytes);

        if (!ipv4_packet.is_valid_packet()) {
            std::cout << "no valid IPv4 packet received" << std::endl;
        } else {
            std::cout << "IPv4 packet with total length " << ipv4_packet.length() << " received" << std::endl;
        }

        // copy data to buffer and return number of received bytes

        return -1;
    }

    auto send(const uint8_t *buffer, size_t len, size_t timeout) -> ssize_t override {
        // write header of Network protocol into tun_buffer

        // append data from buffer with size len to header

        // send out whole tun_buffer
        return -1;
    }

private:
    TunInterface(std::string name, int fd, uint8_t *const buffer, size_t len) : name{std::move(name)}, fd{fd},
                                                                                tun_buffer{buffer}, buffer_len{len} {};

    const std::string name;
    const int fd;
    uint8_t *const tun_buffer;
    const size_t buffer_len;
};

} // namespace space_tcp

#endif //SPACE_TCP_TUN_HPP
