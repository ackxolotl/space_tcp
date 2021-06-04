#include "space_tcp/network/tun.hpp"
#include "space_tcp/log.hpp"
#include "protocol/ipv4.hpp"
#include "space_tcp/space_tcp.hpp"

#include <cstring>

#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <arpa/inet.h>

namespace space_tcp {

// buffer should have the (maximum) size of one S3TP packet + header of the network protocol
auto TunInterface::create(uint8_t *buffer, size_t len, const tun_config &config) -> TunInterface {
    struct in_addr ip_addr{};
    struct ifreq ifr{};
    int fd;

    // get all fields from config struct

    if (!inet_pton(AF_INET, config.source_addr.c_str(), &ip_addr)) {
        error("failed to convert IP address " << config.source_addr);
    }
    // inet_pton returns the address in network byte order -> ntohl
    auto source_addr = ntohl(ip_addr.s_addr);

    if (!inet_pton(AF_INET, config.dest_addr.c_str(), &ip_addr)) {
        error("failed to convert IP address " << config.dest_addr);
    }
    // inet_pton returns the address in network byte order -> ntohl
    auto dest_addr = ntohl(ip_addr.s_addr);

    // open the clone device
    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        error("failed to open /dev/net/tun");
    }

    // we want a tun device and no protocol information
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    // request a specific name for our tun device
    if (!config.dev_name.empty()) {
        strncpy(ifr.ifr_name, config.dev_name.c_str(), IFNAMSIZ);
    }

    // try to create the device
    if (ioctl(fd, TUNSETIFF, reinterpret_cast<void *>(&ifr)) < 0) {
        error("failed to create the tun device");
    }

    return {ifr.ifr_name, fd, buffer, len, source_addr, dest_addr};
}

auto TunInterface::receive(uint8_t *buffer, size_t len, ssize_t timeout) -> ssize_t {
    fd_set input;
    FD_ZERO(&input);
    FD_SET(fd, &input);

    struct timeval to{
            .tv_sec = timeout / 1000,          // milliseconds to seconds
            .tv_usec = timeout % 1000 * 1000   // milliseconds to microseconds
    };

    int n;
    if (timeout == -1) {
        n = select(fd + 1, &input, nullptr, nullptr, nullptr);
    } else {
        n = select(fd + 1, &input, nullptr, nullptr, &to);
    }

    if (n == -1) {
        // this should never happen
        error("error on select");
    } else if (n == 0) {
        // timeout on select
        return -1;
    }

    auto bytes = read(fd, tun_buffer, len);

    if (bytes < 0) {
        error("could not read from TUN interface");
    }

    if (bytes < 20) {
        warn("received less data than minimum IPv4 header size");
        return -1;
    }

    auto packet = Ipv4Packet::create_unchecked(tun_buffer, bytes);

    // valid IPv4 packet?
    if (!packet.is_valid_packet()) {
        return -1;
    }

    // S3TP packet?
    if (packet.protocol() != 0x99) {
        return -1;
    }

    // IPv4 packet from correct peer?
    if (packet.src_ip() != dst_addr) {
        return -1;
    }

    // IPv4 packet for wrong host?
    if (packet.dst_ip() != src_addr) {
        return -1;
    }

    // copy S3TP packet to buffer and return its size
    auto ip_header_size = packet.ihl() * 4;

    for (auto i = ip_header_size; i < bytes; i++) {
        buffer[i - ip_header_size] = tun_buffer[i];
    }

    return bytes - ip_header_size;
}

auto TunInterface::send(const uint8_t *buffer, size_t len, ssize_t timeout) -> ssize_t {
    auto tx_timeout = Time::get_time_in_ms() + timeout;

    if (len < 42) {
        warn("S3TP packet to be transmitted looks truncated");
    }

    // create IPv4 packet in transmit buffer
    auto packet = Ipv4Packet::create_unchecked(tun_buffer, buffer_len);

    // initialize header of IPv4 packet
    packet.initialize(identification++, src_addr, dst_addr);

    // set payload
    packet.set_payload(buffer, len);

    // set IPv4 header checksum
    packet.update_checksum();

    auto sent = -1;

    while (sent < 0) {
        sent = write(fd, tun_buffer, packet.length());

        if (Time::get_time_in_ms() < tx_timeout) {
            break;
        }
    }

    return (sent == packet.length()) ? len : -1;
}

}  // namespace space_tcp
