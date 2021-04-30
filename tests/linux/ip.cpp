#include <gtest/gtest.h>

#include "protocol/ipv4.hpp"

class Ipv4Test : public ::testing::Test {
public:
    Ipv4Test() : packet_1{space_tcp::Ipv4Packet::create_unchecked(packet_1_data, sizeof(packet_1_data))},
                 packet_2{space_tcp::Ipv4Packet::create_unchecked(packet_2_data, sizeof(packet_2_data))} {}

protected:
    space_tcp::Ipv4Packet packet_1;
    space_tcp::Ipv4Packet packet_2;

    uint8_t packet_1_data[195] = {
            0x45, 0x00, 0x00, 0xc3, 0x72, 0xdb, 0x40, 0x00,
            0x01, 0x11, 0xff, 0x53, 0x0a, 0x00, 0x0d, 0x01,
            0xef, 0xff, 0xff, 0xfa, 0xe8, 0x9d, 0x07, 0x6c,
            0x00, 0xaf, 0xe3, 0x5f, 0x4d, 0x2d, 0x53, 0x45,
            0x41, 0x52, 0x43, 0x48, 0x20, 0x2a, 0x20, 0x48,
            0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x0d,
            0x0a, 0x48, 0x4f, 0x53, 0x54, 0x3a, 0x20, 0x32,
            0x33, 0x39, 0x2e, 0x32, 0x35, 0x35, 0x2e, 0x32,
            0x35, 0x35, 0x2e, 0x32, 0x35, 0x30, 0x3a, 0x31,
            0x39, 0x30, 0x30, 0x0d, 0x0a, 0x4d, 0x41, 0x4e,
            0x3a, 0x20, 0x22, 0x73, 0x73, 0x64, 0x70, 0x3a,
            0x64, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72,
            0x22, 0x0d, 0x0a, 0x4d, 0x58, 0x3a, 0x20, 0x31,
            0x0d, 0x0a, 0x53, 0x54, 0x3a, 0x20, 0x75, 0x72,
            0x6e, 0x3a, 0x64, 0x69, 0x61, 0x6c, 0x2d, 0x6d,
            0x75, 0x6c, 0x74, 0x69, 0x73, 0x63, 0x72, 0x65,
            0x65, 0x6e, 0x2d, 0x6f, 0x72, 0x67, 0x3a, 0x73,
            0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x3a, 0x64,
            0x69, 0x61, 0x6c, 0x3a, 0x31, 0x0d, 0x0a, 0x55,
            0x53, 0x45, 0x52, 0x2d, 0x41, 0x47, 0x45, 0x4e,
            0x54, 0x3a, 0x20, 0x43, 0x68, 0x72, 0x6f, 0x6d,
            0x69, 0x75, 0x6d, 0x2f, 0x38, 0x39, 0x2e, 0x30,
            0x2e, 0x34, 0x33, 0x38, 0x39, 0x2e, 0x31, 0x32,
            0x38, 0x20, 0x4c, 0x69, 0x6e, 0x75, 0x78, 0x0d,
            0x0a, 0x0d, 0x0a
    };

    uint8_t packet_2_data[68] = {
            0x45, 0x00, 0x00, 0x44, 0x38, 0xab, 0x40, 0x00,
            0x01, 0x11, 0x49, 0x02, 0x0a, 0x00, 0x0d, 0x01,
            0xe0, 0x00, 0x00, 0xfb, 0x14, 0xe9, 0x14, 0xe9,
            0x00, 0x30, 0x93, 0xa7, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x0b, 0x5f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
            0x63, 0x61, 0x73, 0x74, 0x04, 0x5f, 0x74, 0x63,
            0x70, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00,
            0x00, 0x0c, 0x00, 0x01
    };
};

TEST_F(Ipv4Test, Version) {
    EXPECT_EQ(4, packet_1.version());
}

TEST_F(Ipv4Test, IHL) {
    EXPECT_EQ(5, packet_1.ihl());
}

TEST_F(Ipv4Test, DSCP) {
    EXPECT_EQ(0, packet_1.dscp());
}

TEST_F(Ipv4Test, ECN) {
    EXPECT_EQ(0, packet_1.ecn());
}

TEST_F(Ipv4Test, TotalLength) {
    EXPECT_EQ(195, packet_1.length());
}

TEST_F(Ipv4Test, Identification) {
    EXPECT_EQ(0x72db, packet_1.identification());
}

TEST_F(Ipv4Test, Flags) {
    EXPECT_EQ(0x02, packet_1.flags());
    EXPECT_EQ(0x02, packet_2.flags());
}

TEST_F(Ipv4Test, FragmentOffset) {
    EXPECT_EQ(0, packet_1.fragment_offset());
}

TEST_F(Ipv4Test, TTL) {
    EXPECT_EQ(0x01, packet_1.ttl());
}

TEST_F(Ipv4Test, Protocol) {
    EXPECT_EQ(0x11, packet_1.protocol());
}

TEST_F(Ipv4Test, Checksum) {
    EXPECT_EQ(0xff53, packet_1.checksum());
    EXPECT_EQ(0x4902, packet_2.checksum());
}

TEST_F(Ipv4Test, SourceIP) {
    EXPECT_EQ(0xa000d01, packet_1.src_ip());
}

TEST_F(Ipv4Test, DestinationIP) {
    EXPECT_EQ(0xeffffffa, packet_1.dst_ip());
}

TEST_F(Ipv4Test, Payload) {
    for (int i = 20; i < packet_1.length(); i++) {
        ASSERT_EQ(packet_1_data[i], packet_1.payload()[i - 20]);
    }
}

TEST_F(Ipv4Test, SetFlags) {
    packet_1.set_flags(0x0);
    EXPECT_EQ(0x0, packet_1.flags());

    packet_1.set_flags(0x3);
    EXPECT_EQ(0x3, packet_1.flags());
}

TEST_F(Ipv4Test, SetSourceIp) {
    packet_1.set_src_ip(0x12345678);
    EXPECT_EQ(0x12345678, packet_1.src_ip());

    packet_1.set_src_ip(0x0);
    EXPECT_EQ(0x0, packet_1.src_ip());
}

TEST_F(Ipv4Test, SetDestinationIp) {
    packet_1.set_dst_ip(0x12345678);
    EXPECT_EQ(0x12345678, packet_1.dst_ip());

    packet_1.set_dst_ip(0x0);
    EXPECT_EQ(0x0, packet_1.dst_ip());
}

TEST_F(Ipv4Test, GetAndSetFlags) {
    auto flags = packet_1.flags();
    packet_1.set_flags(flags);
    EXPECT_EQ(flags, packet_1.flags());
}

TEST_F(Ipv4Test, GetAndSetSourceIP) {
    auto ip = packet_1.src_ip();
    packet_1.set_src_ip(ip);
    EXPECT_EQ(ip, packet_1.src_ip());
}

TEST_F(Ipv4Test, GetAndSetDestinationIP) {
    auto ip = packet_1.dst_ip();
    packet_1.set_dst_ip(ip);
    EXPECT_EQ(ip, packet_1.dst_ip());
}

TEST_F(Ipv4Test, GetAndSetChecksum) {
    auto checksum = packet_1.checksum();
    packet_1.set_checksum(checksum);
    EXPECT_EQ(checksum, packet_1.checksum());
}

TEST_F(Ipv4Test, UpdateChecksum) {
    auto checksum = packet_1.checksum();
    packet_1.update_checksum();
    EXPECT_EQ(checksum, packet_1.checksum());

    checksum = packet_2.checksum();
    packet_2.update_checksum();
    EXPECT_EQ(checksum, packet_2.checksum());
}