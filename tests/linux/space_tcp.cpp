#include <gtest/gtest.h>

#include "protocol/space_tcp.hpp"

class S3tpTest : public ::testing::Test {
public:
    S3tpTest() : packet_1{space_tcp::SpaceTcpPacket::create_unchecked(packet_1_data, sizeof(packet_1_data))},
                 packet_2{space_tcp::SpaceTcpPacket::create_unchecked(packet_2_data, sizeof(packet_2_data))} {}

protected:
    space_tcp::SpaceTcpPacket packet_1;
    space_tcp::SpaceTcpPacket packet_2;

    uint8_t packet_1_data[64] = {
            0x11, 0x03, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            0x11, 0x22, 0x00, 0x0a, 0x98, 0x76, 0x54, 0x32,
            0x10, 0x97, 0x86, 0x75, 0x64, 0x53, 0x42, 0x31,
            0x20, 0x96, 0x85, 0x74, 0x63, 0x52, 0x41, 0x30,
            0x95, 0x84, 0x73, 0x62, 0x51, 0x40, 0x94, 0x83,
            0x72, 0x61, 0x50, 0x93, 0xaf, 0xfe, 0xc0, 0xff,
            0xee, 0xc0, 0xff, 0xee, 0xaf, 0xfe
    };

    // FIXME
    uint8_t packet_2_data[80] = {
            0x45, 0x00, 0x00, 0x44, 0x38, 0xab, 0x40, 0x00,
            0x33, 0x44, 0x01, 0x11, 0x49, 0x02, 0x0a, 0x00,
            0x0d, 0x01, 0xe0, 0x00, 0x00, 0xfb, 0x14, 0xe9,
            0x14, 0xe9, 0x00, 0x30, 0x93, 0xa7, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x0b, 0x5f, 0x67, 0x6f, 0x6f, 0x67,
            0x6c, 0x65, 0x63, 0x61, 0x73, 0x74, 0x04, 0x5f,
            0x74, 0x63, 0x70, 0x05, 0x6c, 0x6f, 0x63, 0x61,
            0x6c, 0x00, 0x00, 0x0c, 0x00, 0x01
    };
};

TEST_F(S3tpTest, Version) {
    EXPECT_EQ(0x1, packet_1.version());
}

TEST_F(S3tpTest, MessageType) {
    EXPECT_EQ(0x1, packet_1.msg_type());
}

TEST_F(S3tpTest, Flags) {
    EXPECT_EQ(space_tcp::Flag::Syn | space_tcp::Flag::Ack, packet_1.flags());
}

TEST_F(S3tpTest, SourcePort) {
    EXPECT_EQ(0xaabb, packet_1.src_port());
}

TEST_F(S3tpTest, DestinationPort) {
    EXPECT_EQ(0xccdd, packet_1.dst_port());
}

TEST_F(S3tpTest, SequenceNumber) {
    EXPECT_EQ(0xeeff, packet_1.seq_num());
}

TEST_F(S3tpTest, AcknowledgmentNumber) {
    EXPECT_EQ(0x1122, packet_1.ack_num());
    EXPECT_EQ(0x3344, packet_2.ack_num());
}

TEST_F(S3tpTest, Size) {
    EXPECT_EQ(10, packet_1.size());
    EXPECT_EQ(273, packet_2.size());
}

TEST_F(S3tpTest, Hmac) {
    for (int i = 0; i < 32; i++) {
        ASSERT_EQ(packet_1_data[i + 12], packet_1.hmac()[i]);
    }
}

TEST_F(S3tpTest, Payload) {
    for (int i = 0; i < packet_1.size(); i++) {
        ASSERT_EQ(packet_1_data[i + 44], packet_1.payload()[i]);
    }
}

TEST_F(S3tpTest, SetVersion) {
    packet_1.set_version(0xb);
    EXPECT_EQ(0xb, packet_1.version());
}

TEST_F(S3tpTest, SetMessageType) {
    packet_1.set_msg_type(0x7);
    EXPECT_EQ(0x7, packet_1.msg_type());
}

TEST_F(S3tpTest, SetFlagsBinary) {
    packet_1.set_flags(space_tcp::Flag::NoFlags);
    EXPECT_EQ(space_tcp::Flag::NoFlags, packet_1.flags());

    packet_1.set_flags(space_tcp::Flag::Rst | space_tcp::Flag::Fin);
    EXPECT_EQ(space_tcp::Flag::Rst | space_tcp::Flag::Fin, packet_1.flags());
}

TEST_F(S3tpTest, SetFlagsEnum) {
    packet_1.set_flags(space_tcp::Flag::Syn);
    EXPECT_EQ(0x1, static_cast<uint8_t>(packet_1.flags()));

    packet_1.set_flags(space_tcp::Flag::Ack);
    EXPECT_EQ(0x2, static_cast<uint8_t>(packet_1.flags()));

    packet_1.set_flags(space_tcp::Flag::Rst);
    EXPECT_EQ(0x4, static_cast<uint8_t>(packet_1.flags()));

    packet_1.set_flags(space_tcp::Flag::Fin);
    EXPECT_EQ(0x8, static_cast<uint8_t>(packet_1.flags()));
}

TEST_F(S3tpTest, SetSourcePort) {
    packet_1.set_src_port(0x4321);
    EXPECT_EQ(0x4321, packet_1.src_port());
}

TEST_F(S3tpTest, SetDestinationPort) {
    packet_1.set_dst_port(0x7654);
    EXPECT_EQ(0x7654, packet_1.dst_port());
}

TEST_F(S3tpTest, SetSequenceNumber) {
    packet_1.set_seq_num(0x5432);
    EXPECT_EQ(0x5432, packet_1.seq_num());
}

TEST_F(S3tpTest, SetAcknowledgmentNumber) {
    packet_1.set_ack_num(0x6543);
    EXPECT_EQ(0x6543, packet_1.ack_num());
}

TEST_F(S3tpTest, SetSize) {
    packet_1.set_size(0x8765);
    EXPECT_EQ(0x8765, packet_1.size());
}

TEST_F(S3tpTest, GetAndSetFlags) {
    auto flags = packet_1.flags();

    packet_1.set_flags(space_tcp::Flag::NoFlags);
    EXPECT_EQ(space_tcp::Flag::NoFlags, packet_1.flags());

    packet_1.set_flags(flags);
    EXPECT_EQ(flags, packet_1.flags());
}

TEST_F(S3tpTest, GetAndSetSourcePort) {
    auto port = packet_1.src_port();

    packet_1.set_src_port(0);
    EXPECT_EQ(0, packet_1.src_port());

    packet_1.set_src_port(port);
    EXPECT_EQ(port, packet_1.src_port());
}

TEST_F(S3tpTest, GetAndSetDestinationPort) {
    auto port = packet_1.dst_port();

    packet_1.set_dst_port(0);
    EXPECT_EQ(0, packet_1.dst_port());

    packet_1.set_dst_port(port);
    EXPECT_EQ(port, packet_1.dst_port());
}

TEST_F(S3tpTest, PadMessage) {
    packet_1.pad_payload();

    EXPECT_EQ(16, packet_1.size());
}
