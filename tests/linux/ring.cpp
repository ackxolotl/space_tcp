#include <gtest/gtest.h>

#include "space_tcp/ring.hpp"

TEST(RingTest, FreeSpaceEmpty) {
    uint8_t mem[4]{};

    auto ring = space_tcp::RingBuffer::create(mem, sizeof(mem));

    EXPECT_EQ(sizeof(mem), ring.free_space());
    EXPECT_EQ(0, ring.used_space());
}

TEST(RingTest, FreeSpace) {
    uint8_t mem[4]{};

    auto ring = space_tcp::RingBuffer::create(mem, sizeof(mem));

    uint8_t data[] = "some data";

    EXPECT_EQ(1, ring.push_back(data, 1));
    EXPECT_EQ(3, ring.free_space());
    EXPECT_EQ(1, ring.used_space());

    EXPECT_EQ(1, ring.push_back(data, 1));
    EXPECT_EQ(2, ring.free_space());
    EXPECT_EQ(2, ring.used_space());

    EXPECT_EQ(1, ring.push_back(data, 1));
    EXPECT_EQ(1, ring.free_space());
    EXPECT_EQ(3, ring.used_space());

    EXPECT_EQ(1, ring.push_back(data, 1));
    EXPECT_EQ(0, ring.free_space());
    EXPECT_EQ(4, ring.used_space());

    EXPECT_EQ(-1, ring.push_back(data, 1));
    EXPECT_EQ(0, ring.free_space());
    EXPECT_EQ(4, ring.used_space());
}

TEST(RingTest, PushNullptr) {
    uint8_t mem[4]{};

    auto ring = space_tcp::RingBuffer::create(mem, sizeof(mem));

    EXPECT_EQ(-1, ring.push_back(nullptr, 1));
    EXPECT_EQ(-1, ring.push_back(nullptr, 0));
}

TEST(RingTest, PushData) {
    uint8_t mem[4]{};

    auto ring = space_tcp::RingBuffer::create(mem, sizeof(mem));

    uint8_t data[] = "some data";

    EXPECT_EQ(2, ring.push_back(data, 2));
    EXPECT_EQ('o', ring.data()[1]);

    uint8_t tmp[4]{0};

    EXPECT_EQ(2, ring.pop_front(tmp, sizeof(tmp)));

    EXPECT_EQ('s', tmp[0]);
    EXPECT_EQ('o', tmp[1]);
}

TEST(RingTest, PushTooMuchData) {
    uint8_t mem[4]{};

    auto ring = space_tcp::RingBuffer::create(mem, sizeof(mem));

    uint8_t data[] = "some data";

    EXPECT_EQ(4, ring.push_back(data, sizeof(data)));
    EXPECT_EQ(4, ring.used_space());
    EXPECT_EQ(0, ring.free_space());
}

TEST(RingTest, PushAtOffset) {
    uint8_t mem[4]{};

    auto ring = space_tcp::RingBuffer::create(mem, sizeof(mem));

    uint8_t data[] = "some data";

    EXPECT_EQ(2, ring.push_back(data + 5, 2, 1));

    EXPECT_EQ(0, mem[0]);
    EXPECT_EQ('d', mem[1]);
    EXPECT_EQ('a', mem[2]);
    EXPECT_EQ(0, mem[3]);

    EXPECT_EQ(4, ring.free_space());
    EXPECT_EQ(0, ring.used_space());
}

TEST(RingTest, PushTooMuchDataAtOffset) {
    uint8_t mem[4]{};

    auto ring = space_tcp::RingBuffer::create(mem, sizeof(mem));

    uint8_t data[] = "some data";

    EXPECT_EQ(2, ring.push_back(data, 2));
    EXPECT_EQ(1, ring.push_back(data, 2, 1));

    EXPECT_EQ('s', mem[0]);
    EXPECT_EQ('o', mem[1]);
    EXPECT_EQ(0, mem[2]);
    EXPECT_EQ('s', mem[3]);

    EXPECT_EQ(2, ring.free_space());
    EXPECT_EQ(2, ring.used_space());
}

TEST(RingTest, PushAndPopData) {
    uint8_t mem[4]{};

    auto ring = space_tcp::RingBuffer::create(mem, sizeof(mem));

    uint8_t data[] = "some data";

    ring.push_back(data, 4);
    EXPECT_EQ(4, ring.used_space());

    ring.pop_front(nullptr, 2);
    EXPECT_EQ(2, ring.used_space());

    ring.push_back(data + 5, 2);
    EXPECT_EQ(4, ring.used_space());

    EXPECT_EQ('d', mem[0]);
    EXPECT_EQ('a', mem[1]);
    EXPECT_EQ('m', mem[2]);
    EXPECT_EQ('e', mem[3]);

    EXPECT_EQ(4, ring.pop_front(data, 10000));
    EXPECT_EQ('m', data[0]);
    EXPECT_EQ('e', data[1]);
    EXPECT_EQ('d', data[2]);
    EXPECT_EQ('a', data[3]);
}
