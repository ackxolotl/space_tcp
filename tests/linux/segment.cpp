#include <gtest/gtest.h>

#include "space_tcp/segment.hpp"

TEST(SegmentTest, SmallestSegmentInsert) {
    space_tcp::Segments<2> segments;

    EXPECT_EQ(0, segments.get_smallest_offset_segment().offset);

    EXPECT_EQ(true, segments.insert(13, 3));
    EXPECT_EQ(13, segments.get_smallest_offset_segment().offset);

    EXPECT_EQ(true, segments.insert(10, 3));
    EXPECT_EQ(10, segments.get_smallest_offset_segment().offset);

    // buffer full - 2 segments only
    EXPECT_EQ(false, segments.insert(22, 3));
    EXPECT_EQ(10, segments.get_smallest_offset_segment().offset);
}

TEST(SegmentTest, SmallestSegmentInsertAndDelete) {
    space_tcp::Segments<2> segments;

    EXPECT_EQ(true, segments.insert(17, 2));
    EXPECT_EQ(17, segments.get_smallest_offset_segment().offset);

    EXPECT_EQ(true, segments.insert(5, 3));
    EXPECT_EQ(5, segments.get_smallest_offset_segment().offset);

    EXPECT_EQ(true, segments.remove(5, 3));
    EXPECT_EQ(17, segments.get_smallest_offset_segment().offset);

    EXPECT_EQ(true, segments.remove(17, 2));
    EXPECT_EQ(0, segments.get_smallest_offset_segment().offset);
}

TEST(SegmentTest, SmallestSegmentInsertAndDelete2) {
    space_tcp::Segments<6> segments;

    EXPECT_EQ(true, segments.insert(5, 2));
    EXPECT_EQ(5, segments.get_smallest_offset_segment().offset);

    EXPECT_EQ(true, segments.insert(3, 1));
    EXPECT_EQ(3, segments.get_smallest_offset_segment().offset);

    EXPECT_EQ(true, segments.insert(7, 1));
    EXPECT_EQ(3, segments.get_smallest_offset_segment().offset);

    // try to delete non-existing elements
    EXPECT_EQ(false, segments.remove(0, 9));
    EXPECT_EQ(false, segments.remove(5, 1));
    EXPECT_EQ(false, segments.remove(6, 3));

    EXPECT_EQ(true, segments.remove(5, 2));
    EXPECT_EQ(3, segments.get_smallest_offset_segment().offset);

    EXPECT_EQ(true, segments.remove(3, 1));
    EXPECT_EQ(7, segments.get_smallest_offset_segment().offset);

    EXPECT_EQ(true, segments.insert(6, 1));
    EXPECT_EQ(6, segments.get_smallest_offset_segment().offset);

    EXPECT_EQ(true, segments.insert(9, 1));
    EXPECT_EQ(6, segments.get_smallest_offset_segment().offset);

    EXPECT_EQ(true, segments.remove(6, 1));
    EXPECT_EQ(7, segments.get_smallest_offset_segment().offset);

    EXPECT_EQ(true, segments.remove(7, 1));
    EXPECT_EQ(9, segments.get_smallest_offset_segment().offset);
}