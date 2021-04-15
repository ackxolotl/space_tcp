#include <gtest/gtest.h>

TEST(IsEqTest, IsIndeedEqual) {
    EXPECT_EQ(3, 3);
}

TEST(IsEqTest, IsAlsoEqual) {
    EXPECT_EQ(4, 4);
}