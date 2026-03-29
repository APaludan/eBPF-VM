#include <gtest/gtest.h>
#include <random>
#include <limits>
#include "vm.h"


TEST(EncodingTests, XorInstruction) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<unsigned int> key_dist(0, std::numeric_limits<unsigned int>::max());
    unsigned int key = key_dist(gen);

    unsigned short original_op = OP_LOAD;
    unsigned short original_dst = 1;
    unsigned short original_src = 2;
    long long original_val = 123;

    vm_inst i = {
        .op = original_op,
        .dst = original_dst,
        .src = original_src,
        .val = original_val
    };

    xor_rolling(&i, key);

    EXPECT_NE(i.op, original_op);
    EXPECT_NE(i.dst, original_dst);
    EXPECT_NE(i.src, original_src);
    EXPECT_NE(i.val, original_val);

    xor_rolling(&i, key);

    EXPECT_EQ(i.op, original_op);
    EXPECT_EQ(i.dst, original_dst);
    EXPECT_EQ(i.src, original_src);
    EXPECT_EQ(i.val, original_val);
}