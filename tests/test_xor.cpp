#include <gtest/gtest.h>
#include <random>
#include <limits>
#include "vm.h"

template<typename T>
T random_value() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    std::uniform_int_distribution<T> key_dist(
        std::numeric_limits<T>::min(),
        std::numeric_limits<T>::max());

    return key_dist(gen);
}

TEST(EncodingTests, XorInstruction1)
{
    auto key = random_value<int>();

    unsigned short original_op = OP_CALL;
    unsigned short original_dst = 2;
    unsigned short original_src = 0;
    long long original_val = 14;

    vm_inst i = {
        .op = original_op,
        .dst = original_dst,
        .src = original_src,
        .val = original_val};

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

TEST(EncodingTests, XorInstruction2)
{
    auto key = random_value<int>();

    unsigned short original_op = OP_LOAD;
    unsigned short original_dst = 1;
    unsigned short original_src = 2;
    long long original_val = 123;

    vm_inst i = {
        .op = original_op,
        .dst = original_dst,
        .src = original_src,
        .val = original_val};

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

TEST(EncodingTests, XorInstruction3)
{
    auto key = random_value<int>();

    unsigned short original_op = OP_LOAD;
    unsigned short original_dst = 1;
    unsigned short original_src = 0;
    long long original_val = 1;

    vm_inst i = {
        .op = original_op,
        .dst = original_dst,
        .src = original_src,
        .val = original_val};

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