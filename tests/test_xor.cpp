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

TEST(EncryptionTests, XorInstruction1)
{
    auto key = random_value<int>();

    unsigned short original_op = OP_CALL;
    unsigned short original_dst = 2;
    unsigned short original_src = 0;
    long long original_val = 14;
    short original_offset = 4;

    vm_inst i = {
        .op = original_op,
        .dst = original_dst,
        .src = original_src,
        .val = original_val,
        .offset = original_offset};

    xor_rolling(&i, key);

    EXPECT_NE(i.op, original_op);
    EXPECT_NE(i.dst, original_dst);
    EXPECT_NE(i.src, original_src);
    EXPECT_NE(i.val, original_val);
    EXPECT_NE(i.offset, original_offset);

    xor_rolling(&i, key);

    EXPECT_EQ(i.op, original_op);
    EXPECT_EQ(i.dst, original_dst);
    EXPECT_EQ(i.src, original_src);
    EXPECT_EQ(i.val, original_val);
    EXPECT_EQ(i.offset, original_offset);
}

TEST(EncryptionTests, XorInstruction2)
{
    auto key = random_value<int>();

    unsigned short original_op = OP_LOAD;
    unsigned short original_dst = 1;
    unsigned short original_src = 2;
    long long original_val = 123;
    short original_offset = -5;

    vm_inst i = {
        .op = original_op,
        .dst = original_dst,
        .src = original_src,
        .val = original_val,
        .offset = original_offset};

    xor_rolling(&i, key);

    EXPECT_NE(i.op, original_op);
    EXPECT_NE(i.dst, original_dst);
    EXPECT_NE(i.src, original_src);
    EXPECT_NE(i.val, original_val);
    EXPECT_NE(i.offset, original_offset);

    xor_rolling(&i, key);

    EXPECT_EQ(i.op, original_op);
    EXPECT_EQ(i.dst, original_dst);
    EXPECT_EQ(i.src, original_src);
    EXPECT_EQ(i.val, original_val);
    EXPECT_EQ(i.offset, original_offset);
}

TEST(EncryptionTests, XorInstruction3)
{
    auto key = random_value<int>();

    unsigned short original_op = OP_LOAD;
    unsigned short original_dst = 65432;
    unsigned short original_src = 12345;
    long long original_val = -312431511;
    short original_offset = 32000;

    vm_inst i = {
        .op = original_op,
        .dst = original_dst,
        .src = original_src,
        .val = original_val,
        .offset = original_offset};

    xor_rolling(&i, key);

    EXPECT_NE(i.op, original_op);
    EXPECT_NE(i.dst, original_dst);
    EXPECT_NE(i.src, original_src);
    EXPECT_NE(i.val, original_val);
    EXPECT_NE(i.offset, original_offset);

    xor_rolling(&i, key);

    EXPECT_EQ(i.op, original_op);
    EXPECT_EQ(i.dst, original_dst);
    EXPECT_EQ(i.src, original_src);
    EXPECT_EQ(i.val, original_val);
    EXPECT_EQ(i.offset, original_offset);
}
