#include <gtest/gtest.h>
#include <vm_inst.h>

TEST(FixJumpTest, JumpForward1)
{
    auto program = std::vector({
        vm_inst{OP_JMP, 0, 0, 4, 0}, // jump to exit
        vm_inst{OP_LOAD, 1, 0, 5, 0},
        vm_inst{OP_LOAD, 2, 0, 5, 0},
        vm_inst{OP_ADD, 1, 2, 0, 0},
        vm_inst{OP_EXIT, 0, 0, 0, 0},
    });

    fix_jumps(program);

    const int expected = 2 + 8 + 2 + 2 + 8 + 2 + 2 + 8 + 2 + 2 + 2 + 8;

    EXPECT_EQ(program[0].val, expected);
}

TEST(FixJumpTest, JumpForward2)
{
    auto program = std::vector({
        vm_inst{OP_JMP, 0, 0, 1, 0}, // jump to exit
        vm_inst{OP_EXIT, 0, 0, 0, 0},
    });

    fix_jumps(program);

    const int expected = 2 + 8;

    EXPECT_EQ(program[0].val, expected);
}

TEST(FixJumpTest, JumpForward3)
{
    auto program = std::vector({
        vm_inst{OP_LOAD, 1, 0, 10, 0},
        vm_inst{OP_READ_CTX, 2, 0, 20, 0},
        vm_inst{OP_JNEQ, 1, 2, 2, 0},
        vm_inst{OP_RINGBUF, 0, 0, 0, 0},
        vm_inst{OP_EXIT, 0, 0, 0, 0},
    });

    fix_jumps(program);

    const int expected = 2+2+2+8+2;

    EXPECT_EQ(program[2].val, expected);
}

TEST(FixJumpTest, JumpNone)
{
    auto program = std::vector({
        vm_inst{OP_JMP, 0, 0, 0, 0},
        vm_inst{OP_EXIT, 0, 0, 0, 0},
    });

    fix_jumps(program);

    const int expected = 0;

    EXPECT_EQ(program[0].val, expected);
}

TEST(FixJumpTest, JumpBack1)
{
    auto program = std::vector({
        vm_inst{OP_LOAD, 1, 0, 5, 0},
        vm_inst{OP_LOAD, 2, 0, 5, 0},
        vm_inst{OP_JMP, 0, 0, -1, 0}, // jump to prev instruction
        vm_inst{OP_EXIT, 0, 0, 0, 0},
    });

    fix_jumps(program);

    const int expected = -12;

    EXPECT_EQ(program[2].val, expected);
}

TEST(FixJumpTest, JumpBack2)
{
    auto program = std::vector({
        vm_inst{OP_LOAD, 1, 0, 5, 0},
        vm_inst{OP_LOAD, 2, 0, 5, 0},
        vm_inst{OP_JMP, 0, 0, -2, 0}, // jump to first instruction
        vm_inst{OP_EXIT, 0, 0, 0, 0},
    });

    fix_jumps(program);

    const int expected = -24;

    EXPECT_EQ(program[2].val, expected);
}