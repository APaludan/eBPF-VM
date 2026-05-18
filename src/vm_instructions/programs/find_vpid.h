#pragma once

std::vector<vm_inst> make_kprobe_find_vpid_program()
{
    return {
        {OP_READ_DATA, 1, 0, 0, 0},
        {OP_READ_CTX, 2, 0, sizeof(pid_t), 0},
        {OP_JNEQ, 1, 2, 2, 0},
        {OP_RINGBUF, 0, 0, 0, 0},
        {OP_EXIT, 0, 0, 0, 0},
    };
}
