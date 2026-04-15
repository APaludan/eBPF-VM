#pragma once

std::vector<vm_inst> make_kprobe_pid_task_program(pid_t protected_pid)
{
    return {
        vm_inst{OP_LOAD, 1, 0, protected_pid, 0},
        vm_inst{OP_READ_CTX, 2, 0, sizeof(pid_t), 2768},
        vm_inst{OP_JNEQ, 1, 2, 2, 0},
        vm_inst{OP_RINGBUF, 0, 0, 0, 0},
        vm_inst{OP_EXIT, 0, 0, 0, 0},
    };
}
