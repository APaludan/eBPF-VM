#pragma once

#include <unistd.h>
// block some bpf syscalls
// prevents usage of: `bpftool prog list`, `bpftool link list`, `bpftool map list`
// TODO: make it even more specific so it only block access to our programs/maps/links
std::vector<vm_inst> make_lsm_bpf_program()
{
    const pid_t pid = getpid();
    // kan findes i vmlinux.h -> enum bpf_cmd
    const int cmd_prog_get_next_id = 11;
    const int cmd_link_get_next_id = 31;
    const int cmd_map_get_next_id = 12;
    const int cmd_link_detach = 34;

    return {
        vm_inst{OP_EXIT, 0, 0, 0, 0},
        vm_inst{OP_LOAD, 1, 0, pid, 0},
        vm_inst{OP_CALL, 0, 0, 14, 0},   // bpf_get_current_pid_tgid
        vm_inst{OP_RSHIFT, 0, 0, 32, 0}, // r0 = pid
        vm_inst{OP_JNEQ, 1, 0, 3, 0},
        vm_inst{OP_LOAD, 0, 0, 0, 0},
        vm_inst{OP_EXIT, 0, 0, 0, 0},

        vm_inst{OP_LOAD, 1, 0, cmd_prog_get_next_id, 0},
        vm_inst{OP_LOAD, 2, 0, cmd_link_get_next_id, 0},
        vm_inst{OP_LOAD, 3, 0, cmd_map_get_next_id, 0},
        vm_inst{OP_LOAD, 4, 0, cmd_link_detach, 0},
        vm_inst{OP_READ_CTX, 8, 0, sizeof(int), 0}, // read command to r8
        vm_inst{OP_JEQ, 4, 8, 5, 0},                // if r8 == r1 ||
        vm_inst{OP_JEQ, 1, 8, 4, 0},                // r8 == r1 ||
        vm_inst{OP_JEQ, 2, 8, 3, 0},                // r8 == r2 ||
        vm_inst{OP_JEQ, 3, 8, 2, 0},                // r8 == r3
        vm_inst{OP_JMP, 0, 0, 3, 0},
        vm_inst{OP_RINGBUF, 0, 0, 0, 0},
        vm_inst{OP_LOAD, 0, 0, -EPERM, 0}, // return -EPERM to block operation
        vm_inst{OP_EXIT, 0, 0, 0, 0},
    };
}
