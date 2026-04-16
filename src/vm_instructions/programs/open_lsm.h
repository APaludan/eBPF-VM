#pragma once 

std::vector<vm_inst> make_lsm_open_program(pid_t protected_pid)
{
    const auto proc_super_magic_num = 0x9fa0; // define consts used for the lsm_open program
    unsigned long long maps = 0;              //
    unsigned long long smaps = 0;             //
    unsigned long long mem = 0;               //
    memcpy(&maps, "maps", 5);                 //
    memcpy(&smaps, "smaps", 6);               //
    memcpy(&mem, "mem", 4);

    return {
        // vm_inst(op, dst, src, val, offset)
        vm_inst{OP_LOAD, 1, 0, protected_pid, 0}, // 01) r1 = protected_pid, 0
        vm_inst{OP_CALL, 0, 0, 14, 0},            // 02) bpf_get_current_pid_tgid, 1
        vm_inst{OP_RSHIFT, 0, 0, 32, 0},          // 03) r0 = pid, 2
        vm_inst{OP_JNEQ, 1, 0, 2, 0},             // 04) ,3
        vm_inst{OP_EXIT, 0, 0, 0, 0},             // 05) early exit if call from protected pid, 4

        vm_inst{OP_READ_CTX, 3, 0, sizeof(void *), 32},   // 06) r3 = *inode, 5
        vm_inst{OP_ADD, 3, 0, 40, 0},                     // 07) r3 += 40 (offset), 6
        vm_inst{OP_READ, 4, 3, sizeof(void *), 0},        // 08) r4 = *inode->i_sb, 7
        vm_inst{OP_ADD, 4, 0, 96, 0},                     // 09) r4 += 96 (offset), 8
        vm_inst{OP_READ, 5, 4, sizeof(unsigned long), 0}, // 10) r5 = *i_sb->s_magic, 9
        vm_inst{OP_LOAD, 6, 0, proc_super_magic_num, 0},  // 11) r6 = procfs magic num, 10
        vm_inst{OP_JEQ, 5, 6, 2, 0},                      // 12) ,11
        vm_inst{OP_EXIT, 0, 0, 0, 0},                     // 13) exit if not procfs, 12

        vm_inst{OP_READ_CTX, 3, 0, sizeof(void *), 32}, // 14) r3 = *inode, 15
        vm_inst{OP_SUB, 3, 0, 72, 0},                   // 15) r3 = *proc_inode, 16
        vm_inst{OP_READ, 4, 3, sizeof(void *), 0},      // 16) r4 = *struct pid, 17
        vm_inst{OP_ADD, 4, 0, 144, 0},                  // 17) r4 = *upid[0], 18
        vm_inst{OP_READ, 5, 4, sizeof(int), 0},         // 18) r5 = target pid, 19
        vm_inst{OP_JNEQ, 0, 8, 3, 0},                   // 19) exit if read failed, means it is probably not procfs anyway idk
        vm_inst{OP_JEQ, 5, 1, 3, 0},                    // 20) jump if (r5 == r1), 21
        vm_inst{OP_LOAD, 0, 0, 0, 0},                   // 21) set return val to 0
        vm_inst{OP_EXIT, 0, 0, 0, 0},                   // 22) exit if not protected pid, 23

        vm_inst{OP_READ_CTX, 3, 0, sizeof(void *), 64 + 8}, // 23) r3 = *dentry
        vm_inst{OP_ADD, 3, 0, 32 + 8, 0},                   // 24) r3 = **name
        vm_inst{OP_READ, 3, 3, sizeof(void *), 0},          // 25) r3 = *name
        vm_inst{OP_READ, 5, 3, sizeof(void *), 0},          // 26) r3 = first 8 bytes of name. should probably be on stack and have variable size
        vm_inst{OP_LOAD, 4, 0, (long long)maps, 0},         // 27) 1: load sus filename
        vm_inst{OP_JEQ, 5, 4, 6, 0},                        // 28) 2: if sus jump to submit ringbuf
        vm_inst{OP_LOAD, 4, 0, (long long)smaps, 0},        // 29) 1
        vm_inst{OP_JEQ, 5, 4, 4, 0},                        // 30) 2
        vm_inst{OP_LOAD, 4, 0, (long long)mem, 0},          // 31) 1
        vm_inst{OP_JEQ, 5, 4, 2, 0},                        // 32) 2
        vm_inst{OP_JMP, 0, 0, 4, 0},                        // 33) jump over ringbuf submit if not sus
        vm_inst{OP_RINGBUF, 0, 0, 0, 0},                    //
        vm_inst{OP_PRINTS, 0, 3, 0, 0},                     // 34) print sus file name

        vm_inst{OP_LOAD, 0, 0, 0, 0}, // 35) set return val
        vm_inst{OP_EXIT, 0, 0, 0, 0}, // 36) exit if not protected filename
    };
};