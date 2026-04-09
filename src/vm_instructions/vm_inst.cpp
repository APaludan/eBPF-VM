#include "vm_inst.h"
#include <cstring>

std::vector<vm_inst> make_lsm_open_program(pid_t protected_pid);
std::vector<vm_inst> make_ptrace_program(pid_t protected_pid);
std::vector<vm_inst> make_lsm_bpf_program();

bool is_jump_op(unsigned short op)
{
    return op >= OP_JMP && op <= OP_JGTEQ;
}
size_t inst_serialized_size(const vm_inst &inst)
{
    size_t size = 2;
    if (have_dst(inst.op))
    {
        size += 2;
    }
    if (have_src(inst.op))
    {
        size += 2;
    }
    if (have_val(inst.op))
    {
        size += 8;
    }
    if (have_offset(inst.op))
    {
        size += 2;
    }
    return size;
}

// Converts all values of jump instructions to bytes
void fix_jumps(std::vector<vm_inst> &program)
{
    std::vector<size_t> sizes;
    for (const auto &inst : program)
    {
        auto size = inst_serialized_size(inst);
        sizes.push_back(size);
    }

    for (size_t i = 0; i < program.size(); i++)
    {
        auto &inst = program[i];
        if (!is_jump_op(inst.op))
            continue;

        long long target_inst_idx = i + inst.val;
        long long jump = 0;
        long long idx = i;

        if (inst.val > 0)
        {
            while (idx < target_inst_idx)
            {
                long long inst_size = sizes[idx];
                jump += inst_size;
                idx++;
            }
        }
        else if (inst.val < 0)
        {
            idx--;
            while (idx >= target_inst_idx)
            {
                long long inst_size = sizes[idx];
                jump -= inst_size;
                idx--;
            }
        }

        inst.val = jump;
    }
}

std::unordered_map<int, std::vector<vm_inst>> generate_programs(pid_t protected_pid)
{
    std::unordered_map<int, std::vector<vm_inst>> program_map;

    program_map[PTRACE_PROGRAM] = make_ptrace_program(protected_pid);
    fix_jumps(program_map[PTRACE_PROGRAM]);
    program_map[LSM_OPEN_PROGRAM] = make_lsm_open_program(protected_pid);
    fix_jumps(program_map[LSM_OPEN_PROGRAM]);
    program_map[LSM_BPF_PROGRAM] = make_lsm_bpf_program();
    fix_jumps(program_map[LSM_BPF_PROGRAM]);

    return program_map;
}

// function to create vector with instusction, same functionality as mem_access ptrace ebpf program
std::vector<vm_inst> make_ptrace_program(pid_t protected_pid)
{
    return {
        vm_inst{OP_LOAD, 1, 0, protected_pid, 0},      // 00) r1 = protected_pid
        vm_inst{OP_CALL, 0, 0, 14, 0},                 // 01) call bpf_get_current_pid_tgid (nr 14)
        vm_inst{OP_RSHIFT, 0, 0, 32, 0},               // 02) = r0 >> 32 (extract PID only)
        vm_inst{OP_READ_CTX, 2, 0, sizeof(pid_t), 24}, // 03) read the target pid from ctx + offset 24 = (ctx->args[1])

        vm_inst{OP_JNEQ, 1, 2, 2, 0},    // 04) if r1(protected pid) != r2(target pid): jump to exit (pc +2)
        vm_inst{OP_RINGBUF, 0, 0, 0, 0}, // 05) submit info to ringbuf
        vm_inst{OP_LOAD, 0, 0, 0, 0},    // 06) set exit code
        vm_inst{OP_EXIT, 0, 0, 0, 0}     // 07) exit
    };
};

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

std::vector<uint8_t> serialize_inst(const vm_inst inst, int key)
{
    vm_inst encrypted = inst;
    xor_rolling(&encrypted, key);

    std::vector<uint8_t> buffer(sizeof(vm_inst));
    size_t pos = 0;

    // Helper to copy bytes and advance position
    auto append = [&](const void *src, size_t size)
    {
        uint8_t data[sizeof(vm_inst)] = {0};
        for (size_t i = 0; i < size; i++)
        {
            data[i] = ((uint8_t *)src)[i];
        }

        std::memcpy(buffer.data() + pos, data, size);
        pos += size;
    };

    append(&encrypted.op, sizeof(encrypted.op)); // 2 bytes
    if (have_dst(inst.op))
    {
        append(&encrypted.dst, sizeof(encrypted.dst)); // 2 bytes
    }
    if (have_src(inst.op))
    {
        append(&encrypted.src, sizeof(encrypted.src)); // 2 bytes
    }
    if (have_val(inst.op))
    {
        append(&encrypted.val, sizeof(encrypted.val)); // 8 bytes
    }
    if (have_offset(inst.op))
    {
        append(&encrypted.offset, sizeof(encrypted.offset)); // 2 bytes
    }

    buffer.resize(pos);
    return buffer;
}