#include "vm_inst.h"
#include "junk_inst.h"
#include <cstring>

// Include the programs we want from programs folder
#include "ptrace.h"
#include "bpf_lsm.h"
#include "open_lsm.h"
#include "pid_task.h"
#include "find_vpid.h"
#include "simple_filter.h"
#include "module_load.h"
#include "module_free.h"

std::unordered_map<int, std::vector<vm_inst>> generate_programs(pid_t protected_pid, bool with_junk)
{
    std::unordered_map<int, std::vector<vm_inst>> program_map;

    auto add_prog = [&](int id, std::vector<vm_inst>&& insts) 
    {
        if (with_junk) 
        {
            insts = generate_junk_inst(std::move(insts), 100);
        }
        fix_jumps(insts);
        program_map[id] = std::move(insts);
    };

    // To add a new program, just add it here:
    add_prog(PTRACE_PROGRAM,            make_ptrace_program(protected_pid));
    add_prog(LSM_OPEN_PROGRAM,          make_lsm_open_program(protected_pid));
    add_prog(LSM_BPF_PROGRAM,           make_lsm_bpf_program());
    add_prog(KPROBE_FIND_VPID_PROGRAM,  make_kprobe_find_vpid_program(protected_pid));
    //add_prog(KPROBE_PID_TASK_PROGRAM,   make_kprobe_pid_task_program(protected_pid));
    add_prog(SIMPLE_FILTER_PROGRAM, make_simple_filter_program());
    add_prog(MODULE_LOAD_PROGRAM, make_module_load_program());
    add_prog(MODULE_FREE_PROGRAM, make_module_free_program());

    print_program_map_to_csv(program_map, "vm_inst");

    return program_map;
}



std::vector<uint8_t> serialize_inst(const vm_inst inst, int key)
{
    vm_inst encrypted = inst;
    xor_rolling(&encrypted, key);

    std::vector<uint8_t> buffer(sizeof(vm_inst));
    size_t pos = 0;

    // Helper to copy bytes and advance position
    auto append = [&](const void *src, size_t size)
    {
        std::memcpy(buffer.data() + pos, src, size);
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



bool is_jump_op(unsigned short op)
{
    return op >= OP_JMP && op <= OP_JGTEQ;
}



size_t inst_serialized_size(const vm_inst &inst)
{
    size_t size = sizeof(inst.op);
    if (have_dst(inst.op))
    {
        size += sizeof(inst.dst);
    }
    if (have_src(inst.op))
    {
        size += sizeof(inst.src);
    }
    if (have_val(inst.op))
    {
        size += sizeof(inst.val);
    }
    if (have_offset(inst.op))
    {
        size += sizeof(inst.offset);
    }
    return size;
}



void fix_jumps(std::vector<vm_inst> &program)
{
    // sums of instruction sizes
    // offsets[i] = the byte offset of the instruction at program[i].
    std::vector<size_t> offsets(program.size() + 1, 0);
    for (size_t i = 0; i < program.size(); i++)
    {
        offsets[i + 1] = offsets[i] + inst_serialized_size(program[i]);
    }

    for (size_t i = 0; i < program.size(); ++i)
    {
        auto &inst = program[i];

        if (is_jump_op(inst.op))
        {
            size_t target_idx = i + inst.val;
            inst.val = offsets[target_idx] - offsets[i];
        }
    }
}