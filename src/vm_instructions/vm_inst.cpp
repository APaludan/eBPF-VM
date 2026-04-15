#include "vm_inst.h"
#include "junk_inst.h"
#include <cstring>

// Include the programs we want from programs folder
#include "ptrace.h"
#include "make_lsm.h"
#include "open_lsm.h"



std::unordered_map<int, std::vector<vm_inst>> generate_programs(pid_t protected_pid, bool with_junk)
{
    std::unordered_map<int, std::vector<vm_inst>> program_map;

    if (with_junk == false)
    {
        program_map[PTRACE_PROGRAM] = make_ptrace_program(protected_pid);
        fix_jumps(program_map[PTRACE_PROGRAM]);
        program_map[LSM_OPEN_PROGRAM] = make_lsm_open_program(protected_pid);
        fix_jumps(program_map[LSM_OPEN_PROGRAM]);
        program_map[LSM_BPF_PROGRAM] = make_lsm_bpf_program();
        fix_jumps(program_map[LSM_BPF_PROGRAM]);
    }

    if (with_junk == true)
    {
        program_map[PTRACE_PROGRAM] = generate_junk_inst(make_ptrace_program(protected_pid));
        fix_jumps(program_map[PTRACE_PROGRAM]);
        program_map[LSM_OPEN_PROGRAM] = generate_junk_inst(make_lsm_open_program(protected_pid));
        fix_jumps(program_map[LSM_OPEN_PROGRAM]);
        program_map[LSM_BPF_PROGRAM] = generate_junk_inst(make_lsm_bpf_program());
        fix_jumps(program_map[LSM_BPF_PROGRAM]);        
    }


    //print_program_map_to_csv(program_map, "program_map.csv");

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



void fix_jumps(std::vector<vm_inst>& program) {
    // sums of instruction sizes
    // offsets[i] = the byte offset of the instruction at program[i].
    std::vector<size_t> offsets(program.size() + 1, 0);
    for (size_t i = 0; i < program.size(); i++) {
        offsets[i + 1] = offsets[i] + inst_serialized_size(program[i]);
    }

    for (size_t i = 0; i < program.size(); ++i) {
        auto& inst = program[i];
        
        if (is_jump_op(inst.op)) {
            size_t target_idx = i + inst.val;
            inst.val = offsets[target_idx] - offsets[i];
        }
    }
}