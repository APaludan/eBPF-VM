#pragma once 

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
