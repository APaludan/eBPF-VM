#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-declarations"
#include "vmlinux.h"
#pragma clang diagnostic pop

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "vm.h"
#include <errno.h>

//==========================================
//====          MAP STRUCTURES          ====
//==========================================

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * sizeof(struct vm_event));
} rb SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, unsigned int);
    __type(value, int);
} key_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, VM_MAX_INSTRUCTIONS *MAX_PROGRAMS);
    __type(key, unsigned int);
    __type(value, struct vm_inst);
} programs SEC(".maps");

#include "vm_dispatch.h"

static long vm_callback_fn(unsigned int nr_loops, void *ctx);
static int vm_error(struct vm_state *vm);


//==========================================
//====            HOOK POINTS           ====
//==========================================

//------------- ACTIVE HOOKS (Core VM Execution) -------
// These hooks intercept actual security-relevant events

SEC("lsm/bpf")
int BPF_PROG(restrict_bpf, int cmd, union bpf_attr *attr, unsigned int size)
{
    struct vm_state vm = {0};
    vm.type = LSM_BPF_PROGRAM;
    vm.data = (void *)&cmd;

    bpf_loop(VM_MAX_LOOPS, vm_callback_fn, (void *)&vm, 0);

    int ret = (int)vm.regs[0];
    return (ret == 0) ? 0 : -EPERM;
}

SEC("tp/syscalls/sys_enter_ptrace")
int ebpf_vm_interpreter(struct trace_event_raw_sys_enter *ctx)
{
    struct vm_state vm = {0};

    vm.type = PTRACE_PROGRAM;
    vm.data = (void *)ctx;

    bpf_loop(VM_MAX_LOOPS, vm_callback_fn, (void *)&vm, 0);

    return (int)vm.regs[0];
}

SEC("lsm/file_open")
int BPF_PROG(restrict_proc_access, struct file *file)
{
    struct vm_state vm = {0};

    vm.type = LSM_OPEN_PROGRAM;
    vm.data = (void *)file;

    bpf_loop(VM_MAX_LOOPS, vm_callback_fn, (void *)&vm, 0);

    return 0; // remove when vm prog works correctly

    int ret = (int)vm.regs[0];
    return (ret == 0) ? 0 : -EPERM;
}

//------------- DECOY HOOKS (Obfuscation) -------
// These hooks perform dummy operations to confuse potential attackers
// Decoys create false patterns and misdirection

SEC("tp/syscalls/sys_enter_read")
int trace_read_decoy(struct trace_event_raw_sys_enter *ctx)
{
    struct vm_state vm = {0};
    vm.type = TRACE_READ_PROGRAM;
    vm.data = (void *)ctx;

    bpf_loop(VM_MAX_LOOPS, vm_callback_fn, (void *)&vm, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_write")
int trace_write_decoy(struct trace_event_raw_sys_enter *ctx)
{
    struct vm_state vm = {0};
    vm.type = TRACE_WRITE_PROGRAM;
    vm.data = (void *)ctx;

    bpf_loop(VM_MAX_LOOPS, vm_callback_fn, (void *)&vm, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_open")
int trace_open_decoy(struct trace_event_raw_sys_enter *ctx)
{
    struct vm_state vm = {0};
    vm.type = TRACE_OPEN_PROGRAM;
    vm.data = (void *)ctx;

    bpf_loop(VM_MAX_LOOPS, vm_callback_fn, (void *)&vm, 0);
    return 0;
}

SEC("lsm/inode_permission")
int BPF_PROG(decoy_inode_check, struct inode *inode, int mask)
{
    struct vm_state vm = {0};
    vm.type = INODE_CHECK_PROGRAM;
    vm.data = (void *)inode;

    bpf_loop(VM_MAX_LOOPS, vm_callback_fn, (void *)&vm, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_execve")
int trace_execve_decoy(struct trace_event_raw_sys_enter *ctx)
{
    struct vm_state vm = {0};
    vm.type = TRACE_EXECVE_PROGRAM;
    vm.data = (void *)ctx;

    bpf_loop(VM_MAX_LOOPS, vm_callback_fn, (void *)&vm, 0);
    return 0;
}

//------------- END HOOK POINTS -------

//==========================================
//====             VM LOGIC             ====
//==========================================

// Core VM execution callback - runs per instruction
// Called by bpf_loop() to iterate through program bytecode
static long vm_callback_fn(unsigned int nr_loops, void *ctx)
{
    struct vm_state *vm = (struct vm_state *)ctx;

    //========== INSTRUCTION FETCH & DECRYPTION ==========
    // Fetch encrypted instruction (uses defined vm type in hook point logic to get the right instruction in programs map)
    // PTRACE_PROGRAM = 0 (defined in vm.h) has the first VM_MAX_INSTRUCTIONS entries of the map
    // LSM_OPEN_PROGRAM = 1 (defined in vm.h) has the entries after the first VM_MAX_INSTRUCTIONS entries of the map
    // TODO: make more memory effecient a lot of unused slots atm
    unsigned int program_index_pc = vm->type * VM_MAX_INSTRUCTIONS + vm->pc;
    struct vm_inst *inst_ptr = bpf_map_lookup_elem(&programs, &program_index_pc);

    if (!inst_ptr)
        return 1;

    // Copy to stack
    struct vm_inst inst = *inst_ptr;

    // get key and decrypt instruction
    unsigned int index = 0;
    int *key_ptr = bpf_map_lookup_elem(&key_map, &index);
    if (!key_ptr)
        return vm_error(vm);
    int key = *key_ptr;
    xor_rolling(&inst, key + vm->pc);

    //========== INSTRUCTION VALIDATION ==========
    inst.dst &= VM_NUM_REGS - 1;
    inst.src &= VM_NUM_REGS - 1;

    // just some checks to make verifier happy
    if ((inst.dst >= VM_NUM_REGS) || (inst.src >= VM_NUM_REGS))
    {
        return vm_error(vm);
    }

    //========== INSTRUCTION EXECUTION DISPATCH ==========
    // Dispatch instruction to appropriate handler based on category
    long dispatch_result = vm_execute_instruction(&inst, vm);
    
    if (dispatch_result == 1)
    {
        // Error occurred or exit requested
        return dispatch_result;
    }
    else if (dispatch_result != 0)
    {
        // Control flow instruction handled the PC update
        return 0;
    }

    // Normal instruction completed, increment PC for next instruction
    vm->pc++;
    return 0;
}

//========== ERROR HANDLING ==========
// Records error state and outputs diagnostic information via ring buffer
static int vm_error(struct vm_state *vm)
{
    struct vm_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e)
    {
        e->caller_pid = bpf_get_current_pid_tgid() >> 32;
        e->type = VM_ERROR;
        e->pc = vm->pc;
        bpf_get_current_comm(e->caller_name, sizeof(e->caller_name));

        for (int i = 0; i < VM_NUM_REGS; i++)
        {
            e->reg_values[i] = vm->regs[i];
        }

        bpf_ringbuf_submit(e, 0);
    }
    return 1;
}

//========== LICENSE ==========

char LICENSE[] SEC("license") = "Dual BSD/GPL";
