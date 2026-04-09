#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-declarations"
#include "vmlinux.h"
#pragma clang diagnostic pop

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "vm.h"
#include <errno.h>

static long vm_callback_fn(unsigned int nr_loops, void *ctx);
static int vm_error(struct vm_state *vm);
int get_next_inst(struct vm_inst *inst, struct vm_state *vm);

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
    __uint(max_entries, VM_MAX_PROGRAM_SIZE * MAX_PROGRAMS);
    __type(key, unsigned int);
    __type(value, uint8_t);
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

    return (vm.regs[0] == 0) ? 0 : -EPERM;
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
    // bpf_printk("pc %u", vm.pc);

    return 0; // keep for testing

    return (vm.regs[0] == 0) ? 0 : -EPERM;
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
    struct vm_inst inst = {0};

    int size = get_next_inst(&inst, vm);
    if (size == -1)
        return 1;

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
    else if (dispatch_result == 100)
    {
        // Control flow instruction handled the PC update
        return 0;
    }

    // Normal instruction completed, increment PC for next instruction
    vm->pc += size;
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

// get next 8 bytes. increments `idx` by 2
static bool get_uint16(unsigned int *idx, uint16_t *dst)
{
    uint8_t *b;
#pragma unroll
    for (size_t i = 0; i < sizeof(uint16_t); i++)
    {
        b = bpf_map_lookup_elem(&programs, idx);
        if (b == NULL)
            return false;
        *dst |= ((uint16_t)*b << (8 * i));
        *idx = *idx + 1;
    }
    return true;
}

// get next 8 bytes. increments `idx` by 8
static bool get_uint64(unsigned int *idx, uint64_t *dst)
{
    uint8_t *b;
#pragma unroll
    for (size_t i = 0; i < sizeof(uint64_t); i++)
    {
        b = bpf_map_lookup_elem(&programs, idx);
        if (b == NULL)
            return false;
        *dst |= ((uint64_t)*b << (8 * i));
        *idx = *idx + 1;
    }
    return true;
}

static inline unsigned short peek_op(struct vm_inst *encrypted_inst, int key)
{
    return encrypted_inst->op ^ (unsigned short)next_key(&key);
}

/// @brief get the next instruction from `programs` map and save data in `inst`.
/// @param inst
/// @param vm
/// @return size of instruction in bytes if success, -1 if error
int get_next_inst(struct vm_inst *inst, struct vm_state *vm)
{
    if (!inst || !vm)
        return -1;

    unsigned int key_idx = 0;
    int *key_ptr = bpf_map_lookup_elem(&key_map, &key_idx);
    if (key_ptr == NULL)
        return -1;
    int key = *key_ptr + vm->pc;

    int size = 0;
    unsigned int program_index_pc = vm->type * VM_MAX_PROGRAM_SIZE + vm->pc;

    if (!get_uint16(&program_index_pc, (uint16_t *)&inst->op))
        return -1;

    unsigned short decrypted_op = peek_op(inst, key);
    size += sizeof(inst->op);
    if (have_dst(decrypted_op))
    {
        get_uint16(&program_index_pc, (uint16_t *)&inst->dst);
        size += sizeof(inst->dst);
    }
    if (have_src(decrypted_op))
    {
        get_uint16(&program_index_pc, (uint16_t *)&inst->src);
        size += sizeof(inst->src);
    }
    if (have_val(decrypted_op))
    {
        get_uint64(&program_index_pc, (uint64_t *)&inst->val);
        size += sizeof(inst->val);
    }
    if (have_offset(decrypted_op))
    {
        get_uint16(&program_index_pc, (uint16_t *)&inst->offset);
        size += sizeof(inst->offset);
    }

    xor_rolling(inst, key);

    return size;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";