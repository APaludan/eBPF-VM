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

//==========================================
//====            HOOK POINTS           ====
//==========================================

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

//==========================================
//====             VM LOGIC             ====
//==========================================

static long vm_callback_fn(unsigned int nr_loops, void *ctx)
{
    struct vm_state *vm = (struct vm_state *)ctx;

    // Fetch encrypted instruction (uses defined vm type in hook point logic to get the right instruction in programs map)
    // PTRACE_PROGRAM = 0 (defined in vm.h) has the first VM_MAX_INSTRUCTIONS entries of the map
    // LSM_OPEN_PROGRAM = 1 (defined in vm.h) has the entries after the first VM_MAX_INSTRUCTIONS entries of the map
    // TODO: make more memory effecient a lot of unused slots atm
    unsigned int program_index_pc = vm->type * VM_MAX_INSTRUCTIONS + vm->pc;
    struct vm_inst *inst_ptr = bpf_map_lookup_elem(&programs, &program_index_pc);

    if (!inst_ptr)
        return vm_error(vm);

    // Copy to stack
    struct vm_inst inst = *inst_ptr;

    // get key and decrypt instruction
    unsigned int index = 0;
    int *key_ptr = bpf_map_lookup_elem(&key_map, &index);
    if (!key_ptr)
        return vm_error(vm);
    int key = *key_ptr;
    xor_rolling(&inst, key + vm->pc);

    inst.dst &= 0xFF;
    inst.src &= 0xFF;

    // just some checks to make verifier happy
    if ((inst.dst >= VM_NUM_REGS) || (inst.src >= VM_NUM_REGS))
    {
        return vm_error(vm);
    }

    switch (inst.op)
    {
    case OP_LOAD:
        vm->regs[inst.dst] = inst.val;
        break;

    case OP_ADD:
        vm->regs[inst.dst] += inst.val == 0 ? vm->regs[inst.src] : inst.val;
        break;

    case OP_SUB:
        vm->regs[inst.dst] -= inst.val == 0 ? vm->regs[inst.src] : inst.val;
        break;

    case OP_MULT:
        vm->regs[inst.dst] *= inst.val == 0 ? vm->regs[inst.src] : inst.val;
        break;

    case OP_DIV:
        vm->regs[inst.dst] /= inst.val == 0 ? vm->regs[inst.src] : inst.val;
        break;

    case OP_PRINT:
        bpf_printk("VM Reg[%d] = %llu", inst.src, vm->regs[inst.src]);
        break;

    case OP_PRINTI:
        bpf_printk("VM Reg[%d] = %lli", inst.src, vm->regs[inst.src]);
        break;

    case OP_PRINTS:
        bpf_printk("VM String = %s", (char *)vm->regs[inst.src]);
        break;

    case OP_EXIT:
        return 1;

    case OP_CALL:
        switch (inst.val)
        {
        case 14:
            vm->regs[0] = ((long (*)(void))(long)inst.val)();
            break;

        case 16:
            if (vm->sp + TASK_COMM_LEN > VM_STACK_SIZE)
                return vm_error(vm);

            vm->regs[0] =
                ((long (*const)(void *, unsigned int))(long)inst.val)(
                    (void *)&vm->stack[vm->sp], TASK_COMM_LEN);
            break;

        default:
            bpf_printk("call failed, id: %llu", inst.val);
            return vm_error(vm);
        }
        break;

    case OP_LSHIFT:
        vm->regs[inst.dst] = vm->regs[inst.src] << inst.val;
        break;

    case OP_RSHIFT:
        vm->regs[inst.dst] = vm->regs[inst.src] >> inst.val;
        break;

    case OP_JMP:
        vm->pc += inst.val;
        return 0;

    case OP_JEQ:
        if (vm->regs[inst.dst] == vm->regs[inst.src])
        {
            vm->pc += inst.val;
            return 0;
        }
        break;

    case OP_JNEQ:
        if (vm->regs[inst.dst] != vm->regs[inst.src])
        {
            vm->pc += inst.val;
            return 0;
        }
        break;

    case OP_READ:
    {
        if (inst.val <= 0 || inst.val > (long long)sizeof(vm->regs[0]))
        {
            return vm_error(vm);
        }

        unsigned int size = (unsigned int)inst.val;

        vm->regs[0] = bpf_probe_read_kernel(&vm->regs[inst.dst],
                                            size,
                                            (void *)vm->regs[inst.src]);
        break;
    }

    case OP_READ_CTX:
    {
        if (inst.val <= 0 || inst.val > (long long)sizeof(vm->regs[0]))
        {
            return vm_error(vm);
        }

        unsigned int size = (unsigned int)inst.val;

        vm->regs[0] = bpf_probe_read_kernel(&vm->regs[inst.dst],
                                            size,
                                            vm->data + inst.offset);

        break;
    }

    case OP_RINGBUF:
    {
        struct vm_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
        if (e)
        {
            e->caller_pid = bpf_get_current_pid_tgid() >> 32;
            e->type = vm->type;
            bpf_get_current_comm(e->caller_name, sizeof(e->caller_name));

            for (int i = 0; i < VM_NUM_REGS; i++)
            {
                e->reg_values[i] = vm->regs[i];
            }

            e->pc = vm->pc;
            bpf_ringbuf_submit(e, 0);
        }
        break;
    }

    case OP_LOAD_SP:
        vm->regs[inst.dst] = (unsigned long long)&vm->stack[vm->sp];
        break;

    case OP_SET_SP:
        vm->sp += inst.val;
        break;

    default:
        bpf_printk("Unknown op %i at pc=", inst.op, vm->pc);
        return vm_error(vm);
    }

    vm->pc++;
    return 0;
}

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

char LICENSE[] SEC("license") = "Dual BSD/GPL";
