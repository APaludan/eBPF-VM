#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-declarations"
#include "vmlinux.h"
#pragma clang diagnostic pop

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "vm.h"
#include <errno.h>

volatile const pid_t PROTECTED_PID;

//==========================================
//====          MAP STRUCTURES          ====
//==========================================

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * sizeof(struct vm_event));
} rb SEC(".maps");

//==========================================
//====            HOOK POINTS           ====
//==========================================

//=============================================================================
/*
SEC("lsm/bpf")
int BPF_PROG(restrict_bpf, int cmd, union bpf_attr *attr, unsigned int size)
{
    struct vm_state vm = {0};
    vm.type = LSM_BPF_PROGRAM;
    vm.data = (void *)&cmd;

    bpf_loop(VM_MAX_LOOPS, vm_callback_fn, (void *)&vm, 0);

    return (vm.regs[0] == 0) ? 0 : -EPERM;
}
*/
//=============================================================================
/*
SEC("tp/syscalls/sys_enter_ptrace")
int ebpf_vm_interpreter(struct trace_event_raw_sys_enter *ctx)
{
    struct vm_state vm = {0};

    vm.type = PTRACE_PROGRAM;
    vm.data = (void *)ctx;

    bpf_loop(VM_MAX_LOOPS, vm_callback_fn, (void *)&vm, 0);

    return (int)vm.regs[0];
}
*/
//=============================================================================
/*
SEC("lsm/file_open")
int BPF_PROG(restrict_proc_access, struct file *file)
{
    struct vm_state vm = {0};

    vm.type = LSM_OPEN_PROGRAM;
    vm.data = (void *)file;

    bpf_loop(VM_MAX_LOOPS, vm_callback_fn, (void *)&vm, 0);

    return 0; // keep for testing

    return (vm.regs[0] == 0) ? 0 : -EPERM;
}
*/
//=============================================================================
/*
SEC("kprobe/find_vpid")
int BPF_KPROBE(kprobe_find_vpid, int nr)
{
    struct vm_state vm = {0};

    vm.type = KPROBE_FIND_VPID_PROGRAM;
    vm.data = (void *)&nr;

    bpf_loop(VM_MAX_LOOPS, vm_callback_fn, (void *)&vm, 0);

    return (int)vm.regs[0];
}
*/
//=============================================================================
/*
SEC("kretprobe/pid_task")
int BPF_KRETPROBE(kprobe_pid_task_exit, struct task_struct *return_val)
{
    struct vm_state vm = {0};

    vm.type = KPROBE_PID_TASK_PROGRAM;
    vm.data = (void *)return_val;

    bpf_loop(VM_MAX_LOOPS, vm_callback_fn, (void *)&vm, 0);

    return (int)vm.regs[0];
}
*/
//=============================================================================
/*
SEC("xdp")
int xdp_simple_filter(struct xdp_md *ctx)
{
    struct vm_state vm = {0};
    vm.type = SIMPLE_FILTER_PROGRAM;
    vm.data = (void *)(long)ctx->data;

    bpf_loop(VM_MAX_LOOPS, vm_callback_fn, (void *)&vm, 0);

    return (int)vm.regs[0];
}
*/
//=============================================================================
SEC("tp/module/module_load")
int handle_module_load(struct trace_event_raw_module_load *ctx) 
{
    struct vm_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    u32 name_offset;
    bpf_core_read(&name_offset, sizeof(name_offset), &ctx->__data_loc_name);
    bpf_probe_read_kernel_str(e->caller_name, sizeof(e->caller_name), (void *)ctx + (name_offset & 0xFFFF));

    e->caller_pid = bpf_get_current_pid_tgid() >> 32;
    e->type = MODULE_LOAD_PROGRAM;

    bpf_ringbuf_submit(e, 0);
    return 0;
}


//=============================================================================
SEC("tp/module/module_free")
int handle_module_unload(struct trace_event_raw_module_load *ctx) 
{
    struct vm_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    u32 name_offset;
    bpf_core_read(&name_offset, sizeof(name_offset), &ctx->__data_loc_name);
    bpf_probe_read_kernel_str(e->caller_name, sizeof(e->caller_name), (void *)ctx + (name_offset & 0xFFFF));

    e->caller_pid = bpf_get_current_pid_tgid() >> 32;
    e->type = MODULE_FREE_PROGRAM;

    bpf_ringbuf_submit(e, 0);
    return 0;
}


char LICENSE[] SEC("license") = "Dual BSD/GPL";