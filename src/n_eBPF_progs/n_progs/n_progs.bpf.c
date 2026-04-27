#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-declarations"
#include "vmlinux.h"
#pragma clang diagnostic pop

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "vm.h"
#include <errno.h>

#include <bpf/bpf_endian.h>


#define PROC_SUPER_MAGIC 0x9fa0

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define IPPROTO_ICMP 1
#define IPPROTO_ICMPV6 58


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
SEC("tp/syscalls/sys_enter_ptrace")
int ptrace_entry(struct trace_event_raw_sys_enter *ctx) 
{
    pid_t caller_pid = (pid_t)(bpf_get_current_pid_tgid() >> 32);
    pid_t target;

    bpf_core_read(&target, sizeof(target), &ctx->args[1]);

    if (target != PROTECTED_PID || caller_pid == PROTECTED_PID)
        return 0;

    struct vm_event *e = bpf_ringbuf_reserve(&rb, sizeof(struct vm_event), 0);
    if (!e)
        return 0;

    e->type = PTRACE_PROGRAM;
    e->caller_pid = caller_pid;

    bpf_get_current_comm(e->caller_name, sizeof(e->caller_name));

    bpf_printk("ptrace called by %s(pid %i)",
                e->caller_name, e->caller_pid);

    bpf_ringbuf_submit(e, 0);

    return 0;
}

//=============================================================================
SEC("lsm/file_open")
int BPF_PROG(restrict_proc_access, struct file *file) 
{
    pid_t caller_pid = bpf_get_current_pid_tgid() >> 32;

    if (caller_pid == PROTECTED_PID)
        return 0;

    unsigned long magic = BPF_CORE_READ(file, f_inode, i_sb, s_magic);
    if (magic != PROC_SUPER_MAGIC)
        return 0; // return if not part of procfs

    // file->f_path.dentry->d_name.name
    char *name = (char *)BPF_CORE_READ(file, f_path.dentry, d_name.name);

    bool is_restricted_file_name = (     bpf_strcmp(name, "maps") == 0 
                                        || bpf_strcmp(name, "smaps") == 0 
                                        || bpf_strcmp(name, "mem") == 0);

    if (is_restricted_file_name) 
    {
        char *parent_name = (char *)BPF_CORE_READ(file, f_path.dentry, d_parent, d_name.name);
        char protected_pid_s[16];
        BPF_SNPRINTF(protected_pid_s, sizeof(protected_pid_s), "%d", PROTECTED_PID);

        bool is_parent_protected_pid = bpf_strcmp(protected_pid_s, parent_name) == 0;

        if (is_parent_protected_pid) 
        {
            struct vm_event *event = bpf_ringbuf_reserve(&rb, sizeof(struct vm_event), 0);

            if (!event) 
            {
                return -EPERM;
            }

            event->type = LSM_OPEN_PROGRAM;
            event->caller_pid = caller_pid;

            bpf_get_current_comm(event->caller_name, sizeof(event->caller_name));

            bpf_printk("open called by %s(pid %i)", 
                        event->caller_name, event->caller_pid);

            bpf_ringbuf_submit(event, 0);
            return -EPERM;
        }
        return 0;
  }

  return 0;
}

//=============================================================================
SEC("kprobe/find_vpid")
int BPF_KPROBE(kprobe_find_vpid, int nr) {
  pid_t looked_up_pid = (pid_t)nr;

  if (looked_up_pid != PROTECTED_PID)
    return 0;


  struct vm_event *e = bpf_ringbuf_reserve(&rb, sizeof(struct vm_event), 0);

  if (!e)
    return 0;

  e->type = KPROBE_FIND_VPID_PROGRAM;
  e->caller_pid = bpf_get_current_pid_tgid() >> 32;

  bpf_get_current_comm(e->caller_name, sizeof(e->caller_name));
  bpf_ringbuf_submit(e, 0);

  bpf_printk("vpid lookup by %s, arg: %i", e->caller_name, nr);

  return 0;
}

//=============================================================================

SEC("kretprobe/pid_task")
int BPF_KRETPROBE(kprobe_pid_task_exit, struct task_struct *return_val) {
    pid_t looked_up_pid = BPF_CORE_READ(return_val, pid);

    if (looked_up_pid != PROTECTED_PID)
        return 0;


    struct vm_event *e = bpf_ringbuf_reserve(&rb, sizeof(struct vm_event), 0);
    if (!e)
        return 0;

    e->type = KPROBE_PID_TASK_PROGRAM;
    e->caller_pid = bpf_get_current_pid_tgid() >> 32;

    bpf_get_current_comm(e->caller_name, sizeof(e->caller_name));
    bpf_ringbuf_submit(e, 0);

    bpf_printk("task lookup by %s, arg: %i", e->caller_name, looked_up_pid);

    return 0;
}

//=============================================================================
SEC("xdp")
int xdp_simple_filter(struct xdp_md *xdp)
{
	void *data_end = (void *)(long)xdp->data_end;
	void *data = (void *)(long)xdp->data;
	struct ethhdr *eth = data;
	struct ipv6hdr *ip6;
	struct iphdr *ip;    
    
    if ((void *) (eth + 1) > data_end)
		return XDP_DROP;

    switch (eth->h_proto) 
    {
		case bpf_htons(ETH_P_IP):
			ip = data+sizeof(struct ethhdr);
			if ((void *) (ip + 1) > data_end)
				return XDP_DROP;
			if (ip->protocol != IPPROTO_ICMP) 
				return XDP_PASS;
			break;

        case bpf_htons(ETH_P_IPV6):
			ip6 = data+sizeof(struct ethhdr);
			if ((void *) (ip6 + 1) > data_end)
				return XDP_DROP;
			if (ip6->nexthdr != IPPROTO_ICMPV6)
				return XDP_PASS;
			break;

		default:
			return XDP_PASS;
	}

    return XDP_DROP;
}

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