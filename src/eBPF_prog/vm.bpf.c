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
    __uint(max_entries, VM_DATA_SIZE);
    __type(key, unsigned int);
    __type(value, unsigned long long);
} data SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, VM_MAX_PROGRAM_SIZE * MAX_PROGRAMS);
    __type(key, unsigned int);
    __type(value, uint8_t);
} programs SEC(".maps");

#ifdef ENABLE_COUNTERS
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_PROGRAMS);
    __type(key, unsigned int);
    __type(value, unsigned long long);
} counters SEC(".maps");
#endif

#include "vm_dispatch.h"

static long vm_callback_fn(unsigned int nr_loops, void *ctx);

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
    return 0; // for testing

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
    
    return 0; //For testing

    return (vm.regs[0] == 0) ? 0 : -EPERM;
}

SEC("kprobe/find_vpid")
int BPF_KPROBE(kprobe_find_vpid, int nr)
{
    struct vm_state vm = {0};

    vm.type = KPROBE_FIND_VPID_PROGRAM;
    vm.data = (void *)&nr;


    bpf_loop(VM_MAX_LOOPS, vm_callback_fn, (void *)&vm, 0);

    return (int)vm.regs[0];
}

SEC("kretprobe/pid_task")
int BPF_KRETPROBE(kprobe_pid_task_exit, struct task_struct *return_val)
{
    struct vm_state vm = {0};

    vm.type = KPROBE_PID_TASK_PROGRAM;
    vm.data = (void *)return_val;


    bpf_loop(VM_MAX_LOOPS, vm_callback_fn, (void *)&vm, 0);

    return (int)vm.regs[0];
}

SEC("xdp")
int xdp_simple_filter(struct xdp_md *ctx)
{
    struct vm_state vm = {0};
    vm.type = SIMPLE_FILTER_PROGRAM;
    vm.data = (void *)(long)ctx->data;

    bpf_loop(VM_MAX_LOOPS, vm_callback_fn, (void *)&vm, 0);
    // return vm.regs[0] to block icmp v4 and v6
    return 2;
}

SEC("tp/module/module_load")
int handle_module_load(struct trace_event_raw_module_load *ctx)
{
    struct vm_state vm = {0};

    vm.type = MODULE_LOAD_PROGRAM;
    vm.data = (void *)ctx;

    bpf_loop(VM_MAX_LOOPS, vm_callback_fn, (void *)&vm, 0);

    return (int)vm.regs[0];
}

SEC("tp/module/module_free")
int handle_module_unload(struct trace_event_raw_module_load *ctx)
{
    struct vm_state vm = {0};

    vm.type = MODULE_FREE_PROGRAM;
    vm.data = (void *)ctx;

    bpf_loop(VM_MAX_LOOPS, vm_callback_fn, (void *)&vm, 0);

    return (int)vm.regs[0];
}


#pragma region decoys

//==========================================
//====         DECOY HOOK POINTS        ====
//==========================================

SEC("tp/syscalls/sys_enter_read")
int trace_read(struct trace_event_raw_sys_enter *ctx)
{
    struct vm_state vm = {0};
    vm.type = TRACE_READ_PROGRAM;
    vm.data = (void *)ctx;

    bpf_loop(VM_MAX_LOOPS, vm_callback_fn, (void *)&vm, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_write")
int trace_write(struct trace_event_raw_sys_enter *ctx)
{
    struct vm_state vm = {0};
    vm.type = TRACE_WRITE_PROGRAM;
    vm.data = (void *)ctx;


    bpf_loop(VM_MAX_LOOPS, vm_callback_fn, (void *)&vm, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_open")
int trace_open(struct trace_event_raw_sys_enter *ctx)
{
    struct vm_state vm = {0};
    vm.type = TRACE_OPEN_PROGRAM;
    vm.data = (void *)ctx;

    bpf_loop(VM_MAX_LOOPS, vm_callback_fn, (void *)&vm, 0);
    return 0;
}

SEC("lsm/inode_permission")
int BPF_PROG(inode_check, struct inode *inode, int mask)
{
    struct vm_state vm = {0};
    vm.type = INODE_CHECK_PROGRAM;
    vm.data = (void *)inode;

    bpf_loop(VM_MAX_LOOPS, vm_callback_fn, (void *)&vm, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct vm_state vm = {0};
    vm.type = TRACE_EXECVE_PROGRAM;
    vm.data = (void *)ctx;

    bpf_loop(VM_MAX_LOOPS, vm_callback_fn, (void *)&vm, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_close")
int trace_close(struct trace_event_raw_sys_enter *ctx)
{
    struct vm_state vm = {0};
    vm.type = TRACE_CLOSE_PROGRAM;
    vm.data = (void *)ctx;

    bpf_loop(VM_MAX_LOOPS, vm_callback_fn, (void *)&vm, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_ioctl")
int trace_ioctl(struct trace_event_raw_sys_enter *ctx)
{
    struct vm_state vm = {0};
    vm.type = TRACE_IOCTL_PROGRAM;
    vm.data = (void *)ctx;

    bpf_loop(VM_MAX_LOOPS, vm_callback_fn, (void *)&vm, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
    struct vm_state vm = {0};
    vm.type = TRACE_OPENAT_PROGRAM;
    vm.data = (void *)ctx;

    bpf_loop(VM_MAX_LOOPS, vm_callback_fn, (void *)&vm, 0);
    return 0;
}


SEC("tp/syscalls/sys_enter_unlink")
int trace_unlink(struct trace_event_raw_sys_enter *ctx)
{
    struct vm_state vm = {0};
    vm.type = TRACE_UNLINK_PROGRAM;
    vm.data = (void *)ctx;

    bpf_loop(VM_MAX_LOOPS, vm_callback_fn, (void *)&vm, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_rename")
int trace_rename(struct trace_event_raw_sys_enter *ctx)
{
    struct vm_state vm = {0};
    vm.type = TRACE_RENAME_PROGRAM;
    vm.data = (void *)ctx;

    bpf_loop(VM_MAX_LOOPS, vm_callback_fn, (void *)&vm, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_chmod")
int trace_chmod(struct trace_event_raw_sys_enter *ctx)
{
    struct vm_state vm = {0};
    vm.type = TRACE_CHMOD_PROGRAM;
    vm.data = (void *)ctx;

    bpf_loop(VM_MAX_LOOPS, vm_callback_fn, (void *)&vm, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_chown")
int trace_chown(struct trace_event_raw_sys_enter *ctx)
{
    struct vm_state vm = {0};
    vm.type = TRACE_CHOWN_PROGRAM;
    vm.data = (void *)ctx;

    bpf_loop(VM_MAX_LOOPS, vm_callback_fn, (void *)&vm, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_mkdir")
int trace_mkdir(struct trace_event_raw_sys_enter *ctx)
{
    struct vm_state vm = {0};
    vm.type = TRACE_MKDIR_PROGRAM;
    vm.data = (void *)ctx;

    bpf_loop(VM_MAX_LOOPS, vm_callback_fn, (void *)&vm, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_rmdir")
int trace_rmdir(struct trace_event_raw_sys_enter *ctx)
{
    struct vm_state vm = {0};
    vm.type = TRACE_RMDIR_PROGRAM;
    vm.data = (void *)ctx;

    bpf_loop(VM_MAX_LOOPS, vm_callback_fn, (void *)&vm, 0);
    return 0;
}

SEC("lsm/file_mprotect")
int BPF_PROG(lsm_file_mprotect, struct file *file, unsigned long prot)
{
    struct vm_state vm = {0};
    vm.type = LSM_MPROTECT_PROGRAM;
    vm.data = (void *)file;

    bpf_loop(VM_MAX_LOOPS, vm_callback_fn, (void *)&vm, 0);
    return 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(lsm_bprm_check, struct linux_binprm *bprm)
{
    struct vm_state vm = {0};
    vm.type = LSM_CHECK_SEC_PROGRAM;
    vm.data = (void *)bprm;

    bpf_loop(VM_MAX_LOOPS, vm_callback_fn, (void *)&vm, 0);
    return 0;
}

SEC("lsm/task_alloc")
int BPF_PROG(lsm_task_alloc, struct task_struct *p)
{
    struct vm_state vm = {0};
    vm.type = LSM_TASK_ALLOC_PROGRAM;
    vm.data = (void *)p;

    bpf_loop(VM_MAX_LOOPS, vm_callback_fn, (void *)&vm, 0);
    return 0;
}

SEC("lsm/task_free")
int BPF_PROG(lsm_task_free, struct task_struct *p)
{
    struct vm_state vm = {0};
    vm.type = LSM_TASK_FREE_PROGRAM;
    vm.data = (void *)p;

    bpf_loop(VM_MAX_LOOPS, vm_callback_fn, (void *)&vm, 0);
    return 0;
}

SEC("kprobe/security_file_open")
int BPF_KPROBE(kprobe_file_open, struct file *file)
{
    struct vm_state vm = {0};
    vm.type = KPROBE_SEC_FILE_OPEN_PROGRAM;
    vm.data = (void *)file;

    bpf_loop(VM_MAX_LOOPS, vm_callback_fn, (void *)&vm, 0);
    return 0;
}

SEC("kprobe/security_mmap_file")
int BPF_KPROBE(kprobe_mmap_file, struct file *file, unsigned long prot)
{
    struct vm_state vm = {0};
    vm.type = KPROBE_SEC_MMAP_PROGRAM;
    vm.data = (void *)file;

    bpf_loop(VM_MAX_LOOPS, vm_callback_fn, (void *)&vm, 0);
    return 0;
}

SEC("kprobe/security_file_mprotect")
int BPF_KPROBE(kprobe_file_mprotect, struct file *file, unsigned long prot)
{
    struct vm_state vm = {0};
    vm.type = KPROBE_SEC_MPROTECT_PROGRAM;
    vm.data = (void *)file;

    bpf_loop(VM_MAX_LOOPS, vm_callback_fn, (void *)&vm, 0);
    return 0;
}


SEC("tp/syscalls/sys_enter_clone")
int trace_clone(struct trace_event_raw_sys_enter *ctx)
{
    struct vm_state vm = {0};
    vm.type = TRACE_CLONE_PROGRAM;
    vm.data = (void *)ctx;

    bpf_loop(VM_MAX_LOOPS, vm_callback_fn, (void *)&vm, 0);
    return 0;
}

SEC("tp/iommu/add_device_to_group")
int trace_iommu_add_device(struct bpf_raw_tracepoint_args *ctx)
{
    struct vm_state vm = {0};
    vm.type = TRACE_IOMMU_ADD_GROUP_PROGRAM;
    vm.data = (void *)ctx;

    bpf_loop(VM_MAX_LOOPS, vm_callback_fn, (void *)&vm, 0);
    return 0;
}

SEC("tp/iommu/remove_device_from_group")
int trace_iommu_remove_device(struct bpf_raw_tracepoint_args *ctx)
{
    struct vm_state vm = {0};
    vm.type = TRACE_IOMMU_REMOVE_GROUP_PROGRAM;
    vm.data = (void *)ctx;

    bpf_loop(VM_MAX_LOOPS, vm_callback_fn, (void *)&vm, 0);
    return 0;
}

SEC("tp/iommu/attach_device_to_domain")
int trace_iommu_attach_device(struct bpf_raw_tracepoint_args *ctx)
{
    struct vm_state vm = {0};
    vm.type = TRACE_IOMMU_ADD_DOMAIN_PROGRAM;
    vm.data = (void *)ctx;

    bpf_loop(VM_MAX_LOOPS, vm_callback_fn, (void *)&vm, 0);
    return 0;
}

SEC("tp/iommu/map")
int trace_iommu_map(struct bpf_raw_tracepoint_args *ctx)
{
    struct vm_state vm = {0};
    vm.type = TRACE_IOMMU_MAP_PROGRAM;
    vm.data = (void *)ctx;

    bpf_loop(VM_MAX_LOOPS, vm_callback_fn, (void *)&vm, 0);
    return 0;
}

SEC("tp/iommu/unmap")
int trace_iommu_unmap(struct bpf_raw_tracepoint_args *ctx)
{
    struct vm_state vm = {0};
    vm.type = TRACE_IOMMU_UNMAP_PROGRAM;
    vm.data = (void *)ctx;

    bpf_loop(VM_MAX_LOOPS, vm_callback_fn, (void *)&vm, 0);
    return 0;
}
#pragma endregion

//==========================================
//====             VM LOGIC             ====
//==========================================

// Core VM execution callback - runs per instruction
// Called by bpf_loop() to iterate through program bytecode
static long vm_callback_fn(unsigned int nr_loops, void *ctx)
{
    struct vm_state *vm = (struct vm_state *)ctx;
    struct vm_inst inst = {0};

    if (nr_loops == 0) {
        #ifdef ENABLE_COUNTERS
        unsigned int count_key = (unsigned int)vm->type;
        
        unsigned long long *value = bpf_map_lookup_elem(&counters, &count_key);
        if (value) {
            __sync_fetch_and_add(value, 1);
        }
        #endif
        
        unsigned int key = 0;
        int *key_ptr = bpf_map_lookup_elem(&key_map, &key);
        if (key_ptr) {
            vm->xor_key = *key_ptr;
        } else {
            return vm_error(vm);
        }
    }

    int size = get_next_inst(&inst, vm);
    if (size == -1)
        return 1;

    //========== INSTRUCTION VALIDATION ==========
    inst.dst &= VM_NUM_REGS - 1;
    inst.src &= VM_NUM_REGS - 1;

    // just some checks to make verifier happy
    if (inst.dst >= VM_NUM_REGS || inst.src >= VM_NUM_REGS)
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

//==========================================
//====          ERROR HANDLING          ====
//==========================================

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

    int key = vm->xor_key + vm->pc;

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