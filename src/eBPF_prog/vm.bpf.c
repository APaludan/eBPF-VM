#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "vm.h"
#include <errno.h>

struct
{
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * sizeof(struct vm_event));
} rb SEC(".maps");

struct
{
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, VM_MAX_INSTRUCTIONS * sizeof(struct vm_inst));
  __type(key, __u32);
  __type(value, struct vm_inst);
} bytecode_map SEC(".maps");

static long vm_callback_fn(u64 index, void *ctx)
{
  struct vm_state *vm = (struct vm_state *)ctx;

  struct vm_inst *inst = bpf_map_lookup_elem(vm->map, &vm->pc);
  if (!inst)
    return 1;

  // bpf_printk("instruction: idx(%llu) id(%i)", index, inst->op);

  if (inst->dst >= 4 || (inst->src >= 4 && inst->op != OP_READ_CTX))
    return 1;

  switch (inst->op)
  {
  case OP_LOAD:
    vm->regs[inst->dst] = inst->val;
    break;

  case OP_ADD:
    vm->regs[inst->dst] += vm->regs[inst->src];
    break;

  case OP_MIN:
    vm->regs[inst->dst] -= vm->regs[inst->src];
    break;

  case OP_MULT:
    vm->regs[inst->dst] *= vm->regs[inst->src];
    break;

  case OP_DIV:
    vm->regs[inst->dst] /= vm->regs[inst->src];
    break;

  case OP_PRINT:
    bpf_printk("VM Reg[%d] = %i", inst->dst, vm->regs[inst->dst]);
    break;

  case OP_EXIT:
    return 1;

  case OP_CALL:
    switch (inst->val)
    {
    case 14:
      vm->regs[0] = ((long (*)(void))14)();
      break;
    default:
      bpf_printk("call failed, id: %llu", inst->val);
      return 1;
    }
    break;

  case OP_LSHIFT:
    vm->regs[inst->dst] = vm->regs[inst->src] << inst->val;
    break;

  case OP_RSHIFT:
    vm->regs[inst->dst] = vm->regs[inst->src] >> inst->val;
    break;

  case OP_JMP:
    vm->pc = (u32)inst->val;
    return 0;

  case OP_JEQ:
    if (vm->regs[inst->dst] == vm->regs[inst->src])
    {
      vm->pc = (u32)inst->val;
      return 0;
    }
    break;

  case OP_JNEQ:
    if (vm->regs[inst->dst] != vm->regs[inst->src])
    {
      vm->pc = (u32)inst->val;
      return 0;
    }
    break;

  case OP_READ_CTX:
  {
    unsigned int len = (unsigned long)inst->val;
    if (len > sizeof(vm->regs[inst->dst]))
      return 1;

    int err = bpf_probe_read_kernel(&vm->regs[inst->dst], len, vm->data + (size_t)inst->src);
    if (err)
      bpf_printk("read error, val: %i", err);

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
      for (int i = 0; i < 4; i++)
      {
        e->reg_values[i] = vm->regs[i];
      }
      bpf_ringbuf_submit(e, 0);
    }
    break;
  }

  default:
    // unknown op
    bpf_printk("Unknow op %i at pc=", inst->op, vm->pc);
    return 1;
  }

  vm->pc++;
  return 0;
}

SEC("tp/syscalls/sys_enter_ptrace")
int ebpf_vm_interpreter(struct trace_event_raw_sys_enter *ctx)
{
  struct vm_state vm = {0};
  vm.type = PTRACE2;
  vm.data = (void *)ctx;
  vm.map = &bytecode_map;

  bpf_loop(VM_MAX_LOOPS, vm_callback_fn, (void *)&vm, 0);

  // for (u64 i = 0; i < VM_MAX_LOOPS; i++)
  // {
  //   vm_callback_fn(i, (void *) &vm);
  // }

  return 0;
}


char LICENSE[] SEC("license") = "Dual BSD/GPL";