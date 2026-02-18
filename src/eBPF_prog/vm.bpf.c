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

struct
{
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * sizeof(struct vm_event));
} rb SEC(".maps");

struct
{
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, VM_MAX_INSTRUCTIONS * sizeof(struct vm_inst));
  __type(key, unsigned int);
  __type(value, struct vm_inst);
} bytecode_map SEC(".maps");

SEC("tp/syscalls/sys_enter_ptrace")
int ebpf_vm_interpreter(struct trace_event_raw_sys_enter *ctx)
{
  struct vm_state vm = {0};
  vm.type = PTRACE2;
  vm.data = (void *)ctx;
  vm.map = &bytecode_map;

  bpf_loop(VM_MAX_LOOPS, vm_callback_fn, (void *)&vm, 0);

  return (int)vm.regs[0];
}

static long vm_callback_fn(unsigned int nr_loops, void *ctx)
{
  struct vm_state *vm = (struct vm_state *)ctx;

  struct vm_inst *inst = bpf_map_lookup_elem(vm->map, &vm->pc);
  if (!inst)
    return vm_error(vm);

  if (inst->dst >= VM_NUM_REGS || (inst->src >= VM_NUM_REGS && inst->op != OP_READ_CTX))
    return vm_error(vm);

  switch (inst->op)
  {
  case OP_LOAD:
    vm->regs[inst->dst] = (long long) inst->val;
    break;

  case OP_ADD:
    vm->regs[inst->dst] += inst->val == 0 ? vm->regs[inst->src] : inst->val;
    break;

  case OP_SUB:
    vm->regs[inst->dst] -= inst->val == 0 ? vm->regs[inst->src] : inst->val;
    break;

  case OP_MULT:
    vm->regs[inst->dst] *= inst->val == 0 ? vm->regs[inst->src] : inst->val;
    break;

  case OP_DIV:
    vm->regs[inst->dst] /= inst->val == 0 ? vm->regs[inst->src] : inst->val;
    break;

  case OP_PRINT:
    bpf_printk("VM Reg[%d] = %llu", inst->src, vm->regs[inst->src]);
    break;
  case OP_PRINTI:
    bpf_printk("VM Reg[%d] = %lli", inst->src, vm->regs[inst->src]);
    break;
  case OP_PRINTS:
    bpf_printk("VM String = %s", (char *)vm->regs[inst->src]);
    break;

  case OP_EXIT:
    bpf_printk("Exit after %u loops", nr_loops);
    return 1;

  case OP_CALL:
    switch (inst->val)
    {
    case 14:
      vm->regs[0] = ((long (*)(void))(long)inst->val)();
      break;
    case 16:
      if (vm->sp + TASK_COMM_LEN > VM_STACK_SIZE)
        return vm_error(vm);

      vm->regs[0] = ((long (*const)(void *, unsigned int))(long)inst->val)((void *)&vm->stack[vm->sp], TASK_COMM_LEN);
      break;
    default:
      bpf_printk("call failed, id: %llu", inst->val);
      return vm_error(vm);
    }
    break;

  case OP_LSHIFT:
    vm->regs[inst->dst] = vm->regs[inst->src] << inst->val;
    break;

  case OP_RSHIFT:
    vm->regs[inst->dst] = vm->regs[inst->src] >> inst->val;
    break;

  case OP_JMP:
    vm->pc += inst->val;
    return 0;

  case OP_JEQ:
    if (vm->regs[inst->dst] == vm->regs[inst->src])
    {
      vm->pc += inst->val;
      return 0;
    }
    break;

  case OP_JNEQ:
    if (vm->regs[inst->dst] != vm->regs[inst->src])
    {
      vm->pc += inst->val;
      return 0;
    }
    break;

  case OP_READ_CTX:
  {
    unsigned int len = (unsigned int)inst->val;
    if (len > sizeof(vm->regs[inst->dst]))
      return vm_error(vm);

    int err = bpf_probe_read_kernel(&vm->regs[inst->dst], len, vm->data + (size_t)inst->src);
    if (err)
      return vm_error(vm);

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
      bpf_ringbuf_submit(e, 0);
    }
    break;
  }
  case OP_LOAD_SP:
    vm->regs[inst->dst] = (unsigned long long)&vm->stack[vm->sp];
    break;
  case OP_SET_SP:
    vm->sp += inst->val;
    break;

  default:
    // unknown op
    bpf_printk("Unknow op %i at pc=", inst->op, vm->pc);
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