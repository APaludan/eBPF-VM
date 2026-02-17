#pragma once

#define OP_LOAD 0      // Load: regs[dst] = val
#define OP_ADD 1       // add: regs[dst] += regs[src]
#define OP_MIN 2       // minus
#define OP_MULT 3      // multiply
#define OP_DIV 4       // divide
#define OP_PRINT 5     // print: bpf_printk(regs[dst])
#define OP_EXIT 6      // exit VM
#define OP_CALL 7      // call a function by id: val()
#define OP_LSHIFT 8     // bit shift: src = dst << val
#define OP_RSHIFT 9     // bit shift: src = dst >> val
#define OP_JMP 10       // jump: set pc to a specific value
#define OP_JEQ 11      // jump: if dst == src
#define OP_JNEQ 12     // jump: if dst != src
#define OP_READ_CTX 13 // read from vm.data. src = offset, val = size in bytes
// how to find offsets: sudo cat /sys/kernel/tracing/events/syscalls/sys_enter_ptrace/format
#define OP_RINGBUF 14 // submit vm state to ringbuffer

#define VM_MAX_INSTRUCTIONS 10000
#define VM_MAX_LOOPS 100000

enum vm_event_type
{
  ANY = 0,
  PTRACE2 = 1,
  OPEN2 = 2,
  WRITE2 = 3,
  READ2 = 4,
  VM_WRITE2 = 5,
  VM_READ2 = 6,
  PROCFS2 = 7,
  K_TASK_LOOKUP2 = 8,
  K_VPID_LOOKUP2 = 9,
};

struct vm_event
{
  char caller_name[16];
  pid_t caller_pid;
  unsigned long long reg_values[4];
  enum vm_event_type type;
};

struct vm_inst
{
  unsigned char op;
  unsigned short dst;
  unsigned short src;
  int val;
};

struct vm_state
{
  unsigned long long regs[4];
  unsigned int pc;
  void *map;
  void *data;
  enum vm_event_type type;
};