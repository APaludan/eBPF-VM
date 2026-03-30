#pragma once

// system
#define OP_EXIT 0 // exit VM and eBPF. return code = r0
#define OP_CALL 1 // call a helper function by id (can find id on docs.ebpf.io)

// math things
#define OP_ADD 10    // add regs[dst] += regs[src]
#define OP_SUB 11    // minus
#define OP_MULT 12   // multiply
#define OP_DIV 13    // divide
#define OP_LSHIFT 14 // bit shift dst = src << val
#define OP_RSHIFT 15 // bit shift dst = src >> val

// control flow
#define OP_JMP 30   // jump pc += val
#define OP_JEQ 31   // jump if dst == src
#define OP_JNEQ 32  // jump if dst != src
#define OP_JGT 33   // TODO: jump if dst > src
#define OP_JGTEQ 34 // TODO: jump if dst >= src

// memory
#define OP_LOAD 40     // load regs[dst] = val
#define OP_LOAD_SP 41  // load sp into reg[dst]
#define OP_SET_SP 42   // inc/dec sp by a val or a value of reg[src]
#define OP_READ 43     // read val bytes from ptr
#define OP_READ_CTX 44 // read from vm.data. src = offset, val = size in bytes
                       // how to find offsets:
                       // pahole -C <struct name>
                       // exmaple: pahole -C file
#define OP_PUSH 45     // TODO: push regs[src] onto stack and sp += 8
#define OP_POP 46      // TODO: sp -= 8 and pop top of stack into a regs[dst]
#define OP_MOV 47      // TODO: moves from reg[src] to reg[dst]

// output
#define OP_PRINT 60   // print bpf_printk(regs[src]) as %llu
#define OP_PRINTI 61  // print bpf_printk(regs[src]) as %i
#define OP_PRINTS 62  // prints the string at addr regs[src]
#define OP_RINGBUF 63 // submit vm state to ringbuffer

#define VM_MAX_INSTRUCTIONS 10000
#define VM_MAX_LOOPS 100000
#define VM_STACK_SIZE 256
#define VM_NUM_REGS 16

#define MAX_PROGRAMS 2
#define PTRACE_PROGRAM 0
#define LSM_OPEN_PROGRAM 1

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
    VM_ERROR = 10,
};

struct vm_event
{
    char caller_name[16];
    pid_t caller_pid;
    unsigned long long reg_values[VM_NUM_REGS];
    enum vm_event_type type;
    unsigned int pc;
};

struct vm_inst
{
    unsigned short op;
    unsigned short dst;
    unsigned short src;
    long long val;
};

struct vm_state
{
    unsigned long long regs[VM_NUM_REGS];
    unsigned int pc;
    char stack[VM_STACK_SIZE];
    unsigned short sp;
    void *map;
    void *data;
    enum vm_event_type type;
};

static inline int next_key(int *current)
{
    *current = *current + 7;
    return *current;
}

static inline void xor_rolling(struct vm_inst *data, int key)
{
    data->op ^= (unsigned short)next_key(&key);
    data->dst ^= (unsigned short)next_key(&key) >> 1;
    data->val ^= (long long)next_key(&key);
    data->val ^= (long long)next_key(&key) << 32;
    data->src ^= (unsigned short)next_key(&key) >> 1;
}