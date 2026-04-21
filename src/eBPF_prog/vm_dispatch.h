#pragma once
#include "vm.h"
#include <bpf/bpf_helpers.h>

//! Instruction Dispatch Helper Functions
//! Organized by instruction category for clarity and maintainability

//====================================================================
//  MATH OPERATIONS
//====================================================================

static inline long vm_exec_math_ops(struct vm_inst *inst, struct vm_state *vm)
{
    switch (inst->op)
    {
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

    case OP_LSHIFT:
        vm->regs[inst->dst] = vm->regs[inst->src] << inst->val;
        break;

    case OP_RSHIFT:
        vm->regs[inst->dst] = vm->regs[inst->src] >> inst->val;
        break;

    case OP_AND:
        vm->regs[inst->dst] = vm->regs[inst->dst] & vm->regs[inst->src];
        break;

    default:
        return -1; // Not a math op
    }
    return 0;
}

//====================================================================
//  MEMORY OPERATIONS
//====================================================================

static inline long vm_exec_memory_ops(struct vm_inst *inst, struct vm_state *vm)
{
    switch (inst->op)
    {
        case OP_LOAD:
            vm->regs[inst->dst] = inst->val;
            break;

        case OP_LOAD_SP:
            vm->regs[inst->dst] = (unsigned long long)&vm->stack[vm->sp];
            break;

        case OP_SET_SP:
            vm->sp += inst->val;
            break;

        case OP_READ:
        {
            if (inst->val <= 0 || inst->val > (long long)sizeof(vm->regs[0]))
            {
                return 1; // error
            }

            unsigned int size = (unsigned int)inst->val;
            vm->regs[0] = bpf_probe_read_kernel(&vm->regs[inst->dst],
                                                size,
                                                (void *)vm->regs[inst->src]);
            break;
        }

        case OP_READ_CTX:
        {
            if (inst->val <= 0 || inst->val > (long long)sizeof(vm->regs[0]))
            {
                return 1; // error
            }

            unsigned int size = (unsigned int)inst->val;
            vm->regs[0] = bpf_probe_read_kernel(&vm->regs[inst->dst],
                                                size,
                                                vm->data + inst->offset);
            break;
        }

        case OP_PUSH:
            // TODO: push regs[src] onto stack and sp += 8
            break;

        case OP_POP:
            // TODO: sp -= 8 and pop top of stack into a regs[dst]
            break;

        case OP_MOV:
            // TODO: move from reg[src] to reg[dst]
            vm->regs[inst->dst] = vm->regs[inst->src];
            break;

        default:
            return -1; // Not a memory op
    }

    return 0;
}

//====================================================================
//  CONTROL FLOW OPERATIONS
//====================================================================

static inline long vm_exec_control_flow_ops(struct vm_inst *inst, struct vm_state *vm)
{
    switch (inst->op)
    {
        case OP_JMP:
            vm->pc += inst->val;
            return 100; // Return early, don't increment pc again

        case OP_JEQ:
            if (vm->regs[inst->dst] == vm->regs[inst->src])
            {
                vm->pc += inst->val;
                return 100; // Return early
            }
            break;

        case OP_JNEQ:
            if (vm->regs[inst->dst] != vm->regs[inst->src])
            {
                vm->pc += inst->val;
                return 100; // Return early
            }
            break;

        case OP_JGT:
            if (vm->regs[inst->dst] > vm->regs[inst->src])
            {
                vm->pc += inst->val;
                return 100;
            }
            break;

        case OP_JGTEQ:
            if (vm->regs[inst->dst] >= vm->regs[inst->src])
            {
                vm->pc += inst->val;
                return 100;
            }
            break;

        case OP_EXIT:
            return 1; // Signal exit

        default:
            return -1; // Not a control flow op
    }

    return 0;
}

//====================================================================
//  I/O & OUTPUT OPERATIONS
//====================================================================

static inline long vm_exec_io_ops(struct vm_inst *inst, struct vm_state *vm)
{
    switch (inst->op)
    {
        case OP_PRINT:
            bpf_printk("VM Reg[%d] = %llu", inst->src, vm->regs[inst->src]);
            break;

        case OP_PRINTI:
            bpf_printk("VM Reg[%d] = %lli", inst->src, vm->regs[inst->src]);
            break;

        case OP_PRINTS:
            bpf_printk("VM String = %s", (char *)vm->regs[inst->src]);
            break;

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

        default:
            return -1; // Not an I/O op
    }
    
    return 0;
}

//====================================================================
//  HELPER FUNCTION CALLS
//====================================================================

static inline long vm_exec_helper_calls(struct vm_inst *inst, struct vm_state *vm)
{
    if (inst->op != OP_CALL)
        return -1;

    switch (inst->val)
    {
        case 14:
            vm->regs[0] = ((long (*)(void))(long)inst->val)();
            break;

        case 16:
            if (vm->sp + TASK_COMM_LEN > VM_STACK_SIZE)
            {
                return 1; // error
            }

            vm->regs[0] =
                ((long (*const)(void *, unsigned int))(long)inst->val)(
                    (void *)&vm->stack[vm->sp], TASK_COMM_LEN);
            break;

        default:
            bpf_printk("ERROR: call failed, id: %llu", inst->val);
            return 1; // error
    }

    return 0;
}

//====================================================================
//  MAIN DISPATCHER
//====================================================================

static inline long vm_execute_instruction(struct vm_inst *inst, struct vm_state *vm)
{
    long result;

    // Try dispatch by category
    if ((result = vm_exec_math_ops(inst, vm)) != -1)
        return result;

    if ((result = vm_exec_memory_ops(inst, vm)) != -1)
        return result;

    if ((result = vm_exec_control_flow_ops(inst, vm)) != -1)
        return result;

    if ((result = vm_exec_io_ops(inst, vm)) != -1)
        return result;

    if ((result = vm_exec_helper_calls(inst, vm)) != -1)
        return result;

    // Unknown opcode
    bpf_printk("Unknown opcode: %d at pc=%d, prog type: %i", inst->op, vm->pc, vm->type);
    
    return 1; // error
}