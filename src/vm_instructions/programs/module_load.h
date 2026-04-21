#pragma once

/*
from /sys/kernl/btf/vmlinux

struct trace_event_raw_module_load {
	struct trace_entry ent; = 16 bytes
	unsigned int taints; = 4 bytes
	u32 __data_loc_name;
	char __data[0];
};

TEST:

    sudo modprobe dummy

*/

std::vector<vm_inst> make_module_load_program()
{
    return {
        // set register 1 to  __data_loc_name (offset of 20 bytes)
        vm_inst{OP_READ_CTX, 1, 0, sizeof(uint32_t), 20},
        // store a bit mask to extract some of the __data_loc_name
        vm_inst{OP_LOAD, 2, 0, 0xFFFF, 0},
        // use and operation to get lower bits of register one (moule name in __data_loc_name)
        vm_inst{OP_AND, 1, 2, 0, 0},
        // sent to ringbuffer and exit
        vm_inst{OP_RINGBUF, 0, 0, 0, 0},
        vm_inst{OP_EXIT, 0, 0, 0, 0}
    };
}