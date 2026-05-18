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

    sudo modprobe -r dummy

*/

std::vector<vm_inst> make_module_free_program()
{
    return {
        // set register 1 to  __data_loc_name (offset of 20 bytes)
        {OP_READ_CTX, 1, 0, sizeof(uint32_t), 20},
        // store a bit mask to extract some of the __data_loc_name
        {OP_LOAD, 2, 0, 0xFFFF, 0},
        // use and operation to get lower bits of register one (moule name in __data_loc_name)
        {OP_AND, 1, 2, 0, 0},
        // sent to ringbuffer and exit
        {OP_RINGBUF, 0, 0, 0, 0},
        {OP_EXIT, 0, 0, 0, 0}
    };
}