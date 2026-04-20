#pragma once

std::vector<vm_inst> make_simple_filter_program()
{
    return {
        // r1 = ethertype
        // Read 2 bytes from ctx->data + 12 (Ethernet type/length)
        vm_inst{OP_READ_CTX, 1, 0, 2, 12},

        // r2 = 0x0008 (IPv4 ethertype read as little-endian)
        vm_inst{OP_LOAD, 2, 0, 0x0008, 0},

        // if r1 != r2 -> PASS
        vm_inst{OP_JNEQ, 1, 2, 2, 0},

        // r1 = protocol byte
        // Read 1 byte from ctx->data + 23 (IPv4 protocol field)
        vm_inst{OP_READ_CTX, 1, 0, 1, 23},

        // r2 = 1 (ICMP)
        vm_inst{OP_LOAD, 2, 0, 1, 0},

        // if r1 != r2 -> PASS
        vm_inst{OP_JNEQ, 1, 2, 2, 0},

        // ---- DROP ----
        vm_inst{OP_LOAD, 0, 0, XDP_DROP, 0},   // return XDP_DROP
        vm_inst{OP_EXIT, 0, 0, 0, 0},

        // ---- PASS ----
        vm_inst{OP_LOAD, 0, 0, XDP_PASS, 0},   // return XDP_PASS
        vm_inst{OP_EXIT, 0, 0, 0, 0}
    };
}