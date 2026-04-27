#pragma once

std::vector<vm_inst> make_simple_filter_program()
{
    return {
        // struct xdp_md *ctx 

        //  r1 = ctx->h_proto
        // h_proto field is at offset 12 in Ethernet header 
        // in original program ethhdr (Ethernet header) is defined as ctx->data which is at offset 0 so should just be 12 offset 
        vm_inst{OP_READ_CTX, 1, 0, 2, 12},

        // r2 = 0x0008 
        // (ETH_P_IP read as little-endian, so already converted, no need for bpf_htons)
        vm_inst{OP_LOAD, 2, 0, 0x0008, 0},

        // r3 = 0xDD86
        // same as before ETH_P_IPV6 = 0x86DD which is 0xDD86 as little-endian
        vm_inst{OP_LOAD, 3, 0, 0xDD86, 0},

        // So now we have eth-h_proto in register 1 and the two cases we want ot cheack 
        // case 1: bpf_htons(ETH_P_IP) = r2 and bpf_htons(ETH_P_IPV6) = r3

        //============================ case 1 ============================
        // case 1: bpf_htons(ETH_P_IP) if r1 != r2 -> PASS
        vm_inst{OP_JNEQ, 1, 2, 8, 0},

        // r4 = ctx->protocol
        // in code it is:
        // ip = data+sizeof(strct ethhdr) ethhdr is 14 bytes 
        // ip is the start of the IPv4 header and protocol is at offset 9 
        // therfore 14 + 9 = 23
        // Read 1 byte from ctx->data + 23 (IPv4 protocol field)
        vm_inst{OP_READ_CTX, 4, 0, 1, 23},

        // r5 = 1 (IPPROTO_ICMP)
        vm_inst{OP_LOAD, 5, 0, 1, 0},

        // if r1 != r2 -> PASS
        vm_inst{OP_JNEQ, 4, 5, 3, 0},

        // ---- DROP ----
        vm_inst{OP_LOAD, 0, 0, 1, 0},   // return XDP_DROP
        vm_inst{OP_RINGBUF, 0, 0, 0, 0},
        vm_inst{OP_EXIT, 0, 0, 0, 0},

        //============================ case 2 ============================
        // case 2: bpf_htons(ETH_P_IPV6) = r3 != r1 -> pass
        vm_inst{OP_JNEQ, 1, 2, 8, 0},

        // r4 = ip6->nexthdr
        vm_inst{OP_READ_CTX, 4, 0, 1, 20},

        // r5 = 1 (IPPROTO_ICMP)
        vm_inst{OP_LOAD, 5, 0, 58, 0},

        // if r1 != r2 -> PASS
        vm_inst{OP_JNEQ, 4, 5, 3, 0},

        // ---- DROP ----
        vm_inst{OP_LOAD, 0, 0, 1, 0},   // return XDP_DROP
        vm_inst{OP_RINGBUF, 0, 0, 0, 0},
        vm_inst{OP_EXIT, 0, 0, 0, 0},
    
        // ---- PASS ----
        vm_inst{OP_LOAD, 0, 0, 2, 0},   // return XDP_PASS
        vm_inst{OP_EXIT, 0, 0, 0, 0}
    };
}