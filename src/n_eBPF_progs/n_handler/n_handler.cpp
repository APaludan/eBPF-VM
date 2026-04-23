#include "n_handler.h"
#include "vm.h"
#include "string.h"
#include <bpf/libbpf.h>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <thread>
#include <net/if.h>
#include <vector>

int n_handler::ring_buffer_callback(void *ctx, void *data, size_t data_sz) 
{
    if (data_sz != sizeof(vm_event)) {
        std::cerr << "ERROR: Size mitch match in event" << std::endl;
        return -1; 
    }

    auto *handler = static_cast<n_handler *>(ctx);

    vm_event e;
    std::memcpy(&e, data, sizeof(e));
    handler->on_event(e);

    return 0;
}

int n_handler::load_and_attach_all(pid_t protected_pid) 
{
    if (!on_event || !protected_pid) 
    {
        std::cerr << "ERROR: No on_event callback set or no protected_pid" << std::endl;
        return -1;
    }

    skel_obj.reset(n_progs::open());
    if (!skel_obj || !skel_obj->rodata) 
    {
        std::cerr << "ERROR: Failed to open BPF skeleton object." << std::endl;
        return -1;
    }

    skel_obj.get()->rodata->PROTECTED_PID = protected_pid;

    if (int err = n_progs::load(skel_obj.get())) 
    {
        std::cerr << "ERROR: Failed to load BPF programs into kernel: " << err << std::endl;
        skel_obj.reset();
        return err;
    }

    rb.reset(ring_buffer__new(bpf_map__fd(skel_obj->maps.rb), n_handler::ring_buffer_callback, this, nullptr));

    if (!rb) 
    {
        std::cerr << "ERROR: Failed to create ring buffer" << std::endl;
        return -1;
    }

    if (int err = n_progs::attach(skel_obj.get())) 
    {
            std::cerr << "ERROR: Failed to attach: " << err << std::endl;
            rb.reset();
            return err;
    }

    // Attach XDP program to loopback interface
    int ifindex = if_nametoindex("lo");

    if (ifindex == 0) 
    {
        std::cerr << "ERROR: Failed to get ifindex for lo" << std::endl;
        return -1;
    }

    xdp_link = bpf_program__attach_xdp(skel_obj->progs.xdp_simple_filter, ifindex);

    if (!xdp_link) 
    {
        std::cerr << "ERROR: Failed to attach XDP program to lo" << std::endl;
        return -1;
    }


    loop_thread = std::jthread(
        [this](std::stop_token st)
        {
            while (!st.stop_requested())
            {
                if (ring_buffer__poll(rb.get(), 100) < 0 && errno != EINTR)
                    break;
            }
        });

    return 0;
}

n_handler::n_handler(std::function<void(vm_event)> cb)
    : on_event(std::move(cb)) 
{
}

void n_handler::detach_and_unload_all() 
{
    if (loop_thread.joinable()) 
    {
        loop_thread.request_stop();

        loop_thread.join();
    }

    if (skel_obj) 
    {
        if (xdp_link) 
        {
            bpf_link__destroy(xdp_link);
            xdp_link = nullptr;
        }
    }

    rb.reset();
    skel_obj.reset();

    std::cout << "Normal eBPF program detached and unloaded" << std::endl;
}

n_handler::~n_handler() { detach_and_unload_all(); }