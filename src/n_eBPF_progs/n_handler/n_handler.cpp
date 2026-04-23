#include "n_handler.h"
#include "vm.h"
#include "string.h"
#include <bpf/libbpf.h>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <thread>
#include <net/if.h>

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
    if (!on_event) 
    {
        std::cerr << "ERROR: No on_event callback set" << std::endl;
        return -1;
    }

    skel_obj.reset(n_progs::open_and_load());

    if (!skel_obj) 
    {
        std::cerr << "ERROR: Failed to open and load BPF skeleton object." << std::endl;
        return -1;
    }

    skel_obj.get()->rodata->PROTECTED_PID = protected_pid;

    int rb_fd = bpf_map__fd(skel_obj->maps.rb);
    rb.reset(ring_buffer__new(rb_fd, n_handler::ring_buffer_callback, this, nullptr));

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

    rb.reset();
    skel_obj.reset();

    std::cout << "SUCCESS: VM eBPF program detached and unloaded" << std::endl;
}

n_handler::~n_handler() { detach_and_unload_all(); }