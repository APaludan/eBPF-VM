#pragma once
#include "n_progs.skel.h"
#include "vm.h"
#include <functional>
#include <thread>

class n_handler
{
    private:
        static int ring_buffer_callback(void *ctx, void *data, size_t data_sz);

        std::unique_ptr<struct n_progs, decltype(&n_progs__destroy)> skel_obj{nullptr, n_progs__destroy};
        std::unique_ptr<struct ring_buffer, decltype(&ring_buffer__free)> rb{nullptr, ring_buffer__free};
        std::jthread loop_thread;
        std::function<void(vm_event)> on_event;
        struct bpf_link *xdp_link = nullptr;

    public:
        explicit n_handler(std::function<void(vm_event)> on_event);
        ~n_handler();

        int load_and_attach_all(pid_t protected_pid);
        void detach_and_unload_all();
};
