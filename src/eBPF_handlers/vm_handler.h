#pragma once
#include "vm.skel.h"
#include "vm.h"
#include <functional>
#include <thread>

class vm_handler
{
    private:
        static int ring_buffer_callback(void *ctx, void *data, size_t data_sz);
        int populate_map(int program_type, std::vector<vm_inst> program, bpf_map *map_fd, unsigned int key);
        int insert_data(std::vector<unsigned long long>& data);

        std::unique_ptr<struct vm, decltype(&vm__destroy)> skel_obj{nullptr, vm__destroy};
        std::unique_ptr<struct ring_buffer, decltype(&ring_buffer__free)> rb{nullptr, ring_buffer__free};
        std::jthread loop_thread;
        std::function<void(vm_event)> on_event;
        struct bpf_link *xdp_link = nullptr;

    public:
        explicit vm_handler(std::function<void(vm_event)> on_event);
        ~vm_handler();

        int load_and_attach_all(std::unordered_map<int, std::vector<vm_inst>>& program_map, pid_t protected_pid);
        void detach_and_unload_all();
};
