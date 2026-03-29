#include "vm_handler.h"
#include "vm.h"
#include "string.h"
#include <bpf/libbpf.h>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <thread>
#include <random>

// Ringbuffer callback function, used to call the lampda function when an event arrives
int vm_handler::ring_buffer_callback(void *ctx, void *data, size_t data_sz)
{
    if (data_sz != sizeof(vm_event))
    {
        std::cerr << "Size mitch match in event" << std::endl;
        return -1;
    }

    auto *handler = static_cast<vm_handler *>(ctx);

    vm_event e;
    std::memcpy(&e, data, sizeof(e));
    handler->on_event(e);

    return 0;
}

int vm_handler::load_and_attach_all(std::vector<vm_inst> ptrace_program, std::vector<vm_inst> lsm_open_program)
{
    if (!on_event)
    {
        std::cerr << "No on_event callback set" << std::endl;
        return -1;
    }

    skel_obj.reset(vm::open_and_load());

    if (!skel_obj)
    {
        std::cerr << "ERROR: Failed to open BPF skeleton object" << std::endl;
        return -1;
    }

    rb.reset(ring_buffer__new(bpf_map__fd(skel_obj->maps.rb), vm_handler::ring_buffer_callback, this, nullptr));

    if (!rb)
    {
        std::cerr << "Failed to create ring buffer" << std::endl;
        return -1;
    }

    //====================================================================================================================================
    //======                                                  INSTRUCTION SET START                                                =======
    //====================================================================================================================================

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<unsigned int> key_dist(0, std::numeric_limits<unsigned int>::max());
    unsigned int key = key_dist(gen);
    unsigned int index = 0;
    bpf_map__update_elem(skel_obj->maps.key_map, &index, sizeof(index), &key, sizeof(key), 0);

    auto map_fd = skel_obj->maps.programs;

    for (size_t i = 0; i < ptrace_program.size(); i++)
    {
        vm_inst inst = ptrace_program[i];

        xor_rolling(&inst, key);

        uint32_t program_index_i = PTRACE_PROGRAM * VM_MAX_INSTRUCTIONS + i;
        bpf_map__update_elem(map_fd, &program_index_i, sizeof(program_index_i), &inst, sizeof(inst), 0);
    }

    for (size_t i = 0; i < lsm_open_program.size(); i++)
    {
        vm_inst inst = lsm_open_program[i];

        xor_rolling(&inst, key);

        uint32_t program_index_i = LSM_OPEN_PROGRAM * VM_MAX_INSTRUCTIONS + i;
        bpf_map__update_elem(map_fd, &program_index_i, sizeof(program_index_i), &inst, sizeof(inst), 0);
    }

    //====================================================================================================================================
    //======                                                  INSTRUCTION SET ENDS                                                 =======
    //====================================================================================================================================

    if (int err = skel_obj->attach(skel_obj.get()))
    {
        std::cerr << "Failed to attach: " << err << std::endl;
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

// constructor for vm_handler takes the lambda function as parameter
vm_handler::vm_handler(std::function<void(vm_event)> cb)
    : on_event(std::move(cb))
{
}

// helper function for the deconstructor
void vm_handler::detach_and_unload_all() 
{

    if (loop_thread.joinable())
    {
        loop_thread.request_stop();

        loop_thread.join();
    }

    rb.reset();
    skel_obj.reset();

    std::cout << "vm eBPF programs detached and unloaded" << std::endl;
}

vm_handler::~vm_handler()
{
    detach_and_unload_all();
}