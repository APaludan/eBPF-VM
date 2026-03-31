#pragma once
#include "vm_handler.h"
#include "vm.h"
#include <mutex>
#include <queue>

class vm_agent
{
private:
    vm_handler handler;

    void on_event_cb(const vm_event &e);

    std::queue<vm_event> event_queue;
    std::mutex queue_mutex;

public:
    vm_agent(std::unordered_map<int, std::vector<vm_inst>>);

    std::optional<vm_event> get_next_event();
    void print_event_data(const vm_event &e);
    int err;
};
