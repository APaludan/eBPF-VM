#pragma once
#include "vm_handler.h"
#include "vm.h"
#include <mutex>
#include <queue>

class vm_agent
{
private:
    vm_handler handler;
    pid_t protected_pid;

    void on_event_cb(const vm_event &e);

    std::queue<vm_event> event_queue;
    std::mutex queue_mutex;

public:
    vm_agent(pid_t protected_pid, std::vector<vm_inst>, std::vector<vm_inst>);
    ~vm_agent();

    vm_agent(const vm_agent &) = delete;
    vm_agent &operator=(const vm_agent &) = delete;
    vm_agent(const vm_agent &&) = delete;
    vm_agent &operator=(const vm_agent &&) = delete;

    std::optional<vm_event> get_next_event();
    void print_event_data(const vm_event &e);
};
