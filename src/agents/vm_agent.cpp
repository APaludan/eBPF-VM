#include "vm_agent.h"
#include <iostream>
#include <optional>

std::string_view event_type_to_string(vm_event_type type);

vm_agent::vm_agent(pid_t protected_pid)
    : handler([this](const vm_event &e)
              { on_event_cb(e); })
{
    this->protected_pid = protected_pid;
    handler.LoadAndAttachAll(protected_pid);
}

vm_agent::~vm_agent() {}

void vm_agent::on_event_cb(const vm_event &e)
{
    std::lock_guard<std::mutex> lock(queue_mutex);
    event_queue.push(e);
}

std::optional<vm_event> vm_agent::get_next_event()
{
    std::lock_guard<std::mutex> lock(queue_mutex);
    if (event_queue.empty())
        return std::nullopt;
    auto e = event_queue.front();
    event_queue.pop();
    return e;
}

void vm_agent::set_protected_pid(pid_t protected_pid)
{
    this->protected_pid = protected_pid;
    handler.DetachAndUnloadAll();
    handler.LoadAndAttachAll(protected_pid);
}

int vm_agent::get_pid_id() { return protected_pid; }

void vm_agent::printEventData(const vm_event &e)
{

    std::cout << "====== VM Event ======\n";
    std::cout << "Caller name     : " << e.caller_name << "\n";
    std::cout << "PID             : " << e.caller_pid << "\n";
    std::cout << "Regs            : ";
    for (const auto &val : e.reg_values)
    {
        std::cout << val << " ";
    }
    std::cout << "\n";
    std::cout << "PC              : " << e.pc << "\n";
    std::cout << "Event type      : " << event_type_to_string(e.type) << "\n";
    std::cout << "======================\n";
}

std::string_view event_type_to_string(vm_event_type type)
{
    switch (type)
    {
    case PTRACE2:
        return "PTRACE";
    case OPEN2:
        return "OPEN";
    case VM_WRITE2:
        return "VM_WRITE";
    case VM_READ2:
        return "VM_READ";
    case PROCFS2:
        return "PROCFS";
    case K_TASK_LOOKUP2:
        return "KERNEL_TASK_LOOKUP";
    case K_VPID_LOOKUP2:
        return "KERNEL_VPID_LOOKUP";
    case VM_ERROR:
        return "VM_ERROR";
    default:
        return "UNKNOWN_EVENT";
    }
}
