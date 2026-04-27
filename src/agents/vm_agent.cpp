#include "vm_agent.h"
#include <iostream>

vm_agent::vm_agent(std::unordered_map<int, std::vector<vm_inst>> program_map, pid_t protected_pid, bool n_progs)      
    :   handler([this](const vm_event &e) { on_event_cb(e); }),
        n_handler([this](const vm_event &e) { on_event_cb(e); })
{
    err = handler.load_and_attach_all(program_map);
    if (n_progs == true)
    {
        n_err = n_handler.load_and_attach_all(protected_pid);
    }
}

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

// convert vm_event.type to a string
std::string_view event_type_to_string(int type) 
{
    switch (type)
    {
    case PTRACE_PROGRAM:
        return "PTRACE_PROGRAM";
    case LSM_BPF_PROGRAM:
        return "LSM_BPF_PROGRAM";
    case LSM_OPEN_PROGRAM:
        return "LSM_OPEN_PROGRAM";
    case KPROBE_FIND_VPID_PROGRAM:
        return "KPROBE_FIND_VPID_PROGRAM";
    case KPROBE_PID_TASK_PROGRAM:
        return "KPROBE_PID_TASK_PROGRAM";
    case SIMPLE_FILTER_PROGRAM:
        return "SIMPLE_FILTER_PROGRAM";
    case MODULE_LOAD_PROGRAM:
        return "MODULE_LOAD_PROGRAM";
    case MODULE_FREE_PROGRAM:
        return "MODULE_FREE_PROGRAM";
    case VM_ERROR:
        return "VM_ERROR";
    default:
        return "UNKNOWN_EVENT";
    }
}

void vm_agent::print_event_data(const vm_event &e) 
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
