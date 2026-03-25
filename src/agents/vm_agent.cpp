#include "vm_agent.h"
#include <iostream>
#include <optional>

//std::string_view event_type_to_string(vm_event_type type);                        // (Redundant, moved above only function that uses it: print_event_data)Declare helper function to convert event types to string

vm_agent::vm_agent(pid_t protected_pid, std::vector<vm_inst> ptrace_program, std::vector<vm_inst> lsm_open_program) // vm_agent class constructor 
    : handler([this](const vm_event &e) { on_event_cb(e); })                        // member init list(runs before constuctor body): init handler vaiable (declared in vm_agent.h) with a lambda function that campure the context of the constructed vm_agent, the lambda function takes a referance to a vm_event and call the function on_event_cb (Lambda function is not called as handler is init but when the handler recives an vm_event e)
{   
    this->protected_pid = protected_pid;                                            // Set the private vaiable of this current vm_agent protected_pid to the protected_pid passed to the constructor 
    handler.load_and_attach_all(ptrace_program, lsm_open_program);                  // Call handler helper function 
}

vm_agent::~vm_agent()                                                               // Deconstructor of the vm_agent class
{  

}

void vm_agent::on_event_cb(const vm_event &e)                                       // Callback function that is called when handler receives an event 
{
    std::lock_guard<std::mutex> lock(queue_mutex);                                  // Request mutex for the event_queue
    event_queue.push(e);                                                            // Push the event recieved to the event_queue 
}

std::optional<vm_event> vm_agent::get_next_event()                                  // Optional function (can return an event or null) to get next event in event_queue
{
    std::lock_guard<std::mutex> lock(queue_mutex);                                  // Request mustex for the event_queue                          
    if (event_queue.empty())                                                        // Use <queue> helper function to check if the event_queue is empty
        return std::nullopt;                                                        // The optional null is returned
    auto e = event_queue.front();                                                   // Initialise variable e as the front event of the event_queue
    event_queue.pop();                                                              // Pop the front event of the event_queue (the one stored in variable e)
    return e;                                                                       // Return the front vm_event e
}


std::string_view event_type_to_string(vm_event_type type)                           // Helper function for print_event_data to convert vm_event.type to a string
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

void vm_agent::print_event_data(const vm_event &e)                                  // Helper function to print event data in terminal
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


/* 
=========================
==      NOT USED      ===
=========================

void vm_agent::set_protected_pid(pid_t protected_pid)                               // Function to change the protected_pid
{
    this->protected_pid = protected_pid;
    handler.DetachAndUnloadAll();
    handler.LoadAndAttachAll(protected_pid);
}

int vm_agent::get_pid_id()                                                          // Function to get the private variable of vm_agent class
{  
    return protected_pid;                                                          
}


*/ 