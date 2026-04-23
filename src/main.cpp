#include "vm_agent.h"
#include "vm_inst.h"
#include <iostream>
#include <signal.h>

bool stop_flag = false; 

void siginthandler(int param)
{
    (void)param;
    stop_flag = true;            
    std::cout << std::endl;
}

int main(int argc, char *argv[])
{
    pid_t protected_pid = (argc > 1) ? static_cast<pid_t>(std::stoi(argv[1]))
                                     : static_cast<pid_t>(1);

    vm_agent agent = vm_agent(generate_programs(protected_pid, true), protected_pid);
    if (agent.err == -1 || agent.n_err == -1)
    {
        return 1;
    }

    std::cout << "\n_______________________________________" << std::endl;
    std::cout << "Check the trace pipe in a new terminal:" << std::endl;
    std::cout << "sudo cat /sys/kernel/tracing/trace_pipe" << std::endl;
    std::cout << "Press CTRL+C to unload the programs..." << std::endl;

    signal(SIGINT, siginthandler);

    while (!stop_flag)
    {
        auto maybe_vm_event = agent.get_next_event();
        
        while (maybe_vm_event)
        {
            auto &e = *maybe_vm_event;
            agent.print_event_data(e);
            maybe_vm_event = agent.get_next_event();
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    return 0;
}