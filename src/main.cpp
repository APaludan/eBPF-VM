#include "vm_agent.h"
#include "vm_inst.h"
#include <iostream>
#include <signal.h>

bool stop = false;                                                                            // Stop flag variable 

void siginthandler(int param) {                                                               // Function to handle signal: ctrl+c
  (void)param;                                                                                // Declare parameter "param" is not used (no compiler warnings)
  stop = true;                                                                                // Set stop flag variable to true
  std::cout << std::endl;                                                                     // Ensure msg after signal input are printed on a new line
}

int main(int argc, char *argv[]) {                                                            // Main function: argc = argument counter, argv = argument vector 

  pid_t protected_pid = (argc > 1) ? static_cast<pid_t>(std::stoi(argv[1]))                   // Declare protected pid: pid_t = signed interger type for pid's, static_cast <dest> (src) = convert src type to dst type (cannot cast char* to pid_t therfore need std::stoi to convert argumen (which is char*) to type int first)
                                   : static_cast<pid_t>(1);                                   // Check if argument counter is above 1 (pid given is arg 2) if so set it to the 2nd argument else set it to 1

  vm_agent agent = vm_agent(protected_pid, make_ptrace_program(protected_pid), make_lsm_open_program(protected_pid)); 

  std::cout << "\n========================================================" << std::endl;     // Teminal msg's: uses cout (output) and endl (newline) provided by iostream
  std::cout << "Check the trace pipe in a new terminal:" << std::endl;                        //
  std::cout << "sudo cat /sys/kernel/tracing/trace_pipe" << std::endl;                        //
  std::cout << "Press CTRL+C to unload the programs..." << std::endl;                         // 

  signal(SIGINT, siginthandler);                                                              // signal function provided from signal.h takes a type SIGINT (ctrl+c signal) and a function siginthandler (declared at top of file)

  while (!stop) {                                                                             // While stop flag is false
    
    auto maybe_vm_event = agent.get_next_event();                                             // Use vm_agent helper function to maybe get next vm event 

    while (maybe_vm_event) {                                                                  // While there is a vm event 
      auto &e = *maybe_vm_event;                                                              // Set address of variable e to be the pointer to the current vm event 
      agent.print_event_data(e);                                                                // Use vm_agent helper function to print event in terminal
      maybe_vm_event = agent.get_next_event();                                                // update maybe_vm_event to iterate to the next event or set it to empty (prevent infinie loop)
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(10));                               // Sleep briefly to avoid busy-waiting
  }

  return 0;                                                                                   // End main function
}
