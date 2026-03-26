#pragma once
#include "vm_handler.h"
#include "vm.h"
#include <mutex>
#include <queue>

class vm_agent {
private:                                                // Functions and variable available for vm_agent 
  vm_handler handler;                                   // instance of vm_handler (from vm_handler.h)
  pid_t protected_pid;                                  // variable for Protected pid

  void on_event_cb(const vm_event &e);                  // callback function that takes argument of type vm_event (defined in vm.h)

  std::queue<vm_event> event_queue;                     // Stores elements of type vm_event in a FIFO order
  std::mutex queue_mutex;                               // Mutal exclusion for event_queue (key to access queue)

public:                                                 // Functions and variable available for all that include vm_agent.h
  vm_agent(pid_t protected_pid, std::vector<vm_inst>, std::vector<vm_inst>);  // constructor for the vm_agent class, takes a pid as input 
  ~vm_agent();                                          // Deconstructor for the vm_agent class

  vm_agent(const vm_agent &) = delete;                  // disable copuing and moving of the vm_agent class
  vm_agent &operator=(const vm_agent &) = delete;       //
  vm_agent(const vm_agent &&) = delete;                 //
  vm_agent &operator=(const vm_agent &&) = delete;      //

  //void set_protected_pid(pid_t protected_pid);        // (not used) Function to change pid: changes the pid of vm_agent class then unload and detach and then load and attach it with the new pid
  //int get_pid_id();                                   // (not used) Function that return the private variable protected_pid
  std::optional<vm_event> get_next_event();             // Function to get next event in event_queue (optional since it might be empty)
  void print_event_data(const vm_event &e);             // print a type of vm_event: caller_name, caller_pid, reg_values, pc, type
};
