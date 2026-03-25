#pragma once
#include "vm.skel.h"
#include "vm.h"
#include <functional>
#include <thread>

class vm_handler {
private:                                                                                                // Functions and variable available for vm_handler

  static int ring_buffer_callback(void *ctx, void *data, size_t data_sz);                               // Ring buffer callback function 

  std::unique_ptr<struct vm, decltype(&vm__destroy)> skel_obj{ nullptr, vm__destroy };                  // smart pointers to clean skelton object and ring buffer 
  std::unique_ptr<struct ring_buffer, decltype(&ring_buffer__free)> rb{ nullptr, ring_buffer__free };   //

  std::jthread loop_thread;                                                                             // Treat to poll data from kernel ring buffer
  std::function<void(vm_event)> on_event;                                                               // function passed to the vm_handler constructor

public:                                                                                                 // Functions and variable available for all that include vm_handler.h

  explicit vm_handler(std::function<void(vm_event)> on_event);                                          // vm_handler class constructor 
  ~vm_handler();                                                                                        // vm_handler class deconstructor 

  int load_and_attach_all(pid_t protected_pid);                                                         // Function to load and attach vm_handler class to a given pid
  void detach_and_unload_all();                                                                         // Function to detach and unload the vm_handler class

};
