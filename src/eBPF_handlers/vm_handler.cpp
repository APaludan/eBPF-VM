#include "vm_handler.h"
#include "vm.h"
#include "string.h"
#include <bpf/libbpf.h>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <thread>

int vm_handler::ring_buffer_callback(void *ctx, void *data, size_t data_sz)           // Ringbuffer callback function, used to call the lampda function when an event arrives 
{
  if (data_sz != sizeof(vm_event))                                                    // Check if data is same size as an vm_event 
  {
    std::cerr << "Size mitch match in event" << std::endl;                            // Error msg
    return -1;                                                                        // Return negative value to indicate a processing error
  }

  auto *handler = static_cast<vm_handler *>(ctx);                                     // Pointer vaiable handler, uses static cast to convert the pointer to ctx to a pointer of the class vm_handler

  vm_event e;                                                                         // Declare a vm_event e 
  std::memcpy(&e, data, sizeof(e));                                                   // copy the memory of data into the address of e 
  handler->on_event(e);                                                               // call the member function on_event of handler, on_event is the lambda function passed to the constructor of the vm_handler class 

  return 0;                                                                           // Return zero to indicate processing complete 
}

int vm_handler::load_and_attach_all(std::vector<vm_inst> ptrace_program, std::vector<vm_inst> lsm_open_program ) // load and attach the the vm_handler to a given pid
{
  if (!on_event)                                                                      // check that the vm_handler class has been constructed with a lambda callback function
  {
    std::cerr << "No on_event callback set" << std::endl;                             // Error msg 
    return -1;                                                                        // Return negative value to indicate a processing error
  }

  skel_obj.reset(vm::open_and_load());                                                // init the skelton object from bpf/libbpf.h
  
  if (!skel_obj)                                                                      // check if skeleton object was created
  {
    std::cerr << "ERROR: Failed to open BPF skeleton object" << std::endl;            // Error msg
    return -1;                                                                        // return negativ to indicate processing error 
  }
 
  rb.reset(ring_buffer__new(bpf_map__fd(skel_obj->maps.rb), vm_handler::ring_buffer_callback, this, nullptr)); // create a user space ring buffer

  if (!rb)                                                                            // check if ringbuffer was created
  {
    std::cerr << "Failed to create ring buffer" << std::endl; 
    return -1; 
  }

//====================================================================================================================================
//======                                                  INSTRUCTION SET START                                                =======
//====================================================================================================================================

  bpf_map *map_fd = skel_obj.get()->maps.ptrace_instructions;                         // create a map file decriptor for the ptrace instructions

  for (uint32_t i = 0; i < ptrace_program.size(); i++)                                // for each instruction in ptrace program 
  {
    vm_inst inst = ptrace_program[i];                                                 // set the curret ptrace instruction

    __u8 key = 0x5A;                                                                  // encryption key

    xor_rolling(reinterpret_cast<uint8_t*>(&inst), sizeof(inst), key);                // call xor_rolling defined in vm.h

    bpf_map__update_elem(map_fd, &i, sizeof(i), &inst, sizeof(inst), 0);              // update the map 
  }

  map_fd = skel_obj.get()->maps.lsm_open_instructions;                                // set map filedescriptor ot lsm_open instructions

  for (uint32_t i = 0; i < lsm_open_program.size(); i++)                              // for each instruction in lsm_open
  {
    vm_inst inst = lsm_open_program[i];                                               // set inst as curret instruction

    __u8 key = 0x5A;                                                                  // encryption key

    xor_rolling(reinterpret_cast<uint8_t*>(&inst), sizeof(inst), key);                // call helper function from vm.h

    bpf_map__update_elem(map_fd, &i, sizeof(i), &inst, sizeof(inst), 0);              // update the lsm_open map
  }

//====================================================================================================================================
//======                                                  INSTRUCTION SET ENDS                                                 =======
//====================================================================================================================================
  

  if (int err = skel_obj.get()->attach(skel_obj.get()))                               // (moved down so instruction maps get populated before attaching program) attach skeleton object + check if it can attatch to skeleton object 
  {
    std::cerr << "Failed to attach: " << err << std::endl;
    rb.reset();
    return err; 
  }


  loop_thread = std::jthread                                                          // Declare a loop_thread and Assign a tread
  (
    [this](std::stop_token st)                                                        
    {                                                                                 // The assigned tread takes a lambda function capturing the context of the vm_handler, lambda function takes a stop token as parameter (The std::stop_token is a class that provides a way to call off asynchronous operation requests. It is equivalent to a token that can be transferred through different program fragments, providing the ability to notify about the cancellation of an ongoing process)                                                 
      while (!st.stop_requested())                                                    // while loop (stop_requested(): This function responds with a value of true when a cancellation request has been made, otherwise, it returns false.)
      { 
        if (ring_buffer__poll(rb.get(), 100) < 0 && errno != EINTR) break;            // poll the ringbuffer for data with timeout of 100, data from rb.get must be above 0 (no error returned) and ensure error is not because of interupted system call, if any of these are true loop is broken and tread is exited 
      } 
    }
  );

  return 0;                                                                           // indicate proccess is complete
}

vm_handler::vm_handler(std::function<void(vm_event)> cb)                              // constructor for vm_handler takes the lambda function as parameter 
  : on_event(std::move(cb))                                                           // member init list to set the given lambda function as the on_event function (moves the functionality of the the given function cb to the vm_handler object in form of on_event)
{

}

void vm_handler::detach_and_unload_all()                                              // helper function for the deconstructor
{

  if (loop_thread.joinable())                                                         // check if loop_thread is joinable (joinable if it identifies/represent an active thread of execution)
  {
    loop_thread.request_stop();                                                       // request the stop (end while loop in load_and_attach_all)
    
    loop_thread.join();                                                               // Wait for the thread to terminate before cleanup
  }

  rb.reset();                                                                         // reset rb 
  skel_obj.reset();                                                                   // reset skeleton object

  std::cout << "vm eBPF ptrace_program detached and unloaded" << std::endl;           // detach and unload msg
}

vm_handler::~vm_handler()                                                             // deconstructor for vm_handler class
{ 
  detach_and_unload_all();                                                            // call above helperfunction 
}