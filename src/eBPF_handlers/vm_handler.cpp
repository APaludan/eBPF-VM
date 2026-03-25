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

int vm_handler::load_and_attach_all(pid_t protected_pid)                              // load and attach the the vm_handler to a given pid
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
 
  rb.reset(ring_buffer__new(bpf_map__fd(skel_obj->maps.rb), vm_handler::ring_buffer_callback, this, nullptr));

  if (!rb)                                                                            // check if ringbuffer was created
  {
    std::cerr << "Failed to create ring buffer" << std::endl; 
    return -1; 
  }

//====================================================================================================================================
//======                                                  INSTRUCTION SET START                                                =======
//====================================================================================================================================

  std::vector<vm_inst> ptrace_program =                                               // Vector with instusction, same functionality as mem_access ptrace ebpf program
  {                                             
    vm_inst{OP_LOAD, 1, 0, protected_pid},                                            // 00) r1 = protected_pid
    vm_inst{OP_CALL, 0, 0, 14},                                                       // 01) call bpf_get_current_pid_tgid (nr 14)
    vm_inst{OP_RSHIFT, 0, 0, 32},                                                     // 02) = r0 >> 32 (extract PID only)
    vm_inst{OP_READ_CTX, 2, 24, sizeof(pid_t)},                                       // 03) read the target pid from ctx + offset 24 = (ctx->args[1])

    vm_inst{OP_JNEQ, 1, 2, 2},                                                        // 04) if r1(protected pid) != r2(target pid): jump to exit (pc +2)
    vm_inst{OP_RINGBUF, 0, 0, 0},                                                     // 05) submit info to ringbuf
    vm_inst{OP_LOAD, 0, 0, 0},                                                        // 06) set exit code
    vm_inst{OP_EXIT, 0, 0, 0}                                                         // 07) exit
  };

  bpf_map *map_fd = skel_obj.get()->maps.ptrace_instructions;                         // create a map file decriptor for the ptrace instructions

  for (uint32_t i = 0; i < ptrace_program.size(); i++)                                // for each instruction in ptrace program 
  {
    vm_inst inst = ptrace_program[i];                                                 // set the curret ptrace instruction

    __u8 key = 0x5A;                                                                  // encryption key

    xor_rolling(reinterpret_cast<uint8_t*>(&inst), sizeof(inst), key);                // call xor_rolling defined in vm.h

    bpf_map__update_elem(map_fd, &i, sizeof(i), &inst, sizeof(inst), 0);              // update the map 
  }

  const auto proc_super_magic_num = 0x9fa0;                                           // define consts used for the lsm_open program
  unsigned long long maps = 0;                                                        //
  unsigned long long smaps = 0;                                                       //  
  unsigned long long mem = 0;                                                         //
  memcpy(&maps, "maps", 5);                                                           //
  memcpy(&smaps, "smaps", 6);                                                         //
  memcpy(&mem, "mem", 4);                                                             //

  std::vector<vm_inst> lsm_open_program =                                             // vm_inst(op, dst, src, val)
  {
    vm_inst{OP_LOAD, 1, 0, protected_pid},                                            // 01) r1 = protected_pid, 0
    vm_inst{OP_CALL, 2, 0, 14},                                                       // 02) bpf_get_current_pid_tgid, 1
    vm_inst{OP_RSHIFT, 2, 2, 32},                                                     // 03) r2 = pid, 2
    vm_inst{OP_JNEQ, 1, 2, 2},                                                        // 04) ,3
    vm_inst{OP_EXIT, 0, 0, 0},                                                        // 05) early exit if call from protected pid, 4
    
    vm_inst{OP_READ_CTX, 3, 32, sizeof(void*)},                                       // 06) r3 = *inode, 5
    vm_inst{OP_ADD, 3, 0, 40},                                                        // 07) r3 += 40 (offset), 6
    vm_inst{OP_READ, 4, 3, sizeof(void*)},                                            // 08) r4 = *inode->i_sb, 7
    vm_inst{OP_ADD, 4, 0, 96},                                                        // 09) r4 += 96 (offset), 8
    vm_inst{OP_READ, 5, 4, sizeof(unsigned long)},                                    // 10) r5 = *i_sb->s_magic, 9
    vm_inst{OP_LOAD, 6, 0, proc_super_magic_num},                                     // 11) r6 = procfs magic num, 10
    vm_inst{OP_JEQ, 5, 6, 2},                                                         // 12) ,11
    vm_inst{OP_EXIT, 0, 0, 0},                                                        // 13) exit if not procfs, 12
    
    vm_inst{OP_READ_CTX, 3, 32, sizeof(void*)},                                       // 14) r3 = *inode, 15
    vm_inst{OP_SUB, 3, 0, 72},                                                        // 15) r3 = *proc_inode, 16
    vm_inst{OP_READ, 4, 3, sizeof(void*)},                                            // 16) r4 = *struct pid, 17
    vm_inst{OP_ADD, 4, 0, 144},                                                       // 17) r4 = *upid[0], 18
    vm_inst{OP_READ, 5, 4, sizeof(int)},                                              // 18) r5 = target pid, 19
    vm_inst{OP_JNEQ, 0, 8, 3},                                                        // 19) exit if read failed, means it is probably not procfs anyway idk
    vm_inst{OP_JEQ, 5, 1, 3},                                                         // 20) jump if (r5 == r1), 21
    vm_inst{OP_LOAD, 0, 0, 0},                                                        // 21) set return val to 0
    vm_inst{OP_EXIT, 0, 0, 0},                                                        // 22) exit if not protected pid, 23

    vm_inst{OP_READ_CTX, 3, 64+8, sizeof(void*)},                                     // 23) r3 = *dentry
    vm_inst{OP_ADD, 3, 0, 32+8},                                                      // 24) r3 = **name
    vm_inst{OP_READ, 3, 3, sizeof(void*)},                                            // 25) r3 = *name
    vm_inst{OP_READ, 5, 3, sizeof(void*)},                                            // 26) r3 = first 8 bytes of name. should probably be on stack and have variable size
    vm_inst{OP_LOAD, 4, 0, (long long)maps},                                          // 27) 1: load sus filename
    vm_inst{OP_JEQ, 5, 4, 6},                                                         // 28) 2: if sus jump to submit ringbuf
    vm_inst{OP_LOAD, 4, 0, (long long)smaps},                                         // 29) 1
    vm_inst{OP_JEQ, 5, 4, 4},                                                         // 30) 2
    vm_inst{OP_LOAD, 4, 0, (long long)mem},                                           // 31) 1
    vm_inst{OP_JEQ, 5, 4, 2},                                                         // 32) 2
    vm_inst{OP_JMP, 0, 0, 4},                                                         // 33) jump over ringbuf submit if not sus  
    vm_inst{OP_RINGBUF, 0, 0, 0},                                                     // 
    vm_inst{OP_PRINTS, 0, 3, 0},                                                      // 34) print sus file name
    
    vm_inst{OP_LOAD, 0, 0, 0},                                                        // 35) set return val
    vm_inst{OP_EXIT, 0, 0, 0},                                                        // 36) exit if not protected filename
  };

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