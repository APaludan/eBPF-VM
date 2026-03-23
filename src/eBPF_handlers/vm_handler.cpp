#include "vm_handler.h"
#include "vm.h"
#include "string.h"
#include <bpf/libbpf.h>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <thread>

int vm_handler::ring_buffer_callback(void *ctx, void *data,
                                     size_t data_sz)
{
  if (data_sz != sizeof(vm_event))
  {
    std::cerr << "Size mitch match in event";
    return 1; // Return non-zero to indicate a processing error
  }

  auto *handler = static_cast<vm_handler *>(ctx);

  vm_event e;
  std::memcpy(&e, data, sizeof(e));
  handler->on_event(e);

  return 0;
}

int vm_handler::LoadAndAttachAll(pid_t protected_pid)
{
  if (!on_event)
  {
    std::cerr << "No on_event callback set\n";
    return -1;
  }

  skel_obj.reset(vm::open_and_load());

  if (!skel_obj)
    return (std::cerr << "ERROR: Failed to open BPF skeleton object.\n", -1);

  rb.reset(ring_buffer__new(bpf_map__fd(skel_obj->maps.rb),
                            vm_handler::ring_buffer_callback, this,
                            nullptr));

  if (!rb)
    return (std::cerr << "Failed to create ring buffer\n", -1);

  if (int err = skel_obj.get()->attach(skel_obj.get()))
    return (std::cerr << "Failed to attach: " << err << "\n", rb.reset(), err);

  // has the same functionality as the mem_access ptrace ebpf program
  std::vector<vm_inst> ptrace_program = {
      //      op,   dst, src, val
      vm_inst{OP_LOAD, 1, 0, protected_pid},      // r1 = protected_pid
      vm_inst{OP_CALL, 0, 0, 14},                 // call bpf_get_current_pid_tgid (nr 14)
      vm_inst{OP_RSHIFT, 0, 0, 32},               // r0 = r0 >> 32 (extract PID only)
      vm_inst{OP_READ_CTX, 2, 24, sizeof(pid_t)}, // read the target pid from ctx + offset 24 = (ctx->args[1])
      // NOW:
      // r0 = pid that triggered ebpf
      // r1 = protected pid
      // r2 = target pid
      vm_inst{OP_JNEQ, 1, 2, 2},    // if r1(protected pid) != r2(target pid): jump to exit (pc +2)
      vm_inst{OP_RINGBUF, 0, 0, 0}, // submit info to ringbuf
      vm_inst{OP_LOAD, 0, 0, 0},    // set exit code
      vm_inst{OP_EXIT, 0, 0, 0}     // exit
  };

  bpf_map *map_fd = skel_obj.get()->maps.ptrace_instructions;

for (uint32_t i = 0; i < ptrace_program.size(); i++)
{
    vm_inst inst = ptrace_program[i];

    __u8 key = 0x5A;

    xor_rolling(reinterpret_cast<uint8_t*>(&inst), sizeof(inst), key);

    bpf_map__update_elem(map_fd, &i, sizeof(i),
                         &inst,
                         sizeof(inst), 0);
}

  const auto proc_super_magic_num = 0x9fa0;
  unsigned long long maps = 0;
  unsigned long long smaps = 0;
  unsigned long long mem = 0;
  memcpy(&maps, "maps", 5);
  memcpy(&smaps, "smaps", 6);
  memcpy(&mem, "mem", 4);

  std::vector<vm_inst> lsm_open_program = {
      //      op,   dst, src, val
      vm_inst{OP_LOAD, 1, 0, protected_pid}, // r1 = protected_pid, 0
      vm_inst{OP_CALL, 2, 0, 14},            // bpf_get_current_pid_tgid, 1
      vm_inst{OP_RSHIFT, 2, 2, 32},          // r2 = pid, 2
      vm_inst{OP_JNEQ, 1, 2, 2},              // ,3
      vm_inst{OP_EXIT, 0, 0, 0}, // early exit if call from protected pid, 4
      
      vm_inst{OP_READ_CTX, 3, 32, sizeof(void*)}, // r3 = *inode, 5
      vm_inst{OP_ADD, 3, 0, 40},                  // r3 += 40 (offset), 6
      vm_inst{OP_READ, 4, 3, sizeof(void*)},      // r4 = *inode->i_sb, 7
      vm_inst{OP_ADD, 4, 0, 96},                  // r4 += 96 (offset), 8
      vm_inst{OP_READ, 5, 4, sizeof(unsigned long)},// r5 = *i_sb->s_magic, 9
      vm_inst{OP_LOAD, 6, 0, proc_super_magic_num},// r6 = procfs magic num, 10
      vm_inst{OP_JEQ, 5, 6, 2},                  // ,11
      vm_inst{OP_EXIT, 0, 0, 0},                  // exit if not procfs, 12
      
      vm_inst{OP_READ_CTX, 3, 32, sizeof(void*)}, // r3 = *inode, 15
      vm_inst{OP_SUB, 3, 0, 72},                 // r3 = *proc_inode, 16
      vm_inst{OP_READ, 4, 3, sizeof(void*)},      // r4 = *struct pid, 17
      vm_inst{OP_ADD, 4, 0, 144},                 // r4 = *upid[0], 18
      vm_inst{OP_READ, 5, 4, sizeof(int)},        // r5 = target pid, 19
      vm_inst{OP_JNEQ, 0, 8, 3},                  // exit if read failed, means it is probably not procfs anyway idk
      vm_inst{OP_JEQ, 5, 1, 3},                  // jump if (r5 == r1), 21
      vm_inst{OP_LOAD, 0, 0, 0},                  // set return val to 0
      vm_inst{OP_EXIT, 0, 0, 0},                  // exit if not protected pid, 23

      vm_inst{OP_READ_CTX, 3, 64+8, sizeof(void*)}, // r3 = *dentry
      vm_inst{OP_ADD, 3, 0, 32+8},                  // r3 = **name
      vm_inst{OP_READ, 3, 3, sizeof(void*)},        // r3 = *name
      vm_inst{OP_READ, 5, 3, sizeof(void*)},        // r3 = first 8 bytes of name. should probably be on stack and have variable size
      vm_inst{OP_LOAD, 4, 0, (long long)maps},      // 1: load sus filename
      vm_inst{OP_JEQ, 5, 4, 6},                     // 2: if sus jump to submit ringbuf
      vm_inst{OP_LOAD, 4, 0, (long long)smaps},     // 1
      vm_inst{OP_JEQ, 5, 4, 4},                     // 2
      vm_inst{OP_LOAD, 4, 0, (long long)mem},       // 1
      vm_inst{OP_JEQ, 5, 4, 2},                     // 2
      vm_inst{OP_JMP, 0, 0, 4},                     // jump over ringbuf submit if not sus  
      vm_inst{OP_RINGBUF, 0, 0, 0},                 // 
      vm_inst{OP_PRINTS, 0, 3, 0},                  // print sus file name
      
      vm_inst{OP_LOAD, 0, 0, 0},                    // set return val
      vm_inst{OP_EXIT, 0, 0, 0},                    // exit if not protected filename
  };

  map_fd = skel_obj.get()->maps.lsm_open_instructions;

  for (uint32_t i = 0; i < lsm_open_program.size(); i++)
{
    vm_inst inst = lsm_open_program[i];

    __u8 key = 0x5A;

    xor_rolling(reinterpret_cast<uint8_t*>(&inst), sizeof(inst), key);

    bpf_map__update_elem(map_fd, &i, sizeof(i),
                         &inst,
                         sizeof(inst), 0);
}
  loop_thread = std::jthread([this](std::stop_token st)
                             {
    while (!st.stop_requested()) {
      if (ring_buffer__poll(rb.get(), 100) < 0 && errno != EINTR) break;
    } });

  return 0;
}

vm_handler::vm_handler(std::function<void(vm_event)> cb)
    : on_event(std::move(cb)) {}

void vm_handler::DetachAndUnloadAll()
{

  if (loop_thread.joinable())
  {
    loop_thread.request_stop();
    // Wait for the thread to terminate before cleanup
    loop_thread.join();
  }

  rb.reset();
  skel_obj.reset();

  std::cout << "vm eBPF ptrace_program detached and unloaded.\n";
}

vm_handler::~vm_handler() { DetachAndUnloadAll(); }
