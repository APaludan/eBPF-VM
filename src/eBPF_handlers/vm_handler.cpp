#include "vm_handler.h"
#include "vm.h"
#include "string.h"
#include <bpf/libbpf.h>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <thread>
#include <stop_token>

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

  std::vector<vm_inst> program = {
      //      op,   dst, src, val
      vm_inst{OP_LOAD, 1, 0, protected_pid},      // r1 = protected_pid
      vm_inst{OP_CALL, 0, 0, 14},                 // call bpf_get_current_pid_tgid (nr 14)
      vm_inst{OP_RSHIFT, 0, 0, 32},               // r0 = r0 >> 32 (extract PID only)
      vm_inst{OP_READ_CTX, 2, 24, sizeof(pid_t)}, // read the target pid from ctx + offset 24 = (ctx->args[1])
      // NOW:
      // r0 = pid that triggered ebpf
      // r1 = protected pid
      // r2 = target pid
      vm_inst{OP_JNEQ, 1, 2, 6},    // if r1(protected pid) != r2(target pid): jump to exit
      vm_inst{OP_RINGBUF, 0, 0, 0}, // submit info to ringbuf
      vm_inst{OP_EXIT, 0, 0, 0}     // exit
  };

  bpf_map *map_fd = skel_obj.get()->maps.bytecode_map;

  for (uint32_t i = 0; i < program.size(); i++)
  {
    bpf_map__update_elem(map_fd, &i, sizeof(i), &program[i], sizeof(program[i]), 0);
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

  std::cout << "vm eBPF program detached and unloaded.\n";
}

vm_handler::~vm_handler() { DetachAndUnloadAll(); }
