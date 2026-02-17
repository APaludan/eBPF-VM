#pragma once
#include "vm.skel.h"
#include "vm.h"
#include <functional>
#include <thread>

class vm_handler {
public:
  /// @param on_event A function that runs when new data arrives from eBPF
  /// programs
  explicit vm_handler(std::function<void(vm_event)> on_event);
  ~vm_handler();

  /// @param protected_pid The pid of the game/process to protect
  int LoadAndAttachAll(pid_t protected_pid);
  void DetachAndUnloadAll();

private:
  static int ring_buffer_callback(void *ctx, void *data, size_t data_sz);

  std::unique_ptr<struct vm, decltype(&vm__destroy)> skel_obj{
      nullptr, vm__destroy};

  std::unique_ptr<struct ring_buffer, decltype(&ring_buffer__free)> rb{
      nullptr, ring_buffer__free};

  std::jthread loop_thread;
  std::function<void(vm_event)> on_event;
};
