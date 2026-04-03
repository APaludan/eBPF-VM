#pragma once
#include "vm_handler.h"
#include "vm.h"

std::unordered_map<int, std::vector<vm_inst>> generate_programs(pid_t protected_pid);
std::vector<uint8_t> serialize_inst(const vm_inst& inst);