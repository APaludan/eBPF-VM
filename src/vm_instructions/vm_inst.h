#pragma once
#include "vm_handler.h"
#include "vm.h"

std::unordered_map<int, std::vector<vm_inst>> generate_programs(pid_t protected_pid, bool with_junk);
std::vector<uint8_t> serialize_inst(const vm_inst inst, int key);
void fix_jumps(std::vector<vm_inst> &program);