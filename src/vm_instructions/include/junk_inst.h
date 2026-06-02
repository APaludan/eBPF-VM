#pragma once
#include "vm_handler.h"
#include "vm.h"

std::vector<vm_inst> merge_junk_inst(std::vector<vm_inst> inst_set, size_t max_size);
void print_program_map_to_csv( const std::unordered_map<int, std::vector<vm_inst>>& program_map, const std::string& filename);