#pragma once
#include "vm_handler.h"
#include "vm.h"



std::vector<vm_inst> make_ptrace_program(pid_t protected_pid);
std::vector<vm_inst> make_lsm_open_program(pid_t protected_pid);