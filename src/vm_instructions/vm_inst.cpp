#include "vm_inst.h"

//============================
//==     PTRACE PROGRAM     ==
//============================

std::vector<vm_inst> make_ptrace_program(pid_t protected_pid)   // function to create vector with instusction, same functionality as mem_access ptrace ebpf program
{
  return
  {                                             
    vm_inst{OP_LOAD, 1, 0, protected_pid},                      // 00) r1 = protected_pid
    vm_inst{OP_CALL, 0, 0, 14},                                 // 01) call bpf_get_current_pid_tgid (nr 14)
    vm_inst{OP_RSHIFT, 0, 0, 32},                               // 02) = r0 >> 32 (extract PID only)
    vm_inst{OP_READ_CTX, 2, 24, sizeof(pid_t)},                 // 03) read the target pid from ctx + offset 24 = (ctx->args[1])

    vm_inst{OP_JNEQ, 1, 2, 2},                                  // 04) if r1(protected pid) != r2(target pid): jump to exit (pc +2)
    vm_inst{OP_RINGBUF, 0, 0, 0},                               // 05) submit info to ringbuf
    vm_inst{OP_LOAD, 0, 0, 0},                                  // 06) set exit code
    vm_inst{OP_EXIT, 0, 0, 0}                                   // 07) exit
  };
};

//============================
//==    LSM_OPEN PROGRAM    ==
//============================

std::vector<vm_inst> make_lsm_open_program(pid_t protected_pid)   // vm_inst(op, dst, src, val)
{
  const auto proc_super_magic_num = 0x9fa0;                       // define consts used for the lsm_open program
  unsigned long long maps = 0;                                    //
  unsigned long long smaps = 0;                                   //  
  unsigned long long mem = 0;                                     //
  memcpy(&maps, "maps", 5);                                       //
  memcpy(&smaps, "smaps", 6);                                     //
  memcpy(&mem, "mem", 4);    

  return
  {
    vm_inst{OP_LOAD, 1, 0, protected_pid},                        // 01) r1 = protected_pid, 0
    vm_inst{OP_CALL, 2, 0, 14},                                   // 02) bpf_get_current_pid_tgid, 1
    vm_inst{OP_RSHIFT, 2, 2, 32},                                 // 03) r2 = pid, 2
    vm_inst{OP_JNEQ, 1, 2, 2},                                    // 04) ,3
    vm_inst{OP_EXIT, 0, 0, 0},                                    // 05) early exit if call from protected pid, 4
    
    vm_inst{OP_READ_CTX, 3, 32, sizeof(void*)},                   // 06) r3 = *inode, 5
    vm_inst{OP_ADD, 3, 0, 40},                                    // 07) r3 += 40 (offset), 6
    vm_inst{OP_READ, 4, 3, sizeof(void*)},                        // 08) r4 = *inode->i_sb, 7
    vm_inst{OP_ADD, 4, 0, 96},                                    // 09) r4 += 96 (offset), 8
    vm_inst{OP_READ, 5, 4, sizeof(unsigned long)},                // 10) r5 = *i_sb->s_magic, 9
    vm_inst{OP_LOAD, 6, 0, proc_super_magic_num},                 // 11) r6 = procfs magic num, 10
    vm_inst{OP_JEQ, 5, 6, 2},                                     // 12) ,11
    vm_inst{OP_EXIT, 0, 0, 0},                                    // 13) exit if not procfs, 12
    
    vm_inst{OP_READ_CTX, 3, 32, sizeof(void*)},                   // 14) r3 = *inode, 15
    vm_inst{OP_SUB, 3, 0, 72},                                    // 15) r3 = *proc_inode, 16
    vm_inst{OP_READ, 4, 3, sizeof(void*)},                        // 16) r4 = *struct pid, 17
    vm_inst{OP_ADD, 4, 0, 144},                                   // 17) r4 = *upid[0], 18
    vm_inst{OP_READ, 5, 4, sizeof(int)},                          // 18) r5 = target pid, 19
    vm_inst{OP_JNEQ, 0, 8, 3},                                    // 19) exit if read failed, means it is probably not procfs anyway idk
    vm_inst{OP_JEQ, 5, 1, 3},                                     // 20) jump if (r5 == r1), 21
    vm_inst{OP_LOAD, 0, 0, 0},                                    // 21) set return val to 0
    vm_inst{OP_EXIT, 0, 0, 0},                                    // 22) exit if not protected pid, 23

    vm_inst{OP_READ_CTX, 3, 64+8, sizeof(void*)},                 // 23) r3 = *dentry
    vm_inst{OP_ADD, 3, 0, 32+8},                                  // 24) r3 = **name
    vm_inst{OP_READ, 3, 3, sizeof(void*)},                        // 25) r3 = *name
    vm_inst{OP_READ, 5, 3, sizeof(void*)},                        // 26) r3 = first 8 bytes of name. should probably be on stack and have variable size
    vm_inst{OP_LOAD, 4, 0, (long long)maps},                      // 27) 1: load sus filename
    vm_inst{OP_JEQ, 5, 4, 6},                                     // 28) 2: if sus jump to submit ringbuf
    vm_inst{OP_LOAD, 4, 0, (long long)smaps},                     // 29) 1
    vm_inst{OP_JEQ, 5, 4, 4},                                     // 30) 2
    vm_inst{OP_LOAD, 4, 0, (long long)mem},                       // 31) 1
    vm_inst{OP_JEQ, 5, 4, 2},                                     // 32) 2
    vm_inst{OP_JMP, 0, 0, 4},                                     // 33) jump over ringbuf submit if not sus  
    vm_inst{OP_RINGBUF, 0, 0, 0},                                 // 
    vm_inst{OP_PRINTS, 0, 3, 0},                                  // 34) print sus file name
    
    vm_inst{OP_LOAD, 0, 0, 0},                                    // 35) set return val
    vm_inst{OP_EXIT, 0, 0, 0},                                    // 36) exit if not protected filename
  };
};
