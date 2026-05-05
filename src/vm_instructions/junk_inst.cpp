#include "junk_inst.h"
#include <random>
#include <fstream>
#include <iostream>

//==============================================
//===             HELPER FUNCTIONS           ===             
//==============================================

// TODO: lav den mere tilbøjlig til at vælge lave numre
static std::mt19937 rng(std::random_device{}());
size_t random_int(size_t min, size_t max) 
{
    std::uniform_int_distribution<size_t> dist(min, max);
    return dist(rng);
}

bool is_jmp_op(unsigned short op) 
{
    return op >= OP_JMP && op <= OP_JGTEQ;
}

size_t get_available_junk_space (std::vector<vm_inst> inst_set, size_t max_size)
{
    return max_size - inst_set.size();
}

std::vector<int> get_unused_registers(std::vector<vm_inst> inst_set)
{
    std::vector<int> unused_registers = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};

    for (vm_inst i : inst_set)
    {
        auto used_register = std::find(unused_registers.begin(), unused_registers.end(), i.dst);

        if (used_register != unused_registers.end())
            unused_registers.erase(used_register);
    }   

    return unused_registers;
}

// TODO: lav så den generere random instruktioner
vm_inst make_junk_inst(std::vector<int> unused_registers)
{
    (void)unused_registers;
    vm_inst junk_inst = vm_inst{OP_LOAD, 9, 0, 12345, 0};

    return junk_inst;
}

std::vector<vm_inst> make_junk_inst_set(size_t available_junk_space, std::vector<int> unused_registers) 
{

    std::vector<vm_inst> junk_inst_set;

    for (size_t i = 0; i < available_junk_space; i++)
    {
        vm_inst junk_inst = make_junk_inst(unused_registers);
        junk_inst_set.push_back(junk_inst);
    }

    return junk_inst_set;
}

// TODO: lav function der finder de steder der er "døde" i junk_inst (hvor vi ikke skal indsætte de rigtige instructions)
std::vector<int> get_dead_inst ()
{
    std::vector<int> dead_inst;
    return dead_inst;
}

std::vector<vm_inst> merge_inst_sets(std::vector<vm_inst> inst_set, std::vector<vm_inst> junk_inst_set, size_t max_size)
{
    size_t insert_indx = 0;     
    size_t inst_indx = 0; 
    
    while (inst_indx < inst_set.size())
    {
        if (is_jmp_op(inst_set[inst_indx].op))
        {
            size_t jmp_target_indx = inst_indx + inst_set[inst_indx].val;
            for (size_t i = inst_indx; i <= jmp_target_indx && i < inst_set.size(); i++)
            {
                junk_inst_set.insert(junk_inst_set.begin()+insert_indx, inst_set[i]);
                insert_indx += 1;
                inst_indx += 1;
            }   

        }
        else
        {
            int insert_at = random_int(insert_indx, junk_inst_set.size());
            junk_inst_set.insert(junk_inst_set.begin()+insert_at, inst_set[inst_indx]);
            insert_indx = insert_at+1;
            inst_indx += 1;
        }
    }
    
    return junk_inst_set;

}

//==============================================
//===              MAIN FUNCTION             ===             
//==============================================

std::vector<vm_inst> merge_junk_inst(std::vector<vm_inst> inst_set, size_t max_size)
{
    if (max_size == 0)
        return inst_set;

    int available_junk_space = get_available_junk_space(inst_set, max_size);

    std::vector<int> unused_registers = get_unused_registers(inst_set);

    std::vector<vm_inst> junk_inst_set = make_junk_inst_set(available_junk_space, unused_registers);

    std::vector<vm_inst> merged_junk_inst = merge_inst_sets(inst_set, junk_inst_set, max_size);

    return merged_junk_inst;
}


//==============================================
//===             PRINT INST SET             ===             
//==============================================

void print_program_map_to_csv( const std::unordered_map<int, std::vector<vm_inst>>& program_map, const std::string& filename)
{
    std::ofstream csv_file(filename);

    if (!csv_file.is_open()) 
    {
        throw std::runtime_error("Failed to open file for writing: " + filename);
    }

    csv_file << "Program Type,Index,Opcode,Dst,Src,Val,Offset\n";

    auto program_type_name = [](int type) -> std::string 
    {
        switch (type) 
        {
            case PTRACE_PROGRAM: return "PTRACE_PROGRAM";
            case LSM_OPEN_PROGRAM: return "LSM_OPEN_PROGRAM";
            case LSM_BPF_PROGRAM: return "LSM_BPF_PROGRAM";
            case KPROBE_FIND_VPID_PROGRAM: return "KPROBE_FIND_VPID_PROGRAM";
            case KPROBE_PID_TASK_PROGRAM: return "KPROBE_PID_TASK_PROGRAM";
            case SIMPLE_FILTER_PROGRAM: return "SIMPLE_FILTER_PROGRAM";
            case MODULE_LOAD_PROGRAM: return "MODULE_LOAD_PROGRAM";
            case MODULE_FREE_PROGRAM: return "MODULE_FREE_PROGRAM";
            default: return "UNKNOWN_PROGRAM";
        }
    };

    for (const auto& [program_type, instructions] : program_map) 
    {
        for (size_t i = 0; i < instructions.size(); ++i) 
        {
            const vm_inst& inst = instructions[i];
            csv_file << program_type_name(program_type) << ","
                     << i << ","
                     << inst.op << ","
                     << inst.dst << ","
                     << inst.src << ","
                     << inst.val << ","
                     << inst.offset << "\n";
        }
    }

    csv_file.close();
}