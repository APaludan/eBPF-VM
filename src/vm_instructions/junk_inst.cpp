#include "junk_inst.h"
#include <random>
#include <fstream>
#include <iostream>
#include <bits/stdc++.h>
//==============================================
//===             HELPER FUNCTIONS           ===             
//==============================================

// TODO: lav function der finder de steder der er "døde" i junk_inst (hvor vi ikke skal indsætte de rigtige instructions)
std::vector<int> get_dead_inst ()
{
    std::vector<int> dead_inst;
    return dead_inst;
}

// TODO: lav så den generere random instruktioner
vm_inst make_junk_inst(std::vector<int> unused_registers)
{
    (void)unused_registers;
    vm_inst junk_inst = vm_inst{OP_LOAD, 9, 0, 12345, 0};

    return junk_inst;
}

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


std::vector<size_t> union_2_vectors(std::vector<size_t> v1, std::vector<size_t> v2) {

    std::vector<size_t> res;
    std::unordered_set<size_t> seen;

    for (size_t i : v1) 
    {
        if (seen.find(i) == seen.end()) 
        {
            res.push_back(i);  
            seen.insert(i);
        }
    }

    for (size_t i : v2) 
    {
        if (seen.find(i) == seen.end()) 
        {
            res.push_back(i);
            seen.insert(i);
        }
    }

    return res;
}


std::vector<std::vector<size_t>> union_jmp_indx(std::vector<std::vector<size_t>> jmp_indx)
{
    std::vector<std::vector<size_t>> result;

    if (jmp_indx.size() <= 1)
        return jmp_indx;

    for (size_t i = 0; i < jmp_indx.size(); ++i)
    {
        std::vector<size_t> res = jmp_indx[i];

        size_t j = i + 1;
        while (j < jmp_indx.size())
        {
            if (res.back() < jmp_indx[j].front())
                break;


            res = union_2_vectors(res, jmp_indx[j]);

            jmp_indx.erase(jmp_indx.begin() + j);
        }

        result.push_back(res);
    }

    return result;
}

std::vector<std::vector<size_t>> get_jmp_indx(const std::vector<vm_inst>& inst_set)
{
    std::vector<std::vector<size_t>> jmp_indx;
    size_t inst_set_size = inst_set.size();

    for (size_t i = 0; i < inst_set_size; i++)
    {
        if (is_jmp_op(inst_set[i].op))
        {
            std::vector<size_t> jmp_affected_inst;
            int jmp_val = inst_set[i].val;

            if (jmp_val >= 0)
            {
                for (int j = 0; j < jmp_val; j++)
                    jmp_affected_inst.push_back(i + static_cast<size_t>(j));
            }
            else
            {
                for (int j = 0; j > jmp_val; j--)
                {
                    int safe = i + j;
                    if (safe >= 0)
                        jmp_affected_inst.push_back(static_cast<size_t>(safe));
                }
                std::reverse(jmp_affected_inst.begin(), jmp_affected_inst.end());

            }
            jmp_indx.push_back(jmp_affected_inst);
        }
    }

    std::vector<std::vector<size_t>> final_result = union_jmp_indx(jmp_indx);

    return final_result;
}

std::vector<std::vector<size_t>> get_code_blocks(std::vector<vm_inst> inst_set)
{
    std::vector<std::vector<size_t>> jmp_indx = get_jmp_indx(inst_set);

    size_t inst_set_size = inst_set.size(); 
    std::vector<std::vector<size_t>> code_blocks;
    size_t i = 0;

    while (i < inst_set_size) 
    {
        if (!jmp_indx.empty() && i == jmp_indx[0].at(0))
        {
            code_blocks.push_back(jmp_indx[0]);
            i = i + jmp_indx[0].size();
            jmp_indx.erase(jmp_indx.begin());
        }
        else 
        {
            std::vector<size_t> i_vector = {i};
            code_blocks.push_back(i_vector);
            i += 1;
        }
    }

    return code_blocks;
}

std::vector<vm_inst> merge_inst_sets(std::vector<vm_inst> inst_set, std::vector<vm_inst> junk_inst_set)
{
    std::vector<std::vector<size_t>> code_blocks = get_code_blocks(inst_set);
    size_t insert_indx = 0;  
    
    for (size_t i = 0; i < code_blocks.size(); i++)
    {       
        for (size_t j = 0; j < code_blocks[i].size(); j++)
        {

            int insert_at = (j == 0)
                ? random_int(insert_indx, junk_inst_set.size())
                : insert_indx;
                
            junk_inst_set.insert(junk_inst_set.begin()+insert_at, inst_set[code_blocks[i].at(j)]);
            insert_indx = insert_at+1;

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

    std::vector<vm_inst> merged_junk_inst = merge_inst_sets(inst_set, junk_inst_set);

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