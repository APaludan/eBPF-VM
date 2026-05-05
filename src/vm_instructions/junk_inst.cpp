#include "junk_inst.h"
#include <random>
#include <fstream>

//==============================================
//===             Junk inst set              ===             
//==============================================

// TODO: Create random junk each time

std::vector<vm_inst> junk_1()
{
    return 
    {
        vm_inst{OP_LOAD, 9, 0, 12345, 0},  // r9 = 12345
        vm_inst{OP_ADD, 9, 9, 6789, 0},    // r9 += 6789
        vm_inst{OP_SUB, 9, 9, 6789, 0},    // r9 -= 6789
        vm_inst{OP_MULT, 9, 9, 3, 0},      // r9 *= 3
        vm_inst{OP_DIV, 9, 9, 3, 0},       // r9 /= 3
    };
}

std::vector<vm_inst> junk_2()
{
    return 
    {
        vm_inst{OP_LOAD, 9, 0, 1, 0},       // r9 = 1
        vm_inst{OP_JEQ, 9, 9, 2, 0},        // always true → skip next 2
        vm_inst{OP_LOAD, 9, 0, 999, 0},     // dead code
        vm_inst{OP_ADD, 9, 9, 1, 0},        // dead code
    };
}

std::vector<vm_inst> junk_3()
{
    return 
    {
        vm_inst{OP_LOAD, 9, 0, 7, 0},
        vm_inst{OP_MULT, 9, 9, 6, 0},     // 42
        vm_inst{OP_DIV, 9, 9, 2, 0},      // 21

        vm_inst{OP_JNEQ, 9, 9, 2, 0},     // never taken
        vm_inst{OP_LOAD, 9, 0, 999, 0},   // dead
        vm_inst{OP_ADD, 9, 9, 1, 0},      // dead

        vm_inst{OP_LSHIFT, 9, 9, 1, 0},
        vm_inst{OP_RSHIFT, 9, 9, 1, 0},   // cancel
    };
}

//==============================================
//===             Junk gen logic             ===             
//==============================================

static std::mt19937 rng(std::random_device{}());

int random_int(int min, int max) 
{
    std::uniform_int_distribution<int> dist(min, max);
    return dist(rng);
}

std::vector<vm_inst> random_junk()
{

    int r = random_int(0, 2);

    switch (r)
    {
        case 0:
            return junk_1();
        case 1:
            return junk_2();
        case 2:
            return junk_3();
        default:
            return junk_1();
    }
}

bool is_jmp_op(unsigned short op) 
{
    return op >= OP_JMP && op <= OP_JGTEQ;
}

// TODO: Still neeed to tage højde for MAX_INSTRUCTION (define length of what length the instr set should be) + might be a better way then just skip next offset of instructions for each jump op
std::vector<vm_inst> generate_junk_inst(std::vector<vm_inst> inst_set) 
{

    std::vector<vm_inst> junk_injected_inst;
    size_t i = 0;
    
    while (i < inst_set.size()) 
    {
        junk_injected_inst.push_back(inst_set[i]);
        
        if (is_jmp_op(inst_set[i].op)) 
        {
            if ((int)inst_set[i].val < 0) {
                i++;
                continue;
            }
            size_t target_index = i + inst_set[i].val;

            for (size_t j = i + 1; j <= target_index && j < inst_set.size(); j++)
            {
                junk_injected_inst.push_back(inst_set[j]);
            }

            i = target_index; 

        } else 
        {
            if (random_int(0, 100) <= 100) 
            {
                auto junk = random_junk();
                junk_injected_inst.insert(junk_injected_inst.end(), junk.begin(), junk.end());
            }
        }

        i++;
    }
    
    return junk_injected_inst;
}

//==============================================
//===             Print inst set             ===             
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