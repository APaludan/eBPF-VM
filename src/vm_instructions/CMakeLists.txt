set(VM_INST vm_inst.cpp)

add_library(VM_inst ${VM_INST})

target_include_directories(VM_inst PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(VM_inst eBPF_Handlers)
