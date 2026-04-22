set(eBPF_N_HANDLER n_handler.cpp)

add_library(eBPF_N_Handlers ${eBPF_N_HANDLER})

target_include_directories(
  eBPF_N_Handlers
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
  PUBLIC ${CMAKE_BINARY_DIR}/skeletons)

target_link_libraries(eBPF_N_Handlers DataTypes VM_inst)

add_dependencies(eBPF_N_Handlers vm_skel)
