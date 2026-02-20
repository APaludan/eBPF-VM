set(eBPF_HANDLER_SOURCES vm_handler.cpp)

add_library(eBPF_Handlers ${eBPF_HANDLER_SOURCES})

target_include_directories(
  eBPF_Handlers
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
  PUBLIC ${CMAKE_BINARY_DIR}/skeletons)

target_link_libraries(eBPF_Handlers DataTypes)

add_dependencies(eBPF_Handlers vm_skel)
