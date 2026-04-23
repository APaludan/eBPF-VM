set(AGENTS_SOURCES vm_agent.cpp)

add_library(Agents ${AGENTS_SOURCES})

target_include_directories(Agents PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(Agents eBPF_Handlers eBPF_N_Handlers)
