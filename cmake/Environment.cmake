if(NOT UNIX)
  message(FATAL_ERROR "eBPF only supports Linux.")
endif()


# Check for CLang compiler
find_program(CLANG_EXECUTABLE clang)

if(NOT CLANG_EXECUTABLE)
  message(
    FATAL_ERROR
      "clang is required to build eBPF programs, but was not found in PATH")
endif()


# Check for BPFTool
find_program(BPFT_TOOL bpftool)
if(NOT BPFT_TOOL)
  message(FATAL_ERROR "bpftool is required to generate skeleton headers")
endif()


# Check for ccache
find_program(CCACHE ccache)
if(NOT CCACHE)
  message(FATAL_ERROR "ccache is required to build. Install with:\n sudo pacman -S ccache")
endif()