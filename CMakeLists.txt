cmake_minimum_required(VERSION 3.25.1)

set(CMAKE_C_COMPILER clang)
set(CMAKE_CXX_COMPILER clang++)

project(
  eBPF_VM
  VERSION 1.0.0
  LANGUAGES C CXX
  DESCRIPTION "eBPF obfuscation using virtulization")

set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake/")

add_compile_options(-Wall -Wextra)

include(Environment)
include(CPM)
include(Packages)
include(Compiler)
include(BPF)

include(CTest)

add_subdirectory(src)
add_subdirectory(tests)
