enable_testing()

add_executable(
    vm_tests
    test_xor.cpp
)

# target_include_directories(vm_tests PRIVATE ${CMAKE_SOURCE_DIR}/src)

target_link_libraries(
    vm_tests
    VM_inst
    gtest_main
    # Add other libraries your tests depend on
)

include(GoogleTest)
gtest_discover_tests(vm_tests)