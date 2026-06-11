enable_testing()

add_executable(
    tests
    test_xor.cpp
    test_fix_jumps.cpp
)


target_link_libraries(
    tests
    VM_inst
    gtest_main
    # Add other libraries your tests depend on
)

include(GoogleTest)
gtest_discover_tests(tests)