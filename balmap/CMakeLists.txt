project(balmap)
cmake_minimum_required(VERSION 3.16)

include_directories(.)
add_library( balmap_rt STATIC src/balmap.c )

enable_testing()
include(GoogleTest)
add_executable(test_runner test/test_main.cpp)
target_link_libraries(test_runner balmap_rt gtest_main gtest pthread )

gtest_discover_tests(test_runner)

# set(UNIT_TEST test_runner)
# add_custom_command(
#      TARGET ${UNIT_TEST}
#      COMMENT "Run tests"
#      POST_BUILD 
#      WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
#      COMMAND ${UNIT_TEST}
# )
