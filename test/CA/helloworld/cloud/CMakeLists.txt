cmake_minimum_required (VERSION 2.8)
project (teec_hello)
cmake_policy (SET CMP0037 OLD)

# Add source files
set(SRCS
    ../ca_demo.c
    ../../../../src/CA/cloud/libteec_adaptor.c
)

# Add header file include directories
include_directories(
    ../../../../include/CA
)

# Set options
set(CMAKE_TEEC_HELLO_FLAGS "-fstack-protector-strong -fPIC")
set(CMAKE_TEEC_HELLO_FLAGS "${CMAKE_TEEC_HELLO_FLAGS} -z text -z now -z relro -z noexecstack -pie")

# Set output dir
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR})

# Generate execute file
add_executable(rsa_demo ${SRCS})
target_link_libraries(rsa_demo dl pthread)
set_target_properties(rsa_demo PROPERTIES COMPILE_FLAGS ${CMAKE_TEEC_HELLO_FLAGS})
 
# Clean output
add_custom_target(clean
    COMMAND rm -rf ${PROJECT_SOURCE_DIR}/teec_hello
    COMMAND @echo "clean up"
)
