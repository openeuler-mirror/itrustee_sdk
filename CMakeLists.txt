cmake_minimum_required (VERSION 2.8)
project (teec_adaptor)
cmake_policy (SET CMP0037 OLD)

# Add source files
set(SRCS ./src/CA/cloud/libteec_adaptor.c)

# Add header file include directories
include_directories(
    ./include/CA
    ./thirdparty/open_source/liboundscheck/include
)

# Set options
set(CMAKE_TEEC_ADAPTOR_FLAGS "-fstack-protector-strong -fPIC -ftrapv -s -D_FORTIFY_SOURCE=2 -O2")
set(CMAKE_TEEC_ADAPTOR_FLAGS "${CMAKE_TEEC_ADAPTOR_FLAGS} -z text -z now -z relro -z noexecstack -pie -shared")

# Set output dir
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR})

# Generate .so file
add_library(teec_adaptor SHARED ${SRCS})
set_target_properties(teec_adaptor PROPERTIES COMPILE_FLAGS ${CMAKE_TEEC_ADAPTOR_FLAGS})
 
# Clean output
add_custom_target(clean
    COMMAND rm -rf ${PROJECT_SOURCE_DIR}/libteec_adaptor.so
    COMMAND @echo "clean up"
)

# Install
add_custom_target(install
    COMMAND install -d /opt/itrustee_sdk
    COMMAND cp -rf ${PROJECT_SOURCE_DIR}/build ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/License ${PROJECT_SOURCE_DIR}/thirdparty /opt/itrustee_sdk
    COMMAND install -pm 644 ${PROJECT_SOURCE_DIR}/libteec_adaptor.so /lib64
)
