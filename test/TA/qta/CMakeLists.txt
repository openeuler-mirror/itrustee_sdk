# sdk cmake.
# Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
cmake_minimum_required(VERSION 3.16 FATAL_ERROR)
project(tee_sdk C)

if (PROJECT_SOURCE_DIR STREQUAL PROJECT_BINARY_DIR)
    message(FATAL_ERROR "Forbid compiling in the source tree")
endif()

include(${CMAKE_CURRENT_SOURCE_DIR}/config.cmake)
include($ENV{ITRUSTEE_BUILD_PATH}/build/cmake/common.cmake)

set(LIBRARY_OUTPUT_PATH ${CMAKE_CURRENT_SOURCE_DIR})
set(CURRENT_TARGET_SO "combine")

# enable check daa pairing using MIRACAL library
# you should download the opensource library: miracl/core, copy its dir c/ into src/, and compile core.a
# for instance:
#   cd src; ln -s $MIRACL_DIR/c miracl-c
#   cd miracl-c; export CC=xxx CFLAGS=-fPIC; python3 config64.py -o 33; unset CC CFLAGS
set(ENABLE_DAA_PAIR_MIRACL n)
if ("${ENABLE_DAA_PAIR_MIRACL}" STREQUAL "y")
    set(DAA_PAIR_MIRACL_C_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src/miracl-c)
    set(DAA_PAIR_MIRACL_C_INC ${DAA_PAIR_MIRACL_C_DIR}/)
    set(DAA_PAIR_MIRACL_C_LIB ${DAA_PAIR_MIRACL_C_DIR}/core.a)
    set(DAA_PAIR_MIRACL_C_SRC
        src/daa/validate_akcert.c
        src/daa/daa_structure.c
    )
else()
    set(DAA_PAIR_MIRACL_C_INC "")
    set(DAA_PAIR_MIRACL_C_SRC "")
endif()

# qta need cjson, so you can download cjson and rename cJSON to put it src directory
set(CJSON_INC ${CMAKE_CURRENT_SOURCE_DIR}/src/cJSON)
set(CJSON_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/cJSON/cJSON.c)

set(SDK_C_SOURCES
    ${SDK_C_SOURCES}
    src/tee_qta.c
    ${CJSON_SRC}
    ${DAA_PAIR_MIRACL_C_SRC}
)

set(COMMON_INCLUDES
    ${COMMON_INCLUDES}
    ${CMAKE_CURRENT_SOURCE_DIR}/src/.
    ${CJSON_INC}
    ${DAA_PAIR_MIRACL_C_INC}
)

add_library(${CURRENT_TARGET_SO} SHARED ${SDK_C_SOURCES})
target_include_directories(${CURRENT_TARGET_SO} PUBLIC ${COMMON_INCLUDES})
target_compile_options(${CURRENT_TARGET_SO} PRIVATE ${COMMON_CFLAGS})
target_link_options(${CURRENT_TARGET_SO} PRIVATE ${COMMON_LDFLAGS})

if ("${ENABLE_DAA_PAIR_MIRACL}" STREQUAL "y")
    add_definitions(-DENABLE_DAA_PAIR_MIRACL)
    target_link_libraries(${CURRENT_TARGET_SO} PUBLIC ${DAA_PAIR_MIRACL_C_LIB})
endif()

add_custom_command(
   TARGET ${CURRENT_TARGET_SO} POST_BUILD
   COMMAND ${CMAKE_OBJCOPY} ${CMAKE_CURRENT_SOURCE_DIR}/libcombine.so
   COMMAND python3 -B $ENV{ITRUSTEE_BUILD_PATH}/build/signtools/signtool_v3.py ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR} --privateCfg $ENV{ITRUSTEE_BUILD_PATH}/build/signtools/config_cloud.ini
)
