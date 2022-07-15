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

set(SDK_C_SOURCES
    ${SDK_C_SOURCES}
    ta_demo.c
)

add_library(${CURRENT_TARGET_SO} SHARED ${SDK_C_SOURCES})
target_include_directories(${CURRENT_TARGET_SO} PUBLIC ${COMMON_INCLUDES})
target_compile_options(${CURRENT_TARGET_SO} PRIVATE ${COMMON_CFLAGS})
target_link_options(${CURRENT_TARGET_SO} PRIVATE ${COMMON_LDFLAGS})

add_custom_command(
   TARGET ${CURRENT_TARGET_SO} POST_BUILD
   COMMAND ${CMAKE_OBJCOPY} ${CMAKE_CURRENT_SOURCE_DIR}/libcombine.so
   COMMAND python3 -B $ENV{ITRUSTEE_BUILD_PATH}/build/signtools/signtool_v3.py ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR} --privateCfg $ENV{ITRUSTEE_BUILD_PATH}/build/signtools/config_cloud.ini
)
