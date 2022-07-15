# Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
# compile flags
set(ITRUSTEE_BUILD_PATH $ENV{ITRUSTEE_BUILD_PATH})
set(LIBC ${ITRUSTEE_BUILD_PATH}/thirdparty/open_source/musl)
set(LIBSECURE ${ITRUSTEE_BUILD_PATH}/thirdparty/open_source/libboundscheck)

set(COMMON_INCLUDES
    ${COMMON_INCLUDES}
    ${LIBC}/libc
    ${LIBC}/libc/arch/aarch64
    ${LIBC}/libc/arch/aarch64/bits
    ${LIBC}/libc/arch/generic
    ${LIBSECURE}/include
    ${ITRUSTEE_BUILD_PATH}/include/TA
    ${ITRUSTEE_BUILD_PATH}/include/TA/huawei_ext
)

set(COMMON_CFLAGS
    ${COMMON_CFLAGS}
    -W
    -Wall
    -Werror
    -fno-short-enums
    -fno-omit-frame-pointer
    -fstack-protector-strong
    -Wextra
    -nostdinc
    -march=armv8-a -Os
    -fPIC
    -fno-common
    -fsigned-char
)

set(COMMON_LDFLAGS
    ${COMMON_LDFLAGS}
    "-s"
    "SHELL:-z text"
    "SHELL:-z now"
    "SHELL:-z relro"
    "SHELL:-z noexecstack"
    "SHELL:-z max-page-size=0x1000"
    "SHELL:-z common-page-size=0x1000"
    "-shared"
)

if ("${USE_SMEE}" STREQUAL "y")
    list(APPEND COMMON_LDFLAGS
        "-T${ITRUSTEE_BUILD_PATH}/build/tools/ta_link_64.smee.ld"
    )
else()
    List(APPEND COMMON_LDFLAGS
        "-T${ITRUSTEE_BUILD_PATH}/build/tools/ta_link_64.ld"
    )
endif()
