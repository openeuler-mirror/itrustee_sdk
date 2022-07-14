# Copyright (c) Huawei Technologies Co., Ltd. 2018-2021. All rights reserved.
CUR_DIR=$(shell pwd)
ifeq ($(ITRUSTEE_BUILD_PATH), )
    ITRUSTEE_BUILD_PATH=${CUR_DIR}/../../..
endif
SIGNTOOL_DIR=${ITRUSTEE_BUILD_PATH}/build/signtools

LIBC=$(ITRUSTEE_BUILD_PATH)/thirdparty/open_source/musl
LIBSECURE=$(ITRUSTEE_BUILD_PATH)/thirdparty/open_source/libboundscheck

# set compile parameters
CFLAGS += -W -Wall
CFLAGS += -Werror
CFLAGS += -fno-short-enums
CFLAGS += -fno-omit-frame-pointer
CFLAGS += -fstack-protector-strong
CFLAGS += -Wextra -nostdinc
CFLAGS += -march=armv8-a -Os -fPIC
CFLAGS += -fno-common -fsigned-char

# set header directory
INCLUDEDIR += -I$(LIBC)/libc \
	-I$(LIBC)/libc/arch/aarch64 \
	-I$(LIBC)/libc/arch/aarch64/bits \
	-I$(LIBC)/libc/arch/generic

INCLUDEDIR += -I$(LIBSECURE)/include

INCLUDEDIR += -I$(ITRUSTEE_BUILD_PATH)/include/TA/ \
	-I$(ITRUSTEE_BUILD_PATH)/include/TA/huawei_ext/ \

# set LD flags
LDFLAGS += -s -z text -z now -z relro -z noexecstack -z max-page-size=0x1000 -z common-page-size=0x1000 -shared

ifeq ($(USE_SMEE),y)
	LDFLAGS += -T$(ITRUSTEE_BUILD_PATH)/build/tools/ta_link_64.smee.ld
else
	LDFLAGS += -T$(ITRUSTEE_BUILD_PATH)/build/tools/ta_link_64.ld
endif
