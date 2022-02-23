CUR_DIR=$(shell pwd)
iTrustee_SDK_PATH=${CUR_DIR}/../../../../
SIGNTOOL_DIR=${iTrustee_SDK_PATH}/build/signtools/

LIBC=$(iTrustee_SDK_PATH)/thirdparty/open_source/musl
LIBSECURE=$(iTrustee_SDK_PATH)/thirdparty/open_source/libboundscheck/

# set compile parameters
CFLAGS += -O -W -Wall
CFLAGS += -Werror
CFLAGS += -fno-short-enums
CFLAGS += -fno-omit-frame-pointer
CFLAGS += -fstack-protector-strong
CFLAGS += -Wextra -nostdinc -nodefaultlibs
CFLAGS += -march=armv8-a -Os -Wno-main -fPIC
CFLAGS += -Wno-error=unused-parameter -Wno-error=unused-but-set-variable

CFLAGS += -DCONFIG_AUTH_CLOUD

# set header directory
INCLUDEDIR += -I$(LIBC)/libc \
	-I$(LIBC)/libc/arch/aarch64 \
	-I$(LIBC)/libc/arch/aarch64/bits \
	-I$(LIBC)/libc/arch/generic

INCLUDEDIR += -I$(LIBSECURE)/include

INCLUDEDIR += -I$(iTrustee_SDK_PATH)/include/TA/ \
	-I$(iTrustee_SDK_PATH)/include/TA/huawei_ext/ \

$(info "include is: "$(INCLUDEDIR))

# set LD flags
LDFLAGS += -s -z text -z now -z relro -z noexecstack -shared

LDFLAGS += -T$(iTrustee_SDK_PATH)/build/tools/ta_link_64.ld
