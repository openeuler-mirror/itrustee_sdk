# Copyright (c) Huawei Technologies Co., Ltd. 2018-2021. All rights reserved.
CUR_DIR=$(shell pwd)
ITRUSTEE_BUILD_PATH=${CUR_DIR}/../../../

TARGET_LIB := libqca.so
TARGET_DIR := output
TARGET_LIB_BOUNDSCHECK := libboundscheck.so

LIB_SOURCES := src/ra_operate_api.c

LIB_SOURCES += $(ITRUSTEE_BUILD_PATH)/src/CA/libteec_adaptor.c

LIB_CFLAGS += -Werror -Wall -Wextra -fstack-protector-strong -Wl,-z,relro,-z,now,-z,noexecstack -s -fPIC -D_FORTIFY_SOURCE=2 -O2

LIB_CFLAGS += -I$(ITRUSTEE_BUILD_PATH)/thirdparty/open_source/libboundscheck/include
LIB_CFLAGS += -I$(ITRUSTEE_BUILD_PATH)/include/CA
LIB_CFLAGS += -I./include

LIB_LDFLAGS += -ldl -lpthread
LIB_LDFLAGS += -lboundscheck -L$(ITRUSTEE_BUILD_PATH)/thirdparty/open_source/libboundscheck/lib/

LIB_OBJECTS := $(LIB_SOURCES:.c=.o)

all: $(TARGET_LIB_BOUNDSCHECK) $(TARGET_LIB)

LIB_BOUNDSCHECK_DIR := $(ITRUSTEE_BUILD_PATH)/thirdparty/open_source/libboundscheck/
$(TARGET_LIB_BOUNDSCHECK):
	@echo "compile libboundscheck start"
	@$(MAKE) -C $(LIB_BOUNDSCHECK_DIR)
	@echo "compile libboundscheck finish"

$(TARGET_LIB): $(TARGET_LIB_BOUNDSCHECK) $(LIB_SOURCES)
	@echo "start compile libqca.so ......"
	@$(CC) -shared $(LIB_CFLAGS) -o $@ $(LIB_SOURCES) $(LIB_LDFLAGS)
	@mkdir -p $(TARGET_DIR)
	@mv $(TARGET_LIB) $(TARGET_DIR)
	@echo "compile libqca.so done!"

clean:
	$(MAKE) -C $(LIB_BOUNDSCHECK_DIR) clean
	rm -rf $(LIB_OBJECTS)
	rm -rf $(TARGET_DIR)
