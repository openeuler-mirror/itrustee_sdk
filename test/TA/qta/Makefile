# Copyright (c) Huawei Technologies Co., Ltd. 2018-2021. All rights reserved.
include ./config.mk
include ../../../build/mk/common.mk

SRC += $(wildcard ./src/*.c)

# set header directory
INCLUDEDIR += -I./src

# qta need cJSON code, so download it and put it into src
SRC += ./src/cJSON/cJSON.c
INCLUDEDIR += -I./src/cJSON/

# if enable daa, so need to download pair_miracl lib
ifeq ($(ENABLE_DAA_PAIR_MIRACL), true)
INCLUDEDIR += -I./src/miracl-c
CFLAGS += -DENABLE_DAA_PAIR_MIRACL
LDFLFAGS += -lcore -L./src/miracl-c
SRC += ./src/daa/validate_akcert.c \
       ./src/daa/daa_structure.c
endif

# set target
COBJS := $(SRC:%.c=%.o)
TARGET = $(COBJS)

sec_binary:combine
	python3 -B ${SIGNTOOL_DIR}/signtool_v3.py ${CUR_DIR} ${CUR_DIR} --privateCfg ${SIGNTOOL_DIR}/config_cloud.ini

combine: $(TARGET)
	$(LD) $(LDFLAGS) $(TARGET) $(EXTRAO) -o libcombine.so
	objcopy libcombine.so

src/%.o: ./src/%.c
	$(CC) $(CFLAGS)  $(INCLUDEDIR) -c $< -o $@

%.o: %.c
	$(CC) $(CFLAGS)  $(INCLUDEDIR) -c $< -o $@

clean:
	rm -f $(COBJS) *.so *.sec
