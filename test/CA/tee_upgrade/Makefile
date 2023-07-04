# Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
obj-m := tee_upgrade.o
tee_upgrade-objs := upgrade.o

APP_CFLAGS += -I$(ITRUSTEE_BUILD_PATH)/thirdparty/open_source/libboundscheck/include

APP_LDFLAGS += -lboundscheck

KPATH	:= /usr/src/kernels
KDIR	:= $(KPATH)/$(shell ls $(KPATH))

EXTRA_CFLAGS += -I$(PWD)/../tzdriver

all:
	make -C $(KDIR) M=$(PWD) modules
clean:
	-rm -vrf *.order *.symvers *.mod.c .tmp_version .*o.cmd *.o