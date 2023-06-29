# Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
obj-m := tee_upgrade.o
tee_upgrade-objs := upgrade.o

EXTRA_CFLAGS += -I$(PWD)/../itrustee/platform/libhwsecurec/include/libhwsecurec -I$(PWD)/../iTrustee/platform/libhwsecurec/include

KPATH	:= /usr/src/kernels
KDIR	:= $(KPATH)/$(shell ls $(KPATH))

EXTRA_CFLAGS += -I$(PWD)/../tzdriver

all:
	make -C $(KDIR) M=$(PWD) modules
clean:
	-rm -vrf *.order *.symvers *.mod.c .tmp_version .*o.cmd *.o