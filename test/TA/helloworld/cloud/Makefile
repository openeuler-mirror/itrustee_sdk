include ../config.mk
include ../../../../build/mk/cloud/common.mk

SRC += $(wildcard ./*.c)
SRC += ../ta_demo.c

# set header directory
INCLUDEDIR += -I./include

# set target
COBJS := $(SRC:%.c=%.o)
TARGET = $(COBJS)

sec_binary:combine
	cp ../manifest.txt ./
	python3 -B ${SIGNTOOL_DIR}/signtool_v3.py ${CUR_DIR} ${CUR_DIR} --config ${SIGNTOOL_DIR}/cloud/config_cloud.ini

combine: $(TARGET)
	$(LD) $(LDFLAGS) $(TARGET) $(EXTRAO) -o libcombine.so

src/%.o: ./src/%.c
	$(CC) $(CFLAGS)  $(INCLUDEDIR) -c $< -o $@

%.o: %.c
	$(CC) $(CFLAGS)  $(INCLUDEDIR) -c $< -o $@

clean:
	rm -f $(COBJS) *.so
