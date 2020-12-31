CUR_DIR=$(shell pwd)
iTrustee_SDK_PATH=${CUR_DIR}/../../../../

TARGET_APP := teec_hello

APP_SOURCES := ../ca_demo.c

APP_SOURCES += $(iTrustee_SDK_PATH)/src/CA/cloud/libteec_adaptor.c

APP_CFLAGS += -fstack-protector-strong -fPIC

APP_CFLAGS += -I$(iTrustee_SDK_PATH)/include/CA \

APP_LDFLAGS += -ldl -lpthread

APP_LDFLAGS += -z text -z now -z relro -z noexecstack -pie

APP_OBJECTS := $(APP_SOURCES:.c=.o)
$(TARGET_APP): $(APP_SOURCES)
	@$(CC) $(APP_CFLAGS) -o $@ $(APP_SOURCES) $(APP_LDFLAGS)

clean:
	rm -f *.o $(TARGET_APP)
