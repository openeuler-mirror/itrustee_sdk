CUR_DIR=$(shell pwd)
iTrustee_SDK_PATH=${CUR_DIR}
TARGET_APP := libteec_adaptor.so
APP_SOURCES += $(iTrustee_SDK_PATH)/src/CA/cloud/libteec_adaptor.c
APP_CFLAGS += -fstack-protector-strong -fPIC -ftrapv -s -D_FORTIFY_SOURCE=2 -O2
APP_CFLAGS += -I$(iTrustee_SDK_PATH)/include/CA -I$(iTrustee_SDK_PATH)/thirdparty/open_source/libboundscheck/include

APP_LDFLAGS += -z text -z now -z relro -z noexecstack -pie -shared
$(TARGET_APP): $(APP_SOURCE)
	@$(CC) $(APP_CFLAGS) $(APP_LDFLAGS) $(APP_SOURCES) -o $@

install: $(TARGET_APP)
	install -d /opt/itrustee_sdk
	cp -r build include License thirdparty /opt/itrustee_sdk
	install -pm 644 libteec_adaptor.so /lib64/ 
clean:
	rm -rf *.o $(TARGET_APP)
