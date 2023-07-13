#!/usr/bin/env bash
set -e

SDKDIR=$1
LOCAL_PYTHON_DIR=$2
ROOTDIR=$(pwd)
OUTPUT_PYTHON_DIR=$ROOTDIR/output_python
BUILD_DIR=${ROOTDIR}/build
SDKTARGETSYSROOT=$SDKDIR/sysroot/ccos

mkdir -p ${OUTPUT_PYTHON_DIR}/lib/python3.6/site-packages/
mkdir -p ${BUILD_DIR}/lib/python3.6/site-packages/

export PYTHONPATH=$PYTHONPATH:${LOCAL_PYTHON_DIR}
export PYTHONPATH=$BUILD_DIR/lib/python3.6/site-packages:$PYTHONPATH
export PYTHONHOME=${LOCAL_PYTHON_DIR}
export PATH=${LOCAL_PYTHON_DIR}/bin:$PATH

mkdir -p $PANDAS_PATH/lib/python3.6/site-packages/

export CC="gcc -mlittle-endian --sysroot=$SDKTARGETSYSROOT -fstack-protector-strong -O2 -pipe -ISDKTARGETSYSROOT/usr/include/c++/7.3.0 -ISDKTARGETSYSROOT/usr/include/c++/7.3.0/aarch64-hongmeng-musl -nostdinc -ISDKTARGETSYSROOT/usr/include -ISDKTARGETSYSROOT/usr/lib/gcc/aarch64-hongmeng-musl/7.3.0/include -I$SDKDIR/sysroots/aarch64-euler-elf_all_in_one/usr/include -L$SDKTARGETSYSROOT/usr/lib -L$SDKTARGETSYSROOT/lib -Lbuild/lib -nostdlib -nostartfiles -lc -lhmulibs -lhmsrv_fs -lhmsrv_net -lhwsecurec -lgcc_s -lm -lstdc++ -Wl,--dynamic-linker=/lib/hmld.so.elf -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -Wl,-O1 -Wl,--hash-style=gnu -Wl,--as-needed"

install_scipy(){
	rm -rf build
	python3 setup.py build install --prefix=${ROOTDIR}/build/scipy
}

cd scipy-1.5.4
install_scipy