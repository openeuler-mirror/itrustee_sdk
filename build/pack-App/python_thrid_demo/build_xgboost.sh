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
export PYTHONHOME=${LOCAL_PYTHON_DIR}
export PATH=${LOCAL_PYTHON_DIR}/bin:$PATH

install_py(){
	sed -i '172s/use_omp=1/use_omp=0/g' setup.py
	sed -i '260s/self.use_openmp = 1/self.use_openmp = 0/g' setup.py
	python3 setup.py install --prefix=$BUILD_DIR/
}

export CXXFLAGS=" -fstack-protector-strong -O2 -pipe --sysroot=$SDKTARGETSYSROOT -nostdinc++ -DHAVE_IOSTREAM -ISDKTARGETSYSROOT/usr/include -ISDKTARGETSYSROOT/usr/lib/gcc/aarch64-hongmeng-musl/7.3.0/include -ISDKTARGETSYSROOT/usr/include/c++/7.3.0 -ISDKTARGETSYSROOT/usr/include/c++/7.3.0/aarch64-hongmeng-musl/ -D_GUN_SOURCE -fPIC -fwrapv -DPOCKETFFT_NO_MULTITHREADING"

cd xgboost-1.5.1
rm -rf build

export LDSHARED="gcc -pthread -shared -Wl,-L$OUTPUT_PYTHON_DIR/lib -B$SDKTARGETSYSROOT/usr/lib -L$SDKTARGETSYSROOT/usr/lib -B$SDKTARGETSYSROOT/lib -L$SDKTARGETSYSROOT/lib -v"

export LDFLAGS=" --verbose -L$SDKTARGETSYSROOT/usr/lib -L$SDKTARGETSYSROOT/lib -L$SDKTARGETSYSROOT/usr/lib/gcc/aarch64-hongmeng-musl/7.3.0/ -nostdlib -nostartfiles -lc -lhmulibs -lhmsrv_fs -lhmsrv_net -lhwsecurec -lgcc_S -lstdc++ -Wl,--dynamic-linker=/lib/hmld.so.elf -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -Wl,-O1 -Wl,--hash-style=gnu -Wl,--as-needed"

install_py