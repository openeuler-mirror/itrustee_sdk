#!/bin/bash
# Description: preare toolchains and env for build ta.
# Copyright @ Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan
# PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
# KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
# NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.
set -e

SDKDIR=$1
LOCAL_PYTHON_DIR=$2
ROOTDIR=$(pwd)
SDKTARGETSYSROOT=$SDKDIR/sysroot/ccos

export PYTHONPATH=${LOCAL_PYTHON_DIR}
export PYTHONPATH=$BUILD_DIR/lib/python3.6/site-packages:$PYTHONPATH
export PYTHONHOME=${LOCAL_PYTHON_DIR}
export PATH=${LOCAL_PYTHON_DIR}/bin:$PATH

PREFIX=${ROOTDIR}/build

export CMAKE_CROSSCOMPILING=ON
export CMAKE_SYSTEM_NAME=Linux
export CMAKE_SYSTEM_PROCESSOR=aarch64
export PY_VERSION=3.6.15
export NATIVE_BUILD_DIR=${PREFIX}
export USE_CUDA=0
export BUILD_TEST=0
export USE_NNPACK=0
export USE_QNNPACK=0
export USE_XNNPACK=0
export USE_DISTRIBUTED=0
export USE_OPENMP=0
export USE_NUMPY=1
export ATEN_THREADING="TBB"
export USE_TBB=1
export USE_CUDNN=0
export USE_FBGEMM=0
export USE_KINETO=0
export USE_MKLDNN=0
export PROTOBUF_PROTOC_EXECUTABLE=protoc
export CAFFE2_CUSTOM_PROTOC_EXECUTABLE=protoc
export USE_BREAKPAD=OFF
export BUILD_CAFFE2=OFF
export BUILD_CAFFE2_OPS=OFF
export USE_NUMA=OFF

export CFLAGS=" -fstack-protector-strong -O2 -pipe --sysroot=$SDKTARGETSYSROOT -nostdinc -ISDKTARGETSYSROOT/usr/lib/gcc/aarch64-hongmeng-musl/7.3.0/include -ISDKTARGETSYSROOT/usr/include/c++/7.3.0 -ISDKTARGETSYSROOT/usr/include/c++/7.3.0/aarch64-hongmeng-musl/ -I$SDKDIR/sysroots/aarch64-euler-elf_all_in_one/usr/include/ -ISDKTARGETSYSROOT/usr/lib/gcc/aarch64-hongmeng-musl/7.3.0/include"

export CXXFLAGS=" -D__linux__ -D_GNU_SOURCE -fstack-protector-strong -O2 -pipe --sysroot=$SDKTARGETSYSROOT -nostdinc++ -DHAVE_IOSTREAM -ISDKTARGETSYSROOT/usr/include -ISDKTARGETSYSROOT/usr/lib/gcc/aarch64-hongmeng-musl/7.3.0/include -ISDKTARGETSYSROOT/usr/include/c++/7.3.0 -ISDKTARGETSYSROOT/usr/include/c++/7.3.0/aarch64-hongmeng-musl/ -ISDKTARGETSYSROOT/usr/include/c++/7.3.0/include"

export LDFLAGS=" --verbose -L$SDKTARGETSYSROOT/usr/lib -L$SDKTARGETSYSROOT/lib -L$SDKTARGETSYSROOT/usr/lib/gcc/aarch64-hongmeng-musl/7.3.0/ -nostdlib -nostartfiles -lc -lhmulibs -lhmsrv_fs -lhmsrv_net -lhwsecurec -lgcc_S -lm -lstdc++ -Wl,--dynamic-linker=/lib/hmld.so.elf -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -Wl,-O1 -Wl,--hash-style=gnu -Wl,--as-needed"

install_uuid(){
	rm -rf build
	mkdir build
	cd build
	cmake .. -DCMAKE_CROSSCOMPILING=ON -DCMAKE_SYSTEM_NAME=Linux -DCMAKE_INSTALL_PREFIX=$PREFIX -DPY_VERSION=3.6.15 -DNATIVE_BUILD_DIR=/path/to/sleef/build -DCMAKE_SYSTEM_PROCESSOR=aarch64 -DUSE_CUDA=0 -DBUILD_TEST=0 -DUSE_NNPACK=0 -DUSE_QNNPACK=0 -DUSE_XNNPACK=0 -DUSE_DISTRIBUTED=0 -DUSE_OPENMP=1   -DATEN_THREADING="OMP" -DUSE_TBB=0 -DUSE_CUDNN=0 -DUSE_FBGEMM=0 -DUSE_KINETO=0 -DUSE_MKLDNN=0 -DGLIBCXX_USE_CXX11_ABI=ON -DPROTOBUF_PROTOC_EXECUTABLE=protoc -DCAFFE2_CUSTOM_PROTOC_EXECUTABLE=protoc -DBLAS="OpenBLAS" -DOpenBLAS_HOME="path/to/OpenBLAS_HOME" -DUSE_BREAKPAD=OFF -DBUILD_CAFFE2_OPS=OFF -DUSE_NUMA=OFF
	make -j32 V=3
	make install
}

install_uuid2(){
	rm -rf build
	python setup.py build install --prefix=$PREFIX
}

cd pytorch
install_uuid2