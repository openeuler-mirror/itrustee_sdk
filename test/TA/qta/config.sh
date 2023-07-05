#!/bin/bash
# Copyright Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
# This script is used to compile the demo sdk.
set -e

export SOURCE_PATH=$(dirname $0)
export ABS_SOURCE_PATH=$(cd ${SOURCE_PATH};pwd)
export ITRUSTEE_BUILD_PATH=${ABS_SOURCE_PATH}/../../..

# clean
if [ "$#" -eq 1 ] && [ "$1"x = "clean"x ]; then
    rm -f *.o *.so *.sec
    [ -f manifest.txt ] && rm -f manifest.txt
    if [ -d "cmake_build" ]; then
        rm -rf cmake_build
        echo "rm -rf cmake_build"
    fi
    exit 0
fi

# set target
MANIFEST=manifest.txt
if [ "$#" -eq 1 ]; then
    if [ "$1"x = "qta_report"x ]; then
        TARGET=-DTARGET_QTA_REPORT=y
        MANIFEST=manifest-report.txt
    fi
    if [ "$1"x = "host_qta"x ]; then
        TARGET=-DTARGET_HOST_QTA=y
    fi
fi
cp -f ./manifest/${MANIFEST} ./manifest.txt

echo "Cmake compile TA begin"
if [ -d "cmake_build" ]; then
    rm -rf cmake_build
    echo "rm -rf cmake_build"
fi
mkdir -p cmake_build
echo "mkdir cmake_build"
cd cmake_build/

cmake -DCMAKE_TOOLCHAIN_FILE=${ITRUSTEE_BUILD_PATH}/build/cmake/aarch64_toolchain.cmake ${TARGET} ..

make VERBOSE=1

cd ..
[ -f manifest.txt ] && rm -f manifest.txt
rm -rf cmake_build
