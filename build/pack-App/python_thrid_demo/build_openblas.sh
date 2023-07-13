#!/usr/bin/env bash
set -e

ROOTDIR=$(pwd)
BUILD_DIR=${ROOTDIR}/build

install_openblas(){
	rm -rf build
	mkdir build
	cd build
	cmake .. -DCMAKE_CROSSCOMPILING=ON -DTARGET=ARMV8 -DARCH=aarch64 -DCMAKE_SYSTEM_NAME=Linux -DCMAKE_INSTALL_PREFIX=$BUILD_DIR
	make
	make install
}

rm -rf OpenBLAS-0.3.9
tar -xf OpenBLAS-0.3.9.tar.gz
cd OpenBLAS-0.3.9

install_openblas