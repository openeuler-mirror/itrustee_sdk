#!/usr/bin/env bash
set -e

SDKDIR=$1
LOCAL_PYTHON_DIR=$2
ROOTDIR=$(pwd)
OUTPUT_PYTHON_DIR=$ROOTDIR/output_python
BUILD_DIR=${ROOTDIR}/build
OUTPUT_THIRDLIB=$ROOTDIR/output_thirdlib

mkdir -p ${OUTPUT_THIRDLIB}
mkdir -p ${OUTPUT_PYTHON_DIR}/lib/python3.6/site-packages/
mkdir -p ${BUILD_DIR}/lib/python3.6/site-packages/

install_py(){
	python3 setup.py build --fcompiler=gfortran install --prefix=$BUILD_DIR
}

export PYTHONPATH=$PYTHONPATH:${LOCAL_PYTHON_DIR}
export PYTHONPATH=$BUILD_DIR/lib/python3.6/site-packages:$PYTHONPATH
export PYTHONHOME=${LOCAL_PYTHON_DIR}
export PATH=${LOCAL_PYTHON_DIR}/bin:$PATH
export NPY_DISABLE_SVML=1

rm -rf numpy-1.19.5
unzip numpy-1.19.5.zip
cd numpy-1.19.5

install_py