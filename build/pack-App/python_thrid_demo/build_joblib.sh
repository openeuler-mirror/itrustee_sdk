#!/usr/bin/env bash
set -e

SDKDIR=$1
LOCAL_PYTHON_DIR=$2
ROOTDIR=$(pwd)
OUTPUT_PYTHON_DIR=$ROOTDIR/output_python
BUILD_DIR=${ROOTDIR}/build

install_py(){
	python3 setup.py install --prefix=$BUILD_SIR
}

export PYTHONPATH=$BUILD_DIR/lib/python3.6/site-packages:$PYTHONPATH
export PATH=${LOCAL_PYTHON_DIR}/bin:$PATH

rm -rf joblib-1.1.1
tar -xf joblib-1.1.1.tar.gz
cd joblib-1.1.1

install_py