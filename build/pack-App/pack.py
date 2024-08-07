#!/usr/bin/env python3
# coding=utf-8
#----------------------------------------------------------------------------
# Copyright @ Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan
# PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
# KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
# NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.
# Description: pack python or java files to sec
#----------------------------------------------------------------------------

''' tools for packing apps '''

from __future__ import absolute_import
import sys
import os
import re
import zlib
import struct
import logging
import subprocess
sys.path.append('../pack-Config')
from Config_pre import gen_data_for_sign
# set logging level for INFO
logging.basicConfig(level=logging.INFO)


COMPRESS_LEVEL = 9
MAGIC1 = 0xA5A55A5A
MAGIC2 = 0x55AA


def add_head_to_tgz(infile, infile_size, tgz_version):
    """ add head to tgz """
    raw_tag = 'IHHI256s'
    with os.fdopen(os.open("libcombine.so", os.O_RDWR | os.O_CREAT, 0o755), \
                   "wb", 0o755) as combine_fd:
        with os.fdopen(os.open(infile, os.O_RDWR | os.O_CREAT, 0o755), \
               "rb", 0o755) as tgz_fd:
            tgz_str = tgz_fd.read()
        reserved_seg = ""
        header = struct.pack(raw_tag, MAGIC1, MAGIC2, tgz_version, \
                             infile_size, bytes(reserved_seg.encode('utf-8')))
        combine_fd.write(header)
        combine_fd.write(tgz_str)


def compress(infile, dst, level):
    """ do compress """
    with os.fdopen(os.open(dst, os.O_RDWR | os.O_CREAT, 0o755), \
                   "wb", 0o755) as out_file_fd:
        with open(infile, "rb", 0o755) as file_op:
            compress_fd = zlib.compressobj(level)
            data = file_op.read(1024)
            while data:
                out_file_fd.write(compress_fd.compress(data))
                data = file_op.read(1024)
            out_file_fd.write(compress_fd.flush())


def run_cmd(command):
    """ run shell cmd """
    ret = subprocess.run(command, shell=False, check=True)
    if ret.returncode != 0:
        logging.error("run command failed.")
        sys.exit(1)


def run_clean(file_name):
    """ delete build files """
    files_to_remove = [
        "libcombine.so",
        "config",
        "manifest.txt",
        "configs.xml",
        "data_for_sign",
        "{}.tar".format(file_name),
        "{}.tar.gz".format(file_name)
    ]

    for file in files_to_remove:
        if os.path.exists(file):
            cmd = ["rm", file]
            run_cmd(cmd)

    logging.info("success to clean")


def get_file_type(file_name):
    """ get the user file type """
    for root, dirs, files in os.walk(file_name):
        file_name_list = str(files)
        if ".py" in file_name_list:
            file_type_num = "6" # means python
            return file_type_num
        if ("java" in file_name_list) or (".class" in file_name_list):
            file_type_num = "7" # means java
            return file_type_num
    logging.info("info: the default file type value is raw executable type")
    file_type_num = "8" # default raw executable
    return file_type_num


def replace_file_content(input_file, out_file, pkg_name, pkg_type_num):
    """ replace the specified content of the file """
    with os.fdopen(os.open(out_file, os.O_RDWR | os.O_CREAT, 0o755), \
                   "w", 0o755) as out_file_fd:
        with os.fdopen(os.open(input_file, os.O_RDWR | os.O_CREAT, 0o755), \
                       "r", 0o755) as file_op:
            content_str = file_op.read()
            content_str = content_str.replace("APP_TYPE", str(pkg_type_num))
            content_str = content_str.replace("APP_NAME", pkg_name)
            out_file_fd.write(content_str)


def whitelist_check(intput_str):
    """ whitelist check """
    if not re.match(r"^[A-Za-z0-9\/\-_.]+$", intput_str):
        return 1
    return 0


def make_package(file_name, tar_file_name, file_path, tgz_file_name):
    """ make package """
    # 1. make package
    try:
        cmd = ["tar", "cvf", tar_file_name, file_path]
        run_cmd(cmd)
        tar_file_size = os.path.getsize(tar_file_name)
    except RuntimeError:
        logging.error("pack failed in packaging.")
        run_clean(file_name)
        return 1

    # 2. make tgz file
    try:
        compress(tar_file_name, tgz_file_name, COMPRESS_LEVEL)
    except RuntimeError:
        logging.error("pack failed in compression.")
        run_clean(file_name)
        return 1

    # 3. change tgz file to libcombine.so and add head
    tgz_version = 1
    try:
        add_head_to_tgz(tgz_file_name, tar_file_size, tgz_version)
    except RuntimeError:
        logging.error("pack failed in header addition.")
        run_clean(file_name)
        return 1
    return 0


def main():
    """ main process """
    if len(sys.argv) < 2:
        logging.error("pack.py need input folders")
        sys.exit(1)
    file_name = sys.argv[1]
    work_path = os.getcwd()
    input_path = sys.argv[2] if len(sys.argv) > 2 else work_path
    output_path = sys.argv[3] if len(sys.argv) > 3 else work_path
    file_path = os.path.join(input_path, file_name)  # combine input_path and file_name
    if whitelist_check(file_name):
        logging.error("file name is incorrect")
        sys.exit(1)
    tar_file_name = "{}.tar".format(file_name)
    tgz_file_name = "{}.tar.gz".format(file_name)
    ta_cert_file_path = "pack_tools/ta_cert.der"
    signtool_path = "{}/../signtools/signtool_v3.py".format(work_path)
    ini_file_path = "{}/../signtools/config_cloud_app.ini".format(work_path)

    # clean before pack app
    run_clean(file_name)
    if os.path.exists(file_path):
        logging.info("start pack %s", file_path)
    else:
        logging.error("%s is not exist, please check", file_path)
        sys.exit(1)

    # 1. get file type
    file_type_num = get_file_type(file_name)

    # 2. make package
    if make_package(file_name, tar_file_name, file_path, tgz_file_name):
        logging.error("packing failed")
        sys.exit(1)

    # 3. replace file name type content
    replace_file_content("pack_tools/manifest_mask.txt", "manifest.txt", \
                         file_name, file_type_num)
    replace_file_content("pack_tools/configs_mask.xml", "configs.xml", \
                         file_name, file_type_num)

    # 4. build config
    config_path = "{}/config".format(work_path) # this parameter is not required but must exist.
    try:
        gen_data_for_sign(work_path, ta_cert_file_path, config_path)
        cmd = ["mv", "data_for_sign", "config"]
        run_cmd(cmd)
    except RuntimeError:
        logging.error("pack failed in config building.")
        run_clean(file_name)
        sys.exit(1)

    # 5. do sign process
    try:
        cmd = ["python3", "-B", signtool_path, work_path, output_path, "--privateCfg", ini_file_path]
        run_cmd(cmd)
    except RuntimeError:
        logging.error("pack failed in signing.")
        run_clean(file_name)
        sys.exit(1)

    # 6. do clean
    run_clean(file_name)
    logging.info("success to packing %s", file_name)

if __name__ == '__main__':
    main()
