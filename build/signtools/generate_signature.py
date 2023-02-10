#!/usr/bin/env python
# coding=utf-8
#----------------------------------------------------------------------------
# Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan
# PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
# KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
# NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.
# Description: tools for generating a trusted application load image
#----------------------------------------------------------------------------

import os
import stat
import subprocess
import logging

from generate_hash import gen_hash


def gen_ta_signature(cfg, uuid_str, raw_data, raw_data_path, hash_file_path, \
    out_file_path, out_path, key_info_data, is_big_ending):
    msg_file = os.path.join(out_path, "temp", "config_msg")
    fd_msg = os.open(msg_file, os.O_WRONLY | os.O_CREAT, \
        stat.S_IWUSR | stat.S_IRUSR)
    msg_file_fp = os.fdopen(fd_msg, "wb")
    msg_file_fp.write(raw_data)
    msg_file_fp.close()
    if cfg.sign_type == '1': # signed with local key
        if cfg.padding_type == '0':
            gen_hash(cfg.hash_type, raw_data, hash_file_path)
            cmd = "openssl pkeyutl -sign -inkey {} -in {} -out {}".\
                format(cfg.sign_key, hash_file_path, out_file_path)
        elif cfg.padding_type == '1':
            if cfg.hash_type == '0':
                cmd = "openssl dgst -sign {} -sha256 -sigopt \
                    rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 \
                    -out {} {}".format(cfg.sign_key, out_file_path, msg_file)
            else:
                cmd = "openssl dgst -sign {} -sha512 -sigopt \
                    rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 \
                    -out {} {}".format(cfg.sign_key, out_file_path, msg_file)
        try:
            subprocess.check_output(cmd.split(), shell=False)
        except Exception:
            logging.error("sign operation failed")
            raise RuntimeError
    else:
        logging.error("unhandled signtype %s", cfg.sign_type)

    return


