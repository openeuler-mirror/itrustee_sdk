#!/usr/bin/env python
# coding:utf-8
#----------------------------------------------------------------------------
# Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
# iTrustee licensed under the Mulan PSL v2.
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

import subprocess

from generate_hash import gen_hash


def gen_ta_signature(cfg, uuid_str, raw_data, raw_data_path, hash_file_path, \
    out_file_path, out_path, key_info_data):
    if cfg.sign_type == '1': # signed with local key
        gen_hash(cfg.hash_type, raw_data, hash_file_path)
        cmd = "openssl rsautl -sign -inkey {} -in {} -out {}".\
            format(cfg.sign_key, hash_file_path, out_file_path)
        try:
            subprocess.check_output(cmd.split(), shell=False)
        except Exception:
            print("sign operation failed")
            raise RuntimeError
    else:
        print("unhandled signtype %s" % cfg.sign_type)

    return


