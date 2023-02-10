#!/usr/bin/env python
# coding=utf-8
#----------------------------------------------------------------------------
# Copyright @ Huawei Technologies Co., Ltd. 2022-2023. All rights reserved.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan
# PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
# KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
# NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.
# tools for generating a signed config
#----------------------------------------------------------------------------

import struct
import os
import stat
import sys
import re
import configparser
import logging

CONFIG_VERSION = 2


class Configuration:
    ''' Configuration '''
    sign_alg = "RSA_PKCS1"

    def __init__(self, file_name):
        parser = configparser.ConfigParser()
        parser.read(file_name)
        self.sign_alg = parser.get("signConfigPrivateCfg", "configSignAlg")
        if whitelist_check(self.sign_alg):
            logging.error("configSignAlg is invalid.")
            sys.exit(1)


def whitelist_check(intput_str):
    if not re.match(r"^[A-Za-z0-9\/\-_.]+$", intput_str):
        return 1
    return 0


def gen_config_section(input_path, output_path, verify_type):
    ''' generate config file section '''
    data_for_sign = os.path.join(input_path, "data_for_sign")
    signature = os.path.join(input_path, "data_for_sign.rsa")
    signed_config = os.path.join(output_path, "config")
    config_certpath = os.path.join(input_path, "taconfig.der")

    config_path = input_path + '/../../signtools'
    config_file = os.path.join(config_path, "config_tee_private_sample.ini")
    if not os.path.exists(config_file):
        logging.critical("config_tee_private_sample.ini is not exist.")
        sign_conf_alg = 1
    else:
        cfg = Configuration(config_file)
        if cfg.sign_alg == "RSA_PKCS1":
            sign_conf_alg = 1
        elif cfg.sign_alg == "RSA_PSS":
            sign_conf_alg = 3
        elif cfg.sign_alg == "ECDSA":
            sign_conf_alg = 2

    data_for_sign_size = os.path.getsize(data_for_sign)
    with open(data_for_sign, 'rb') as data_for_sign_fp:
        data_for_sign_buf = data_for_sign_fp.read(data_for_sign_size)

    signature_size = os.path.getsize(signature)
    with open(signature, 'rb') as signature_fp:
        signature_buf = signature_fp.read(signature_size)

    if(verify_type == "TYPE_PUBKEY"):
        sign_verify_buf = struct.pack('III', 0, sign_conf_alg, 0) + signature_buf
    elif(verify_type == "TYPE_CERT"):
        config_cert_size = os.path.getsize(config_certpath)
        with open(config_certpath, 'rb') as config_cert_fp:
            config_cert_buf = config_cert_fp.read(config_cert_size)
        sign_verify_buf = struct.pack('III', 1, sign_conf_alg, config_cert_size) + \
                config_cert_buf + signature_buf

    fd_sign = os.open(signed_config, os.O_WRONLY | os.O_CREAT, \
            stat.S_IWUSR | stat.S_IRUSR)
    signed_config_fp = os.fdopen(fd_sign, "wb")
    # write data (header + ta cert + tlv config)
    signed_config_fp.write(data_for_sign_buf)
    # write config cert
    signed_config_fp.write(sign_verify_buf)
    signed_config_fp.close()


def main():
    argvs = sys.argv
    input_file = argvs[1]
    output_file = argvs[2]
    verify_type = argvs[3]
    if not os.path.exists(input_file):
        logging.error("input does not exist.")
        exit()
    if not os.path.exists(output_file):
        logging.error("ta_cert_path does not exist.")
        exit()

    if whitelist_check(input_file):
        logging.error("input is incorrect.")
        exit()
    if whitelist_check(output_file):
        logging.error("output is incorrect.")
        exit()
    if whitelist_check(verify_type):
        logging.error("output is incorrect.")
        exit()

    gen_config_section(input_file, output_file, verify_type)


if __name__ == '__main__':
    main()

