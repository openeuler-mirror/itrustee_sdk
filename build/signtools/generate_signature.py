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
import base64
import binascii
import logging

from generate_hash import gen_hash
from gmssl import sm2
from gmssl import sm3, func


def sm3_z(sm2_crypt, data):
    """ use sm3 cal hash """
    sm3_zt = '0080' + '31323334353637383132333435363738' + \
        sm2_crypt.ecc_table['a'] + sm2_crypt.ecc_table['b'] + sm2_crypt.ecc_table['g'] + \
        sm2_crypt.public_key
    sm3_zt = binascii.a2b_hex(sm3_zt)
    sm3_za = sm3.sm3_hash(func.bytes_to_list(sm3_zt))
    sm3_m = (sm3_za + data.hex()).encode('utf-8')
    sm3_e = sm3.sm3_hash(func.bytes_to_list(binascii.a2b_hex(sm3_m)))
    return sm3_e


def sign_with_sm3(sm2_crypt, data, random_hex_str):
    """ use sm3 sign """
    sign_data = binascii.a2b_hex(sm3_z(sm2_crypt, data).encode('utf-8'))
    if random_hex_str is None:
        random_hex_str = func.random_hex(sm2_crypt.para_len)
    sign = sm2_crypt.sign(sign_data, random_hex_str)
    return sign


def read_key_pem(file_path, arr):
    """ get key from pem file """
    with open(file_path, 'r') as pem_fp:
        pem_p = pem_fp.read()
    begin = pem_p.find(arr[0]) + arr[1]
    end = pem_p.find(arr[2])
    key = pem_p[begin:end].replace('\n', '')

    key = base64.b64decode(key).hex()[arr[3]:arr[4]]
    return key


def get_array(str_array):
    """ converting strings to arrays """
    hex_array = []
    for tmp in str_array:
        hex_array.append(int(tmp, 16))
    return hex_array


def get_str_array(code_str):
    """ converting strings to arrays """
    str_list = list(code_str)
    index = 0
    prefix_bit = 2
    tmp = 0
    while index < len(str_list):
        if tmp == prefix_bit:
            str_list.insert(index, ',')
            prefix_bit = 3
            tmp = 0
        tmp += 1
        index += 1
    code_str = ''.join(str_list)
    return get_array(code_str.split(','))


def gen_ta_signature(cfg, uuid_str, raw_data, raw_data_path, hash_file_path, \
    out_file_path, out_path, key_info_data, temp_path):
    msg_file = os.path.join(out_path, "temp", "config_msg")
    fd_msg = os.open(msg_file, os.O_WRONLY | os.O_CREAT, \
        stat.S_IWUSR | stat.S_IRUSR)
    msg_file_fp = os.fdopen(fd_msg, "wb")
    msg_file_fp.write(raw_data)
    msg_file_fp.close()
    if cfg.sign_type == '1': # signed with local key
        if cfg.sign_ta_alg == '3': # SM2
            array = ['-----BEGIN EC PRIVATE KEY-----', 31, '-----END EC PRIVATE KEY-----', 14, 78]
            priv_key = read_key_pem(cfg.sign_key, array)
            array_pub = ['-----BEGIN EC PRIVATE KEY-----', 31, '-----END EC PRIVATE KEY-----', 114, 242]
            pub_key = read_key_pem(cfg.sign_key, array_pub)
            sm2_crypt = sm2.CryptSM2(public_key=pub_key, private_key=priv_key)
            sm2_crypt.mode = 1
            random_hex_str = func.random_hex(sm2_crypt.para_len)
            signature = sign_with_sm3(sm2_crypt, raw_data, random_hex_str)
            temp_sig = get_str_array(signature)
            final_sig = b''.join(map(lambda x:int.to_bytes(x, 1, 'little'), temp_sig))

            fd_out = os.open(out_file_path, os.O_WRONLY | os.O_CREAT, \
                stat.S_IWUSR | stat.S_IRUSR)
            out_fp = os.fdopen(fd_out, "wb")
            out_fp.write(final_sig)
            out_fp.close()
        else:
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
                print("========================== sign success =====================================")
                subprocess.check_output(cmd.split(), shell=False)
            except Exception:
                logging.error("sign operation failed")
                print("========================== sign error =====================================")
                raise RuntimeError
    else:
        logging.error("unhandled signtype %s", cfg.sign_type)

    return
