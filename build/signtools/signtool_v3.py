#!/usr/bin/env python
# coding=utf-8
#----------------------------------------------------------------------------
# Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
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

import struct
import os
import stat
import binascii
import shutil
import argparse
import configparser
import re
import base64
import logging


from manifest import process_manifest_file
from generate_signature import gen_ta_signature
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


TYPE_PUBKEY     = 0
TYPE_CERT       = 1
TYPE_CERT_CHAIN = 2

MAGIC1 = 0xA5A55A5A
MAGIC2 = 0x55AA

# ELF Definitions
ELF_TYPE = 32
ELF_HDR_SIZE = 52
ELF_PHDR_SIZE = 32
ELF_INFO_MAGIC0_INDEX = 0
ELF_INFO_MAGIC1_INDEX = 1
ELF_INFO_MAGIC2_INDEX = 2
ELF_INFO_MAGIC3_INDEX = 3
#'\x7f'
ELF_INFO_MAGIC0 = 127
#'E'
ELF_INFO_MAGIC1 = 69
#'L'
ELF_INFO_MAGIC2 = 76
#'F'
ELF_INFO_MAGIC3 = 70
ELF_INFO_CLASS_INDEX = 4
ELF_INFO_CLASS_32 = 1
ELF_INFO_CLASS_64 = 2
ELF_INFO_VERSION_INDEX = 6
ELF_INFO_VERSION_CURRENT = 1
ELF_BLOCK_ALIGN = 0x1000

SEC_HEADER_BYTES = 16
SING_BIG_ENDIAN = False
# set logging level for INFO
logging.basicConfig(level=logging.INFO)


def check_cfg_whitelist_format(input_str):
    ''' input_str can be an empty string '''
    if input_str != "":
        if whitelist_check(input_str):
            return 1
    return 0


def whitelist_check(input_str):
    if not re.match(r"^[A-Za-z0-9\/\-_.]+$", input_str):
        return 1
    return 0


def check_cfg_integer_format(input_str):
    ''' input_str can be an empty string '''
    if input_str != "":
        if integer_check(input_str):
            return 1
    return 0


def integer_check(intput_str):
    if not str(intput_str).isdigit():
        return 1
    return 0


#----------------------------------------------------------------------------
# Verify ELF header contents from an input ELF file
#----------------------------------------------------------------------------
def verify_elf_header(elf_path):
    elf_type = 0
    with open(elf_path, 'rb') as elf:
        elf_data = struct.unpack('B' * 16, elf.read(16))
        elf_type = elf_data[4]
        if ((elf_data[ELF_INFO_MAGIC0_INDEX] != ELF_INFO_MAGIC0) or \
                (elf_data[ELF_INFO_MAGIC1_INDEX] != ELF_INFO_MAGIC1) or \
                (elf_data[ELF_INFO_MAGIC2_INDEX] != ELF_INFO_MAGIC2) or \
                (elf_data[ELF_INFO_MAGIC3_INDEX] != ELF_INFO_MAGIC3) or \
                (elf_data[ELF_INFO_VERSION_INDEX] != \
                ELF_INFO_VERSION_CURRENT)):
            logging.error("invalid elf header info")
            raise RuntimeError

        if ((elf_type == 1 and elf_data[ELF_INFO_CLASS_INDEX] != \
                ELF_INFO_CLASS_32) or \
                (elf_type == 2 and elf_data[ELF_INFO_CLASS_INDEX] != \
                ELF_INFO_CLASS_64) or \
                (elf_type != 1 and elf_type != 2)):
            logging.error("invliad elf format")
            raise RuntimeError


class AllCfg:
    release_type = "1"
    otrp_flag = "0"
    sign_type = "0"
    enc_key_alg = "0"
    public_key = ""
    pub_key_len = ""
    enc_cont_alg = "0"
    key_protect_v = "2"
    re_sign_flag = "0"
    server_ip = ""
    config_path = ""
    sign_key = ""
    sign_key_type = "0"
    sign_alg = "RSA"
    ta_cert_chain = ""
    ta_version = 3
    in_path = ""
    out_path = ""
    sign_plat = 0
    sign_ta_alg = "0"


class PublicCfg:
    def __init__(self, file_name, all_cfg):
        cfg_section = "signSecPublicCfg"
        parser = configparser.ConfigParser()
        parser.read(file_name)

        if parser.has_option(cfg_section, "secReleaseType"):
            all_cfg.release_type = parser.get(cfg_section, "secReleaseType")
        if parser.has_option(cfg_section, "secOtrpFlag"):
            all_cfg.otrp_flag = parser.get(cfg_section, "secOtrpFlag")

        all_cfg.sign_type = parser.get(cfg_section, "secSignType")
        if parser.has_option(cfg_section, "secSignServerIp"):
            all_cfg.server_ip = parser.get(cfg_section, "secSignServerIp")

        all_cfg.config_path = parser.get(cfg_section, "configPath")
        all_cfg.sign_key = parser.get(cfg_section, "secSignKey")
        if parser.has_option(cfg_section, "secTaVersion"):
            all_cfg.ta_version = int(parser.get(cfg_section, "secTaVersion"))
        else:
            all_cfg.ta_version = 3
        if parser.has_option(cfg_section, "secSignKeyType"):
            all_cfg.sign_key_type = parser.get(cfg_section, "secSignKeyType")
        if parser.has_option(cfg_section, "secTaCertChain"):
            all_cfg.ta_cert_chain = parser.get(cfg_section, "secTaCertChain")


class PrivateCfg:
    def __init__(self, file_name, all_cfg):
        cfg_section = 'signSecPrivateCfg'
        parser = configparser.ConfigParser()
        parser.read(file_name)

        if parser.has_option(cfg_section, "secEncryptKey"):
            all_cfg.public_key = parser.get(cfg_section, "secEncryptKey")

        if parser.has_option(cfg_section, "secEncryptKeyLen"):
            all_cfg.pub_key_len = parser.get(cfg_section, "secEncryptKeyLen")

        if parser.has_option(cfg_section, "secReSignFlag"):
            all_cfg.re_sign_flag = parser.get(cfg_section, "secReSignFlag")

        all_cfg.hash_type = parser.get(cfg_section, "secHashType")
        all_cfg.sign_key_len = parser.get(cfg_section, "secSignKeyLen")
        all_cfg.padding_type = parser.get(cfg_section, "secPaddingType")

        if parser.has_option(cfg_section, "secSignAlg"):
            all_cfg.sign_alg = parser.get(cfg_section, "secSignAlg")

        if parser.has_option(cfg_section, "secEncryptKeyInfoAlg"):
            all_cfg.enc_key_alg = parser.get(cfg_section, "secEncryptKeyInfoAlg")
        if parser.has_option(cfg_section, "secEncryptContentAlg"):
            all_cfg.enc_cont_alg = parser.get(cfg_section, "secEncryptContentAlg")
        if parser.has_option(cfg_section, "secKeyProtectVersion"):
            all_cfg.key_protect_v = parser.get(cfg_section, "secKeyProtectVersion")
        if parser.has_option(cfg_section, "secSignTaAlg"):
            all_cfg.sign_ta_alg = parser.get(cfg_section, "secSignTaAlg")


def check_key_info(cfg):
    ''' check ini key info '''
    ret = 0
    if check_cfg_whitelist_format(cfg.sign_key):
        logging.error("secSignKey is invalid.")
        ret = 1
    if check_cfg_integer_format(cfg.sign_key_len):
        logging.error("secSignKeyLen is invalid.")
        ret = 1
    if check_cfg_whitelist_format(cfg.public_key):
        logging.error("secEncryptKey is invalid.")
        ret = 1
    if check_cfg_integer_format(cfg.pub_key_len):
        logging.error("secEncryptKeyLen is invalid.")
        ret = 1
    if check_cfg_integer_format(cfg.re_sign_flag):
        logging.error("secReSignFlag is invalid.")
        ret = 1
    return ret


def check_cfg(cfg):
    ''' check setting info '''
    ret = 0
    if check_cfg_integer_format(cfg.release_type):
        logging.error("secReleaseType is invalid.")
        ret = 1
    if check_cfg_integer_format(cfg.otrp_flag):
        logging.error("secOtrpFlag is invalid.")
        ret = 1
    if check_cfg_integer_format(cfg.sign_type):
        logging.error("secSignType is invalid.")
        ret = 1
    if check_cfg_whitelist_format(cfg.server_ip):
        logging.error("secSignServerIp is invalid.")
        ret = 1
    if check_cfg_whitelist_format(cfg.config_path):
        logging.error("configPath is invalid.")
        ret = 1
    if check_cfg_integer_format(cfg.hash_type):
        logging.error("secHashType is invalid.")
        ret = 1
    if check_cfg_integer_format(cfg.padding_type):
        logging.error("secPaddingType is invalid.")
        ret = 1
    if check_cfg_whitelist_format(cfg.sign_alg):
        logging.error("secSignAlg is invalid.")
        ret = 1
    if check_key_info(cfg) != 0:
        ret = 1
    return ret


def gen_key_version(cfg):
    ''' gen key version '''
    key_version = 0
    key_version = key_version | (int(cfg.enc_cont_alg) << 24)
    key_version = key_version | (int(cfg.enc_key_alg) << 16)
    if cfg.pub_key_len == '4096':
        key_version = key_version | 0x0300
    elif cfg.pub_key_len == '3072':
        key_version = key_version | 0x0200
    elif cfg.pub_key_len == '2048':
        key_version = key_version | 0x0000
    elif cfg.pub_key_len == '256':
        key_version = key_version | 0x0100
    elif cfg.pub_key_len == '':
        return int(0x0000)
    else:
        logging.info("unhandled pulic key len %s", cfg.pub_key_len)
        raise RuntimeError
    key_version = key_version | (int(cfg.key_protect_v))
    return key_version


def gen_header(content_len, cfg):
    ''' gen header by endian '''
    key_version = gen_key_version(cfg)
    if SING_BIG_ENDIAN:
        head_tag = '>IHHII'
    else:
        head_tag = 'IHHII'
    return struct.pack(head_tag, MAGIC1, MAGIC2, cfg.ta_version, content_len, key_version)


def get_sign_alg(cfg):
    sign_alg = 0
    sign_alg = sign_alg | (int(cfg.release_type) << 28)
    sign_alg = sign_alg | (int(cfg.padding_type) << 27)
    sign_alg = sign_alg | ((int(cfg.hash_type) & 1) << 26)
    sign_alg = sign_alg | ((int(cfg.hash_type) & 2) << 25)
    sign_alg = sign_alg | (int(cfg.sign_ta_alg) << 20)
    if cfg.sign_alg == "RSA":
        sign_alg = sign_alg | (2 << 20)
    elif cfg.sign_alg == "ECDSA":
        sign_alg = sign_alg | (1 << 20)
    if cfg.sign_type in '4' '5':
        sign_alg = sign_alg | 0x0000C000
    else:
        if cfg.sign_key_len == "2048":
            sign_alg = sign_alg | 0x00002048
        elif cfg.sign_key_len == "4096":
            sign_alg = sign_alg | 0x00004096
        elif cfg.sign_key_len == "256":
            sign_alg = sign_alg | 0x00000256
    return sign_alg


def gen_aes_key_info(cfg):
    iv_data = get_random_bytes(16)
    if SING_BIG_ENDIAN:
        aes_tag = '>3I'
    else:
        aes_tag = '<3I'
    if cfg.enc_cont_alg == '1':
        random_size = 16
        key_data = get_random_bytes(16)
    else:
        random_size = 32
        key_data = get_random_bytes(32)
    sign_alg = get_sign_alg(cfg)
    key_info = struct.pack(aes_tag, random_size, 16, sign_alg)
    key_info += key_data
    key_info += iv_data
    return key_data, iv_data, key_info


def gen_sign_alg_info(cfg, out_file_path):
    sign_alg = get_sign_alg(cfg)
    logging.info("sign_alg value is 0x%x", sign_alg)
    if SING_BIG_ENDIAN:
        info_tag = '>I'
    else:
        info_tag = 'I'
    fd_out = os.open(out_file_path, os.O_WRONLY | os.O_CREAT, \
        stat.S_IWUSR | stat.S_IRUSR)
    out_file = os.fdopen(fd_out, "wb")
    out_file.write(struct.pack(info_tag, 0))
    out_file.write(struct.pack(info_tag, 0))
    out_file.write(struct.pack(info_tag, sign_alg))
    out_file.close()


def read_key_pem(file_path, arr):
    ''' read key pem '''
    with open(file_path, 'r') as pem_fp:
        pem_p = pem_fp.read()
    begin = pem_p.find(arr[0]) + arr[1]
    end = pem_p.find(arr[2])
    key = pem_p[begin:end].replace('\n', '')

    key = base64.b64decode(key).hex()[arr[3]:arr[4]]
    return key


def encrypt_aes_key(pubkey_path, in_data, out_path, cfg):
    ''' encrypt aes key '''
    if cfg.enc_cont_alg == '1':
        from gmssl import sm2
        array = ['-----BEGIN PUBLIC KEY-----', 27, '-----END PUBLIC KEY-----', 52, 183]
        pubkey = read_key_pem(pubkey_path, array)

        not_use = '000000000000000000000000000000000000000000000000000000000000000000'
        # Fixed offset two bits, Skip 04 Prefix
        sm2_crypt = sm2.CryptSM2(public_key=pubkey[2:], private_key=not_use)
        sm2_crypt.mode = 1
        ciphertext = sm2_crypt.encrypt(in_data)
    else:
        with open(pubkey_path, 'rb') as pubkey_file_fd:
            pubkey_file = pubkey_file_fd.read(os.path.getsize(pubkey_path))
        pubkey = RSA.importKey(pubkey_file)
        cipher = PKCS1_OAEP.new(pubkey)
        ciphertext = cipher.encrypt(in_data)

    fd_out = os.open(out_path, os.O_WRONLY | os.O_CREAT, \
        stat.S_IWUSR | stat.S_IRUSR)
    out_file = os.fdopen(fd_out, "wb")
    out_file.write(ciphertext)
    out_file.close()


def gen_signature(cfg, uuid_str, data_for_sign, key_info_data, temp_path):
    ''' gen signature '''
    raw_data_path = os.path.join(temp_path, "dataForSign.bin")
    hash_file_path = os.path.join(temp_path, "rawDataHash.bin")
    signature_path = os.path.join(temp_path, "signature.bin")

    gen_ta_signature(cfg, uuid_str, data_for_sign, raw_data_path, \
        hash_file_path, signature_path, cfg.out_path, key_info_data, temp_path)
    os.chmod(signature_path, stat.S_IWUSR | stat.S_IRUSR)


def gen_raw_data(manifest_data_path, manifest_ext_path, elf_file_path, \
        config_path, raw_file_path, ta_version):
    manifest_size = os.path.getsize(manifest_data_path)
    manifest_ext_size = os.path.getsize(manifest_ext_path)
    elf_size = os.path.getsize(elf_file_path)
    config_size = 0

    if "pack-App" not in elf_file_path:
        verify_elf_header(elf_file_path)

    fd_op = os.open(raw_file_path, os.O_WRONLY | os.O_CREAT, \
        stat.S_IWUSR | stat.S_IRUSR)
    file_op = os.fdopen(fd_op, "wb")
    header = ""
    if os.path.isfile(config_path):
        config_size = os.path.getsize(config_path)
    if SING_BIG_ENDIAN:
        raw_tag = '>IIIII'
    else:
        raw_tag = 'IIIII'
    header = struct.pack(raw_tag, ta_version, manifest_size, \
            manifest_ext_size, \
            elf_size, config_size)
    file_op.write(header)

    with open(manifest_data_path, 'rb') as manifest_data:
        file_op.write(manifest_data.read(manifest_size))

    with open(manifest_ext_path, 'rb') as manifest_ext:
        file_op.write(manifest_ext.read(manifest_ext_size))

    with open(elf_file_path, 'rb') as elf:
        file_op.write(elf.read(elf_size))
    if config_size != 0:
        with open(config_path, 'rb') as config:
            file_op.write(config.read(config_size))
    file_op.close()


def aes_encrypt(key_data, iv_data, in_file_path, out_file_path, cfg):
    """ encrypt aes key info """
    in_size = os.path.getsize(in_file_path)
    with open(in_file_path, 'rb') as in_file:
        in_data = in_file.read(in_size)
    if cfg.enc_cont_alg == '1':
        from gmssl.sm4 import CryptSM4, SM4_ENCRYPT
        crypt_sm4 = CryptSM4()
        crypt_sm4.set_key(key_data, SM4_ENCRYPT)
        ciphertext = crypt_sm4.crypt_cbc(iv_data, in_data)
    else:
        padding = 16 - in_size % 16
        in_data += bytes([padding]) * padding
        cipher = AES.new(key_data, AES.MODE_CBC, iv_data)
        ciphertext = cipher.encrypt(in_data)

    fd_out = os.open(out_file_path, os.O_WRONLY | os.O_CREAT, \
        stat.S_IWUSR | stat.S_IRUSR)
    out_file = os.fdopen(fd_out, "wb")
    out_file.write(ciphertext)
    out_file.close()


def parser_api_level(mk_compile_cfg, cmake_compile_cfg):
    default_api_level = 1
    compile_cfg_file = ''

    # The config.mk file is first searched.
    # The config.cmake file is searched only when the config.mk file does
    # not exist. If the API_LEVEL macro is not defined in either of the
    # two files, the default value LEVEL 1 is used.
    if os.path.exists(mk_compile_cfg):
        compile_cfg_file = mk_compile_cfg
    elif os.path.exists(cmake_compile_cfg):
        compile_cfg_file = cmake_compile_cfg
    else:
        logging.info("Build config file doesn't exist, ignore it")
        return default_api_level

    with open(compile_cfg_file) as file_op:
        for line in file_op:
            if line.startswith("#") or "-DAPI_LEVEL" not in line:
                continue
            key, value = line.strip().split("-DAPI_LEVEL=")
            logging.info("key info %s", key)
            logging.info("ta_api_level = %s", value[0])
            return value[0]

    logging.info("Build Config file doesn't define API_LEVEL")
    return default_api_level


def update_api_level(cfg, manifest):
    ''' update api level '''
    mk_compile_cfg = os.path.join(cfg.in_path, "config.mk")
    cmake_compile_cfg = os.path.join(cfg.in_path, "config.cmake")
    data = ''
    with open(manifest, 'r') as file_op:
        for line in file_op:
            if line.startswith("#") or "gpd.ta.api_level" not in line:
                data += line

    api_level = parser_api_level(mk_compile_cfg, cmake_compile_cfg)
    line = "\ngpd.ta.api_level:{}\n".format(api_level)
    data += line
    fd_op = os.open(manifest, os.O_WRONLY | os.O_CREAT, \
        stat.S_IWUSR | stat.S_IRUSR)
    file_op = os.fdopen(fd_op, "w")
    file_op.writelines(data)
    file_op.close()


def update_otrp_flag(manifest):
    data = ''
    with open(manifest, 'r') as file_op:
        for line in file_op:
            if line.startswith("#") or "gpd.ta.otrp_flag" not in line:
                data += line
    line = "\ngpd.ta.otrp_flag:{}\n".format('true')
    data += line
    fd_op = os.open(manifest, os.O_WRONLY | os.O_CREAT, \
        stat.S_IWUSR | stat.S_IRUSR)
    file_op = os.fdopen(fd_op, "w")
    file_op.writelines(data)
    file_op.close()


def gen_data_for_sign(cfg, content_len, key_data, raw_file):
    ''' gen data for sign '''
    header = gen_header(int(content_len), cfg)
    raw_file_len = os.path.getsize(raw_file)
    with open(raw_file, 'rb') as raw_fp:
        raw_data = raw_fp.read(raw_file_len)

    data_sign = header
    data_sign += key_data
    data_sign += raw_data
    return data_sign


def pack_signature(signature_path, signature_size):
    add_size = 72 - signature_size
    with open(signature_path, 'rb+') as signature_file:
        signature_buf = signature_file.read(signature_size)
        signature_file.seek(0)
        for _ in range(0, add_size):
            signature_file.write(b'\x00')
        signature_file.write(signature_buf)


def check_if_is_drv(manifest_path):
    with open(manifest_path, 'r') as mani_fp:
        for each_line in mani_fp:
            if each_line.startswith("#") or not each_line.strip():
                continue
            name = each_line.split(":")[0].strip()
            if name == "gpd.ta.target_type" and \
                str(each_line.split(":")[1].strip()) == "1":
                return 1
    return 0


def get_sign_cert_block_buffer(cfg, signature_path, signature_size):
    ''' get sign and cert buffer '''
    with open(signature_path, 'rb') as signature_file:
        signature_buf = signature_file.read(signature_size)
    ta_cert_len = 0
    if cfg.sign_key_type == TYPE_PUBKEY:
        sign_verify_buf = struct.pack('II', TYPE_PUBKEY, 0) + signature_buf
    else:
        ta_cert_path = cfg.ta_cert_chain
        ta_cert_len = os.path.getsize(ta_cert_path)
        with open(ta_cert_path, 'rb') as ta_cert_file:
            ta_cert_buf = ta_cert_file.read(ta_cert_len)
        if cfg.sign_key_type == TYPE_CERT:
            sign_verify_buf = struct.pack('II', TYPE_CERT, ta_cert_len) + ta_cert_buf + signature_buf
        else:
            sign_verify_buf = struct.pack('II', TYPE_CERT_CHAIN, ta_cert_len) + ta_cert_buf + signature_buf
    return sign_verify_buf


def get_ta_sign_len(cfg):
    ''' get ta sign len '''
    if cfg.sign_type == '4':
        from generate_signature import get_ta_cms_sign_len
        return get_ta_cms_sign_len()
    if cfg.sign_type == '5':
        return 0
    if int(cfg.sign_key_len) == 256:
        return 72
    return int(cfg.sign_key_len) / 8


def parser_config(cfg, manifest_path, manifest_ext_path):
    ''' parser config '''
    dyn_conf_xml_file_path = os.path.join(cfg.in_path, "dyn_perm.xml")
    tag_parse_dict_file_path = os.path.join(os.getcwd(), "tag_parse_dict.csv")
    if os.path.exists(dyn_conf_xml_file_path):
        # V3.1 ta/drv do not need manifest_ext
        if not os.path.exists(cfg.config_path):
            from dyn_conf_parser import parser_dyn_conf
            parser_dyn_conf(dyn_conf_xml_file_path, manifest_ext_path, \
                            tag_parse_dict_file_path, cfg.in_path)
    else:
        if check_if_is_drv(manifest_path) == 1:
            if not os.path.exists(cfg.config_path):
                ans = "gpd.ta.dynConf:00000\n"
                manifest_ext_path_fd = os.open(manifest_ext_path, \
                                               os.O_RDWR, 0o600)
                with os.fdopen(manifest_ext_path_fd, 'a+') as mani_ext_fp:
                    mani_ext_fp.write(ans)

    # parser auth config xml: the auth info must be packed in the end of manifest_ext.
    auth_xml_file_path = os.path.join(cfg.in_path, "auth_config.xml")
    if os.path.exists(auth_xml_file_path):
        from auth_conf_parser import parser_auth_xml
        parser_auth_xml(auth_xml_file_path, manifest_ext_path, SING_BIG_ENDIAN)


def get_key_info_data(cfg, raw_file_path, key_data_path, raw_data_path):
    ''' get key info data '''
    is_encrypt_sec = True
    if cfg.public_key == "" or cfg.pub_key_len == "":
        is_encrypt_sec = False

    if is_encrypt_sec is True:
        # generate AES or SM4 key info to encrypt raw data
        key_data, iv_data, key_info_data = gen_aes_key_info(cfg)
        encrypt_aes_key(cfg.public_key, key_info_data, key_data_path, cfg)
        # use AES-CBC or SM4-CBC to encrypt TA content
        aes_encrypt(key_data, iv_data, raw_file_path, raw_data_path, cfg)
    else:
        gen_sign_alg_info(cfg, key_data_path)
        with open(key_data_path, 'rb') as key_info_fp:
            key_info_data = key_info_fp.read(os.path.getsize(key_data_path))

    return key_info_data


def get_content_len(cfg, key_data_path, raw_data_path):
    ''' get content len '''
    sign_len = get_ta_sign_len(cfg)
    if cfg.ta_version == 5:
        ta_cert_path = cfg.ta_cert_chain
        if cfg.sign_key_type == TYPE_PUBKEY:
            ta_cert_len = 0
        else:
            ta_cert_len = os.path.getsize(ta_cert_path)
        content_len = os.path.getsize(key_data_path) \
            + 4 + 4 + ta_cert_len + sign_len \
            + os.path.getsize(raw_data_path)
    else:
        content_len = os.path.getsize(key_data_path) \
            + sign_len \
            + os.path.getsize(raw_data_path)

    return content_len


def get_data_path(cfg, temp_path):
    ''' get data path '''
    enc_key_path = os.path.join(temp_path, "KeyInfo.enc")
    enc_raw_path = os.path.join(temp_path, "rawData.enc")
    key_info_path = os.path.join(temp_path, "KeyInfo")
    raw_file_path = os.path.join(temp_path, "rawData")

    is_encrypt_sec = True
    if cfg.public_key == "" or cfg.pub_key_len == "":
        is_encrypt_sec = False

    if is_encrypt_sec is True:
        key_data_path = enc_key_path
        raw_data_path = enc_raw_path
    else:
        key_data_path = key_info_path
        raw_data_path = raw_file_path

    return key_data_path, raw_data_path


def find_so(in_path_1):
    ''' find so '''
    path_list = os.listdir(in_path_1)
    for file_name in path_list:
        if os.path.splitext(file_name)[1] == ".so":
            logging.info(file_name)
            return file_name
    return ""


def prepare_data(cfg, temp_path):
    ''' get sec image '''
    manifest_path = os.path.join(cfg.in_path, "manifest.txt")
    manifest_data_path = os.path.join(temp_path, "manifestData.bin")
    manifest_ext_path = os.path.join(temp_path, "manifestExt.bin")
    elf_file_path = os.path.join(cfg.in_path, find_so(cfg.in_path))
    raw_file_path = os.path.join(temp_path, "rawData")
    key_data_path, raw_data_path = get_data_path(cfg, temp_path)

    # 1. parser_manifest
    manifest_info = process_manifest_file(os.path.join(cfg.in_path, "configs.xml"), \
            manifest_path, manifest_data_path, manifest_ext_path, SING_BIG_ENDIAN)
    if manifest_info.ret is False:
        raise RuntimeError

    # 2. update_api_level
    update_api_level(cfg, manifest_ext_path)

    # 3. update_otrp_flag
    if cfg.otrp_flag == "1":
        logging.info("package otrp sec file\n")
        update_otrp_flag(manifest_ext_path)

    # 4. parser_dyn_conf
    parser_config(cfg, manifest_path, manifest_ext_path)

    # 5. gen_raw_data
    gen_raw_data(manifest_data_path, manifest_ext_path, elf_file_path, \
            cfg.config_path, raw_file_path, cfg.ta_version)

    # 6. gen aes key, and encrypt aes key with RSA key,
    #    and encrypt raw data with aes key
    key_info_data = get_key_info_data(cfg, raw_file_path, key_data_path, raw_data_path)

    # 7. generate content_len and data_for_sign
    content_len = get_content_len(cfg, key_data_path, raw_data_path)
    data_for_sign = gen_data_for_sign(cfg, content_len, key_info_data, raw_file_path)

    # 8. parse code segment
    if os.path.exists("get_ta_elf_hash.py"):
        uuid_str = manifest_info.uuid_str
        uuid_str = uuid_str[0:36]
        if os.path.exists(elf_file_path):
            from get_ta_elf_hash import get_code_segment_from_elf
            get_code_segment_from_elf(elf_file_path, data_for_sign, uuid_str, cfg.out_path)

    if manifest_info.manifest_txt_exist is False and os.path.exists(manifest_path):
        os.remove(manifest_path)

    return manifest_info, data_for_sign, key_info_data


def update_content_len(cfg, key_data_path, raw_data_path, signature_path):
    ''' update content len '''
    sign_len = get_ta_sign_len(cfg)
    signature_size = os.path.getsize(signature_path)
    content_len = get_content_len(cfg, key_data_path, raw_data_path)
    if sign_len == 72:
        if signature_size != 72:
            pack_signature(signature_path, signature_size)
    elif sign_len == 0:
        sign_len = signature_size
        # generate Main Header
        content_len = os.path.getsize(key_data_path) \
                + sign_len \
                + os.path.getsize(raw_data_path)

    return content_len


def pack_sec_img(cfg, manifest_info, temp_path):
    ''' pack sec img '''
    signature_path = os.path.join(temp_path, "signature.bin")
    key_data_path, raw_data_path = get_data_path(cfg, temp_path)

    content_len = update_content_len(cfg, key_data_path, raw_data_path, signature_path)
    header = gen_header(int(content_len), cfg)
    sec_img_path = os.path.join(cfg.out_path, manifest_info.product_name)
    fd_image = os.open(sec_img_path, os.O_WRONLY | os.O_CREAT, \
        stat.S_IWUSR | stat.S_IRUSR)
    sec_image = os.fdopen(fd_image, "wb")
    # write to sec file [1.header info]
    sec_image.write(header)
    with open(key_data_path, 'rb') as key_data_fp:
        sec_image.write(key_data_fp.read(os.path.getsize(key_data_path)))
    # write to sec file [3.signature]
    if cfg.ta_version == 5:
        sign_cert_buf = get_sign_cert_block_buffer(cfg, signature_path, os.path.getsize(signature_path))
        sec_image.write(sign_cert_buf)
    else:
        with open(signature_path, 'rb') as signature_file:
            sec_image.write(signature_file.read(os.path.getsize(signature_path)))
    with open(raw_data_path, 'rb') as raw_data_fp:
        sec_image.write(raw_data_fp.read(os.path.getsize(raw_data_path)))
    sec_image.truncate(int(SEC_HEADER_BYTES) + int(content_len))
    sec_image.close()
    logging.info("=========================SUCCESS============================")
    logging.info("generate sec(common format) load image success: ")
    logging.info(sec_img_path)
    logging.info("============================================================")


def gen_sec_image(temp_path, cfg):
    ''' get sec image '''
    shutil.rmtree(temp_path, ignore_errors=True)
    os.mkdir(temp_path)
    os.chmod(temp_path, stat.S_IRWXU)

    manifest_info, data_for_sign, key_info_data = prepare_data(cfg, temp_path)

    uuid_str = manifest_info.uuid_str
    uuid_str = uuid_str[0:36]
    logging.info("uuid str %s", uuid_str)
    gen_signature(cfg, uuid_str, data_for_sign, key_info_data, temp_path)

    pack_sec_img(cfg, manifest_info, temp_path)


def print_file(file_path):
    ''' print file content '''
    file_size = os.path.getsize(file_path)
    with open(file_path, 'rb') as file_fd:
        file_info = file_fd.read(file_size)
    buf = [hex(int(i)) for i in file_info]
    output = " ".join(buf)
    logging.error("%s", output)


def check_inout_path(in_path, out_path):
    ''' check inpath or outpath valid '''
    if not os.path.exists(in_path):
        logging.error("input_path does not exist.")
        return 1
    if not os.path.exists(out_path):
        logging.error("out_path does not exist.")
        return 1
    if whitelist_check(in_path):
        logging.error("input_path is incorrect.")
        return 1
    if whitelist_check(out_path):
        logging.error("out_path is incorrect.")
        return 1

    return 0


def define_parser():
    ''' define parser '''
    parser = argparse.ArgumentParser()
    parser.add_argument("in_path", help="input path of data to be signed. \
            (libcombine.so; manifest.txt; ...", type=str)
    parser.add_argument("out_path", help="input path of signed file. \
            (xxx.sec)", type=str)
    parser.add_argument("--publicCfg", \
        help="sign cfg for ta developer", type=str)
    parser.add_argument("--privateCfg", \
        help="sign cfg for product developer", type=str)
    parser.add_argument("--sign_endian", \
        help="sign endian (little/big default little)", type=str)
    parser.add_argument("--sign_plat", \
        help="sign plat (pnf/wireless_hert/wireless_marp/wireless_debug default pnf)", type=str)
    return parser


def init_cfg(args):
    ''' init cfg '''
    global SING_BIG_ENDIAN
    cfg = AllCfg()
    if args.privateCfg:
        PrivateCfg(args.privateCfg, cfg)
    else:
        logging.error("please config private cfg file")
        raise RuntimeError

    if args.publicCfg:
        PublicCfg(args.publicCfg, cfg)
    else:
        PublicCfg(args.privateCfg, cfg)

    if args.sign_endian and args.sign_endian == "big":
        SING_BIG_ENDIAN = True
    if args.sign_plat and args.sign_plat == "wireless_hert":
        cfg.sign_plat = 1
    if args.sign_plat and args.sign_plat == "wireless_marp":
        cfg.sign_plat = 2
    if args.sign_plat and args.sign_plat == "wireless_debug":
        cfg.sign_plat = 3
    if args.sign_plat and args.sign_plat == "optics":
        cfg.sign_plat = 4
    if args.sign_plat and args.sign_plat == "microwave":
        cfg.sign_plat = 5

    if check_cfg(cfg):
        logging.error("the configuration file field is incorrect.")
        raise RuntimeError
    cfg.in_path = os.path.realpath(args.in_path)
    cfg.out_path = os.path.realpath(args.out_path)
    if check_inout_path(cfg.in_path, cfg.out_path):
        raise RuntimeError
    return cfg


def main():
    sign_tool_dir = os.path.dirname(os.path.realpath(__file__))
    parser = define_parser()
    args = parser.parse_args()
    cfg = init_cfg(args)
    os.chdir(sign_tool_dir)

    if cfg.re_sign_flag == "1":
        from re_generate_signature import re_sign_sec_img
        re_sign_sec_img(cfg.in_path, cfg.out_path, cfg)
    else:
        if cfg.sign_type == '4':
            from generate_signature import check_signature
            retry_time = 0
            result = -1
            while retry_time <= 10 and result != 0:
                temp_path = os.path.join(cfg.out_path, "temp")
                gen_sec_image(temp_path, cfg)
                result = check_signature(temp_path)
                shutil.rmtree(temp_path)
                retry_time += 1
            if retry_time > 10 and result != 0:
                raise RuntimeError
        else:
            temp_path = os.path.join(cfg.out_path, "temp")
            gen_sec_image(temp_path, cfg)
            #remove temp files
            shutil.rmtree(temp_path)


if __name__ == '__main__':
    main()

