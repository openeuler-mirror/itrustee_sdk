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
# tools for generating data for signing
#----------------------------------------------------------------------------

import struct
import os
import stat
import sys
import hashlib
import subprocess
import re
import logging
import shutil
import xml.etree.ElementTree as ET
sys.path.append('../signtools')
from dyn_conf_parser import parser_config_xml
from dyn_conf_parser import parser_dyn_conf

CONFIG_VERSION    = 2
BASE_POLICY_VERSION_TEE = 0b001

XML2TLV_PARSE_TOOL_INDEX = 1
XML2TLV_PY_VALUE = 1 << XML2TLV_PARSE_TOOL_INDEX


def get_policy_version():
    ''' get policy type '''
    policy_ver = BASE_POLICY_VERSION_TEE | XML2TLV_PY_VALUE
    return policy_ver


def run_cmd(command):
    ret = subprocess.run(command, shell=False, check=True)
    if ret.returncode != 0:
        logging.error("run command failed.")
        sys.exit(1)


def whitelist_check(intput_str):
    if not re.match(r"^[A-Za-z0-9\/\-_.]+$", intput_str):
        return 1
    return 0


class load_config_header:
    str = struct.Struct('IHHIIIIIIIII')

    def __init__(self, data):
        unpacked_data   = (load_config_header.str).unpack(data.encode())
        self.unpacked_data  = unpacked_data
        self.magic_num      = unpacked_data[0]
        self.version        = unpacked_data[1]
        self.policy_versio  = unpacked_data[2]
        self.context_len    = unpacked_data[3]
        self.ta_cert_len    = unpacked_data[4]
        self.config_len     = unpacked_data[5]
        self.sign_verify_len = unpacked_data[6]
        self.reserved1      = unpacked_data[7]
        self.reserved2      = unpacked_data[8]
        self.reserved3      = unpacked_data[9]
        self.reserved4      = unpacked_data[10]
        self.reserved5      = unpacked_data[11]

    def get_packed_data(self):
        values = [self.magic_num,
                  self.version,
                  self.policy_version,
                  self.context_len,
                  self.ta_cert_len,
                  self.config_len,
                  self.sign_verify_len,
                  self.reserved1,
                  self.reserved2,
                  self.reserved3,
                  self.reserved4,
                  self.reserved5,
                 ]
        return (load_config_header.str).pack(*values)


def pkg_config_header(hdr_len, magic_num, version, policy_version, \
        context_len, ta_cert_len, config_len, sign_verify_len):
    config_hd_len = hdr_len
    config_hd = load_config_header('\0' * config_hd_len)
    config_hd.magic_num  = magic_num
    config_hd.version    = version
    config_hd.policy_version = policy_version
    config_hd.context_len = context_len
    config_hd.ta_cert_len = ta_cert_len
    config_hd.config_len  = config_len
    config_hd.sign_verify_len = sign_verify_len
    return config_hd


#----------------------------------------------------------------------------
# generate hash use SHA256
#----------------------------------------------------------------------------
def generate_sha256_hash(in_buf):
    # Initialize a SHA256 object from the Python hash library
    obj = hashlib.sha256()
    # Set the input buffer and return the output digest
    obj.update(in_buf)
    return obj.digest()


def check_dyn_perm(xml_config_file, input_path):
    ''' check_dyn_perm '''
    xml_tree = ET.parse(xml_config_file)
    xml_root = xml_tree.getroot()
    drv_perm = None
    for child in xml_root.findall('drv_perm'):
        if child != '':
            drv_perm = child
            if os.path.exists(os.path.join(input_path, 'temp')):
                out_save_file = os.path.join(input_path, \
                    'temp/configs_bak.xml')
                xml_tree.write(out_save_file, encoding="utf-8")
            xml_root.remove(child)
    if drv_perm is not None:
        newtree = ET.ElementTree(drv_perm)
        if os.path.exists(os.path.join(input_path, 'temp')):
            out_file = os.path.join(input_path, 'temp/dyn_perm.xml')
            newtree.write(out_file, encoding="utf-8")
        xml_tree.write(xml_config_file)
        return 1
    return 0


def creat_temp_folder(input_path_creat):
    ''' creat temp '''
    creat_temp = os.path.join(input_path_creat, 'temp')
    if os.path.exists(creat_temp):
        shutil.rmtree(creat_temp)
    temp_path = os.path.join(input_path_creat, 'temp')
    cmd = ["mkdir", temp_path]
    run_cmd(cmd)


def delete_temp_folder(input_path_delete):
    ''' delete temp '''
    delete_temp = os.path.join(input_path_delete, 'temp')
    delete_config_tlv = os.path.join(input_path_delete, 'config_tlv')
    if os.path.exists(delete_temp):
        shutil.rmtree(delete_temp)
    if os.path.exists(delete_config_tlv):
        os.remove(delete_config_tlv)


def convert_xml2tlv(xml_file, tlv_file, input_path):
    ''' configs.xml exchange to tlv '''
    if (get_policy_version() & (1 << XML2TLV_PARSE_TOOL_INDEX)) == XML2TLV_PY_VALUE:
        csv_dir = os.path.realpath(os.path.join(os.getcwd(), 'xml2tlv_tools/csv'))
        tag_parse_dict_file_path = \
            os.path.join(csv_dir, 'tag_parse_dict.csv')
        parser_config_xml(xml_file, tag_parse_dict_file_path, \
            tlv_file, input_path)
        if os.path.isfile(tlv_file):
            logging.critical("convert xml to tlv success")
        else:
            logging.error("convert xml to tlv failed")
            raise RuntimeError
    else:
        logging.error("invlid policy version")
        raise RuntimeError


def get_target_type_in_config(config_path, in_path):
    ''' get target type '''
    tree = ET.parse(config_path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    modes = stat.S_IRUSR | stat.S_IWUSR
    drv_target_type = tree.find('./TA_Manifest_Info/target_type')
    if drv_target_type is not None:
        if drv_target_type.text == "1":
            ans = "gpd.ta.dynConf:00000\n"
            out_tlv = os.path.join(in_path, 'config_tlv')
            with os.fdopen(os.open(out_tlv, flags, modes), 'w+') as conf:
                conf.write(ans)


def gen_data_for_sign(input_path, ta_cert_path, config_cert_path):
    ''' convert xml to tlv '''
    logging.critical(os.getcwd())
    creat_temp_folder(input_path)
    tlv_dynconf_data = os.path.join(input_path, "config_tlv")
    xml_config_file = os.path.join(input_path, "configs.xml")
    tlv_config_file = os.path.join(input_path, "temp/configs_tlv")
    if check_dyn_perm(xml_config_file, input_path) != 0:
        sys.path.append('../signtools')
        dyn_conf_xml_file_path = os.path.join(input_path, 'temp/dyn_perm.xml')
        # may be use abspath
        csv_dir = os.path.realpath(os.path.join(os.getcwd(), 'xml2tlv_tools/csv'))
        tag_parse_dict_file_path = \
             os.path.join(csv_dir, 'tag_parse_dict.csv')
        parser_dyn_conf(dyn_conf_xml_file_path, "", tag_parse_dict_file_path, input_path)
        convert_xml2tlv(xml_config_file, tlv_config_file, input_path)
        src_file_path = os.path.join(input_path, 'temp/configs_bak.xml')
        cmd = ["mv", src_file_path, xml_config_file]
        run_cmd(cmd)
    else:
        convert_xml2tlv(xml_config_file, tlv_config_file, input_path)
        get_target_type_in_config(xml_config_file, input_path)
    config_cert_size = 0
    if os.path.exists(config_cert_path):
        config_cert_size = os.path.getsize(config_cert_path)

    if os.path.exists(tlv_dynconf_data):
        with open(tlv_config_file, 'rb') as tlv_config_fp:
            tlv_config_buf = \
                tlv_config_fp.read(os.path.getsize(tlv_config_file))
        with open(tlv_dynconf_data, 'rb') as tlv_dynconf_fp:
            tlv_config_buf = tlv_config_buf + \
                tlv_dynconf_fp.read(os.path.getsize(tlv_dynconf_data)) + b"\n"
        tlv_data_size = len(tlv_config_buf)
    else:
        tlv_data_size = os.path.getsize(tlv_config_file)
        with open(tlv_config_file, 'rb') as tlv_config_fp:
            tlv_config_buf = tlv_config_fp.read(tlv_data_size)

    ta_cert_size = 4 + os.path.getsize(ta_cert_path)
    with open(ta_cert_path, 'rb') as ta_cert_fp:
        ta_cert_buf = struct.pack('I', 1) + ta_cert_fp.read(ta_cert_size)

    sign_data_size = 4 + 4 + 4 + config_cert_size + 512

    config_hd_len = 44
    context_size = ta_cert_size + tlv_data_size + sign_data_size
    config_header = pkg_config_header(config_hd_len, 0xABCDABCD, \
            CONFIG_VERSION, get_policy_version(), \
            context_size, ta_cert_size, tlv_data_size, sign_data_size)

    logging.critical(os.getcwd())
    data_for_sign = os.path.join(input_path, "data_for_sign")
    fd_sign = os.open(data_for_sign, os.O_WRONLY | os.O_CREAT, \
        stat.S_IWUSR | stat.S_IRUSR)
    data_for_sign_fp = os.fdopen(fd_sign, "wb")
    data_for_sign_fp.write(config_header.get_packed_data())
    data_for_sign_fp.write(ta_cert_buf)
    data_for_sign_fp.write(tlv_config_buf)
    data_for_sign_fp.close()
    delete_temp_folder(input_path)


def main():
    argvs = sys.argv
    ta_input_path = argvs[1]
    ta_cert_path = argvs[2]
    config_cert_path = argvs[3]
    if not os.path.exists(ta_input_path):
        logging.error("ta_input_path does not exist.")
        sys.exit(1)
    if not os.path.exists(ta_cert_path):
        logging.error("ta_cert_path does not exist.")
        sys.exit(1)
    if not os.path.exists(config_cert_path):
        # cloud Product Signing Config May Not Have Certificates
        logging.error("config_cert_path does not exist.")

    if whitelist_check(ta_input_path):
        logging.error("ta_input_path is incorrect.")
        sys.exit(1)
    if whitelist_check(ta_cert_path):
        logging.error("ta_cert_path is incorrect.")
        sys.exit(1)
    if whitelist_check(config_cert_path):
        logging.error("config_cert_path is incorrect.")
        sys.exit(1)
    gen_data_for_sign(ta_input_path, ta_cert_path, config_cert_path)


if __name__ == '__main__':
    main()
