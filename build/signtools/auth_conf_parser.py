#!/usr/bin/env python3
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
# tools for parsering the dynamic ca caller infomation
#----------------------------------------------------------------------------
from __future__ import absolute_import
import os
import stat
import logging
import hashlib
import struct
from ctypes import create_string_buffer
from ctypes import c_uint32
from ctypes import sizeof
from ctypes import memmove
from ctypes import byref
from defusedxml import ElementTree as ET

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s line:%(lineno)d %(levelname)s:%(name)s:%(message)s',
                    datefmt='%H:%M:%S'
                    )


# caller base config
MAX_CALLER_NUM = 16
MAX_CMDLINE_LEN = 256
MAX_USERNAME_LEN = 256
AUTH_CONFIG_KEY = "gpd.ta.auth:"
DEFAULT_AUTH_TYPE_UID = True


# init caller info
g_caller_num = 0
g_caller_enable = 1
g_hash_byte_list = bytes("", 'utf-8')
g_auth_type = True  # default auth type: cmdline + uid
g_big_endian = False


def print_hash(byte_buf):
    """ print caller hash """
    buf = [hex(int(i)) for i in byte_buf]
    logging.info(" ".join(buf))


def calc_sha256(buf):
    """ calcuate sha256 """
    md = hashlib.sha256()
    md.update(buf)
    return md.digest()


def calc_cmdline_uid_hash(cmdline, uid):
    """ calcuate cmdline||uid hash """
    c_uid = c_uint32(uid)
    c_str = create_string_buffer(cmdline.encode('utf-8'), len(cmdline) + sizeof(c_uid))
    memmove(byref(c_str, len(c_str.value)), byref(c_uid), sizeof(c_uid))
    return calc_sha256(c_str)


def calc_cmdline_username_hash(cmdline, username):
    """ calcuate cmdline||username hash """
    c_str = create_string_buffer((cmdline + username).encode('utf-8'), len(cmdline) + MAX_USERNAME_LEN)
    return calc_sha256(c_str)


def check_auth_enable_type(value):
    """ check auth_enable type """
    if len(value) == 0:
        raise RuntimeError("auth_enable value must be configured")
    if value != "true" and value != 'false':
        raise RuntimeError("auth_enable value must be true or false", value)


def get_auth_enable_value(value):
    """ check auth_enable value """
    global g_caller_enable
    if value == "false":
        g_caller_enable = 0
    else:
        g_caller_enable = 1


def check_auth_type(value):
    """ check auth type """
    if len(value) == 0:
        raise RuntimeError("auth_uid_type value must be configured")
    if value != "true" and value != 'false':
        raise RuntimeError("auth_uid_type value must be true or false", value)


def get_auth_type_value(value):
    """ check auth type value """
    global g_auth_type
    if value == "false":
        g_auth_type = False
    else:
        g_auth_type = True


def check_item_type(item):
    """ check item value """
    if item.tag != "item" or len(item.attrib) != 2:
        raise RuntimeError("invaild item attrib", item.tag, item.attrib, len(item.attrib))


def check_cmdline_type(value):
    """ check cmdline type """
    if len(value) == 0 or len(value) > MAX_CMDLINE_LEN:
        raise RuntimeError("invaild cmdline, the cmdline length must be in range (0, {}]".format(MAX_CMDLINE_LEN), \
            value, len(value))


def check_uid_type(value):
    """ check uid type """
    if int(value, 10) > 0xffffffff or int(value, 10) < 0:
        raise RuntimeError("invaild uid, the uid value must be in [0, 0xffffffff]", value)


def check_username_type(value):
    """ check username type """
    if len(value) == 0 or len(value) > MAX_USERNAME_LEN:
        raise RuntimeError("invaild username, the username length must be in range (0, {}]".format(MAX_USERNAME_LEN), \
            value, len(value))


def get_item_value(item, auth_type):
    """ get item value """
    cmdline = ""
    uid = 0
    username = ""
    caller_hash = ""
    global g_caller_num
    global g_hash_byte_list

    if auth_type == DEFAULT_AUTH_TYPE_UID:
        attr_key = "uid"
    else:
        attr_key = "username"

    for attr in item.attrib:
        value = item.attrib[attr]
        if attr == "cmdline":
            check_cmdline_type(value)
            cmdline = value
        elif attr == attr_key:
            if auth_type == DEFAULT_AUTH_TYPE_UID:
                check_uid_type(value)
                uid = int(value, 10)
            else:
                check_username_type(value)
                username = value
        else:
            raise RuntimeError("invaild item attr", attr)

    if auth_type == DEFAULT_AUTH_TYPE_UID:
        caller_hash = calc_cmdline_uid_hash(cmdline, uid)
        logging.info("cmdline %s, uid %s", cmdline, uid)
    else:
        caller_hash = calc_cmdline_username_hash(cmdline, username)
        logging.info("cmdline %s, username %s", cmdline, username)
    print_hash(caller_hash)
    if g_big_endian is True:
        pack_format = ">32s"
    else:
        pack_format = "32s"
    g_hash_byte_list = g_hash_byte_list + struct.pack(pack_format, caller_hash)
    g_caller_num = g_caller_num + 1
    if g_caller_num > MAX_CALLER_NUM:
        raise RuntimeError("Exceed max caller num", MAX_CALLER_NUM)


def handle_auth_base_info(child):
    """ handle auth_base_info """
    for attr in child.attrib:
        if attr == "auth_enable":
            check_auth_enable_type(child.attrib.get(attr))
            get_auth_enable_value(child.attrib.get(attr))
        elif attr == "auth_type_uid":
            check_auth_type(child.attrib.get(attr))
            get_auth_type_value(child.attrib.get(attr))
        else:
            raise RuntimeError("invaild auth_base_info attrib", attr)


def handle_auth_item(child, auth_type):
    """ handle auth item """
    for item in child:
        check_item_type(item)
        get_item_value(item, auth_type)


def do_parser_auth_conf(root):
    """ do parser auth config """
    auth_tag = "auth_cmdline_uid"
    xml_line_num = 0
    for child in root:
        if child.tag == "auth_base_info":
            if xml_line_num != 0:
                raise RuntimeError("the auth_base_info must be configured first")
            handle_auth_base_info(child)
            if g_auth_type != DEFAULT_AUTH_TYPE_UID:
                auth_tag = "auth_cmdline_username"
        elif child.tag == auth_tag:
            handle_auth_item(child, g_auth_type)
        else:
            raise RuntimeError("not support xml tag", child.tag)
        xml_line_num = xml_line_num + 1


def parser_auth_xml(auth_xml_file_path, manifest_ext_path, big_endian=False):
    """ parser auth xml """
    global g_caller_num
    global g_hash_byte_list
    global g_big_endian

    g_big_endian = big_endian

    if not os.path.exists(auth_xml_file_path):
        raise RuntimeError("auth_config.xml file doesn't exist")

    tree = ET.parse(auth_xml_file_path)
    root = tree.getroot()

    # parser auth config
    do_parser_auth_conf(root)

    # gen auth header
    if g_caller_enable == 0:
        g_caller_num = 0
        g_hash_byte_list = bytes("", 'utf-8')

    if g_big_endian is True:
        pack_format = ">II"
    else:
        pack_format = "II"
    auth_header = struct.pack(pack_format, g_caller_enable, g_caller_num)

    #write auth to mani_ext
    if not os.path.exists(manifest_ext_path):
        fd_ext = os.open(manifest_ext_path, os.O_WRONLY | os.O_CREAT, stat.S_IWUSR | stat.S_IRUSR)
    else:
        fd_ext = os.open(manifest_ext_path, os.O_RDWR, 0o600)
    with os.fdopen(fd_ext, 'ba+') as fp_mani_ext:
        fp_mani_ext.write(bytes(AUTH_CONFIG_KEY, "utf-8"))
        fp_mani_ext.write(auth_header)
        fp_mani_ext.write(g_hash_byte_list)
        fp_mani_ext.write(bytes("\n", "utf-8"))
        fp_mani_ext.close()
