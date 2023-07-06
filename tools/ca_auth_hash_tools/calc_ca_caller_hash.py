#!/usr/bin/env python3
# coding=utf-8
#----------------------------------------------------------------------------
# Copyright @ Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
# calc ca caller hash for AddCaller_CA
#----------------------------------------------------------------------------

import hashlib
from ctypes import sizeof
from ctypes import c_uint32
from ctypes import create_string_buffer
from ctypes import memmove
from ctypes import byref
import binascii
import struct
import logging
import os
from defusedxml import ElementTree as ET

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s line:%(lineno)d %(levelname)s:%(name)s:%(message)s',
                    datefmt='%H:%M:%S'
                    )

MAX_PKGNAME_LEN = 256
MAX_USERNAME_LEN = 256
MAX_MODULUS_LEN = 1024
MAX_PUB_EXP_LEN = 256


def print_hash(byte_buf):
    """ print caller hash """
    buf = [hex(int(i)) for i in byte_buf]
    output = " ".join(buf)
    logging.info("caller hash: %s", output)


def check_native_ca_item(item):
    """ check native ca item vaule """
    if item.tag != "item" or len(item.attrib) != 2:
        raise RuntimeError("invalid item attrib", item.tag, item.attrib, len(item.attrib))


def check_apk_hap_ca_item(item):
    """ check apk_hap item vaule """
    if item.tag != "item" or len(item.attrib) != 3:
        raise RuntimeError("invalid item attrib", item.tag, item.attrib, len(item.attrib))


def check_pkgname_type(value):
    """ check pkgname type """
    if len(value) == 0 or len(value) > MAX_PKGNAME_LEN:
        raise RuntimeError("invalid pkgname, the pkgname length must be in range (0, {}]".format(MAX_PKGNAME_LEN), \
            value, len(value))


def check_uid_type(value):
    """ check uid type """
    if int(value, 10) > 0xffffffff or int(value, 10) < 0:
        raise RuntimeError("invalid uid, the uid value must be in [0, 0xffffffff]", value)


def check_username_type(value):
    """ check username type """
    if len(value) == 0 or len(value) > MAX_USERNAME_LEN:
        raise RuntimeError("invalid username, the username length must be in range (0, {}]".format(MAX_USERNAME_LEN), \
            value, len(value))


def check_module_type(value):
    """ check module type """
    if len(value) == 0 or (len(value) / 2) > MAX_MODULUS_LEN:
        raise RuntimeError("invalid module, the module length must be in range (0, {}]".format(MAX_MODULUS_LEN * 2), \
            value, len(value))


def check_exponent_type(value):
    """ check exponent type """
    if len(value) == 0 or (len(value) / 2) > MAX_PUB_EXP_LEN:
        raise RuntimeError( \
            "invalid exponent, the exponent length must be in range (0, {}]".format(MAX_PUB_EXP_LEN * 2), \
            value, len(value))


def calc_sha256(buf):
    """ calcuate sha256 """
    hash_op = hashlib.sha256()
    hash_op.update(buf)
    return hash_op.digest()


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


def calc_apk_caller_hash(apk_pkg_name, apk_modulus, apk_public_exponent):
    """ calcuate pkg_name||modulus||exponent hash """
    hex_modulus = binascii.a2b_hex(apk_modulus)
    hex_exponent = binascii.a2b_hex(apk_public_exponent)
    pub_key_format = "{}s{}s".format(len(hex_modulus), len(hex_exponent))
    hex_pub_key = struct.pack(pub_key_format, hex_modulus, hex_exponent)
    c_str = create_string_buffer((apk_pkg_name).encode('utf-8'), \
        len(apk_pkg_name) + len(hex_pub_key))
    memmove(byref(c_str, len(c_str.value)), bytes(hex_pub_key), len(hex_pub_key))
    return calc_sha256(c_str)


def handle_cmdline_uid_item_hash(item):
    """ handle cmdline_uid_item hash """
    cmdline = ""
    uid = 0
    for attr in item.attrib:
        value = item.attrib[attr]
        if attr == "cmdline":
            check_pkgname_type(value)
            cmdline = value
        elif attr == "uid":
            check_uid_type(value)
            uid = int(value, 10)
        else:
            raise RuntimeError("invalid item attr", attr)
    caller_hash = calc_cmdline_uid_hash(cmdline, uid)
    logging.info("cmdline: %s, uid: %s", cmdline, uid)
    print_hash(caller_hash)


def handle_cmdline_uid(child):
    """ handle cmdline_uid """
    for item in child:
        check_native_ca_item(item)
        handle_cmdline_uid_item_hash(item)


def handle_cmdline_username_item_hash(item):
    """handle cmdline_username_item hash """
    cmdline = ""
    username = ""
    for attr in item.attrib:
        value = item.attrib[attr]
        if attr == "cmdline":
            check_pkgname_type(value)
            cmdline = value
        elif attr == "username":
            check_username_type(value)
            username = value
        else:
            raise RuntimeError("invalid item attr", attr)
    caller_hash = calc_cmdline_username_hash(cmdline, username)
    logging.info("cmdline: %s, username: %s", cmdline, username)
    print_hash(caller_hash)


def handle_cmdline_username(child):
    """ handle cmdline_username """
    for item in child:
        check_native_ca_item(item)
        handle_cmdline_username_item_hash(item)


def handle_apk_hap_item_hash(item):
    """ handle apk_hap_item hash """
    pkg_name = ""
    modulue = ""
    exponent = ""
    for attr in item.attrib:
        value = item.attrib[attr]
        if attr == "pkg_name":
            check_pkgname_type(value)
            pkg_name = value
        elif attr == "modulue":
            check_module_type(value)
            modulue = value
        elif attr == "exponent":
            check_exponent_type(value)
            exponent = value
        else:
            raise RuntimeError("invalid item attr", attr)
    caller_hash = calc_apk_caller_hash(pkg_name, modulue, exponent)
    logging.info("pkg_name: %s, module: %s, exponent: %s", pkg_name, modulue, exponent)
    print_hash(caller_hash)


def handle_apk_hap(child):
    """handle apk_hap """
    for item in child:
        check_apk_hap_ca_item(item)
        handle_apk_hap_item_hash(item)


def do_calc_caller_info_hash(ca_caller_info_root):
    """ calc caller info hash """
    for child in ca_caller_info_root:
        if child.tag == "cmdline_uid":
            handle_cmdline_uid(child)
        elif child.tag == "cmdline_username":
            handle_cmdline_username(child)
        elif child.tag == "apk_hap":
            handle_apk_hap(child)
        else:
            raise RuntimeError("not support xml tag", child.tag)


def main():
    """ main """
    ca_caller_info_xml = "ca_caller_info.xml"
    if not os.path.exists(ca_caller_info_xml):
        raise RuntimeError("caller_info.xml file doesn't exist")

    tree = ET.parse(ca_caller_info_xml)
    ca_caller_info_root = tree.getroot()

    # parser caller info file
    do_calc_caller_info_hash(ca_caller_info_root)


if __name__ == "__main__":
    main()
