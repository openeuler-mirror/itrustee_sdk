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
import string
import struct
import uuid
import os
import re
import stat
import logging


PRODUCT_TA_IMAGE = 1
PRODUCT_DYN_LIB = 2
PRODUCT_SERVICE_IMAGE = 3
PRODUCT_CLIENT_IMAGE = 4
PRODUCT_DRIVER_IMAGE = 5


class PackUuid:
    # Structure object to align and package the TEE_UUID
    data = struct.Struct('IHH8b')

    def __init__(self, data, big_endian=False):
        unpacked_data = (PackUuid.data).unpack(str.encode(data))
        self.unpacked_data = unpacked_data
        self.time_low = unpacked_data[0]
        self.time_mid = unpacked_data[1]
        self.time_hi_version = unpacked_data[2]
        self.clock_seq_node = unpacked_data[3]
        if big_endian:
            PackUuid.data = struct.Struct('>IHH8b')

    def print_values(self):
        logging.critical("ATTRIBUTE / VALUE")
        for attr, value in self.__dict__.items():
            logging.critical(attr, value)

    def get_pack_data(self):
        values = [self.time_low,
                self.time_mid,
                self.time_hi_version,
                self.clock_seq_node,
                ]

        return (PackUuid.data).pack(*values)


#----------------------------------------------------------------------------
# Manifest
#----------------------------------------------------------------------------
class Manifest:

    # Structure object to align and package the Manifest
    data = struct.Struct('I' * 6)

    def __init__(self, data, big_endian=False):
        unpacked_data = (Manifest.data).unpack(str.encode(data))
        self.unpacked_data = unpacked_data
        self.single_instance = unpacked_data[0]
        self.multi_session = unpacked_data[1]
        self.multi_command = unpacked_data[2]
        self.heap_size = unpacked_data[3]
        self.stack_size = unpacked_data[4]
        self.instancekeepalive = unpacked_data[5]
        if big_endian:
            Manifest.data = struct.Struct('>' + 'I' * 6)

    def print_values(self):
        logging.critical("ATTRIBUTE / VALUE")
        for attr, value in self.__dict__.items():
            logging.critical(attr, value)

    def get_pack_data(self):
        values = [self.single_instance,
                self.multi_session,
                self.multi_command,
                self.heap_size,
                self.stack_size,
                self.instancekeepalive,
                ]

        return (Manifest.data).pack(*values)


#----------------------------------------------------------------------------
# verify property name in manifest file
#----------------------------------------------------------------------------
def verify_property_name(str_line):
    logging.critical("verify property name")
    alphas = string.ascii_letters + string.digits
    cont = "".join([alphas, '-', '_', '.'])
    if len(str_line) > 1:
        if str_line[0] not in alphas:
            logging.error("invalid first letter in property name")
            return False
        else:
            for otherchar in str_line[1:]:
                if otherchar not in cont:
                    logging.error("invalid char in property name")
                    return False
    else:
        logging.error("invalid property name")
        return False

    return True


#----------------------------------------------------------------------------
# verify property value in manifest file
#----------------------------------------------------------------------------
def verify_property_value(str_line):
    logging.critical("verify property value")
    filt_letter = chr(0) + chr(10) + chr(13)
    for thechar in str_line:
        if thechar in filt_letter:
            logging.error("invalid letter in prop value")
            return False
    return True


#----------------------------------------------------------------------------
# remove tabs and space in property value
#----------------------------------------------------------------------------
def trailing_space_tabs(str_line):
    logging.critical("trailing space tabs in value head and trail")
    space_tabs = chr(9) + chr(32) + chr(160)
    space_tabs_newlines = space_tabs + chr(10) + chr(13)

    logging.critical("str in: %s", str_line)
    index = 0
    for thechar in str_line:
        if thechar in space_tabs:
            index += 1
        else:
            break
    headvalue = str_line[index:]

    strlen = len(headvalue)

    strlen -= 1

    while strlen > 0:
        if headvalue[strlen] in space_tabs_newlines:
            strlen -= 1
        else:
            break

    str_ret = headvalue[0:strlen + 1] + chr(10)
    logging.critical("str ret: %s", str_ret)

    return str_ret


#----------------------------------------------------------------------------
# verify manifest file, parse manifest file, generate a new manfiest file
#----------------------------------------------------------------------------
def parser_manifest(manifest, manifest_data_path, mani_ext, big_endian=False):
    logging.critical("verify manifest")
    target_type = PRODUCT_TA_IMAGE

    uuid_val = PackUuid('\0' * 16, big_endian)

    #manifest default
    manifest_val = Manifest('\0' * 24, big_endian)

    manifest_val.single_instance = 1
    manifest_val.multi_session = 0
    manifest_val.multi_command = 0
    manifest_val.instancekeepalive = 0
    manifest_val.heap_size = 16384
    manifest_val.stack_size = 2048

    service_name = 'external_service'
    dyn_conf_target_type = 0

    with open(manifest, 'r') as mani_fp:
        fd_ext = os.open(mani_ext, os.O_WRONLY | os.O_CREAT, \
            stat.S_IWUSR | stat.S_IRUSR)
        mani_ext_fp = os.fdopen(fd_ext, "wb")
        for each_line in mani_fp:
            logging.critical(each_line)
            if each_line.startswith("#") or not each_line.strip():
                continue
            index = each_line.find(':', 1, len(each_line))

            prop_name = each_line[0:index]
            prop_name_t = each_line[0:index + 1]
            prop_value_t = each_line[index + 1:]
            logging.critical("name is: %s; value is: %s", prop_name, prop_value_t)

            prop_value = trailing_space_tabs(prop_value_t)
            prop_len = len(prop_value)
            prop_value_v = prop_value[0:prop_len - 1]
            logging.critical("prop value_v: %s", prop_value_v)

            if verify_property_name(prop_name) is False:
                logging.error("manifest format invalid, please check it")
                mani_ext_fp.close()
                return (False, 0, 0)

            if verify_property_value(prop_value_v) is False:
                logging.error("manifest format invalid, please check it")
                mani_ext_fp.close()
                return (False, 0, 0)

            # name:value to lowcase, and parse manifest
            prop_name_low = prop_name.lower()
            logging.critical("name lower: %s", prop_name_low)
            if 'gpd.ta.appid' == prop_name_low:
                logging.critical("compare name is srv id")
                uuid_val = uuid.UUID(prop_value_v)
                logging.critical("uuid str %s", uuid_val)
                logging.critical("val fields %s", uuid_val.fields)

            elif 'gpd.ta.singleinstance' == prop_name_low:
                prop_value_low = prop_value_v.lower()
                if 'true' == prop_value_low:
                    manifest_val.single_instance = 1
                elif 'false' == prop_value_low:
                    manifest_val.single_instance = 0
                else:
                    logging.error("single_instance value error!")

            elif 'gpd.ta.multisession' == prop_name_low:
                prop_value_low = prop_value_v.lower()
                if 'true' == prop_value_low:
                    manifest_val.multi_session = 1
                elif 'false' == prop_value_low:
                    manifest_val.multi_session = 0
                else:
                    logging.error("multi_session value error!")

            elif 'gpd.ta.multicommand' == prop_name_low:
                prop_value_low = prop_value_v.lower()
                if 'true' == prop_value_low:
                    manifest_val.multi_command = 1
                elif 'false' == prop_value_low:
                    manifest_val.multi_command = 0
                else:
                    logging.error("multi_command value error!")

            elif 'gpd.ta.instancekeepalive' == prop_name_low:
                prop_value_low = prop_value_v.lower()
                if 'true' == prop_value_low:
                    manifest_val.instancekeepalive = 1
                elif 'false' == prop_value_low:
                    manifest_val.instancekeepalive = 0
                else:
                    logging.error("instancekeepalive value error!")

            elif 'gpd.ta.datasize' == prop_name_low:
                manifest_val.heap_size = int(prop_value_v)
                logging.critical('b')

            elif 'gpd.ta.stacksize' == prop_name_low:
                manifest_val.stack_size = int(prop_value_v)
                logging.critical('b')

            elif 'gpd.ta.service_name' == prop_name_low:
                service_name = prop_value_v
                logging.critical('b')

            elif 'gpd.ta.dynconf' == prop_name_low:
                mani_ext_fp.close()
                logging.error("gpd.ta.dynConf is reserved, cannot set")
                return (False, 0, 0)

            else:
                logging.critical('b')
                #write have not paresed manifest into sample.manifest file
                mani_ext_fp.write(str.encode(prop_name_t))
                mani_ext_fp.write(str.encode(prop_value))
                if 'gpd.ta.is_lib' == prop_name_low:
                    prop_value_low = prop_value_v.lower()
                    if 'true' == prop_value_low:
                        target_type = PRODUCT_DYN_LIB
                elif 'gpd.ta.target_type' == prop_name_low:
                    dyn_conf_target_type = int(prop_value_v)
                    if dyn_conf_target_type > 0xFFFF or \
                        dyn_conf_target_type < 0:
                        mani_ext_fp.close()
                        logging.error("gpd.ta.target_type must \
                                       in range [0, 0xFFFF]")
                        return (False, 0, 0)

        mani_ext_fp.close()
        #write the whole parsed manifest into sample.manifest file

    service_name_len = len(service_name)
    logging.critical("service name: %s", service_name)
    logging.critical("service name len: %s", service_name_len)

    max_service_len = 64

    # dyn_conf_target_type is 1 means that is drv
    if dyn_conf_target_type == 1:
        max_service_len = 32
        target_type = PRODUCT_DRIVER_IMAGE
        if not re.match(r"^[A-Za-z0-9_]*$", service_name):
            logging.error("drv's name only can use [A-Z] [a-z] [0-9] and '_'")
            return (False, 0, 0)

    if dyn_conf_target_type == 3:
        max_service_len = 32
        target_type = PRODUCT_SERVICE_IMAGE
        if not re.match(r"^[A-Za-z0-9_]*$", service_name):
            logging.error("drv's name only can use \
                           [A-Z] [a-z] [0-9] and '_'")
            return (False, 0, 0)
    if dyn_conf_target_type == 4:
        max_service_len = 32
        target_type = PRODUCT_CLIENT_IMAGE
        if not re.match(r"^[A-Za-z0-9_]*$", service_name):
            logging.error("drv's name only can use \
                           [A-Z] [a-z] [0-9] and '_'")
            return (False, 0, 0)

    if service_name_len > max_service_len:
        logging.error("service name len cannot larger than %s", str(max_service_len))
        return (False, 0, 0)

    # get manifest string file len
    manifest_str_size = os.path.getsize(mani_ext)
    logging.critical('manifest str size %s', manifest_str_size)
    # 2> manifest + service_name
    if big_endian:
        logging.critical("bytes len %s", len(uuid_val.bytes))
    else:
        logging.critical("bytes len %s", len(uuid_val.bytes_le))
    logging.critical("bytes len %s", len(manifest_val.get_pack_data()))
    logging.critical("bytes len %s", len(service_name))

    # 3> unparsed manifest, string manifest
    with open(mani_ext, 'rb') as string_mani_fp:
        logging.critical("read manifest string size %s", manifest_str_size)
        manifest_string_buf = string_mani_fp.read(manifest_str_size)
        logging.critical("manifest strint: %s", manifest_string_buf)

    #---- write manifest parse context to manifest file
    fd_out = os.open(manifest_data_path, os.O_WRONLY | os.O_CREAT, \
        stat.S_IWUSR | stat.S_IRUSR)
    out_manifest_fp = os.fdopen(fd_out, "wb")
    if big_endian:
        out_manifest_fp.write(uuid_val.bytes)
    else:
        out_manifest_fp.write(uuid_val.bytes_le)
    out_manifest_fp.write(str.encode(service_name))
    out_manifest_fp.write(manifest_val.get_pack_data())
    out_manifest_fp.close()

    uuid_str = str(uuid_val)
    product_name = str(uuid_val)
    if target_type == PRODUCT_TA_IMAGE:
        logging.critical("product type is ta image")
        product_name = "".join([uuid_str, ".sec"])
    elif target_type == PRODUCT_DRIVER_IMAGE:
        logging.critical("product type is driver")
        product_name = "".join([service_name, ".sec"])
    elif target_type == PRODUCT_SERVICE_IMAGE:
        logging.critical("product type is service")
        product_name = "".join([service_name, ".sec"])
    elif target_type == PRODUCT_CLIENT_IMAGE:
        logging.critical("product type is client")
        product_name = "".join([service_name, ".so.sec"])
    elif target_type == PRODUCT_DYN_LIB:
        logging.critical("product type is dyn lib")
        product_name = "".join([uuid_str, service_name, ".so.sec"])
    else:
        logging.error("invalid product type!")
        return (False, 0, 0)

    return (True, product_name, uuid_str)


class ManifestInfo:
    ''' get manifest info '''
    def __init__(self, ret, product_name, uuid_str, manifest_txt_exist):
        self.ret = ret
        self.product_name = product_name
        self.uuid_str = uuid_str
        self.manifest_txt_exist = manifest_txt_exist


def process_manifest_file(xml_config_path, manifest_path, \
    manifest_data_path, mani_ext, big_endian=False):

    manifest_txt_exist = True
    if not os.path.exists(manifest_path):
        logging.critical("xml trans manifest cfg")
        manifest_txt_exist = False
        from xml_trans_manifest import trans_xml_to_manifest
        trans_xml_to_manifest(xml_config_path, manifest_path)

    ret, product_name, uuid_str = parser_manifest(manifest_path, \
        manifest_data_path, mani_ext, big_endian)
    manifest_info = ManifestInfo(ret, product_name, uuid_str, manifest_txt_exist)
    return manifest_info
