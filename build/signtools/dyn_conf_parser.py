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
# tools for generating a trusted application dyn perm parser
#----------------------------------------------------------------------------

import string
import os
import stat
import logging
from defusedxml import ElementTree as ET
from dyn_conf_checker import dyn_perm_check
from dyn_conf_checker import check_and_classify_attr
from dyn_conf_checker import check_csv_sym
from dyn_conf_checker import check_ta_config


type_trans = {"TYPE_NONE": "-1",
              "TYPE_CLASS": "0",
              "TYPE_BOOL": "1",
              "TYPE_INT": "2",
              "TYPE_CHAR": "3"}

# the length len in tlv
DYN_CONF_LEN_LEN = 4

tag_dict = {}
type_dict = {}
trans_dict = {}


def get_csv_size(path):

    with open(path, "r", encoding="utf-8") as csvfile:
        lines = csvfile.readlines()
        return len(lines)
    return 0


def get_csv_data(path, lnum, rnum):

    with open(path, "r", encoding="utf-8") as csvfile:
        count = 0
        lines = csvfile.readlines()
        for line in lines:
            if count == lnum:
                return str(line.split(",")[rnum]).strip()
            count = count + 1
    return ""


def classify_tag(tag):

    while len(tag) < 3:
        tag = "0%s" % (tag)

    return tag


# save tag type and trans dict
def handle_tag_dict(path):

    for i in range(0, get_csv_size(path)):
        dyn_sym = get_csv_data(path, i, 0)
        tag_dict[dyn_sym] = classify_tag(get_csv_data(path, i, 1))
        type_dict[dyn_sym] = type_trans.get(get_csv_data(path, i, 2))
        trans_dict[dyn_sym] = get_csv_data(path, i, 3)


def check_target_data_been_found(sym, find_out, path):

    if find_out == 1:
        raise RuntimeError(sym + " can only set one time in " + path)


# trans value sym by trans dict
def handle_trans(value, path):

    datas = value.split("|")

    for i, data in enumerate(datas):
        find_out = 0
        target_data = data
        for j in range(0, get_csv_size(path)):
            sym = get_csv_data(path, j, 0)
            tag = get_csv_data(path, j, 1)
            check_csv_sym(sym)
            check_csv_sym(tag)
            if sym == target_data:
                # if one sym has been set more than one time in csv
                check_target_data_been_found(sym, find_out, path)
                datas[i] = tag
                find_out = 1 # means we find sym in dict

        if find_out == 0:
            raise RuntimeError("cannot find {} in {}".format(datas[i], path))

    ans = datas[0]
    for i in range(1, len(datas)):
        ans = "%s|%s" % (ans, datas[i])

    return ans


def get_value_by_name_in_config(config_name, in_path):

    config_file = os.path.join(in_path, config_name)
    if not os.path.exists(config_file):
        logging.error("configs.xml file doesn't exist")
        return ""
    xml_tree = ET.parse(config_file)
    drv_perm = xml_tree.find('./TA_Basic_Info/service_name')
    return drv_perm.text


def get_value_by_name_in_manifest(manifest_name, in_path):

    manifest = os.path.join(in_path, "manifest.txt")
    if not os.path.exists(manifest):
        name = get_value_by_name_in_config("configs.xml", in_path)
        if name != "":
            return name
    else:
        with open(manifest, 'r') as mani_fp:
            for each_line in mani_fp:
                if each_line.startswith("#") or not each_line.strip():
                    continue
                name = each_line.split(":")[0].strip()
                if "{" + name + "}" == manifest_name:
                    return str(each_line.split(":")[1].strip())

    raise RuntimeError("{" + manifest_name + "}" + \
                       "cannot find in " + manifest)


def get_value_trans(old_item, value, attrib, key, in_path):

    # if name contains '.csv' means
    # we can transform value by {manifest_name}.csv
    # manifest_name must in manifest.txt
    if ".csv" in trans_dict.get(key):
        manifest_name = trans_dict.get(key).split(".csv")[0]
        manifest_value = get_value_by_name_in_manifest(manifest_name, in_path)
        trans_file_path = os.path.join(in_path, "{}.csv".format(manifest_value))
        return handle_trans(value, trans_file_path)
    # if name not contains '.csv' means
    # we can transform value by {attrib[attri]}.csv
    # attrib[attri] must in xml file
    for attri in attrib:
        if old_item + attri == trans_dict.get(key):
            if len(attrib[attri]) == 0:
                raise RuntimeError("you should set drv name while \
                                    you set drv permission")
            trans_file_path = os.path.join(in_path, "{}.csv".format(attrib[attri]))
            return handle_trans(value, trans_file_path)

    raise RuntimeError("cannot find second trans file",\
        key, trans_dict.get(key))


def item_zip(old_item, attr, value, attrib, in_path):

    dyn_key = old_item + attr
    dyn_type = type_dict.get(dyn_key)
    origin_value = value

    if len(trans_dict.get(dyn_key)) > 0:
        value = get_value_trans(old_item, value, attrib, dyn_key, in_path)

    # check the xml is invalid for dyn perm
    dyn_perm_check(dyn_key, attrib, value, origin_value)

    if dyn_type == type_trans.get("TYPE_BOOL"):
        if value.lower() == "true":
            return "1"
        elif value.lower() == "false":
            return "0"
        else:
            raise Exception("bool can only be true or false")
    elif dyn_type == type_trans.get("TYPE_INT"):
        if '0x' in value:
            return str(int(value, base=16))
        elif '0b' in value:
            return str(int(value, base=2))
        else:
            return str(int(value, base=10))
    elif dyn_type == type_trans.get("TYPE_CHAR"):
        return value
    else:
        raise RuntimeError("unknown type")


def get_length(value):

    length = len(value)
    off = int((DYN_CONF_LEN_LEN / 2 - 1) * 8)
    ans = ""

    for _ in range(int(DYN_CONF_LEN_LEN / 2)):
        tmp = ""
        dyn_len = (length >> off) & 0xFF;
        if dyn_len >= 0 and dyn_len <= 0xF:
            tmp = "0"
        tmp += str(hex(dyn_len)).split("x")[1]
        ans += tmp
        off -= 8

    return ans


def do_parser_dyn_conf(old_item, ele, in_path):

    attrs = ""
    if len(ele.attrib) > 0:
        for attr in ele.attrib:
            ele.attrib[attr] = check_and_classify_attr(old_item,\
                attr, ele.attrib.get(attr))
            tag = tag_dict.get(old_item + attr)
            dyn_type = type_dict.get(old_item + attr)
            if dyn_type == type_trans.get("TYPE_NONE"):
                continue

            value = item_zip(old_item, attr, ele.attrib[attr],
                             ele.attrib, in_path)
            length = get_length(value)
            attrs = attrs + tag + dyn_type + length + value
    else:
        for child in ele:
            tmp_attrs = do_parser_dyn_conf(old_item + child.tag + "/",
                                           child, in_path)
            if tmp_attrs == "":
                continue
            attrs = attrs + tmp_attrs

    # handle inner context
    if check_ta_config(old_item, ele.text) is True and \
       ele.text is not None and len(ele.text.strip()) > 0:
        inner_text = item_zip(old_item + ele.tag, "", ele.text, {}, in_path)
        attrs = attrs + tag_dict.get(old_item + ele.tag) + \
                        type_dict.get(old_item + ele.tag) + \
                        get_length(inner_text) + inner_text

    if len(tag_dict.get(old_item)) == 0 or attrs == "":
        return ""

    return tag_dict.get(old_item) + type_dict.get(old_item) + \
           get_length(attrs) + attrs


def parser_dyn_conf(dyn_conf_xml_file_path, manifest_ext_path,
                    tag_parse_dict_path, in_path):

    if not os.path.exists(dyn_conf_xml_file_path):
        logging.error("dyn perm xml file doesn't exist")
        return

    if not os.path.exists(tag_parse_dict_path):
        logging.error("tag_parse_dict.csv file doesn't exist")
        return

    handle_tag_dict(tag_parse_dict_path)
    tree = ET.parse(dyn_conf_xml_file_path)
    root = tree.getroot()

    ans = do_parser_dyn_conf(root.tag + "/", root, in_path)
    if ans == "":
        ans = "00000"

    ans = "gpd.ta.dynConf:" + ans + "\n"

    if not os.path.exists(manifest_ext_path):
        out_tlv = os.path.join(in_path, "config_tlv")
        with os.fdopen(os.open(out_tlv, \
            os.O_RDWR | os.O_TRUNC | os.O_CREAT, \
            stat.S_IWUSR | stat.S_IRUSR), 'w+') as conf:
            conf.write(ans)
    else:
        #write items to mani_ext
        manifest_ext_path_fd = os.open(manifest_ext_path, os.O_RDWR, 0o600)
        with os.fdopen(manifest_ext_path_fd, 'a+') as mani_ext_fp:
            mani_ext_fp.write(ans)


def parser_config_xml(config_xml_file_path, tag_parse_dict_path, \
    out_path, in_path):

    if not os.path.exists(config_xml_file_path):
        logging.error("config xml file doesn't exist")
        return
    if not os.path.exists(tag_parse_dict_path):
        logging.error("tag_parse_dict.csv file doesn't exist")
        return

    handle_tag_dict(tag_parse_dict_path)
    tree = ET.parse(config_xml_file_path)
    root = tree.getroot()

    ans = do_parser_dyn_conf(root.tag + "/", root, in_path)
    if ans == "":
        ans = "00000"

    # write items to mani_ext
    config_path_fd = os.open(out_path, os.O_CREAT | os.O_RDWR, 0o600)
    with os.fdopen(config_path_fd, 'a+') as config_fp:
        config_fp.write(ans)
