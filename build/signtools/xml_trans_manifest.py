#!/usr/bin/env python
# coding=utf-8
#----------------------------------------------------------------------------
# Copyright (c) Huawei Technologies Co., Ltd. 2020-2023. All rights reserved.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan
# PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
# KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
# NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.
# Description: tools for xml trans
#----------------------------------------------------------------------------

import os
import logging
from defusedxml import ElementTree as ET


type_trans = {"TYPE_NONE": "-1",
              "TYPE_CLASS": "0",
              "TYPE_BOOL": "1",
              "TYPE_INT": "2",
              "TYPE_CHAR": "3"}

type_dict = {}
manifest_dict = {}


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


# save tag type and manifest item dict
def handle_manifest_tag_dict(path):
    for index in range(0, get_csv_size(path)):
        dyn_sym = get_csv_data(path, index, 0)
        type_dict[dyn_sym] = type_trans.get(get_csv_data(path, index, 2))
        manifest_dict[dyn_sym] = get_csv_data(path, index, 3)


def process_xml_to_manifest(config_xml_file_path, manifest_path):
    tree = ET.parse(config_xml_file_path)
    root = tree.getroot()
    #Layer 1 node name
    old_item = root.tag
    attrs = ""
    write_data = False

    #write items to manifest.txt
    manifest_fd = os.open(manifest_path, os.O_CREAT | os.O_RDWR, 0o600)
    manifest_fp = os.fdopen(manifest_fd, "wb")

    #Traversing the second layer of the xml file
    for child in root:
        child_item = "{}/{}".format(old_item, child.tag)
        #Traversing the third layer of the xml file
        for children in child:
            children_item = "{}/{}".format(child_item, children.tag)
            dyn_type = type_dict.get(children_item + attrs)
            manifest_item_name = manifest_dict.get(children_item + attrs)
            if dyn_type == type_trans.get("TYPE_CHAR"):
                value = "{}: {}\n".format(manifest_item_name, children.text)
                manifest_fp.write(value.encode())
                write_data = True

    #close manifest.txt file
    manifest_fp.close()
    if write_data is False:
        os.remove(manifest_path)


def trans_xml_to_manifest(config_xml_file_path, manifest_path):
    if not os.path.exists(config_xml_file_path):
        logging.error("config xml file doesn't exist")
        return
    if not os.path.exists("./manifest_tag_parse_dict.csv"):
        logging.error("config manifest_tag_parse_dict.csv file doesn't exist")
        return
    if os.path.exists(manifest_path):
        return

    handle_manifest_tag_dict("./manifest_tag_parse_dict.csv")
    process_xml_to_manifest(config_xml_file_path, manifest_path)
