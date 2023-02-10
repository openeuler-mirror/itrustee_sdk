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
# tools for generating a trusted application dyn perm checker
#----------------------------------------------------------------------------


import re
import uuid

uuid_split_sym_list = ['-']
spilt_sym_list = [';', '|', ',']
unused_sym_list = ['_']
unique_list = []
permission_unique_dict = {}
cmd_unique_dict = {}


def check_csv_sym(value):

    for sym in value:
        if sym in unused_sym_list:
            continue
        elif sym >= 'A' and sym <= 'Z':
            continue
        elif sym >= 'a' and sym <= 'z':
            continue
        elif sym >= '0' and sym <= '9':
            continue
        else:
            raise RuntimeError("has invalid sym in csv", value)


def classify_uuid_list(value):

    ans = ""
    uuid_list = value.split(',')
    for uuid_item in uuid_list:
        ans = "%s%s," % (ans, str(uuid.UUID(uuid_item)))

    return ans[:len(ans) - 1].strip()


def check_context_sym(old_item, attr, value):

    if len(value) == 0:
        return -1

    for sym in value:
        if sym in uuid_split_sym_list:
            continue
        elif sym in spilt_sym_list:
            continue
        elif sym in unused_sym_list:
            continue
        elif sym >= 'A' and sym <= 'Z':
            continue
        elif sym >= 'a' and sym <= 'z':
            continue
        elif sym >= '0' and sym <= '9':
            continue
        else:
            raise RuntimeError("has invalid sym in xml", \
                old_item + attr, value)
    return 0


def do_split_and_classify(old_item, attr, split_sym_index, value):

    ans = ""
    value_list = value.split(spilt_sym_list[split_sym_index])
    for val in value_list:
        val = val.strip()
        if len(val) == 0:
            raise RuntimeError("cannot split empty region", value)
        if split_sym_index == len(spilt_sym_list) - 1:
            if check_context_sym(old_item, attr, val) != 0:
                raise RuntimeError("xml attrib cannot be NULL", \
                    old_item + attr, value)
            ans += val + spilt_sym_list[split_sym_index]
        else:
            ans += do_split_and_classify(old_item, attr, split_sym_index + 1,\
                                         val) + spilt_sym_list[split_sym_index]

    return ans[: len(ans) - 1]


def check_and_classify_attr(old_item, attr, value):

    if len(value) == 0:
        raise RuntimeError("tag %s%s is NULL in xml" % (old_item, attr))

    value = do_split_and_classify(old_item, attr, 0, value)

    if attr == "uuid":
        value = classify_uuid_list(value)

    return value


def check_iomap_range(iomap_range):

    if len(iomap_range) == 0:
        raise RuntimeError("you must define iomap_range")

    iomap_range.replace(" ", "")
    iomap_ranges = iomap_range.split(";")
    for iomap in iomap_ranges:
        addrs = iomap.split(",")
        # check if range is start,end format
        if len(addrs) == 0:
            continue

        if len(addrs) != 2:
            raise RuntimeError("iomap must be start1,end1;\
start2,end2....", addrs)

        if '0x' not in addrs[0] or '0x' not in addrs[1]:
            raise RuntimeError("addr must be hex like \
0xF8555000", addrs[0], addrs[1])

        # check if addr is 4K aligned
        start = int(addrs[0], 16)
        end = int(addrs[1], 16)
        if start > 0xffffffffffffffff or end > 0xffffffffffffffff:
            raise RuntimeError("addr is so large", addrs[0], addrs[1])
        if start % 0x1000 != 0 or end % 0x1000 != 0:
            raise RuntimeError("addr must be 4K aligned", addrs[0], addrs[1])
        if end <= start:
            raise RuntimeError("iomap range start must \
smaller than end ", addrs[0], addrs[1])

    return 0


def check_thread_limit(value):

    if len(value) > 0:
        thread_limit = int(value)
        if thread_limit > 0xffffffff or thread_limit <= 0:
            raise RuntimeError("thread_limit is invalid", thread_limit)


def check_upgrade(value):

    if len(value) > 0:
        if value.lower() != 'true' and value.lower() != 'false':
            raise RuntimeError("upgrade must be true or false", value)


def check_virt2phys(value):

    if len(value) > 0:
        if value.lower() != 'true' and value.lower() != 'false':
            raise RuntimeError("virt2phys must be true or false", value)


def check_exception_mode(value):

    if value != "restart" and value != "syscrash" and value != "ddos":
        raise RuntimeError("unknown exception mode", value)


def check_chip_type(attrib, value):

    if len(value) == 0:
        raise RuntimeError("chip_type cannot be NULL")

    if not re.match(r"[A-Za-z0-9_,]*$", value):
        raise RuntimeError("there has invalid sym in chip type", value)

    chips = value.split(",")
    for chip in chips:
        chip_item = chip.lower().strip()
        if len(chip_item) > 31:
            raise RuntimeError("{} length is larger than 31".format(chip_item), chip_item)

    flag = 0
    for attr in attrib:
        if attr != "chip_type":
            flag = 1
            break
    if flag == 0:
        raise RuntimeError("you cannot only set chip_type in item")


def check_drv_name(value):

    if len(value) > 31 or len(value) == 0:
        raise RuntimeError("drv name should not be NULL or \
length larger than 31", value)


def check_irq(value):

    if len(value) == 0:
        raise RuntimeError("irq cannot be NULL")

    if ';' in value or '|' in value:
        raise RuntimeError("irq can only split by ,", value)

    irq_list = value.split(',')
    for irq in irq_list:
        num = int(irq, 10)
        if num < 32:
            raise RuntimeError("irq shoule not smaller than 32", value)


def check_map_secure_uuid(attrib, value):

    if len(value) != 36:
        raise RuntimeError("uuid len is invalid", value)

    flag = 0
    for attr in attrib:
        if attr == "region":
            flag = 1

    if flag == 0:
        raise RuntimeError("please set region in map secure item", attrib)


def check_map_secure_region(attrib, value):

    if len(value) == 0:
        raise RuntimeError("region cannot be NULL")

    flag = 0
    for attr in attrib:
        if attr == "uuid":
            flag = 1

    if flag == 0:
        raise RuntimeError("please set uuid in map secure item", attrib)

    check_iomap_range(value)


def check_drv_cmd_perm_info_item_permission(attrs, perm):

    if len(perm) == 0:
        raise RuntimeError("permssion len should not be NULL")

    if not re.match(r"^[0-9]*$", perm):
        raise RuntimeError("there has invalid sym in perm", perm)

    if int(perm, 10) > 64 or int(perm, 10) < 1:
        raise RuntimeError("perm can only in range 1-64", perm)

    flag = 0

    for attr in attrs:
        if attr == "cmd" and len(attrs[attr]) != 0:
            flag = 1
            break

    if flag == 0:
        raise RuntimeError("you should set cmd while you set cmd permission")


def check_drv_cmd_perm_info_item_cmd(attrs, dyn_key):

    if len(dyn_key) == 0:
        raise RuntimeError("dyn_key len should not be 0")

    flag = 0

    cmd = ""
    for attr in attrs:
        if attr == "permission" and len(attrs[attr]) != 0:
            flag = 1
        if attr == "cmd" and len(attrs[attr]) != 0:
            cmd = attrs[attr]
            if (dyn_key, attrs[attr]) in unique_list:
                raise RuntimeError("one cmd can only set \
permission once", attrs[attr])

    unique_list.append((dyn_key, cmd))

    if flag == 0:
        raise RuntimeError("you should set permission while \
you set cmd permission")


def check_mac_info_item_permission(attrs, perm):

    if len(perm) == 0:
        raise RuntimeError("permssion len should not be 0")

    if ',' in perm or ';' in perm:
        raise RuntimeError("multi permssion can only split by | ", perm)

    flag = 0

    for attr in attrs:
        if attr == "uuid" and len(attrs[attr]) != 0:
            flag = 1
            break

    if flag == 0:
        raise RuntimeError("you should set uuid while \
you set drvcall's permission")

    for perm_num in perm.split("|"):
        if int(perm_num, 10) > 64 or int(perm_num, 10) < 1:
            raise RuntimeError("perm can only in range 1-64", perm)


def check_mac_info_item_uuid(attrs, dyn_key):

    if len(dyn_key) == 0:
        raise RuntimeError("dyn_key len should not be 0")

    uuid_str = ""
    for attr in attrs:
        if attr == "uuid" and len(attrs[attr]) != 0:
            uuid_str = attrs[attr]
            if ',' in uuid_str:
                raise RuntimeError("uuid in mac can only set one", uuid_str)
            if (dyn_key, uuid_str) in unique_list:
                raise RuntimeError("uuid can only set once in mac", uuid_str)

    unique_list.append((dyn_key, uuid_str))


def check_permssion_unique(value, origin_value):

    value_list = value.split("|")
    origin_value_list = origin_value.split("|")
    if len(value) == 0 or len(value_list) != len(origin_value_list):
        RuntimeError("permssion trans by csv failed", value, origin_value)

    for (i, _) in enumerate(value_list):
        if value_list[i] in permission_unique_dict.keys() and \
           permission_unique_dict.get(value_list[i]) != origin_value_list[i]:
            raise RuntimeError("different permission set same num in csv",\
                value, origin_value)
        permission_unique_dict[value_list[i]] = origin_value_list[i]


def check_cmd_unique(value, origin_value):

    value_list = value.split("|")
    origin_value_list = origin_value.split("|")
    if len(value) == 0 or len(value_list) != len(origin_value_list):
        RuntimeError("cmd trans by csv failed", value, origin_value)

    for (i, _) in enumerate(value_list):
        if value_list[i] in cmd_unique_dict.keys() and \
           cmd_unique_dict.get(value_list[i]) != origin_value_list[i]:
            raise RuntimeError("different cmd set same num in csv", \
                               value, origin_value)
        cmd_unique_dict[value_list[i]] = origin_value_list[i]


def check_perm_apply_item(attrs, perm):

    if len(perm) == 0:
        raise RuntimeError("permssion len should not be 0")

    flag = 0

    for attr in attrs:
        if attr == "name" and len(attrs[attr]) != 0:
            flag = 1
            break

    if flag == 0:
        raise RuntimeError("you should set drv's name while \
you set drv's permission")


def check_ta_config_service_name(service_name):

    if len(service_name) == 0 or len(service_name) >= 40:
        raise Exception("service name is invalid", service_name)


def check_ta_config_stack_size(stack_size):

    if int(stack_size, 10) > 0xffffffff or int(stack_size, 10) <= 0:
        raise Exception("stack size is invalid", stack_size)


def check_ta_config_heap_size(heap_size):

    if int(heap_size, 10) > 0xffffffff or int(heap_size, 10) <= 0:
        raise Exception("heap size is invalid", heap_size)


def check_ta_config_rpmb_size(rpmb_size):

    if int(rpmb_size, 10) > 0xffffffff or int(rpmb_size, 10) <= 0:
        raise Exception("rpmb size is invalid", rpmb_size)


def check_ta_config_device_id(device_id):

    if len(device_id) != 64:
        raise Exception("device_id len is invalid", device_id)

    for sym in device_id:
        if sym >= 'A' and sym <= 'Z':
            continue
        elif sym >= '0' and sym <= '9':
            continue
        else:
            raise RuntimeError("has invalid sym in device_id", sym, device_id)


def dyn_perm_check(dyn_key, attrib, value, origin_value):

    if dyn_key == 'drv_perm/drv_basic_info/thread_limit':
        check_thread_limit(value)
    elif dyn_key == 'drv_perm/drv_basic_info/upgrade':
        check_upgrade(value)
    elif dyn_key == 'drv_perm/drv_basic_info/virt2phys':
        check_virt2phys(value)
    elif dyn_key == 'drv_perm/drv_basic_info/exception_mode':
        check_exception_mode(value)
    elif dyn_key == 'drv_perm/drv_io_map/item/chip_type':
        check_chip_type(attrib, value)
    elif dyn_key == 'drv_perm/drv_io_map/item/iomap':
        check_iomap_range(value)
    elif dyn_key == 'drv_perm/irq/item/irq':
        check_irq(value)
    elif dyn_key == 'drv_perm/map_secure/item/chip_type':
        check_chip_type(attrib, value)
    elif dyn_key == 'drv_perm/map_secure/item/uuid':
        check_map_secure_uuid(attrib, value)
        return
    elif dyn_key == 'drv_perm/map_secure/item/region':
        check_map_secure_region(attrib, value)
    elif dyn_key == 'drv_perm/map_nosecure/item/chip_type':
        check_chip_type(attrib, value)
    elif dyn_key == 'drv_perm/map_nosecure/item/uuid':
        # uuid has been checked in classify_uuid()
        return
    elif dyn_key == 'drv_perm/drv_cmd_perm_info/item/cmd':
        # cmd has been trans by csv, so it must be valied
        check_drv_cmd_perm_info_item_cmd(attrib, dyn_key)
        check_cmd_unique(value, origin_value)
        return
    elif dyn_key == 'drv_perm/drv_cmd_perm_info/item/permission':
        check_drv_cmd_perm_info_item_permission(attrib, value)
        check_permssion_unique(value, origin_value)
    elif dyn_key == 'drv_perm/drv_mac_info/item/uuid':
        # uuid has been checked in classify_uuid()
        check_mac_info_item_uuid(attrib, dyn_key)
        return
    elif dyn_key == 'drv_perm/drv_mac_info/item/permission':
        check_mac_info_item_permission(attrib, value)
        check_permssion_unique(value, origin_value)
    elif dyn_key == 'drvcall_conf/drvcall_perm_apply/item/permission':
        check_perm_apply_item(attrib, value)
        check_permssion_unique(value, origin_value)
    elif dyn_key == 'ConfigInfo/TA_Basic_Info/service_name/service_name':
        check_ta_config_service_name(value)
    elif dyn_key == 'ConfigInfo/TA_Basic_Info/uuid/uuid':
        classify_uuid_list(value)
    elif dyn_key == 'ConfigInfo/TA_Manifest_Info/stack_size/stack_size':
        check_ta_config_stack_size(value)
    elif dyn_key == 'ConfigInfo/TA_Manifest_Info/heap_size/heap_size':
        check_ta_config_heap_size(value)
    elif dyn_key == 'ConfigInfo/TA_Control_Info/RPMB_Info/RPMB_size/RPMB_size':
        check_ta_config_rpmb_size(value)
    elif dyn_key == \
        'ConfigInfo/TA_Control_Info/DEBUG_Info/DEBUG_device_id/DEBUG_device_id':
        check_ta_config_device_id(value)
    else:
        return


def check_text_ava(old_item, text):

    if text is None or len(text.strip()) == 0:
        raise Exception("text is invalied", old_item)


ta_config_item_list = [
    'ConfigInfo/TA_Basic_Info/service_name/',
    'ConfigInfo/TA_Basic_Info/uuid/',
    'ConfigInfo/TA_Manifest_Info/instance_keep_alive/',
    'ConfigInfo/TA_Manifest_Info/stack_size/',
    'ConfigInfo/TA_Manifest_Info/heap_size/',
    'ConfigInfo/TA_Manifest_Info/multi_command/',
    'ConfigInfo/TA_Manifest_Info/multi_session/',
    'ConfigInfo/TA_Manifest_Info/single_instance/',
    'ConfigInfo/TA_Control_Info/RPMB_Info/RPMB_size/',
    'ConfigInfo/TA_Control_Info/RPMB_Info/RPMB_Permission/RPMB_general/',
    'ConfigInfo/TA_Control_Info/SE_Info/SE_open_session/',
    'ConfigInfo/TA_Control_Info/TUI_Info/TUI_general/',
    'ConfigInfo/TA_Control_Info/DEBUG_Info/debug_status/',
    'ConfigInfo/TA_Control_Info/DEBUG_Info/DEBUG_device_id/']


def check_ta_config(old_item, text):

    if old_item in ta_config_item_list:
        check_text_ava(old_item, text)

    return True
