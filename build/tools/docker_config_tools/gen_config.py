#!/usr/bin/env python3
# coding=utf-8
#----------------------------------------------------------------------------
# Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
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
"""Description: gen config.json
"""
import sys
import os
import stat
import logging
import json

DST_FILE = "config.json"
start_args = ["start.sh"]
stop_args = ["stop.sh"]


def main():
    """ must specify dest dir """
    if len(sys.argv) < 2:
        logging.error("too few arguments!")
        raise RuntimeError

    start_args.extend(sys.argv[1:])
    stop_args.extend(sys.argv[1:2])
    dirs = sys.argv[1]
    if not os.path.exists(dirs):
        os.makedirs(dirs)
    file_name = os.path.join(dirs, DST_FILE)
    if os.path.isfile(file_name):
        os.remove(file_name)

    with open("config_template.json", "r") as file:
        content = json.load(file)
        content["prestart"][0]["args"] = start_args
        content["poststop"][0]["args"] = stop_args

        flags = os.O_RDWR | os.O_CREAT
        modes = stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH
        with os.fdopen(os.open(file_name, flags, modes), 'w+') as json_file:
            json.dump(content, json_file, indent=4)

if __name__ == '__main__':
    main()

