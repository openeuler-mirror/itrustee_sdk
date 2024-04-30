#!/bin/bash
# Description: this script is used to clean tee resource when docker poststop
# Copyright Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
# iTrustee licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan
# PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
# KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
# NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.
id=$(cat $1/id.txt)
tee_teleport --clean --grpid=$id > stop.log
