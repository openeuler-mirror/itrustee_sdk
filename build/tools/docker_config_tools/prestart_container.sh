#!/bin/bash
# Description: Add files related to ccos derived keys.
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
container_id=$(pwd | awk -F '/' '{print $NF}')
nsid=$(lsns -t pid -o ns,ppid | grep $PPID | awk '{print $1}')

tee_teleport --nsid=${nsid} --containerid=$container_id --config-container
