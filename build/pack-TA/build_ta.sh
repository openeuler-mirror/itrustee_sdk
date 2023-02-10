#!/bin/bash
# Description: preare toolchains and env for build ta.
# Copyright @ Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan
# PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
# KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
# NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.
set -e

LOCAL_PATH="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

ITRUSTEE_SDK_PATH=$LOCAL_PATH/../signtools/

INPUT_PATH=$LOCAL_PATH/input
OUTPUT_PATH=$LOCAL_PATH/output

python3 -B ${ITRUSTEE_SDK_PATH}/signtool_v3.py ${INPUT_PATH} ${OUTPUT_PATH} --privateCfg ${ITRUSTEE_SDK_PATH}/config_cloud.ini
