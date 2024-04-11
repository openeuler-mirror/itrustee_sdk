#!/bin/bash
# Description: this script is used to config tee resource when docker prestart
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
set -e
nsid=$(lsns -t pid -o ns,ppid | grep $PPID | awk '{print $1}')

cnt=1
for i in $@
do
        if [ $cnt -gt 1 ]
        then
                cmd+=" $i"
        fi
        cnt=$(($cnt + 1))
done
echo $cmd > $1/cmd.log
set +e
tee_teleport --config-resource --nsid=$nsid $cmd > $1/std.log
result=$?
echo $result > $1/id.txt
if [ $result -eq 255 ]
then
        exit -1
fi
