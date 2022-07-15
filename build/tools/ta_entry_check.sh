#!/bin/bash
# Copyright Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
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

#params: $1-readelf cmd; $2-libcombine.so; $3-USE_ENTRY_BINARY; $4-DYN_LINK; $5-TARGET_IS_ARM64

# if USE_ENTRY_BINARY is y, means link elf_main_entry.o
# no need to check
if [ "$3" == "y" ]; then
	echo "------ no need to check task_entry ----"
	exit 0
fi

# for ta not link elf_main_entry.o
# should not define tee_task_entry symbol
echo "------------- check TA tee_task_entry begin --------------"
task_entry=$($1 -s $2 | grep -w tee_task_entry) || true
if [[ "$task_entry" != "" ]]; then
	echo "----- ERROR TA should not define tee_task_entry symbol ---"
	echo "        $task_entry"
	exit 1
fi
echo "------------- check TA tee_task_entry succ --------------"

# if TARGET_IS_ARM64 is y, means is aarch64 TA
# for aarch64 ta no need to compile ta_magic.c
if [ "$5" == "y" ]; then
	echo "------- aarch64 TA no need check magic ----"
	exit 0
fi

# if DYN_LINK is y, means is DYN TA
# for 32bit dyn ta should compile ta_magic.c
# since it not link elf_main_entry.o
task_magic=$($1 -S $2 | grep -w ".magic") || true
if [ "$4" == "y" ]; then
	echo "------- check TA magic begin ------"
	if [[ "$task_magic" == "" ]]; then
		echo "------ ERROR DYN TA should compile ta_magic.c -----"
		exit 1
	fi;
	echo "------- check TA magic succ ------"
fi
