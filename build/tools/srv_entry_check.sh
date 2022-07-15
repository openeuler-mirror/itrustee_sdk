#!/bin/bash
# Copyright Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
set -e

echo "------------- check SRV tee_task_entry begin --------------"
task_entry=$($1 -s $2 | grep -w tee_task_entry) || true
if [[ "$task_entry" != "" ]]; then
	exit 0
else
    echo "----- SRV should define tee_task_entry symbol ---"
    exit 1
fi
echo "------------- check SRV tee_task_entry succ --------------"
