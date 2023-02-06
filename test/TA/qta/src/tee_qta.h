/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */
#ifndef TEE_QTA_H
#define TEE_QTA_H
#include <tee_defines.h>
#include <tee_ext_api.h>

#define PARAM_TWO         2
#define PARAM_THREE       3
#define PARAM_NUM         4
#define SHAREMEM_LIMIT    0x100000
#define IN_RESERVED_SIZE  0x2000
#define OUT_RESERVED_SIZE 0x3000
#define REMOTE_ATTEST_CMD 0x1001

#define REINTERPRET_CAST(dest_type, source_type, temp)                        \
    ((__extension__(union { source_type source; dest_type dest; })(temp)).dest)

#endif

