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
#ifndef LIBQCA_RA_OPERATE_H
#define LIBQCA_RA_OPERATE_H

#include <stdint.h>
#include "tee_client_api.h"
#include "ra_client_api.h"

#define SHAREMEM_LIMIT            (0x100000) /* 1 MB */
#define PARAMS_RESERVED_SIZE      (0x2000)
#define OUT_DATA_RESERVED_SIZE    (0x3000)
#define REMOTE_ATTEST_CMD         (0x1001)

#endif
