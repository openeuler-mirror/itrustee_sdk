/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * licensed under the Mulan PSL v2.
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

#define SHAREMEM_LIMIT 0x100000 /* 1MB */
#define PROVISION_RESERVED_SIZE    (0x1000)
#define SAVE_AKCERT_RESERVED_SIZE  (0x2000)
#define REPORT_RESERVED_SIZE       (0x3000)

#define USER_DATA_SIZE 64
/* scenario number */
#define RA_SCENARIO_NO_AS        0
#define RA_SCENARIO_AS_NO_DAA    1
#define RA_SCENARIO_AS_WITH_DAA  2

enum qca_commands_id {
    INIT_PROVISION  = 0x1001,
    REQUEST_REPORT  = 0x1002,
    SAVE_AKCERT     = 0x1003,
};

struct report_input_params {
    TEEC_UUID uuid;
    uint8_t user_data[USER_DATA_SIZE];
    uint32_t user_size;
    bool with_tcb;
    uint32_t param_count;
    struct ra_params params[0];
} __attribute__((__packed__));

struct provision_input_params {
    uint32_t scenario;
    uint32_t param_count;
    struct ra_params params[0];
} __attribute__((__packed__));

#endif
