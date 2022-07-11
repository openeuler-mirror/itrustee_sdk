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
#ifndef TEE_QTA_H
#define TEE_QTA_H
#include <tee_defines.h>
#include <tee_ext_api.h>

#define PARAMS_RESERVED_COUNT 1
#define SHAREMEM_LIMIT 0x100000 /* maximum param size 1M */
#define PROVISION_RESERVED_SIZE    (0x1000) /* minimum provision size is 4K */
#define REPORT_RESERVED_SIZE       (0x3000) /* minimum report size is 12K */
#define SAVE_AKCERT_RESERVED_SIZE  (0x2000) /* maximum akcert size is 8K */

enum qta_cmd_id {
    CMD_INIT_PROVISION  =  0x1001,
    CMD_REQUEST_REPORT  =  0x1002,
    CMD_SAVE_AKCERT     =  0x1003,
};

#define USER_DATA_SIZE           64
/* scenario number */
#define RA_SCENARIO_NO_AS        0
#define RA_SCENARIO_AS_NO_DAA    1
#define RA_SCENARIO_AS_WITH_DAA  2

struct ra_data_offset {
    uint32_t data_len;
    uint32_t data_offset;
};

struct ra_params {
    uint32_t tags;
    union {
        uint32_t integer;
        struct ra_data_offset blob;
    } data;
} __attribute__((__packed__));

struct report_input_params {
    TEE_UUID uuid;
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
