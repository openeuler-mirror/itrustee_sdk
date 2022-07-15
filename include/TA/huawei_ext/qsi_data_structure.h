/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * iTrustee licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Description: Data Structure Definations of QSI.
 */
#ifndef QSI_DATA_STRUCTURE_H
#define QSI_DATA_STRUCTURE_H
#include <tee_defines.h>

enum seal_operation {
    SEAL,
    UNSEAL
};

struct seal_param {
    uint8_t *data;
    size_t size;
    uint8_t *cipher_data;
    size_t *cipher_size;
    uint32_t algorithm;
    enum seal_operation operation;
};

struct qsi_provision_params {
    uint32_t scenario;
    uint32_t param_set_size;
    uint8_t *param_set;
    uint32_t out_size;
    uint8_t *out_data;
};

struct qsi_report_params {
    TEE_UUID uuid;
    void *user_data;
    uint32_t user_size;
    uint32_t param_set_size;
    uint8_t *param_set;
    void *report;
    uint32_t report_size;
    bool with_tcb;
};

struct qsi_save_akcert_params {
    uint32_t length;
    uint8_t *buffer;
};

struct ra_buffer_data {
    uint32_t length;
    uint8_t *buffer;
};

#endif
