/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2023. All rights reserved.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */
#include "ra_operate_api.h"
#include <stdio.h>
#include <stdlib.h>
#include "tee_client_api.h"
#include "securec.h"
#include "ra_log.h"
#include "ra_client_api.h"

static const TEEC_UUID g_tee_qta_uuid = {
    0xe08f7eca, 0xe875, 0x440e, {
        0x9a, 0xb0, 0x5f, 0x38, 0x11, 0x36, 0xc6, 0x00
    }
};

static TEEC_Result set_remote_attest_out_data(TEEC_SharedMemory *shared_out, uint32_t out_size,
    struct ra_buffer_data *out)
{
    if (out == NULL || out->buf == NULL) {
        return TEEC_SUCCESS;
    }
    if (out_size == 0) {
        out->size = out_size;
        return TEEC_SUCCESS;
    } else if (out_size > out->size) {
        tloge("out size is too short\n");
        return TEEC_ERROR_SHORT_BUFFER;
    }
    if (memcpy_s(out->buf, out->size, shared_out->buffer, out_size) != EOK) {
        tloge("memcpy shared out buffer failed\n");
        return TEEC_ERROR_GENERIC;
    }
    out->size = out_size;
    return TEEC_SUCCESS;
}

static TEEC_Result handle_remote_attest(TEEC_Context *context, TEEC_Session *session, struct ra_buffer_data *in,
    struct ra_buffer_data *out)
{
    uint32_t origin;
    TEEC_Operation operation = {0};
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT, TEEC_MEMREF_PARTIAL_OUTPUT,
        TEEC_VALUE_OUTPUT, TEEC_NONE);

    TEEC_SharedMemory shared_in;
    (void)memset_s(&shared_in, sizeof(shared_in), 0, sizeof(shared_in));
    shared_in.size = in->size;
    shared_in.flags = TEEC_MEM_INPUT;
    TEEC_Result result = TEEC_AllocateSharedMemory(context, &shared_in);
    if (result != TEEC_SUCCESS) {
        tloge("allocate shared input failed, result = 0x%x.\n", result);
        return result;
    }
    operation.params[0].memref.parent = &shared_in;
    operation.params[0].memref.size = shared_in.size;
    operation.params[0].memref.offset = 0;
    (void)memcpy_s(shared_in.buffer, in->size, in->buf, in->size);

    TEEC_SharedMemory shared_out;
    (void)memset_s(&shared_out, sizeof(shared_out), 0, sizeof(shared_out));
    shared_out.flags = TEEC_MEM_OUTPUT;
    if (out != NULL && out->buf != NULL) {
        shared_out.size = out->size;
        result = TEEC_AllocateSharedMemory(context, &shared_out);
        if (result != TEEC_SUCCESS) {
            tloge("allocate shared output failed, result = 0x%x.\n", result);
            goto clear1;
        }
        (void)memset_s(out->buf, out->size, 0, out->size);
        (void)memset_s(shared_out.buffer, shared_out.size, 0, shared_out.size);
    }
    operation.params[1].memref.parent = &shared_out;
    operation.params[1].memref.size = shared_out.size;
    operation.params[1].memref.offset = 0;

    result = TEEC_InvokeCommand(session, REMOTE_ATTEST_CMD, &operation, &origin);
    if (result != TEEC_SUCCESS) {
        tloge("invoke command failed, result = 0x%x\n", result);
        goto clear2;
    }

    result = set_remote_attest_out_data(&shared_out, operation.params[2].value.a, out);
clear2:
    if (out != NULL && out->buf != NULL)
        TEEC_ReleaseSharedMemory(&shared_out);
clear1:
    TEEC_ReleaseSharedMemory(&shared_in);
    return result;
}

TEEC_Result RemoteAttest(struct ra_buffer_data *in, struct ra_buffer_data *out)
{
    if (in == NULL || in->buf == NULL || in->size == 0 || in->size > PARAMS_RESERVED_SIZE) {
        tloge("check input failed\n");
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    if (out != NULL) {
        if (out->size > SHAREMEM_LIMIT || (out->buf == NULL && out->size > 0) ||
            (out->buf != NULL && out->size < OUT_DATA_RESERVED_SIZE)) {
            tloge("check output failed\n");
            return TEEC_ERROR_BAD_PARAMETERS;
        }
    }

    TEEC_Context context = {0};
    TEEC_Session session = {0};
    TEEC_Operation operation = {0};
    TEEC_UUID uuid = g_tee_qta_uuid;

    TEEC_Result result = TEEC_InitializeContext(NULL, &context);
    if (result != TEEC_SUCCESS) {
        tloge("init context is failed, result is 0x%x\n", result);
        return result;
    }

    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    result = TEEC_OpenSession(&context, &session, &uuid, TEEC_LOGIN_IDENTIFY, NULL, &operation, NULL);
    if (result != TEEC_SUCCESS) {
        tloge("open session is failed, result is 0x%x\n", result);
        goto cleanup_1;
    }

    result = handle_remote_attest(&context, &session, in, out);
    if (result != TEEC_SUCCESS) {
        tloge("handle remote attest failed, result is 0x%x\n", result);
        goto cleanup_2;
    }

cleanup_2:
    TEEC_CloseSession(&session);
cleanup_1:
    TEEC_FinalizeContext(&context);
    return result;
}
