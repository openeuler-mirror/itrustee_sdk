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

static const enum ra_tags g_tag_white_list [] = {
    RA_TAG_HASH_TYPE,
};

static bool check_provision_scenario_invalid(uint32_t scenario)
{
    if (scenario == RA_SCENARIO_NO_AS || scenario == RA_SCENARIO_AS_NO_DAA)
        return false;
    return true;
}

#define WHITE_LIST_TAG_COUNT (sizeof(g_tag_white_list) / sizeof(g_tag_white_list[0]))

static bool check_tag_is_valid(uint32_t tag)
{
    uint32_t index = 0;
    for (index = 0; index < WHITE_LIST_TAG_COUNT; ++index) {
        if (tag == g_tag_white_list[index])
            return true;
    }
    return false;
}

static bool check_input_paramset_invalid(struct ra_buffer_data *param_set)
{
    uint32_t length = param_set->size;
    struct ra_params_set_t *ra_param_set = (struct ra_params_set_t *)param_set->buf;
    uint32_t param_count = ra_param_set->param_count;
    if (length != sizeof(uint32_t) + param_count * sizeof(struct ra_params) || length > SHAREMEM_LIMIT) {
        tloge("invalid param length\n");
        return true;
    }
    struct ra_params *param = NULL;
    for (uint32_t index = 0; index < param_count; ++index) {
        param = &(ra_param_set->params[index]);
        if (check_tag_is_valid(param->tags) == false) {
            tloge("invalid param tag\n");
            return true;
        }
    }
    return false;
}

static int32_t init_opera_and_shared_mem(TEEC_Context *context, TEEC_SharedMemory *shared_mem,
    TEEC_Operation *operation, struct ra_buffer_data *rsp, struct ra_buffer_data *msg)
{
    TEEC_Result result;
    (void)memset_s(operation, sizeof(TEEC_Operation), 0, sizeof(TEEC_Operation));
    (*operation).started = 1;
    (*operation).paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_VALUE_OUTPUT, TEEC_NONE, TEEC_NONE);
    shared_mem->size = (rsp == NULL ? msg->size : rsp->size);
    shared_mem->flags = TEEC_MEM_OUTPUT | TEEC_MEM_INPUT;
    if (shared_mem->size > SHAREMEM_LIMIT) {
        tloge("too large shared mem size to be allocated\n");
        return -1;
    }
    result = TEEC_AllocateSharedMemory(context, shared_mem);
    if (result != TEEC_SUCCESS) {
        tloge("allocate shared memory failed, result = 0x%x\n", result);
        return -1;
    }
    (*operation).params[0].memref.parent = shared_mem;
    (*operation).params[0].memref.size = shared_mem->size;
    (*operation).params[0].memref.offset = 0;
    return 0;
}

static int32_t handle_cmd_id(uint32_t cmd_id, TEEC_SharedMemory *shared_mem, struct ra_buffer_data *msg)
{
    int32_t ret = 0;
    if (cmd_id == INIT_PROVISION || cmd_id == REQUEST_REPORT || cmd_id == SAVE_AKCERT) {
        if (memcpy_s((void *)shared_mem->buffer, shared_mem->size, msg->buf, msg->size) != EOK) {
            tloge("memcpy buffer failed\n");
            ret = -1;
        }
    } else {
        tloge("cmd id invalid!\n");
        return -1;
    }
    return ret;
}

static TEEC_Result handle_cmd(uint32_t cmd_id, struct ra_buffer_data *msg, struct ra_buffer_data *rsp)
{
    TEEC_Context context = {0};
    TEEC_Session session = {0};
    TEEC_Operation operation = {0};
    TEEC_Result result;
    uint32_t origin;
    TEEC_UUID uuid = g_tee_qta_uuid;

    result = TEEC_InitializeContext(NULL, &context);
    if (result != TEEC_SUCCESS) {
        tloge("init context is failed! result is 0x%x\n", result);
        return TEEC_ERROR_GENERIC;
    }

    (void)memset_s(&operation, sizeof(TEEC_Operation), 0, sizeof(TEEC_Operation));
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    result = TEEC_OpenSession(&context, &session, &uuid, TEEC_LOGIN_IDENTIFY, NULL, &operation, NULL);
    if (result != TEEC_SUCCESS) {
        tloge("open session is failed! result is 0x%x\n", result);
        goto cleanup_0;
    }

    TEEC_SharedMemory shared_mem;
    result = init_opera_and_shared_mem(&context, &shared_mem, &operation, rsp, msg);
    if (result != 0)
        goto cleanup_1;
    result = handle_cmd_id(cmd_id, &shared_mem, msg);
    if (result != 0)
        goto cleanup_2;
    
    result = TEEC_InvokeCommand(&session, cmd_id, &operation, &origin);
    if (result != TEEC_SUCCESS) {
        tloge("invoke cmd 0x%x failed, result = 0x%x, origin = 0x%x\n", cmd_id, result, origin);
        goto cleanup_2;
    }
    if (rsp != NULL) {
        rsp->size = operation.params[1].value.a;
        if (memcpy_s(rsp->buf, rsp->size, (void *)shared_mem.buffer, rsp->size) != EOK) {
            tloge("memcpy buffer failed\n");
            result = TEEC_ERROR_GENERIC;
            goto cleanup_2;
        }
    }
cleanup_2:
    TEEC_ReleaseSharedMemory(&shared_mem);
cleanup_1:
    TEEC_CloseSession(&session);
cleanup_0:
    TEEC_FinalizeContext(&context);
    return result;
}

TEEC_Result RemoteAttestSaveAKCert(struct ra_buffer_data *akcert)
{
    if (akcert == NULL || akcert->buf == NULL || akcert->size == 0 || akcert->size > SAVE_AKCERT_RESERVED_SIZE) {
        tloge("bad input params\n");
        return TEEC_ERROR_BAD_PARAMETERS;
    }
    TEEC_Result result = TEEC_SUCCESS;
    struct ra_buffer_data msg;
    msg.buf = akcert->buf;
    msg.size = akcert->size;

    tlogi("Try to call save AK cert.\n");
    result = handle_cmd(SAVE_AKCERT, &msg, NULL);
    if (result != TEEC_SUCCESS) {
        tloge("Call Save AK Cert Failed, result = 0x%x\n", result);
        return result;
    }
    tlogi("Call Save AK Cert success.\n");

    return result;
}

TEEC_Result RemoteAttestProvision(uint32_t scenario, struct ra_buffer_data *param_set, struct ra_buffer_data *out_data)
{
    if (param_set == NULL || param_set->buf == NULL || out_data == NULL || out_data->size == 0 || 
        out_data->size < PROVISION_RESERVED_SIZE || out_data->size > SHAREMEM_LIMIT) {
        tloge("bad input params or short out data size\n");
        return TEEC_ERROR_BAD_PARAMETERS;
    }
    if (check_provision_scenario_invalid(scenario) == true || check_input_paramset_invalid(param_set) == true) {
        tloge("invalid scenario number or input alg param\n");
        return TEEC_ERROR_BAD_PARAMETERS;
    }
    struct provision_input_params *ra_input = malloc(sizeof(uint32_t) + param_set->size);
    if (ra_input == NULL) {
        tloge("malloc provision input param failed\n");
        return TEEC_ERROR_OUT_OF_MEMORY;
    }
    ra_input->scenario = scenario;
    (void)memcpy_s(&(ra_input->param_count), param_set->size, param_set->buf, param_set->size);

    TEEC_Result ret = TEEC_SUCCESS;
    struct ra_buffer_data msg = {0};
    struct ra_buffer_data rsp;

    msg.buf = (uint8_t *)ra_input;
    msg.size = param_set->size + sizeof(uint32_t);

    rsp.buf = malloc(out_data->size);
    if (rsp.buf == NULL) {
        tloge("malloc out data buffer failed\n");
        ret = TEEC_ERROR_OUT_OF_MEMORY;
        goto cleanup_0;
    }
    rsp.size = out_data->size;
    ret = handle_cmd(INIT_PROVISION, &msg, &rsp);
    if (ret != TEEC_SUCCESS) {
        tloge("Call Provision Failed, ret = 0x%x\n", ret);
        goto cleanup_1;
    }
    /* handle out data buffer and size according to scenario number */
    if (scenario == RA_SCENARIO_NO_AS) {
        out_data->size = 0;
    } else {
        out_data->size = rsp.size;
        (void)memcpy_s(out_data->buf, out_data->size, rsp.buf, rsp.size);
    }
    tlogi("Call Provision success.\n");

cleanup_1:
    free(rsp.buf);
cleanup_0:
    free(ra_input);
    return ret;
}

TEEC_Result RemoteAttestReport(TEEC_UUID ta_uuid, struct ra_buffer_data *usr_data, struct ra_buffer_data *param_set,
    struct ra_buffer_data *report, bool with_tcb)
{
    if (usr_data == NULL || usr_data->buf == NULL || usr_data->size == 0 || usr_data->size > USER_DATA_SIZE ||
        report == NULL || report->buf == NULL || report->size < REPORT_RESERVED_SIZE ||
        report->size > SHAREMEM_LIMIT || with_tcb != false) {
        tloge("bad input params\n");
        return TEEC_ERROR_BAD_PARAMETERS;
    }
    if (check_input_paramset_invalid(param_set) == true) {
        tloge("invalid input alg param\n"); 
        return TEEC_ERROR_BAD_PARAMETERS;
    }
    TEEC_Result result = TEEC_SUCCESS;
    struct ra_buffer_data msg;
    struct ra_buffer_data rsp;
    struct report_input_params *ra_input = malloc(sizeof(struct report_input_params) + param_set->size);
    if (ra_input == NULL) {
        tloge("malloc report input param failed\n");
        return TEEC_ERROR_OUT_OF_MEMORY;
    }
    (void)memset_s(ra_input, sizeof(struct report_input_params), 0, sizeof(struct report_input_params));
    /* init struct report_input_params */
    ra_input->uuid = ta_uuid;
    ra_input->with_tcb = with_tcb;
    (void)memcpy_s(ra_input->user_data, USER_DATA_SIZE, usr_data->buf, usr_data->size);
    ra_input->user_size = usr_data->size;
    (void)memcpy_s(&(ra_input->param_count), param_set->size, param_set->buf, param_set->size);

    msg.buf = (uint8_t *)ra_input;
    msg.size = sizeof(struct report_input_params) + param_set->size;

    rsp.buf = malloc(report->size);
    if (rsp.buf == NULL) {
        tloge("malloc report buffer failed\n");
        result = TEEC_ERROR_OUT_OF_MEMORY;
        goto cleanup_0;
    }
    rsp.size = report->size;
    tlogi("Try to call Attestation Report.\n");

    result = handle_cmd(REQUEST_REPORT, &msg, &rsp);
    if (result != TEEC_SUCCESS) {
        tloge("Call Attestation Report Failed, result = 0x%x\n", result);
        goto cleanup_1;
    }
    report->size = rsp.size;
    (void)memcpy_s(report->buf, report->size, rsp.buf, rsp.size);
    tlogi("Call Attestation Report success, report size = %u\n", report->size);

cleanup_1:
    free(rsp.buf);
cleanup_0:
    free(ra_input);
    return result;
}

