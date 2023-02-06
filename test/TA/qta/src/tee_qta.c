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
#include "tee_qta.h"
#include <tee_log.h>
#include <tee_ext_api.h>
#include "tee_ra_api.h"
#include "securec.h"
#include <cJSON.h>

#ifdef ENABLE_DAA_PAIR_MIRACL
#include "daa/validate_akcert.h"
#endif

TEE_Result TA_CreateEntryPoint(void)
{
    TEE_Result ret;
    /* TA auth CA */

    /* TA auth TA */
    ret = AddCaller_TA_all();
    if (ret != TEE_SUCCESS)
        return ret;

    tlogi("tee_qta: CreateEntryPoint success.\n");
    return ret;
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types, TEE_Param params[PARAM_NUM], void **session_context)
{
    (void)param_types;
    (void)params;
    (void)session_context;
    tlogi("tee_qta: OpenSessionEntryPoint success.\n");
    return TEE_SUCCESS;
}

static bool check_akcert_params_valid(struct ra_buffer_data *akcert)
{
    bool result = false;
    if (akcert == NULL || akcert->buffer == NULL || akcert->length == 0 || akcert->length > SHAREMEM_LIMIT) {
        tloge("akcert params is invalid\n");
        return result;
    }

    char *akcert_buf = REINTERPRET_CAST(char *, uint8_t *, akcert->buffer);
    cJSON *json = cJSON_Parse(akcert_buf);
    if (json == NULL) {
        tloge("check akcert json failed\n");
        return result;
    }

    char *handler = cJSON_GetStringValue(cJSON_GetObjectItem(json, "handler"));
    if (handler == NULL || strcmp(handler, "saveakcert-output") != 0) {
        tloge("check akcert handler failed\n");
        goto clear;
    }

    cJSON *payload = cJSON_GetObjectItem(json, "payload");
    if (payload == NULL) {
        tloge("check akcert payload failed\n");
        goto clear;
    }

    char *version = cJSON_GetStringValue(cJSON_GetObjectItem(payload, "version"));
    if (version == NULL || strcmp(version, "TEE.RA.1.0") != 0) {
        tloge("check akcert version failed\n");
        goto clear;
    }

    char *scenario = cJSON_GetStringValue(cJSON_GetObjectItem(payload, "scenario"));
    if (scenario == NULL || strcmp(scenario, "sce_as_with_daa") != 0) {
        tloge("check akcert scenario failed\n");
        goto clear;
    }
#ifdef ENABLE_DAA_PAIR_MIRACL
    char *hex_akcert = cJSON_GetStringValue(cJSON_GetObjectItem(payload, "hex_akcert"));
    if (validate_akcert(hex_akcert, strlen(hex_akcert)) != TEE_SUCCESS) {
        tloge("check akcert using pairing failed\n");
        goto clear;
    }
#endif
    result = true;
clear:
    cJSON_Delete(json);
    return result;
}

static TEE_Result qta_validate_akcert(struct ra_buffer_data *akcert)
{
    TEE_Result result = TEE_ERROR_GENERIC;
    if (!check_akcert_params_valid(akcert)) {
        tloge("qta validate akcert: check params invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    char *akcert_buf = REINTERPRET_CAST(char *, uint8_t *, akcert->buffer);
    cJSON *json = cJSON_Parse(akcert_buf);
    cJSON *handler = cJSON_CreateString("validateakcert-input");
    if (handler == NULL) {
        tloge("qta validate akcert: handler is null\n");
        goto clear1;
    }
    if (!cJSON_ReplaceItemInObject(json, "handler", handler)) {
        tloge("qta validate akcert: replace handler in json failed\n");
        cJSON_Delete(handler);
        goto clear1;
    }

    char *json_buf = cJSON_Print(json);
    if (json_buf == NULL) {
        tloge("json buf is null");
        goto clear1;
    }

    if (strlen(json_buf) > IN_RESERVED_SIZE) {
        tloge("qta validate akcert: json size is invalid\n");
        result = TEE_ERROR_BAD_PARAMETERS;
        goto clear2;
    }

    uint32_t in_size = strlen(json_buf);
    uint8_t *in_buf = REINTERPRET_CAST(uint8_t *, char *, json_buf);
    struct ra_buffer_data in = {in_size, in_buf};
    result = ra_qsi_invoke(&in, NULL);
    if (result != TEE_SUCCESS)
        tloge("qta validate akcert failed\n");
clear2:
    cJSON_free(json_buf);
clear1:
    cJSON_Delete(json);
    return result;
}

static TEE_Result local_attest(struct ra_buffer_data *in, struct ra_buffer_data *out)
{
    TEE_Result result;
    char *buf = REINTERPRET_CAST(char *, uint8_t *, in->buffer);
    cJSON *json = cJSON_Parse(buf);
    if (json == NULL) {
        tloge("check local attest json failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    char *handler = cJSON_GetStringValue(cJSON_GetObjectItem(json, "handler"));
    if (handler == NULL) {
        tloge("handler is null\n");
        result = TEE_ERROR_BAD_PARAMETERS;
        goto clear;
    }
    if (strcmp(handler, "report-input") != 0) {
        tloge("check local attest handler failed\n");
        result = TEE_ERROR_BAD_PARAMETERS;
        goto clear;
    }
    result = ra_qsi_invoke(in, out);
clear:
    cJSON_Delete(json);
    return result;
}

static TEE_Result qta_local_attest(uint32_t param_types, TEE_Param *params)
{
    bool ret = check_param_type(param_types, TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE);
    if (!ret || params == NULL) {
        tloge("qta local attest: bad params\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (params[0].memref.buffer == NULL || params[0].memref.size == 0 ||
        params[0].memref.size > IN_RESERVED_SIZE || params[1].memref.buffer == NULL ||
        params[1].memref.size < OUT_RESERVED_SIZE || params[1].memref.size > SHAREMEM_LIMIT) {
        tloge("qta local attest: invalid memref info\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    struct ra_buffer_data in;
    struct ra_buffer_data out;
    in.buffer = params[0].memref.buffer;
    in.length = params[0].memref.size;
    out.buffer = params[1].memref.buffer;
    out.length = params[1].memref.size;

    TEE_Result result = local_attest(&in, &out);
    if (result != TEE_SUCCESS) {
        tloge("local attest failed\n");
        return result;
    }
    params[PARAM_TWO].value.a = out.length;
    return result;
}

static TEE_Result qta_remote_attest(uint32_t param_types, TEE_Param *params)
{
    bool ret = check_param_type(param_types, TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE);
    if (!ret || params == NULL) {
        tloge("qta remote attest: bad params\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (params[0].memref.buffer == NULL || params[0].memref.size == 0 ||
        params[0].memref.size > IN_RESERVED_SIZE || params[1].memref.size > SHAREMEM_LIMIT ||
        (params[1].memref.buffer != NULL && params[1].memref.size < OUT_RESERVED_SIZE) ||
        (params[1].memref.buffer == NULL && params[1].memref.size > 0)) {
        tloge("qta remote attest: invalid memref info\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    struct ra_buffer_data in;
    struct ra_buffer_data out;
    in.buffer = params[0].memref.buffer;
    in.length = params[0].memref.size;
    out.buffer = params[1].memref.buffer;
    out.length = params[1].memref.size;
    TEE_Result result = ra_qsi_invoke(&in, &out);
    if (result == TEE_PENDING) {
        return qta_validate_akcert(&out);
    } else if (result == TEE_SUCCESS) {
        params[PARAM_TWO].value.a = out.length;
        return result;
    }
    tloge("ra qsi invoke failed\n");
    return result;
}

TEE_Result TA_InvokeCommandEntryPoint(void *session_context, uint32_t cmd_id,
    uint32_t param_types, TEE_Param params[PARAM_NUM])
{
    tlogi("tee_qta: Enter TA_InvokeCommandEntryPoint.\n");
    (void)session_context;
    if (cmd_id != REMOTE_ATTEST_CMD) {
        tloge("tee_qta: InvokeCommandEntryPoint failed, cmd: 0x%x.\n", cmd_id);
        return TEE_ERROR_INVALID_CMD;
    }

    caller_info cinfo;
    (void)memset_s(&cinfo, sizeof(cinfo), 0, sizeof(cinfo));
    TEE_Result ret = TEE_EXT_GetCallerInfo(&cinfo, sizeof(cinfo));
    if (ret != TEE_SUCCESS) {
        tloge("tee_qta: Get call info failed.\n");
        return ret;
    }
    if (cinfo.session_type == SESSION_FROM_TA) {
        ret = qta_local_attest(param_types, params);
        if (ret != TEE_SUCCESS)
            tloge("tee_qta: local attest failed, cmd: 0x%x, ret: 0x%x.\n", cmd_id, ret);
        else
            tlogi("tee_qta: InvokeCommandEntryPoint success.\n");
        return ret;
    }

    ret = qta_remote_attest(param_types, params);
    if (ret != TEE_SUCCESS)
        tloge("tee_qta: remote attest failed, cmd: 0x%x, ret: 0x%x.\n", cmd_id, ret);
    else
        tlogi("tee_qta: InvokeCommandEntryPoint success.\n");
    return ret;
}

void TA_CloseSessionEntryPoint(void *session_context)
{
    (void)session_context;
    tlogi("tee_qta: CloseSessionEntryPoint success.\n");
}

void TA_DestroyEntryPoint(void)
{
    tlogi("tee_qta: DestroyEntryPoint success.\n");
}
