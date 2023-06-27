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
#include "tee_qta.h"
#include <tee_log.h>
#include <tee_ext_api.h>
#include "tee_ra_api.h"
#include "securec.h"
#include <cJSON.h>
#ifdef CONFIG_HOST_QTA
#include "container_info.h"
#endif
#if defined(CONFIG_QTA_REPORT) || defined (CONFIG_HOST_QTA)
#include "container_verify.h"
#endif
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

static cJSON *parse(uint8_t *buffer, uint32_t length)
{
    char *buf = REINTERPRET_CAST(char *, uint8_t *, buffer);
    char *json_buffer = TEE_Malloc(length + 1, 0);
    if (json_buffer == NULL) {
        tloge("malloc buffer failed\n");
        return NULL;
    }
    (void)memcpy_s(json_buffer, length, buf, length);
    cJSON *json = cJSON_Parse(json_buffer);
    if (json == NULL)
        tloge("check akcert json failed\n");

    TEE_Free(json_buffer);
    return json;
}

static bool check_akcert_params_valid(struct ra_buffer_data *akcert)
{
    bool result = false;
    if (akcert == NULL || akcert->buffer == NULL || akcert->length == 0 || akcert->length > SHAREMEM_LIMIT) {
        tloge("akcert params is invalid\n");
        return result;
    }

    cJSON *json = parse(akcert->buffer, akcert->length);
    if (json == NULL) {
        tloge("json parse failed\n");
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

static bool is_report_request(cJSON *json)
{
    char *handler = cJSON_GetStringValue(cJSON_GetObjectItem(json, "handler"));
    if (handler == NULL) {
        tloge("in handler is null\n");
        return false;
    }
    if (strcmp(handler, "report-input") != 0)
        return false;
    return true;
}

static TEE_Result insert_request_uuid(cJSON *json, char *uuid)
{
    cJSON *payload = cJSON_GetObjectItem(json, "payload");
    if (payload == NULL) {
        tloge("payload is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (cJSON_AddStringToObject(payload, "requester_uuid", uuid) == NULL) {
        tloge("insert requester uuid failed\n");
        return TEE_ERROR_GENERIC;
    }
    return TEE_SUCCESS;
}

static TEE_Result qta_validate_akcert(struct ra_buffer_data *akcert)
{
    TEE_Result result = TEE_ERROR_GENERIC;
    if (!check_akcert_params_valid(akcert)) {
        tloge("qta validate akcert: check params invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    cJSON *json = parse(akcert->buffer, akcert->length);
    if (json == NULL) {
        tloge("qta validate akcert: json parse failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

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

#define UUID_STR_FORMAT_LEN   37
static TEE_Result get_uuid_str(const TEE_UUID *uuid, char *buff, uint32_t len)
{
    if (uuid == NULL || buff == NULL || len < UUID_STR_FORMAT_LEN) {
        tloge("invalid input parameter\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    int ret = snprintf_s(buff, len, UUID_STR_FORMAT_LEN - 1, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        uuid->timeLow, uuid->timeMid, uuid->timeHiAndVersion, uuid->clockSeqAndNode[0],
        uuid->clockSeqAndNode[1], uuid->clockSeqAndNode[2], uuid->clockSeqAndNode[3],
        uuid->clockSeqAndNode[4], uuid->clockSeqAndNode[5], uuid->clockSeqAndNode[6],
        uuid->clockSeqAndNode[7]);
    if (ret <= 0) {
        tloge("convert uuid to string failed\n");
        return TEE_ERROR_GENERIC;
    }
    return TEE_SUCCESS;
}

static TEE_Result local_attest(struct ra_buffer_data *in, struct ra_buffer_data *out, const TEE_UUID *uuid)
{
    TEE_Result result;
    cJSON *json = parse(in->buffer, in->length);
    if (json == NULL) {
        tloge("check local attest json failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (!is_report_request(json)) {
        tloge("check report request failed\n");
        result = TEE_ERROR_BAD_PARAMETERS;
        goto clear1;
    }

    char str_uuid[UUID_STR_FORMAT_LEN] = { 0 };
    result = get_uuid_str(uuid, str_uuid, UUID_STR_FORMAT_LEN);
    if (result != TEE_SUCCESS) {
        tloge("get uuid str failed\n");
        goto clear1;
    }

    result = insert_request_uuid(json, str_uuid);
    if (result != TEE_SUCCESS) {
        tloge("insert request uuid failed\n");
        goto clear1;
    }

    char *json_buf = cJSON_Print(json);
    if (json_buf == NULL) {
        tloge("json buf is null\n");
        result = TEE_ERROR_GENERIC;
        goto clear1;
    }

    if (strlen(json_buf) > IN_RESERVED_SIZE) {
        tloge("json size is invalid\n");
        result = TEE_ERROR_GENERIC;
        goto clear2;
    }

    in->length = strlen(json_buf);
    in->buffer = REINTERPRET_CAST(uint8_t *, char *, json_buf);
    result = ra_qsi_invoke(in, out);
clear2:
    cJSON_free(json_buf);
clear1:
    cJSON_Delete(json);
    return result;
}

static TEE_Result qta_local_attest(uint32_t param_types, TEE_Param *params, const TEE_UUID *uuid)
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

    TEE_Result result = local_attest(&in, &out, uuid);
    if (result != TEE_SUCCESS) {
        tloge("local attest failed\n");
        return result;
    }
    params[PARAM_TWO].value.a = out.length;
    return result;
}

#ifdef CONFIG_QTA_REPORT
static TEE_Result verify_container_info(cJSON *json)
{
    cJSON *payload = cJSON_GetObjectItem(json, "payload");
    if (payload == NULL) {
        tloge("verify container info: get payload failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    cJSON *info = cJSON_GetObjectItem(payload, "container_info");
    if (info == NULL) {
        tloge("verify container info: get container_info failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    char *id = cJSON_GetStringValue(cJSON_GetObjectItem(info, "id"));
    if (id == NULL) {
        tloge("verify container info: get id failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint32_t nsid = 0;
    TEE_Result ret = tee_ext_get_nsid(&nsid);
    if (ret != TEE_SUCCESS) {
        tloge("verify container info: get nsid failed\n");
        return ret;
    }
    ret = call_qta_verify_container(id, nsid);
    if (ret != TEE_SUCCESS)
        tloge("verify container info failed, 0x%x\n", ret);
    return ret;
}
#endif

static TEE_Result remote_attest(struct ra_buffer_data *in, struct ra_buffer_data *out, uint32_t *value)
{
    TEE_Result result;
    cJSON *json = parse(in->buffer, in->length);
    if (json == NULL) {
        tloge("check in json failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (is_report_request(json)) {
    #ifdef CONFIG_QTA_REPORT
        result = verify_container_info(json);
        if (result != TEE_SUCCESS) {
            tloge("verify container info failed\n");
            goto clear;
        }
    #endif
        result = insert_request_uuid(json, "");
        if (result != TEE_SUCCESS) {
            tloge("insert request uuid failed\n");
            goto clear;
        }
        char *json_buf = cJSON_Print(json);
        if (json_buf == NULL) {
            tloge("json buf is null\n");
            result = TEE_ERROR_GENERIC;
            goto clear;
        }

        if (strlen(json_buf) > IN_RESERVED_SIZE) {
            tloge("json size is invalid\n");
            result = TEE_ERROR_GENERIC;
            cJSON_free(json_buf);
            goto clear;
        }

        in->length = strlen(json_buf);
        in->buffer = REINTERPRET_CAST(uint8_t *, char *, json_buf);
        result = ra_qsi_invoke(in, out);
        if (result == TEE_SUCCESS)
            *value = out->length;
        cJSON_free(json_buf);
    } else {
        result = ra_qsi_invoke(in, out);
        if (result == TEE_PENDING) {
            result = qta_validate_akcert(out);
        } else if (result == TEE_SUCCESS) {
            *value = out->length;
        }
    }
clear:
    cJSON_Delete(json);
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

    TEE_Result result = remote_attest(&in, &out, &params[PARAM_TWO].value.a);
    if (result != TEE_SUCCESS)
        tloge("qta remote attest: ra qsi invoke failed\n");
    return result;
}

#ifdef CONFIG_HOST_QTA
static TEE_Result handle_container_info(uint32_t cmd_id, uint32_t param_types,
    TEE_Param *params)
{
    (void)cmd_id;
    TEE_Result ret = TEE_ERROR_GENERIC;
    if (init_container_list() != TEE_SUCCESS)
        return ret;
    bool check = check_param_type(param_types, TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (!check || params == NULL) {
        tloge("qta container info: check param type failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (params[0].memref.buffer == NULL || params[0].memref.size == 0 ||
        params[0].memref.size > IN_RESERVED_SIZE) {
        tloge("qta container info: check params failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    cJSON *input = parse(params[0].memref.buffer, params[0].memref.size);
    if (input == NULL) {
        tloge("qta container info: parse failed\n");
        return TEE_ERROR_GENERIC;
    }
    char *id = cJSON_GetStringValue(cJSON_GetObjectItem(input, "container_id"));
    if (id == NULL) {
        tloge("qta container info: get id failed\n");
        goto clean;
    }

    /* register */
    cJSON *json_nsid = cJSON_GetObjectItem(input, "nsid");
    if (json_nsid == NULL) {
        tloge("qta container info: get nsid failed\n");
        goto clean;
    }
    uint32_t nsid = cJSON_GetNumberValue(json_nsid);
    ret = register_container(id, nsid);
clean:
    cJSON_Delete(input);
    if (ret != TEE_SUCCESS)
        tloge("qta container info: handle cmd 0x%x failed\n", cmd_id);
    return ret;
}
#endif

static TEE_Result handle_remote_attest(uint32_t cmd_id, uint32_t param_types, TEE_Param *params)
{
    caller_info cinfo;
    (void)memset_s(&cinfo, sizeof(cinfo), 0, sizeof(cinfo));
    TEE_Result ret = TEE_EXT_GetCallerInfo(&cinfo, sizeof(cinfo));
    if (ret != TEE_SUCCESS) {
        tloge("tee_qta: Get call info failed.\n");
        return ret;
    }
    if (cinfo.session_type == SESSION_FROM_TA) {
        ret = qta_local_attest(param_types, params, &(cinfo.caller_identity.caller_uuid));
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

TEE_Result TA_InvokeCommandEntryPoint(void *session_context, uint32_t cmd_id,
    uint32_t param_types, TEE_Param params[PARAM_NUM])
{
    tlogi("tee_qta: Enter TA_InvokeCommandEntryPoint.\n");
    (void)session_context;
    TEE_Result ret = TEE_ERROR_GENERIC;
    switch (cmd_id) {
    case REMOTE_ATTEST_CMD:
        ret = handle_remote_attest(cmd_id, param_types, params);
        break;
#ifdef CONFIG_HOST_QTA
    case REGISTER_CONTAINER_CMD:
        ret = handle_container_info(cmd_id, param_types, params);
        break;
    case VERIFY_CONTAINER_CMD:
        ret = handle_container_verify(param_types, params);
        break;
#endif
    default:
        tloge("tee_qta: invalid cmd 0x%x\n", cmd_id);
    }
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
