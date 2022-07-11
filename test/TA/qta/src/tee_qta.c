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
#include "tee_qta.h"
#include <tee_log.h>
#include <tee_ext_api.h>
#include "tee_ra_api.h"
#include "securec.h"

TEE_Result TA_CreateEntryPoint(void)
{
    TEE_Result ret;
    /* TA auth CA */
    ret = addcaller_ca_exec("/vendor/bin/ra_client_test", "root");
    if (ret != TEE_SUCCESS)
        return ret;
    ret = AddCaller_TA_all();
    if (ret != TEE_SUCCESS)
        return ret;
    tlogi("tee_qta: CreateEntryPoint success.\n");
    return ret;
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types, TEE_Param params[4], void **session_context)
{
    (void)param_types;
    (void)params;
    (void)session_context;
    tlogi("tee_qta: OpenSessionEntryPoint success.\n");
    return TEE_SUCCESS;
}

static bool check_provision_input_params(struct provision_input_params *ra_input, uint32_t out_size)
{
    if (out_size < PROVISION_RESERVED_SIZE || out_size > SHAREMEM_LIMIT)
        return false;
    if (ra_input->scenario > RA_SCENARIO_AS_NO_DAA)
        return false;
    uint32_t param_count = ra_input->param_count;
    if (param_count > PARAMS_RESERVED_COUNT)
        return false;
    uint32_t param_set_size = param_count * sizeof(struct ra_params) + sizeof(uint32_t);
    if (param_set_size > out_size || param_set_size > SHAREMEM_LIMIT)
        return false;
    return true;
}

static TEE_Result qta_provision(uint32_t param_types, TEE_Param *params)
{
    TEE_Result ret;
    bool check_ret = check_param_type(param_types, TEE_PARAM_TYPE_MEMREF_INOUT,
        TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (!check_ret || params == NULL) {
        tloge("qta provision: qta provision bad params\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t out_size = params[0].memref.size;
    if (params[0].memref.buffer == NULL || out_size == 0 || out_size < sizeof(struct provision_input_params)) {
        tloge("qta provision: invalid memref buffer and size\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    struct provision_input_params *ra_input = (struct provision_input_params *)params[0].memref.buffer;
    if (check_provision_input_params(ra_input, out_size) == false) {
        tloge("qta provision: bad params\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint8_t *output = TEE_Malloc(out_size, 0);
    if (output == NULL) {
        tloge("qta provision: malloc provision buffer failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    struct qsi_provision_params provision_params;
    (void)memset_s(&provision_params, sizeof(provision_params), 0, sizeof(provision_params));
    provision_params.scenario = ra_input->scenario;
    provision_params.param_set_size = ra_input->param_count * sizeof(struct ra_params) + sizeof(uint32_t);
    provision_params.param_set = (uint8_t *)&(ra_input->param_count);
    provision_params.out_data = output;
    provision_params.out_size = out_size;

    tlogi("qta provision: provision begin\n");
    ret = ra_qsi_provision(&provision_params);
    if (ret != TEE_SUCCESS) {
        tloge("qta provision: provision failed, ret 0x%x\n", ret);
        goto clear;
    }
    out_size = provision_params.out_size;
    if (memcpy_s((void *)params[0].memref.buffer, params[0].memref.size, output, out_size) != EOK) {
        tloge("qta provision: copy out data failed\n");
        TEE_Free(output);
        return TEE_ERROR_GENERIC;
    }
    params[1].value.a = out_size;
    tlogi("qta provision: provision end, out size = %u\n", out_size);
clear:
    TEE_Free(output);
    return ret;
}

static bool check_report_input_params(struct report_input_params *ra_input, uint32_t out_size)
{
    if (out_size < REPORT_RESERVED_SIZE || out_size > SHAREMEM_LIMIT)
        return false;
    if (ra_input->user_size > USER_DATA_SIZE || ra_input->user_size == 0)
        return false;
    uint32_t param_count = ra_input->param_count;
    if (param_count > PARAMS_RESERVED_COUNT)
        return false;
    uint32_t param_set_size = param_count * sizeof(struct ra_params) + sizeof(uint32_t);
    if (param_set_size > out_size || param_set_size > SHAREMEM_LIMIT)
        return false;
    return true;
}

static TEE_Result qta_report(uint32_t param_types, TEE_Param *params)
{
    TEE_Result ret;
    bool check_ret = check_param_type(param_types, TEE_PARAM_TYPE_MEMREF_INOUT,
        TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (!check_ret || params == NULL) {
        tloge("qta report: bad params\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t out_size = params[0].memref.size;
    if (params[0].memref.buffer == NULL || out_size == 0 || out_size < sizeof(struct report_input_params)) {
        tloge("qta report: invalid memref buffer and size\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    struct report_input_params *ra_input = (struct report_input_params *)params[0].memref.buffer;
    if (check_report_input_params(ra_input, out_size) == false) {
        tloge("qta report: bad memref size params\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    void *output = (void *)TEE_Malloc(out_size, 0);
    if (output == NULL) {
        tloge("qta report: malloc report buffer failed.\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    struct qsi_report_params ra_params;
    (void)memset_s(&ra_params, sizeof(ra_params), 0, sizeof(ra_params));
    ra_params.uuid = ra_input->uuid;
    ra_params.user_data = ra_input->user_data;
    ra_params.user_size = ra_input->user_size;
    ra_params.report = output;
    ra_params.report_size = out_size;
    ra_params.with_tcb = ra_input->with_tcb;
    ra_params.param_set = (uint8_t *)&(ra_input->param_count);
    ra_params.param_set_size = ra_input->param_count * sizeof(struct ra_params) + sizeof(uint32_t);

    ret = ra_qsi_report(&ra_params);
    if (ret != TEE_SUCCESS) {
        tloge("qta report: ra failed, ret 0x%x\n", ret);
        goto err;
    }
    tlogi("qta report end, msg from qsi length = %u\n", ra_params.report_size);
    out_size = ra_params.report_size;

    if(memcpy_s((void *)params[0].memref.buffer, params[0].memref.size, output, out_size) != EOK) {
        tloge("qta report: memcpy buffer failed\n");
        TEE_Free(output);
        return TEE_ERROR_GENERIC;
    }
    params[1].value.a = out_size;
err:
    TEE_Free(output);
    return ret;
}

static bool check_save_akcert_params(struct qsi_save_akcert_params *akcert_params)
{
    if (akcert_params->buffer == NULL || akcert_params->length == 0 ||
        akcert_params->length > SAVE_AKCERT_RESERVED_SIZE)
        return false;
    return true;
}

static TEE_Result qta_save_akcert(uint32_t param_types, TEE_Param *params)
{
    TEE_Result ret;
    bool check_ret = check_param_type(param_types, TEE_PARAM_TYPE_MEMREF_INOUT,
        TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (!check_ret || params == NULL) {
        tloge("qta save akcert: bad params\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (params[0].memref.buffer == NULL || params[0].memref.size == 0 || params[0].memref.size > SHAREMEM_LIMIT) {
        tloge("qta save akcert: null param memref buffer and size\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint32_t *out_size = &(params[1].value.a);
    struct qsi_save_akcert_params akcert_params;
    (void)memset_s(&akcert_params, sizeof(akcert_params), 0, sizeof(akcert_params));
    akcert_params.buffer = (void *)params[0].memref.buffer;
    akcert_params.length = params[0].memref.size;
    if (check_save_akcert_params(&akcert_params) == false) {
        tloge("qta save akcert: bad akcert params\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    tlogi("qta save akcert: save akcert into tee begin\n");

    ret = ra_qsi_save_akcert(&akcert_params);
    if (ret != TEE_SUCCESS) {
        tloge("qta save akcert: save ak cert failed, ret 0x%x\n", ret);
        return ret;
    }
    *out_size = akcert_params.length;
    tlogi("qta save akcert end\n");
    return TEE_SUCCESS;
}

static bool check_caller_perm(uint32_t cmd_id)
{
    TEE_Result ret;
    caller_info cinfo = { 0 };
    ret = TEE_EXT_GetCallerInfo(&cinfo, sizeof(cinfo));
    if (ret != TEE_SUCCESS)
        return false;
    if (cinfo.session_type == SESSION_FROM_TA) {
        if (cmd_id == CMD_REQUEST_REPORT)
            return true;
        else
            return false;
    }

    return true;
}

TEE_Result TA_InvokeCommandEntryPoint(void *session_context, uint32_t cmd_id,
    uint32_t param_types, TEE_Param params[4])
{
    tlogi("Enter TA_InvokeCommandEntryPoint\n");
    (void)session_context;
    TEE_Result ret;
    bool ckprm_ret = false;

    ckprm_ret = check_caller_perm(cmd_id);
    if (!ckprm_ret) {
        tloge("pls check permission!\n");
        return TEE_ERROR_ACCESS_DENIED;
    }

    tlogi("cmd_id is 0x%x start\n", cmd_id);
    switch (cmd_id) {
    case CMD_INIT_PROVISION:
        ret = qta_provision(param_types, params);
        break;
    case CMD_REQUEST_REPORT:
        ret = qta_report(param_types, params);
        break;
    case CMD_SAVE_AKCERT:
        ret = qta_save_akcert(param_types, params);
        break;
    default:
        ret = TEE_ERROR_INVALID_CMD;
        break;        
    }
    if (ret != TEE_SUCCESS)
        tloge("tee_qta: InvokeCommandEntryPoint failed, cmd: 0x%x, ret: 0x%x\n", cmd_id, ret);
    else
        tlogi("tee_qta: InvokeCommandEntryPoint success\n");
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
