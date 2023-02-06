/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2023. All rights reserved.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Description: TA template code for reference
 */

#include <tee_ext_api.h>
#include <tee_log.h>
#include <securec.h>

#define TA_TEMPLATE_VERSION "demo_20200601"
#define PARAM_COUNT      4
#define OUT_BUFFER_INDEX 3

enum {
    CMD_GET_TA_VERSION = 1,
};

static TEE_Result get_ta_version(char* buffer, size_t *buf_len)
{
    const char *version = TA_TEMPLATE_VERSION;

    if (*buf_len < strlen(version) + 1) {
        tloge("buffer is too short for storing result");
        *buf_len = strlen(version) + 1;
        return TEE_ERROR_SHORT_BUFFER;
    }

    errno_t err = strncpy_s(buffer, *buf_len, version, strlen(version) + 1);
    if (err != EOK)
        return TEE_ERROR_SECURITY;

    *buf_len = strlen(version) + 1;

    return TEE_SUCCESS;
}

/**
 * Function TA_CreateEntryPoint
 * Description:
 *   The function TA_CreateEntryPoint is the Trusted Application's constructor,
 *   which the Framework calls when it creates a new instance of this Trusted Application.
 */
TEE_Result TA_CreateEntryPoint(void)
{
    TEE_Result ret;

    tlogd("----- TA entry point ----- ");
    tlogd("TA version: %s", TA_TEMPLATE_VERSION);

    ret = addcaller_ca_exec("/vendor/bin/demo_hello", "root");
    if (ret == TEE_SUCCESS) {
        tlogd("TA entry point: add ca whitelist success");
    } else {
        tloge("TA entry point: add ca whitelist failed");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

/**
 * Function TA_OpenSessionEntryPoint
 * Description:
 *   The Framework calls the function TA_OpenSessionEntryPoint
 *   when a client requests to open a session with the Trusted Application.
 *   The open session request may result in a new Trusted Application instance
 *   being created.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t parm_type,
    TEE_Param params[PARAM_COUNT], void** session_context)
{
    (void)parm_type;
    (void)params;
    (void)session_context;
    tlogd("---- TA open session -------- ");

    return TEE_SUCCESS;
}

/**
 * Function TA_InvokeCommandEntryPoint:
 * Description:
 *   The Framework calls this function when the client invokes a command
 *   within the given session.
 */
TEE_Result TA_InvokeCommandEntryPoint(void* session_context, uint32_t cmd,
    uint32_t parm_type, TEE_Param params[PARAM_COUNT])
{
    TEE_Result ret;
    (void)session_context;

    tlogd("---- TA invoke command ----------- ");
    switch (cmd) {
    case CMD_GET_TA_VERSION:
        if (!check_param_type(parm_type,
            TEE_PARAM_TYPE_NONE,
            TEE_PARAM_TYPE_NONE,
            TEE_PARAM_TYPE_NONE,
            TEE_PARAM_TYPE_MEMREF_OUTPUT)) {
            tloge("Bad expected parameter types");
            return TEE_ERROR_BAD_PARAMETERS;
        }
        if (params[OUT_BUFFER_INDEX].memref.buffer == NULL ||
            params[OUT_BUFFER_INDEX].memref.size == 0) {
            tloge("InvokeCommand with bad, cmd is %u", cmd);
            return TEE_ERROR_BAD_PARAMETERS;
        }
        ret = get_ta_version(params[OUT_BUFFER_INDEX].memref.buffer, &params[OUT_BUFFER_INDEX].memref.size);
        if (ret != TEE_SUCCESS) {
            tloge("InvokeCommand Failed 0x%x. cmd is %u", ret, cmd);
            return ret;
        }
        break;
    default:
        tloge("Unknown cmd is %u", cmd);
        ret = TEE_ERROR_BAD_PARAMETERS;
    }

    return  ret;
}

/**
 * Function TA_CloseSessionEntryPoint:
 * Description:
 *   The Framework calls this function to close a client session.
 *   During the call to this function the implementation can use
 *   any session functions.
 */
void TA_CloseSessionEntryPoint(void* session_context)
{
    (void)session_context;
    tlogd("---- close session ----- ");
}

/**
 * Function TA_DestroyEntryPoint
 * Description:
 *   The function TA_DestroyEntryPoint is the Trusted Application's destructor,
 *   which the Framework calls when the instance is being destroyed.
 */
void TA_DestroyEntryPoint(void)
{
    tlogd("---- destroy TA ---- ");
}
