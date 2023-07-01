/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */
#include "container_verify.h"
#include <stdint.h>
#include <securec.h>
#include <tee_log.h>
#include "tee_qta.h"
#include <tee_core_api.h>
#ifndef CONFIG_QTA_REPORT
#include <tee_ext_api.h>
#include "container_info.h"
#endif

#define PARAM_NUM 4

#ifdef CONFIG_QTA_REPORT
#define TEE_QTA_UUID                                       \
    {                                                      \
        0xe08f7eca, 0xe875, 0x440e,                        \
        {                                                  \
            0x9a, 0xb0, 0x5f, 0x38, 0x11, 0x36, 0xc6, 0x00 \
        }                                                  \
    }
#else
#define TEE_QTA_REPORT_UUID                                \
    {                                                      \
        0x4f84c0e0, 0x4c3f, 0x422f,                        \
        {                                                  \
            0x97, 0xdc, 0x14, 0xbf, 0xa2, 0x31, 0x4a, 0xd1 \
        }                                                  \
    }
#endif

TEE_Result check_container_id(const char container_id[])
{
    if (container_id == NULL || strnlen(container_id, CONTAINER_ID_STR_LEN + 1) != CONTAINER_ID_STR_LEN) {
        tloge("check container id failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

#ifdef CONFIG_QTA_REPORT
TEE_Result call_qta_verify_container(const char *id, uint32_t nsid)
{
    if (check_container_id(id) != TEE_SUCCESS || nsid == 0) {
        tloge("verify container: check input failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    TEE_TASessionHandle session;
    TEE_Param params[PARAM_NUM];
    TEE_UUID uuid = TEE_QTA_UUID;
    char container_id[CONTAINER_ID_STR_LEN + 1] = {0};
    errno_t rc = strcpy_s(container_id, sizeof(container_id), id);
    if (rc != EOK) {
        tloge("verify container: strcpy failed, %d\n", rc);
        return TEE_ERROR_GENERIC;
    }
    (void)memset_s(params, PARAM_NUM * sizeof(TEE_Param), 0, PARAM_NUM * sizeof(TEE_Param));
    uint32_t param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    TEE_Result ret = TEE_OpenTASession(&uuid, 0, param_types, params, &session, NULL);
    if (ret != TEE_SUCCESS) {
        tloge("verify container: failed to OpenTASession, ret is 0x%x\n", ret);
        return ret;
    }

    param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    params[0].memref.buffer = container_id;
    params[0].memref.size = sizeof(container_id);
    params[1].value.a = nsid;

    ret = TEE_InvokeTACommand(session, 0, VERIFY_CONTAINER_CMD, param_types, params, NULL);
    if (ret != TEE_SUCCESS)
        tloge("verify container: invoke cmd failed, ret is 0x%x\n", ret);
    TEE_CloseTASession(session);
    return ret;
}
#else
TEE_Result handle_container_verify(uint32_t param_types, TEE_Param *params)
{
    caller_info cinfo;
    TEE_UUID uuid = TEE_QTA_REPORT_UUID;
    (void)memset_s(&cinfo, sizeof(cinfo), 0, sizeof(cinfo));
    if (init_container_list() != TEE_SUCCESS)
        return TEE_ERROR_GENERIC;

    TEE_Result ret = TEE_EXT_GetCallerInfo(&cinfo, sizeof(cinfo));
    if (ret != TEE_SUCCESS) {
        tloge("verify container get caller info failed.\n");
        return ret;
    }
    if (cinfo.session_type != SESSION_FROM_TA || cinfo.caller_identity.group_id == 0 ||
        TEE_MemCompare(&cinfo.caller_identity.caller_uuid, &uuid, sizeof(uuid)) != 0) {
        tloge("verify container check caller failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    bool param_ret = check_param_type(param_types, TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (!param_ret || params == NULL) {
        tloge("verify container check param type failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (params[0].memref.buffer == NULL || params[0].memref.size == 0 ||
        params[0].memref.size > IN_RESERVED_SIZE || params[1].value.a == 0) {
        tloge("verify container check params failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t tmp_nsid = 0;
    ret = get_nsid_by_container_id(params[0].memref.buffer, &tmp_nsid);
    if (ret != TEE_SUCCESS) {
        tloge("verify container get nsid failed\n");
        return ret;
    }
    if (tmp_nsid == params[1].value.a)
        return TEE_SUCCESS;
    tloge("verify container failed\n");
    return TEE_ERROR_GENERIC;
}
#endif
