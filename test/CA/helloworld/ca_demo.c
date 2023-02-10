/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Description: C file template for CA
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include "tee_client_api.h"

#define VERSION_BUFFER_SIZE 256
#define OPERATION_START_FLAG 1
#define OUT_BUFF_INDEX 3

static const TEEC_UUID g_demoTemplateUuid = {
    0xe3d37f4a, 0xf24c, 0x48d0, { 0x88, 0x84, 0x3b, 0xdd, 0x6c, 0x44, 0xe9, 0x88 }
};

enum {
    CMD_GET_TA_VERSION = 1,
};

int main(void)
{
    TEEC_Context context = {0};
    TEEC_Session session = {0};
    TEEC_Result result;
    TEEC_Operation operation = {0};
    uint32_t origin = 0;

    char versionBuf[VERSION_BUFFER_SIZE] = {0};
    unsigned int bufLen = VERSION_BUFFER_SIZE;

    result = TEEC_InitializeContext(NULL, &context);
    if (result != TEEC_SUCCESS) {
        printf("teec initial failed");
        goto cleanup_1;
    }

    /* MUST use TEEC_LOGIN_IDENTIFY method */
    operation.started = OPERATION_START_FLAG;
    operation.paramTypes = TEEC_PARAM_TYPES(
        TEEC_NONE,
        TEEC_NONE,
        TEEC_NONE,
        TEEC_NONE);

    result = TEEC_OpenSession(
        &context, &session, &g_demoTemplateUuid, TEEC_LOGIN_IDENTIFY, NULL, &operation, &origin);
    if (result != TEEC_SUCCESS) {
        printf("teec open session failed");
        goto cleanup_2;
    }

    operation.started = OPERATION_START_FLAG;
    operation.paramTypes = TEEC_PARAM_TYPES(
        TEEC_NONE,
        TEEC_NONE,
        TEEC_NONE,
        TEEC_MEMREF_TEMP_OUTPUT);
    operation.params[OUT_BUFF_INDEX].tmpref.buffer = versionBuf;
    operation.params[OUT_BUFF_INDEX].tmpref.size = bufLen;

    result = TEEC_InvokeCommand(&session, CMD_GET_TA_VERSION, &operation, &origin);
    if (result != TEEC_SUCCESS) {
        printf("invoke failed, codes=0x%x, origin=0x%x", result, origin);
    } else {
        printf("Succeed to load TA, TA's version: %s.\n", versionBuf);
    }

    TEEC_CloseSession(&session);
cleanup_2:
    TEEC_FinalizeContext(&context);
cleanup_1:
    return 0;
}
