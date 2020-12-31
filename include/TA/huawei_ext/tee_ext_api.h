/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * iTrustee licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#ifndef TEE_EXT_API_H
#define TEE_EXT_API_H

#include "tee_defines.h"
#include "tee_core_api.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cpluscplus */
#endif /* __cpluscplus */

/*
 * below definitions are defined by Platform SDK released previously
 * for compatibility:
 * don't make any change to the content below
 */
#define TEE_INFO_RESERVED       0xFFFFFFFF
#define TEE_RETURN_AGENT_BUFFER 0x99
#define TEE_INVALID_AGENT       0x66
#define TEE_AGENT_LOCK          0x33

#define TEE_GET_REEINFO_SUCCESS 0
#define TEE_GET_REEINFO_FAILED  1

#define RESERVED_BUF_SIZE 32
typedef struct __caller_info {
    uint32_t session_type;
    union {
        TEE_UUID caller_uuid;
        uint8_t ca_info[RESERVED_BUF_SIZE];
    } caller_identity;
    uint8_t reserved[RESERVED_BUF_SIZE];
} caller_info;

/*
 * Get caller info of current session, refer caller_info struct for more details
 *
 * @param caller_info_data [OUT] caller info to be returned
 * @param length           [IN] sizeof struct caller_info
 *
 * return TEE_SUCCESS operation success
 * return others failed to get caller info
 */
TEE_Result TEE_EXT_GetCallerInfo(caller_info *caller_info_data, uint32_t length);

/*
 * verify TA's caller's identify
 * TA can call this API to add caller's info,
 * which is allowed to call this TA.
 * this API is for CA in form of JAR or binary-excuteble file.
 *
 * @param ca_name       [IN]        CA caller's process name
 * @param user_name     [IN]        CA caller's username
 *
 * return TEE_SUCCESS operation
 * return others failed to add caller info for target CA
 */
TEE_Result addcaller_ca_exec(const char *ca_name, const char *user_name);

/*
 * TA call this API allow others TA open session with itself
 *
 * return TEE_SUCCESS operation success
 * result others operation failed
 */
TEE_Result AddCaller_TA_all(void);

#define SESSION_FROM_CA      0
#define SESSION_FROM_TA      1
#define SESSION_FROM_UNKNOWN 0xFF
/*
 * get cruurent session type
 *
 * @return session type of current session
 */
uint32_t TEE_GetSessionType(void);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cpluscplus */
#endif /* __cpluscplus */

#endif
