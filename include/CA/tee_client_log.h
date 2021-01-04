/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * iTrustee licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#ifndef TEE_CLIENT_LOG_H
#define TEE_CLIENT_LOG_H

#include <syslog.h>

#ifdef TEEC_DEBUG
#define TEEC_Debug(...) syslog(LOG_USER | LOG_INFO, __VA_ARGS__);
#else
#define TEEC_Debug(...)
#endif

#define TEEC_Error(...) syslog(LOG_USER | LOG_INFO, __VA_ARGS__);

#endif
