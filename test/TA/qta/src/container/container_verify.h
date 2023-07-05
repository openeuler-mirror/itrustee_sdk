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
#ifndef QTA_CONTAINER_VERIFY_H
#define QTA_CONTAINER_VERIFY_H

#include <tee_defines.h>
#define CONTAINER_ID_STR_LEN 64

TEE_Result check_container_id(const char container_id[]);
#ifdef CONFIG_QTA_REPORT
TEE_Result call_qta_verify_container(const char *id, uint32_t nsid);
#else
TEE_Result handle_container_verify(uint32_t param_types, TEE_Param *params);
#endif
#endif
