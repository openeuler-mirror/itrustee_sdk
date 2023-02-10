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
#ifndef LIBQCA_RA_LOG_H
#define LIBQCA_RA_LOG_H

#define TAG_WARN "[warn]"
#define TAG_INFO "[info]"
#define TAG_ERROR "[error]"
#define TAG_DEBUG "[debug]"

#define LIBQCA_PREFIX "libqca"

#define tloge(fmt, args...) printf("[%s] %s %d:" fmt " ", LIBQCA_PREFIX, TAG_ERROR, __LINE__, ##args)
#define tlogd(fmt, args...) printf("[%s] %s %d:" fmt " ", LIBQCA_PREFIX, TAG_DEBUG, __LINE__, ##args)
#define tlogi(fmt, args...) printf("[%s] %s %d:" fmt " ", LIBQCA_PREFIX, TAG_INFO, __LINE__, ##args)
#define tlogw(fmt, args...) printf("[%s] %s %d:" fmt " ", LIBQCA_PREFIX, TAG_WARN, __LINE__, ##args)

#endif
