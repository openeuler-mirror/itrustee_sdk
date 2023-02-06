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
 * Description: soft device key engine
 */
#ifndef __CRYPTO_DEVICE_KEY_WRAPPER_H__
#define __CRYPTO_DEVICE_KEY_WRAPPER_H__

#include <stdint.h>
#include <tee_defines.h>

/*
 * Get oem huk.
 *
 * @param huk      [OUT] The oem huk buffer
 * @param key      [IN]  The hmac key buffer
 * @param key_size [IN]  The length of hmac key buffer
 *
 * @return  0: Get oem huk success
 * @return -1: Get oem huk failed
 */
int32_t get_class_oem_huk(uint8_t *huk, const uint8_t *key, uint32_t key_size);

#endif
