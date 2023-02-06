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
#include "daa_structure.h"

#include <securec.h>
#include <errno.h>
#include <tee_defines.h>
#include <tee_log.h>
#include <tee_ext_api.h>
#include <tee_core_api.h>

#define HEX_STR_SIZE_PER_CHAR       2
#define BIT_4                       4
#define BYTE_HIGH_BIT_4             0xF0
#define BYTE_LOW_BIT_4              0xF
#define BYTE_CONVERT_ERROR          0xFF
#define is_between_value(value, min, max)  (((value) >= (min)) && ((value) <= (max)))
#define cal_char_value(value, min, inc)    ((value) - (min) + (inc))
static uint8_t hex2ch(uint8_t c)
{
    if (is_between_value(c, '0', '9')) {
        return cal_char_value(c, '0', 0);
    } else if (is_between_value(c, 'a', 'f')) {
        return cal_char_value(c, 'a', 10);
    } else if (is_between_value(c, 'A', 'F')) {
        return cal_char_value(c, 'A', 10);
    } else {
        tloge("hex2ch: Error! Input is not a hex value!");
        return BYTE_CONVERT_ERROR;
    }
}

void free_daa_grp_pubkey(struct daa_grp_pubkey *pubkey)
{
    if (pubkey == NULL || pubkey->pt_size == 0 || pubkey->pt_size > DAA_ECC_PT_MAX_SIZE)
        return;
    for (uint32_t i = 0; i < DAA_GRP_PUBKEY_DIMS; i++) {
        if (pubkey->pt_buf[i]) {
            free(pubkey->pt_buf[i]);
            pubkey->pt_buf[i] = NULL;
        }
    }
    pubkey->pt_size = 0;
}

static TEE_Result hex_array2ch_array(uint8_t *hex_cert, uint8_t *cert, uint32_t cert_size)
{
    uint8_t ch_high, ch_low;
    for (uint32_t j = 0; j < cert_size; j++) {
        ch_high = hex2ch(hex_cert[HEX_STR_SIZE_PER_CHAR * j]);
        ch_low = hex2ch(hex_cert[HEX_STR_SIZE_PER_CHAR * j + 1]);
        if (ch_high == BYTE_CONVERT_ERROR || ch_low == BYTE_CONVERT_ERROR) {
            tloge("bad hex string, j %u\n", j);
            return TEE_ERROR_BAD_PARAMETERS;
        }
        cert[j] = ((ch_high << BIT_4) & BYTE_HIGH_BIT_4) + ch_low;
    }
    return TEE_SUCCESS;
}

TEE_Result alloc_daa_grp_pubkey(uint8_t *hex_array[DAA_GRP_PUBKEY_DIMS], uint32_t hex_pt_size,
                                struct daa_grp_pubkey *pubkey)
{
    tlogi("TA request to convert daa group key\n");
    if (hex_array == NULL || hex_pt_size == 0 || hex_pt_size > DAA_ECC_PT_MAX_SIZE || pubkey == NULL) {
        tloge("bad params to convert daa grp pubkeys\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_Result ret;
    pubkey->pt_size = hex_pt_size / HEX_STR_SIZE_PER_CHAR;
    for (uint32_t i = 0; i < DAA_GRP_PUBKEY_DIMS; i++) {
        pubkey->pt_buf[i] = (uint8_t*)malloc(pubkey->pt_size);
        if (pubkey->pt_buf[i] == NULL) {
            tloge("alloc pubkey failed\n");
            ret = TEE_ERROR_OUT_OF_MEMORY;
            goto err;
        }
    }

    /* copy data */
    for (uint32_t i = 0; i < DAA_GRP_PUBKEY_DIMS; i++) {
        ret = hex_array2ch_array(hex_array[i], pubkey->pt_buf[i], pubkey->pt_size);
        if (ret != TEE_SUCCESS) {
            tloge("bad hex string, i %u\n", i);
            goto err;
        }
    }

    tlogi("convert daa group key succeed!\n");
    return TEE_SUCCESS;
err:
    free_daa_grp_pubkey(pubkey);
    pubkey = NULL;
    return ret;
}

static TEE_Result get_akcert_one_field(struct daa_ak_cert *cert, uint32_t idx, uint8_t *field_buf, uint32_t field_size)
{
    uint32_t pos = 0;
    uint32_t x_size = 0;
    uint32_t y_size = 0;

    /* get x field */
    if (memcpy_s(&x_size, sizeof(uint32_t), field_buf + pos, sizeof(uint32_t)) != 0)
        return TEE_ERROR_GENERIC;
    pos += (uint32_t)sizeof(uint32_t);
    if (x_size > field_size || pos > field_size - x_size)
        return TEE_ERROR_BAD_PARAMETERS;
    cert->pt_buf[(idx << 1)] = field_buf + pos;

    if (cert->pt_size != 0 && cert->pt_size != x_size) {
        tloge("the pt_size for all extract data do not match! %u vs. %u\n", x_size, cert->pt_size);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    cert->pt_size = x_size;
    pos += x_size;

    /* get y field */
    if (pos > field_size - sizeof(uint32_t))
        return TEE_ERROR_BAD_PARAMETERS;
    if (memcpy_s(&y_size, sizeof(uint32_t), field_buf + pos, sizeof(uint32_t)) != 0)
        return TEE_ERROR_GENERIC;
    pos += (uint32_t)sizeof(uint32_t);
    if (y_size > field_size || pos > field_size - y_size)
        return TEE_ERROR_BAD_PARAMETERS;
    cert->pt_buf[(idx << 1) + 1] = field_buf + pos;
    if (cert->pt_size != y_size) {
        tloge("the pt_size for all extract data do not match! %u vs. %u\n", y_size, cert->pt_size);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

TEE_Result convert_daa_ak_cert(struct daa_ak_cert *cert, uint8_t *akcert, uint32_t akcert_size)
{
    if (cert == NULL || akcert == NULL || akcert_size < (uint32_t)sizeof(uint32_t) ||
        akcert_size > DAA_SAVE_AKCERT_MAX_SIZE)
        return TEE_ERROR_BAD_PARAMETERS;

    uint32_t pos = 0;
    TEE_Result ret;
    uint32_t field_size = 0;
    uint8_t *field_buf = NULL;
    for (uint32_t i = 0; i < (DAA_AK_CERT_DIMS >> 1); i++) {
        if (pos > akcert_size - (uint32_t)sizeof(uint32_t))
            return TEE_ERROR_BAD_PARAMETERS;

        if (memcpy_s(&field_size, sizeof(uint32_t), akcert + pos, sizeof(uint32_t)) != 0)
            return TEE_ERROR_GENERIC;

        pos += (uint32_t)sizeof(uint32_t);
        field_buf = akcert + pos;

        ret = get_akcert_one_field(cert, i, field_buf, field_size);
        if (ret != TEE_SUCCESS) {
            tloge("get one field[%u] from akcert failed\n", i);
            return ret;
        }

        pos += field_size;
    }
    tlogi("convert daa_ak_cert succeed!\n");
    return TEE_SUCCESS;
}

TEE_Result load_daa_hex_akcert(uint8_t *hex_cert, uint32_t hex_cert_size, uint8_t *cert, uint32_t cert_size)
{
    if (hex_cert == NULL || cert == NULL || hex_cert_size == 0 ||
        hex_cert_size / HEX_STR_SIZE_PER_CHAR != cert_size) {
        tloge("cannot convert hex to raw, bad params\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return hex_array2ch_array(hex_cert, cert, cert_size);
}
