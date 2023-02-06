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
#ifndef TEE_QTA_DAA_STRUCTURE_H
#define TEE_QTA_DAA_STRUCTURE_H
#include <tee_defines.h>

#define DAA_ECC_PT_MAX_SIZE         256
#define DAA_SAVE_AKCERT_MAX_SIZE    0x1000

enum {
    DAA_GRP_PK_X_X0 = 0,
    DAA_GRP_PK_X_Y0,
    DAA_GRP_PK_X_X1,
    DAA_GRP_PK_X_Y1,
    DAA_GRP_PK_Y_X0,
    DAA_GRP_PK_Y_Y0,
    DAA_GRP_PK_Y_X1,
    DAA_GRP_PK_Y_Y1,
    DAA_GRP_PUBKEY_DIMS
};
struct daa_grp_pubkey {
    uint8_t *pt_buf[DAA_GRP_PUBKEY_DIMS];
    uint32_t pt_size; /* size of all uint8_t* is pt_size */
};

enum {
    DAA_AK_CERT_A_X = 0,
    DAA_AK_CERT_A_Y,
    DAA_AK_CERT_B_X,
    DAA_AK_CERT_B_Y,
    DAA_AK_CERT_C_X,
    DAA_AK_CERT_C_Y,
    DAA_AK_CERT_D_X,
    DAA_AK_CERT_D_Y,
    DAA_AK_CERT_DIMS
};
struct daa_ak_cert {
    uint8_t *pt_buf[DAA_AK_CERT_DIMS];
    uint32_t pt_size; /* size of all uint8_t* is pt_size */
};

/*
 * utils for validate_akcert before invoking ECC's pairing functions.
 * These functions does not invoke tcmgr service. They runs in libtcmgr only.
 */

/*
 * convert @hex_array to @pubkey
 */
TEE_Result alloc_daa_grp_pubkey(uint8_t *hex_array[DAA_GRP_PUBKEY_DIMS], uint32_t hex_pt_size,
                                struct daa_grp_pubkey *pubkey);
void free_daa_grp_pubkey(struct daa_grp_pubkey *pubkey);
TEE_Result convert_daa_ak_cert(struct daa_ak_cert *cert, uint8_t *akcert, uint32_t akcert_size);
TEE_Result load_daa_hex_akcert(uint8_t *hex_cert, uint32_t hex_cert_size, uint8_t *cert, uint32_t cert_size);
#endif
