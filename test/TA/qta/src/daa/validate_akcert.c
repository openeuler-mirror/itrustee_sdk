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
#include "validate_akcert.h"
#include <tee_log.h>
#include <tee_ext_api.h>
#include <securec.h>

#include <pair_FP512BN.h>
#include "daa_structure.h"

#define DAA_GRP_KEY_PK_X_X0 "0cb2c846b963556d3651f89a490a0257039637dfee774caedb32513eccec6789" \
                            "e29269aa054814000227a6d34bb29c67fe399ebe1dd6c9f6b33604d5b990912c"
#define DAA_GRP_KEY_PK_X_X1 "7be073749d20ff1a57131f66c0271f219b8b767f924b8ab187fc480bfbf84ff2" \
                            "6ce81aa42549fb100b851d9867c5e12baa5362417c4d2b5f3726ad1f5bf9b98b"
#define DAA_GRP_KEY_PK_X_Y0 "a4523e489bd2245a5ee92255b3e54dd0a90fd1f0f4712514dce6ab85397bba3a" \
                            "7a2921956f14fc2207495ecb7a2442df36092254fbb29bbab2fed41ff198d0ae"
#define DAA_GRP_KEY_PK_X_Y1 "7daf3d8855ed007da8d41d143ae8a086c5a63ae665856ecff09af7fe9eecf066" \
                            "5f8527de27a0cd606ffe7ca18a6988c4830a28d0f9ece0f1f08dbc4ea526c36f"

#define DAA_GRP_KEY_PK_Y_X0 "d2c6994dee1b5dc071d5d547f26471bcd6aef7c2dc2ce112b9475bdecc0e85a7" \
                            "2015841f85a8de39506396cec11c520975f6d985b262c6f97413d2632f899896"
#define DAA_GRP_KEY_PK_Y_X1 "e391d2d0cf2703b327ffb88615bfe6d7a9c5715007c9bfa91ff6b01210000a8e" \
                            "ddff2a310a2af6e042135b399989b7f54833ea96d5cbc93ae5da61ee63669941"
#define DAA_GRP_KEY_PK_Y_Y0 "ffbde64729b2f8a212bfe2eef22c7b62edd77a78bc5e7f3c6782bcd839d26e0c" \
                            "7cea338240874edc3654bd3293974a7581ec168bfaee35bb093a8302bce9ac90"
#define DAA_GRP_KEY_PK_Y_Y1 "03836c48550cf1c9dc5c455201e248acccf7a5395f9d4cc477734fdbaf8330d9" \
                            "7386aa451893824994cbedfdde7f9a8b8b7baad4b0b4dca8201135392b4910d4"

#define DAA_GRP_KEY_PK_LEN  (sizeof(DAA_GRP_KEY_PK_X_X0))

#define DAA_GRP_PK_ELE_NUM        2
#define DAA_GRP_AK_CERT_ELE_NUM   4

#define GRP_PK_EACH_ELE_DIM     4 /* ((uint32_t)DAA_GRP_PUBKEY_DIMS / (uint32_t)DAA_GRP_PK_ELE_NUM) */
#define GRP_PK_EACH_ELE_IDX2    2
#define GRP_PK_EACH_ELE_IDX3    3
static TEE_Result daa_grp_pk_to_ecp(struct daa_grp_pubkey *grp_pk, ECP2_FP512BN *ecp2[DAA_GRP_PK_ELE_NUM])
{
    for (uint32_t i = 0; i < DAA_GRP_PK_ELE_NUM; i++) {
        FP2_FP512BN fp2_bn_x, fp2_bn_y;
        BIG_512_60 bn_x0, bn_y0, bn_x1, bn_y1;
        BIG_512_60_fromBytes(bn_x0, (char*)(uintptr_t)(grp_pk->pt_buf[GRP_PK_EACH_ELE_DIM * i + 0]));
        BIG_512_60_fromBytes(bn_y0, (char*)(uintptr_t)(grp_pk->pt_buf[GRP_PK_EACH_ELE_DIM * i + 1]));
        BIG_512_60_fromBytes(bn_x1,
            (char*)(uintptr_t)(grp_pk->pt_buf[GRP_PK_EACH_ELE_DIM * i + GRP_PK_EACH_ELE_IDX2]));
        BIG_512_60_fromBytes(bn_y1,
            (char*)(uintptr_t)(grp_pk->pt_buf[GRP_PK_EACH_ELE_DIM * i + GRP_PK_EACH_ELE_IDX3]));
        FP2_FP512BN_from_BIGs(&fp2_bn_x, bn_x0, bn_y0);
        FP2_FP512BN_from_BIGs(&fp2_bn_y, bn_x1, bn_y1);
        if (ECP2_FP512BN_set(ecp2[i], &fp2_bn_x, &fp2_bn_y) == 0) {
            tloge("bad point[%u] when converting DAA pubkey to ECP2\n", i);
            return TEE_ERROR_GENERIC;
        }
    }
    return TEE_SUCCESS;
}

#define AK_CERT_EACH_ELE_DIM    2 /* ((uint32_t)DAA_AK_CERT_DIMS / (uint32_t)DAA_GRP_AK_CERT_ELE_NUM) */
static TEE_Result daa_ak_cert_to_ecp(struct daa_ak_cert *ak_cert, ECP_FP512BN *ecp[DAA_GRP_AK_CERT_ELE_NUM])
{
    for (uint32_t i = 0; i < DAA_GRP_AK_CERT_ELE_NUM; i++) {
        BIG_512_60 big_x, big_y;
        BIG_512_60_fromBytes(big_x, (char*)(uintptr_t)(ak_cert->pt_buf[AK_CERT_EACH_ELE_DIM * i]));
        BIG_512_60_fromBytes(big_y, (char*)(uintptr_t)(ak_cert->pt_buf[AK_CERT_EACH_ELE_DIM * i + 1]));
        if (ECP_FP512BN_set(ecp[i], big_x, big_y) == 0) {
            tloge("bad point[%u] when converting DAA ak cert to ECP\n", i);
            return TEE_ERROR_GENERIC;
        }
    }
    return TEE_SUCCESS;
}

struct validate_daa_pair_context {
    ECP_FP512BN a, b, c, d;
    ECP2_FP512BN ecp2_x, ecp2_y;
    FP12_FP512BN pair_lhs, pair_rhs;
    ECP2_FP512BN p2;
};

static TEE_Result validate_daa_pairs(struct daa_grp_pubkey *grp_pk, struct daa_ak_cert *ak_cert)
{
    TEE_Result pairings_ok;
    tlogi("qta begins to validate daa pairs\n");
    struct validate_daa_pair_context context;
    (void)memset_s(&context, sizeof(context), 0, sizeof(context));

    if (ECP2_FP512BN_generator(&context.p2) == 0) {
        tloge("bad point when getting P2\n");
        return TEE_ERROR_GENERIC;
    }

    ECP2_FP512BN *ecp2[DAA_GRP_PK_ELE_NUM] = { &context.ecp2_x, &context.ecp2_y };
    pairings_ok = daa_grp_pk_to_ecp(grp_pk, ecp2);
    if (pairings_ok != TEE_SUCCESS) {
        tloge("convert group pubkey to ECP2_FP512BN failed\n");
        return pairings_ok;
    }

    ECP_FP512BN *ecp[DAA_GRP_AK_CERT_ELE_NUM] = { &context.a, &context.b, &context.c, &context.d };
    pairings_ok = daa_ak_cert_to_ecp(ak_cert, ecp);
    if (pairings_ok != TEE_SUCCESS) {
        tloge("convert DAA ak cert to ECP_FP512BN failed\n");
        return pairings_ok;
    }

    PAIR_FP512BN_ate(&context.pair_lhs, &context.ecp2_y, &context.a);
    PAIR_FP512BN_fexp(&context.pair_lhs);

    PAIR_FP512BN_ate(&context.pair_rhs, &context.p2, &context.b);
    PAIR_FP512BN_fexp(&context.pair_rhs);
    if (FP12_FP512BN_equals(&context.pair_lhs, &context.pair_rhs) == 0) {
        tloge("validate DAA pair[0] failed\n");
        return TEE_ERROR_GENERIC;
    }
    ECP_FP512BN_add(&context.d, &context.a);

    PAIR_FP512BN_ate(&context.pair_lhs, &context.ecp2_x, &context.d);
    PAIR_FP512BN_fexp(&context.pair_lhs);

    PAIR_FP512BN_ate(&context.pair_rhs, &context.p2, &context.c);
    PAIR_FP512BN_fexp(&context.pair_rhs);

    if (FP12_FP512BN_equals(&context.pair_lhs, &context.pair_rhs) == 0) {
        tloge("validate DAA pair[1] failed\n");
        return TEE_ERROR_GENERIC;
    }
    tlogi("qta finishes check daa pair: pairings_ok = %u, expect value = %u\n", pairings_ok, TEE_SUCCESS);
    return pairings_ok;
}

TEE_Result validate_akcert(char *hex_input, uint32_t hex_input_size)
{
    if (hex_input == NULL || hex_input_size == 0 || hex_input_size > DAA_SAVE_AKCERT_MAX_SIZE)
        return TEE_ERROR_BAD_PARAMETERS;

    TEE_Result ret;

    tlogi("prepare to init daa group pubkeys\n");
    struct daa_grp_pubkey grp_pk;
    (void)memset_s(&grp_pk, sizeof(grp_pk), 0, sizeof(grp_pk));
    uint8_t* array[] = { (uint8_t*)DAA_GRP_KEY_PK_X_X0, (uint8_t*)DAA_GRP_KEY_PK_X_X1, (uint8_t*)DAA_GRP_KEY_PK_X_Y0,
        (uint8_t*)DAA_GRP_KEY_PK_X_Y1, (uint8_t*)DAA_GRP_KEY_PK_Y_X0, (uint8_t*)DAA_GRP_KEY_PK_Y_X1,
        (uint8_t*)DAA_GRP_KEY_PK_Y_Y0, (uint8_t*)DAA_GRP_KEY_PK_Y_Y1 };
    ret = alloc_daa_grp_pubkey(array, DAA_GRP_KEY_PK_LEN, &grp_pk);
    if (ret != TEE_SUCCESS) {
        tloge("validate akcert: alloc daa group keys failed, ret 0x%x\n",  ret);
        return ret;
    }

    tlogi("prepare to load daa ak_cert\n");
    uint32_t input_size = hex_input_size >> 1;
    uint8_t *input = TEE_Malloc(input_size, 0);
    if (input == NULL) {
        tloge("validate akcert: alloc input buffer failed, ret 0x%x\n",  ret);
        ret = TEE_ERROR_OUT_OF_MEMORY;
        goto clear;
    }
    ret = load_daa_hex_akcert((uint8_t*)(uintptr_t)hex_input, hex_input_size, input, input_size);
    if (ret != TEE_SUCCESS) {
        tloge("validate akcert: convert hex str to raw failed, ret 0x%x\n",  ret);
        goto clear;
    }

    struct daa_ak_cert ak_cert;
    (void)memset_s(&ak_cert, sizeof(ak_cert), 0, sizeof(ak_cert));
    ret = convert_daa_ak_cert(&ak_cert, input, input_size);
    if (ret != TEE_SUCCESS) {
        tloge("validate akcert: validate daa pairs failed, ret 0x%x\n",  ret);
        goto clear;
    }

    ret = validate_daa_pairs(&grp_pk, &ak_cert);
    if (ret != TEE_SUCCESS) {
        tloge("validate akcert: validate daa pairs failed, ret 0x%x\n",  ret);
        goto clear;
    }
clear:
    if (input)
        TEE_Free(input);
    free_daa_grp_pubkey(&grp_pk);
    return ret;
}
