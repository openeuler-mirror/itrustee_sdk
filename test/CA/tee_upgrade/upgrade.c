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
 * Description: C file template for CA
 */

#include "teek_client_api.h"
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <securec.h>
#include <linux/slab.h>

#define PART_IAMGE_LEN             0x100000
#define UPGRADE_SEND_IMAGE_BEGIN  0xaa
#define UPGRADE_SEND_IMAGE_UPDATE  0xbb
#define UPGRADE_SEND_IMAGE_FINISH  0xcc
#define MAX_IMAGE_LENGTH 0x1000000
#ifndef CONFIG_TEE_IMG_PATH
#define CONFIG_TEE_IMG_PATH "/var/itrustee/image/trustedcore.img"
#endif

/* array index */
#define ARRAY_INDEX2 2
#define ARRAY_INDEX3 3

extern int tee_reboot(void);

static int32_t teek_open_app_file(struct file *fp, char **fileBuf, uint32_t total_img_len)
{
    loff_t pos = 0;
    uint32_t read_size;
    char *fileBuffer = NULL;

    if (total_img_len == 0 || total_img_len > MAX_IMAGE_LENGTH) {
        tloge("img len is invalied, len=%u\n", total_img_len);
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    fileBuffer = vmalloc(total_img_len);
    if (ZERO_OR_NULL_PTR((unsigned long)(uintptr_t)fileBuffer)) {
        tloge("alloc TA file buffer(size=%u) failed\n", total_img_len);
        return TEEC_ERROR_GENERIC;
    }

    read_size = (uint32_t)kernel_read(fp, fileBuffer, total_img_len, &pos);
    if (read_size != total_img_len) {
        tloge("read ta file failed, read size/total size=%u/%u\n", read_size, total_img_len);
        vfree(fileBuffer);
        return TEEC_ERROR_GENERIC;
    }

    *fileBuf = fileBuffer;

    return TEEC_SUCCESS;
}

static int32_t teek_read_app(const char *load_file, char **fileBuf, uint32_t *file_len)
{
    int32_t ret;
    struct file *fp = NULL;

    fp = filp_open(load_file, O_RDONLY, 0);
    if (!fp || IS_ERR(fp)) {
        tloge("open file error, err=%ld\n", PTR_ERR(fp));
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    if (!fp->f_inode) {
        tloge("node is NULL\n");
        filp_close(fp, 0);
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    *file_len = (uint32_t)(fp->f_inode->i_size);

    ret = teek_open_app_file(fp, fileBuf, *file_len);
    if (ret != TEEC_SUCCESS) {
        tloge("do read app fail\n");
    }

    if (fp != NULL) {
        filp_close(fp, 0);
        fp = NULL;
    }

    return ret;
}

static void teek_free_app(bool load_app_flag, char **fileBuf)
{
    if (load_app_flag && fileBuf != NULL && ZERO_OR_NULL_PTR((unsigned long)(uintptr_t)(*fileBuf))) {
        vfree(*fileBuf);
        *fileBuf = NULL;
    }
}

static int32_t teek_get_app(const char *ta_path, char **fileBuf, uint32_t *file_len)
{
    int32_t ret;

    if (!ta_path)
        return TEEC_ERROR_BAD_PARAMETERS;

    if (!fileBuf || !file_len) {
        tloge("load app params invalied\n");
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    ret = teek_read_app(ta_path, fileBuf, file_len);
    if (ret != TEEC_SUCCESS)
        tloge("teec load app error, err=%d\n", ret);

    return ret;
}

static int send_image_begin(TEEC_Session *tee_session, uint32_t image_length)
{
    uint32_t origin = 0;
    TEEC_Operation operation = {0};
    int ret = 0;

    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_VALUE_INPUT);
    operation.params[ARRAY_INDEX3].value.a = image_length;

    ret = TEEK_InvokeCommand(tee_session, UPGRADE_SEND_IMAGE_BEGIN, &operation, &origin);
    if (ret != 0) {
        tloge("TEEK_InvokeCommand failed\n");
        return -1;
    }
    return 0;
}

static int send_image_update(TEEC_Session *tee_session, char *fileBuf, uint32_t image_length)
{
    uint32_t origin = 0;
    uint32_t idx = 0;
    uint32_t left_len = image_length;
    int ret = 0;

    TEEC_Operation operation = {0};
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_MEMREF_TEMP_INPUT, TEEC_NONE);

    while (left_len > 0) {
        uint32_t len = (left_len >= PART_IAMGE_LEN) ? PART_IAMGE_LEN : left_len;
        operation.params[ARRAY_INDEX2].tmpref.buffer = fileBuf + idx * PART_IAMGE_LEN;
        operation.params[ARRAY_INDEX2].tmpref.size = len;
        ret = TEEK_InvokeCommand(tee_session, UPGRADE_SEND_IMAGE_UPDATE, &operation, &origin);
        if (ret != 0) {
            tloge("send image update failed\n");
            return -1;
        }
        left_len -= len;
        idx++;
    }
    return 0;
}

static int send_image_finish(TEEC_Session *tee_session)
{
    uint32_t origin = 0;
    int ret = 0;
    TEEC_Operation operation = {0};
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

    ret = TEEK_InvokeCommand(tee_session, UPGRADE_SEND_IMAGE_FINISH, &operation, &origin);
    if (ret != 0) {
        tloge("send image finish failed\n");
        return -1;
    }

    return ret;
}

static int get_new_tee_image(TEEC_Session *tee_session)
{
    char *fileBuf = NULL;
    uint32_t image_length = 0;

    int ret = teek_get_app(CONFIG_TEE_IMG_PATH, &fileBuf, &image_length);
    if (ret != 0) {
        tloge("get new tee image failed, use origin tee\n");
        teek_free_app(true, &fileBuf);
        return -1;
    }

    ret = send_image_begin(tee_session, image_length);
    if (ret != 0) {
        tloge("send image begin failed\n");
        teek_free_app(true, &fileBuf);
        return -1;
    }

    ret = send_image_update(tee_session, fileBuf, image_length);
    if (ret != 0) {
        tloge("send image update failed\n");
        teek_free_app(true, &fileBuf);
        return -1;
    }

    ret = send_image_finish(tee_session);
    if (ret != 0) {
        tloge("send image end failed\n");
        teek_free_app(true, &fileBuf);
        return -1;
    }

    teek_free_app(true, &fileBuf);
    return 0;
}


// 9ab6f960-54f3-4317-a8f7-e92ed12b6ae2.sec
static const TEEC_UUID g_tee_uuid = {
    0x9ab6f960U, 0x54f3, 0x4317,
    { 0xa8, 0xf7, 0xe9, 0x2e, 0xd1, 0x2b, 0x6a, 0xe2 }
};

static int32_t __init upgrade_init(void)
{
    TEEC_Result ret;
    TEEC_Context ctx;
    TEEC_Operation operation = {0};
    TEEC_Session tee_session;
    uint32_t origin = 0;
    uint32_t root_id = 0;

    ret = TEEK_InitializeContext(NULL, &ctx);
    if (ret != 0) {
        tloge("initialize context failed\n");
        return -1;
    }

    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT);
    operation.params[ARRAY_INDEX2].tmpref.buffer = (void *)(&root_id);
    operation.params[ARRAY_INDEX2].tmpref.size = sizeof(root_id);
    operation.params[ARRAY_INDEX3].tmpref.buffer = (void *)("tee_upgrade");
    operation.params[ARRAY_INDEX3].tmpref.size = strlen("tee_upgrade") + 1;

    ctx.ta_path = (uint8_t *)("/var/itrustee/image/9ab6f960-54f3-4317-a8f7-e92ed12b6ae2.sec");
    ret = TEEK_OpenSession(&ctx, &tee_session, &g_tee_uuid, TEEC_LOGIN_IDENTIFY, NULL, &operation, &origin);
    if (ret != 0) {
        tloge("TEEK_OpenSession failed\n");
        TEEK_FinalizeContext(&ctx);
        return -1;
    }

    ret = get_new_tee_image(&tee_session);
    if (ret != 0) {
        TEEK_CloseSession(&tee_session);
        TEEK_FinalizeContext(&ctx);
        return -1;
    }

    TEEK_CloseSession(&tee_session);
    TEEK_FinalizeContext(&ctx);
    ret = (TEEC_Result)tee_reboot();
    if (ret != TEEC_SUCCESS)
        return -1;
    tlogi("teeos upgrade done\n");
    return 0;
}


static void __exit upgrade_exit(void)
{
    tlogi("remove upgrade ca\n");
}

module_init(upgrade_init);
module_exit(upgrade_exit);

MODULE_AUTHOR("Huawei Tech. Co., Ltd.");
MODULE_DESCRIPTION("TEE UPGRADE");
MODULE_LICENSE("GPL");
MODULE_VERSION("V1.0");
