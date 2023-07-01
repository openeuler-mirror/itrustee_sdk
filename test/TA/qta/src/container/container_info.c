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
#include "container_info.h"
#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>
#include <securec.h>
#include <tee_log.h>
#include "dlist.h"
#include "container_verify.h"

#define MAX_CONTAINER_CNT 0xFF
static pthread_mutex_t g_container_list_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool g_container_list_init = false;
static uint32_t g_container_cnt;
static struct dlist_node g_container_list;

struct container_info {
    struct dlist_node list;
    char container_id[CONTAINER_ID_STR_LEN + 1];
    uint32_t nsid;
};

TEE_Result init_container_list(void)
{
    if (pthread_mutex_lock(&g_container_list_mutex) != 0) {
        tloge("lock container list failed\n");
        return TEE_ERROR_GENERIC;
    }

    if (!g_container_list_init) {
        dlist_init(&g_container_list);
        g_container_list_init = true;
    }

    (void)pthread_mutex_unlock(&g_container_list_mutex);
    return TEE_SUCCESS;
}

TEE_Result get_nsid_by_container_id(char container_id[], uint32_t *nsid)
{
    if (check_container_id(container_id) != TEE_SUCCESS || nsid == NULL) {
        tloge("get nsid check failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (pthread_mutex_lock(&g_container_list_mutex) != 0) {
        tloge("lock container list failed\n");
        return TEE_ERROR_GENERIC;
    }

    *nsid = 0;
    struct container_info *node = NULL;
    dlist_for_each_entry(node, &g_container_list, struct container_info, list) {
        if (strcmp(node->container_id, container_id) == 0) {
            *nsid = node->nsid;
            break;
        }
    }

    (void)pthread_mutex_unlock(&g_container_list_mutex);
    return TEE_SUCCESS;
}

TEE_Result register_container(char container_id[], uint32_t nsid)
{
    TEE_Result ret = TEE_ERROR_GENERIC;
    if (check_container_id(container_id) != TEE_SUCCESS || nsid == 0) {
        tloge("register check failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (pthread_mutex_lock(&g_container_list_mutex) != 0) {
        tloge("lock container list failed\n");
        return TEE_ERROR_GENERIC;
    }

    /* if already registered, update nsid */
    struct container_info *info_node = NULL;
    dlist_for_each_entry(info_node, &g_container_list, struct container_info, list) {
        if (strcmp(info_node->container_id, container_id) == 0) {
            info_node->nsid = nsid;
            ret = TEE_SUCCESS;
            goto end;
        }
    }

    struct container_info *node = malloc(sizeof(*node));
    if (node == NULL) {
        tloge("malloc info node failed\n");
        ret = TEE_ERROR_OUT_OF_MEMORY;
        goto end;
    }
    errno_t rc = strcpy_s(node->container_id, sizeof(node->container_id), container_id);
    if (rc != EOK) {
        tloge("failed to set container id, rc %d\n", rc);
        free(node);
        ret = TEE_ERROR_GENERIC;
        goto end;
    }
    node->nsid = nsid;

    if (g_container_cnt < MAX_CONTAINER_CNT) {
        dlist_insert_head(&node->list, &g_container_list);
        g_container_cnt++;
        ret = TEE_SUCCESS;
    } else {
        tloge("container count exceeds limit\n");
        free(node);
    }
end:
    (void)pthread_mutex_unlock(&g_container_list_mutex);
    return ret;
}
