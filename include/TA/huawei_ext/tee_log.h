/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * iTrustee licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#ifndef __TEE_LOG_H
#define __TEE_LOG_H

#include "tee_defines.h"

#define DEBUG_TAG   "[debug]"
#define INFO_TAG    "[info]"
#define WARNING_TAG "[warning]"
#define ERROR_TAG   "[error]"

#define LEVEL_DEBUG   2
#define LEVEL_WARNING 1
#define LEVEL_ERROR   0

#define TAG_VERB  "[verb]"
#define TAG_DEBUG "[debug]"
#define TAG_INFO  "[info]"
#define TAG_WARN  "[warn]"
#define TAG_ERROR "[error]"

typedef enum {
    LOG_LEVEL_ERROR = 0,
    LOG_LEVEL_WARN  = 1,
    LOG_LEVEL_INFO  = 2,
    LOG_LEVEL_DEBUG = 3,
    LOG_LEVEL_VERBO = 4,
    LOG_LEVEL_ON    = 5,
} LOG_LEVEL;

void uart_cprintf(const char *fmt, ...);
void uart_printf_func(const char *fmt, ...);

void tee_print(LOG_LEVEL log_level, const char *fmt, ...);
void tee_print_driver(LOG_LEVEL log_level, const char *log_tag, const char *fmt, ...);
extern const char *g_debug_prefix;

#define TEE_LogPrintf(fmt, args...) SLog(fmt, ##args)
#ifdef LOG_ON
#ifdef DRIVER_LOG_TAG
#define tlogv(fmt, args...) \
    tee_print_driver(LOG_LEVEL_VERBO, DRIVER_LOG_TAG, "%s %d:" fmt "", TAG_VERB, __LINE__, ##args)
#define tlogd(fmt, args...) \
    tee_print_driver(LOG_LEVEL_DEBUG, DRIVER_LOG_TAG, "%s %d:" fmt "", TAG_DEBUG, __LINE__, ##args)
#define tlogi(fmt, args...) \
    tee_print_driver(LOG_LEVEL_INFO, DRIVER_LOG_TAG, "%s %d:" fmt "", TAG_INFO, __LINE__, ##args)
#define tlogw(fmt, args...) \
    tee_print_driver(LOG_LEVEL_WARN, DRIVER_LOG_TAG, "%s %d:" fmt "", TAG_WARN, __LINE__, ##args)
#else
#define tlogv(fmt, args...) tee_print(LOG_LEVEL_VERBO, "%s %d:" fmt "", TAG_VERB, __LINE__, ##args)
#define tlogd(fmt, args...) tee_print(LOG_LEVEL_DEBUG, "%s %d:" fmt "", TAG_DEBUG, __LINE__, ##args)
#define tlogi(fmt, args...) tee_print(LOG_LEVEL_INFO, "%s %d:" fmt "", TAG_INFO, __LINE__, ##args)
#define tlogw(fmt, args...) tee_print(LOG_LEVEL_WARN, "%s %d:" fmt "", TAG_WARN, __LINE__, ##args)
#endif
#else
#define tlogv(fmt, args...) \
    do {                    \
    } while (0)
#define tlogd(fmt, args...) \
    do {                    \
    } while (0)
#define tlogi(fmt, args...) \
    do {                    \
    } while (0)
#define tlogw(fmt, args...) \
    do {                    \
    } while (0)
#endif /* ENG_VERSION */

#ifndef TLOGE_NO_TIMESTAMP
#ifdef DRIVER_LOG_TAG
#define tloge(fmt, args...) \
    tee_print_driver(LOG_LEVEL_ERROR, DRIVER_LOG_TAG, "%s %d:" fmt " ", TAG_ERROR, __LINE__, ##args)
#else
#define tloge(fmt, args...) tee_print(LOG_LEVEL_ERROR, "%s %d:" fmt " ", TAG_ERROR, __LINE__, ##args)
#endif
#else
#define tloge(fmt, args...) printf("[%s] %s %d:" fmt " ", g_debug_prefix, TAG_ERROR, __LINE__, ##args)
#endif

void ta_print(LOG_LEVEL log_level, const char *fmt, ...);

#ifdef LOG_ON
#define ta_logv(fmt, args...) ta_print(LOG_LEVEL_VERBO, "%s %d: " fmt "\n", TAG_VERB, __LINE__, ##args)
#define ta_logd(fmt, args...) ta_print(LOG_LEVEL_DEBUG, "%s %d: " fmt "\n", TAG_DEBUG, __LINE__, ##args)
#define ta_logi(fmt, args...) ta_print(LOG_LEVEL_INFO, "%s %d: " fmt "\n", TAG_INFO, __LINE__, ##args)
#define ta_logw(fmt, args...) ta_print(LOG_LEVEL_WARN, "%s %d: " fmt "\n", TAG_WARN, __LINE__, ##args)
#else
#define ta_logv(fmt, args...) \
    do {                      \
    } while (0)
#define ta_logd(fmt, args...) \
    do {                      \
    } while (0)
#define ta_logi(fmt, args...) \
    do {                      \
    } while (0)
#define ta_logw(fmt, args...) \
    do {                      \
    } while (0)
#endif
#define ta_loge(fmt, args...) ta_print(LOG_LEVEL_ERROR, "%s %d: " fmt "\n", TAG_ERROR, __LINE__, ##args)

/* in debug version users can dynamically modify the loglevel ,in release version, users have to modify the level by
 * compile */
#ifndef DEBUG_VERSION

#ifdef TA_DEBUG
#define ta_debug(fmt, args...) uart_printf_func("%s %s: " fmt "", DEBUG_TAG, __FUNCTION__, ##args)
#else
#define ta_debug(fmt, args...)
#endif

#else

#define ta_debug(fmt, args...)                                                   \
    do {                                                                         \
        uint32_t level;                                                          \
        level = get_value();                                                     \
        if (level >= LEVEL_DEBUG) {                                              \
            uart_printf_func("%s %s: " fmt "", DEBUG_TAG, __FUNCTION__, ##args); \
        }                                                                        \
    } while (0)

#define ta_warning(fmt, args...)                                                 \
    do {                                                                         \
        uint32_t level;                                                          \
        level = get_value();                                                     \
        if (level >= LEVEL_WARNING) {                                            \
            uart_printf_func("%s %s: " fmt "", DEBUG_TAG, __FUNCTION__, ##args); \
        }                                                                        \
    } while (0)

#endif

#define ta_info(fmt, args...)  uart_printf_func("%s: " fmt "", INFO_TAG, ##args)
#define ta_error(fmt, args...) uart_printf_func("%s: " fmt " ", ERROR_TAG, ##args)
#define TA_LOG
#ifdef TA_LOG

#define TRACE_S   "[Trace]"
#define WARNING_S "[Warning]"
#define ERROR_S   "[Error]"

/*
 * Print trace level's log.
 *
 * @param fmt  [IN]   assert condition.
 * @param args [IN]   params for format config.
 *
 * @return void
 */
#define SLogTrace(fmt, args...) SLog("%s: " fmt "\n", TRACE_S, ##args)

/*
 * Print warning level's log.
 *
 * @param fmt  [IN]   assert condition.
 * @param args [IN]   params for format config.
 *
 * @return void
 */
#define SLogWarning(fmt, args...) SLog("%s: " fmt "\n", WARNING_S, ##args)

/*
 * Print error level's log.
 *
 * @param fmt  [IN]   assert condition.
 * @param args [IN]   params for format config.
 *
 * @return void
 */
#define SLogError(fmt, args...) SLog("%s: " fmt "\n", ERROR_S, ##args)

/*
 * Assert api for tee log, note: should call Panic to deal, here just return
 *
 * @param exp [IN]    Printf log's format config style.
 *
 * @return void
 */
#define SAssert(exp)                                                                         \
    do {                                                                                     \
        if (!(exp)) {                                                                        \
            SLog("Assertion [ %s ] Failed: File %s, Line %d\n", #exp, "__FILE__", __LINE__); \
            return 0xFFFF0001;                                                               \
        }                                                                                    \
    } while (0);
#else
#define SLogTrace(fmt, args...)   ((void)0)
#define SLogWarning(fmt, args...) ((void)0)
#define SLogError(fmt, args...)   ((void)0)
#define SAssert(exp)              ((void)0)
#endif

/*
 * Output log to tee log file.
 *
 * @param fmt [IN]    Printf log's format config style.
 *
 * @return void
 */
void SLog(const char *fmt, ...);
uint32_t get_value(void);
#endif
