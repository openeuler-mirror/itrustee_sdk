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

#ifndef __TEE_TIME_API_H
#define __TEE_TIME_API_H

#include "tee_defines.h"

#define TEE_TIMEOUT_INFINITE (0xFFFFFFFF)

typedef struct {
    uint32_t seconds;
    uint32_t millis;
} TEE_Time;

typedef struct {
    int32_t seconds;
    int32_t millis;
    int32_t min;
    int32_t hour;
    int32_t day;
    int32_t month;
    int32_t year;
} TEE_Date_Time;

typedef struct {
    uint32_t type;
    uint32_t timer_id;
    uint32_t timer_class;
    uint32_t reserved2;
} TEE_timer_property;

typedef enum {
    ANTI_ROOT_TIMER = 1,
} TEE_Anti_Root_Timer_Type;

/*
 * Get current TEE system rtc time
 *
 * @param time [OUT] current system rtc time
 * @return void
 */
void get_sys_rtc_time(TEE_Time *time);

/*
 * Get current TEE system time
 *
 * @param time [OUT] current system time
 * @return void
 */
void TEE_GetSystemTime(TEE_Time *time);

/*
 * Waits for the specified number of milliseconds
 *
 * @param timeout [IN] specified number of milliseconds
 *
 * @return  TEE_SUCCESS success
 * @return  TEE_ERROR_CANCEL the wait has been cancelled
 * @return  TEE_ERROR_OUT_OF_MEMORY not enough memory is available to complete the operation
 */
TEE_Result TEE_Wait(uint32_t timeout);

/*
 * Retrieves the persistent time of the Trusted Application
 *
 * @param time [IN] the persistent time of the Trusted Application
 *
 * @return  TEE_SUCCESS success
 * @return  TEE_ERROR_TIME_NOT_SET the persistent time has not been set
 * @return  TEE_ERROR_TIME_NEEDS_RESET the persistent time has been set but may have been
 * corrupted and MUST no longer be trusted
 * @return  TEE_ERROR_OVERFLOW the number of seconds in the TA Persistent Time overflows the range of a uint32_t
 * @return  TEE_ERROR_OUT_OF_MEMORY not enough memory is available to complete the operation
 */
TEE_Result TEE_GetTAPersistentTime(TEE_Time *time);

/*
 * Set the persistent time of the current Trusted Application
 *
 * @param time [IN] the persistent time of the Trusted Application
 *
 * @return  TEE_SUCCESS success
 * @return  TEE_ERROR_OUT_OF_MEMORY not enough memory is available to complete the operation
 * @return  TEE_ERROR_STORAGE_NO_SPACE insufficient storage space is available to complete the operation
 */
TEE_Result TEE_SetTAPersistentTime(TEE_Time *time);

/*
 * Get current REE system time
 *
 * @param time [OUT] current REE system time
 * @return void
 */
void TEE_GetREETime(TEE_Time *time);

/*
 * Get string of current REE system time
 *
 * @param time_str     [OUT]  current REE system time string
 * @param time_str_len [OUT]  the length of time string
 * @return void
 */
void TEE_GetREETimeStr(char *time_str, uint32_t time_str_len);

/*
 * Create rtc timer event
 *
 * @param time_seconds   [IN] specified number of seconds
 * @param timer_property [IN] specified property of timer
 *
 * @return  TEE_SUCCESS success
 * @return  TEE_ERROR_GENERIC create timer fail
 */
TEE_Result TEE_EXT_CreateTimer(uint32_t time_seconds, TEE_timer_property *timer_property);

/*
 * Destory rtc timer event
 *
 * @param timer_property [IN] specified property of timer
 *
 * @return  TEE_SUCCESS success
 * @return  TEE_ERROR_GENERIC destroy timer fail
 */
TEE_Result TEE_EXT_DestoryTimer(TEE_timer_property *timer_property);

/*
 * Get expire time of rtc timer event
 *
 * @param timer_property [IN] specified property of timer
 * @param time_seconds   [OUT] expire time of rtc timer event
 *
 * @return  TEE_SUCCESS success
 * @return  TEE_ERROR_GENERIC get expire time fail
 */
TEE_Result TEE_EXT_GetTimerExpire(TEE_timer_property *timer_property, uint32_t *time_seconds);

/*
 * Get remain time of rtc timer event
 *
 * @param timer_property [IN] specified property of timer
 * @param time_seconds   [OUT] remain time of rtc timer event
 *
 * @return  TEE_SUCCESS success
 * @return  TEE_ERROR_GENERIC get remain time fail
 */
TEE_Result TEE_EXT_GetTimerRemain(TEE_timer_property *timer_property, uint32_t *time_seconds);

/*
 * Get secure rtc time
 *
 * @return current rtc seconds
 */
unsigned int __get_secure_rtc_time(void);
#endif
