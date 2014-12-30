#ifndef _COMMON_KEDA_H_
#define _COMMON_KEDA_H_

#include "../vpheader.h"

#define PROXY_COUNT 128

typedef int(*mtp_call_back)(pvp_uthttp put, char **ut_buf, u32 *pack_len);

int __kd_ga_video_proxy(u32 lip, u32 dip, u16 l_base_port, u16 d_base_port, int count_proxy, int step, u16 tout);
int process_keda_comp_protocol(pvp_uthttp put, char **ut_buf, u32 *pack_len, mtp_call_back func_process_data);

#endif  // _COMMON_KEDA_H_

