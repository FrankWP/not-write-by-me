#ifndef	_MOD_MONITOR_FLOW_H_
#define	_MOD_MONITOR_FLOW_H_
#include <time.h>

#define CLOSE    0
#define THROUGH  1

int get_max_flow_rate(u32 ipaddr);
int init_prio_ip_para(u32 plat_id, u32 dst_ip);
int is_ip_in_fstip(u32 dst_ip);
int ip_can_through(int *flg, u32 dst_ip, time_t *t_old);
int query_prio_ips(u32 plat_id);

#endif	// _MOD_MONITOR_FLOW_H_

