#ifndef __CONFIG_H
#define __CONFIG_H

typedef struct netmulit_cfg {
	int		task_id;	/* inside and outside to contact */
	int		netm_ip;	/* mulit brodcast address */
} netm_cfg_t;

typedef struct netmulit_task_list {
	char						neti[8];	/* net interface */
	int							inter_addr; /* interface address that output address */
	netm_cfg_t					nm_cfg;
	struct netmulit_task_list	*next;
} netm_task_list_t;

typedef struct common_cfg {
	u_char sis_if[SIZE_NAME];
	int sis_in_ip;
	int sis_out_ip;
} COM_CFG_T;

typedef struct router_cfg {
	u_char rt_if[SIZE_NAME];
	int rt_src_ip;
	int rt_dst_ip;
	int rt_netmask;
} RT_CFG_T;

/******************
 *   Functions    *
 ******************/
void parse_com_line(const char *line, COM_CFG_T *cc);
void parse_router_line(const char *line, RT_CFG_T *rc);
int cfg_load(const char *filep, const char *sec, void *cfg_list);

#endif
