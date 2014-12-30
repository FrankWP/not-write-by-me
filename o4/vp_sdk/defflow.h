#ifndef __FLOW_DEF_H
#define __FLOW_DEF_H

#include "common.h"

#define  FIFOMODE    (O_CREAT | O_RDWR | O_NONBLOCK)
#define  OPENMODE    (O_RDONLY | O_NONBLOCK)

#define  FIFO_SERVER "/var/flow_fifo"

typedef struct flow_stat
{
    u32    sce_ip;
    u32    sce_port;
    u32    des_ip;
    u32    des_port;
    u32    platform_id;
    char   usr_name[16];
    char   dvs_id[32];
    l_int  t_start;
    l_int  t_end;
    l_int  t_update;
    l_int  fs_value;
    struct flow_stat *plink;
} flow_stat_t;

#endif // __FLOW_DEF_H
