#ifndef __FLOWCLI_H
#define __FLOWCLI_H

#include "common.h"
#include "defflow.h"

int write_flow_value(char *user, u32 sip, u16 sport,
        u32 dip, u16 dport, char *dvs_id, l_int flow, l_int plid);

#endif
