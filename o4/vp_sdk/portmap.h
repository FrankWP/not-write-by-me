#ifndef port_map
#define port_map

#include "vp_uthttp.h"

int load_portmap(vp_uthtrans *portmap);
int load_portmap_cfg(vp_uthtrans *__ut, const char *cfgPath);

#endif // port_map
