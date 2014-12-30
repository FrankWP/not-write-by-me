#ifndef  __POOL_PORT_H
#define  __POOL_PORT_H

#include "common.h"
#include "toplist.h"

#define  N_USE       0x00
#define  Y_USE       0x01

#define  PP_TOTAL    5000 
#define  INIT_PORT   4601 
//#define  PP_TOTAL    4500
//#define  INIT_PORT   4001 

#define  PP_SMNAME  "pool_port"

extern pthread_mutex_t     pp_mutex;
extern pthread_mutexattr_t pp_attr;

typedef struct POOL_PORT {
    char flag;             /* 0-port no use; 1-port use */
    u16  port;
	u16  dport;
    u32  dip;
} pp_list;

#define INIT_PP_MUTEX() do { \
    pthread_mutexattr_init(&pp_attr); \
    pthread_mutexattr_setpshared(&pp_attr, PTHREAD_PROCESS_SHARED); \
    pthread_mutex_init(&pp_mutex, &pp_attr); \
    pthread_mutexattr_destroy(&pp_attr); \
} while (0)

#define DESTROY_PP_MUTEX() do { \
    pthread_mutex_destroy(&pp_mutex); \
    shm_unlink(PP_SMNAME); \
} while (0)

u16  pplist_getidle_port();
int	pplist_getidle_port2(u16 *port1, u16 *port2);
int pplist_getidle_port2_step(u16 *host_port1, u16 *host_port2, int step);
u16  pplist_getidle_port_x();
u16  pplist_getidle_port_t(int offset);
void pplist_init_value();
void pplist_set_flag(pp_list *pplist, u16 port);
void pplist_print();
int  load_portpool();
void destroy_portpool();

u16  pplist_find_port(u32 dip);
u16  pplist_getidle_port_ip(u32 dip);
void pplist_set_flag_port(u16 port);

pp_list * create_pp_smem(const char * psmid);

struct play_record {
#define  IP_COUNT    2000
#define  PORT_RECORD 2000
    char flag[IP_COUNT];    // port applications sign
    u16  start_port;        // init begin port (PORT_RECORD)
    u16  lport[IP_COUNT];   // local mapping port
    u16  dport[IP_COUNT];   // mapping dest port
    char dip[IP_COUNT][32]; // Mapping dest ip
};
extern struct play_record playrecord;

void init_record_server();
u16  search_record_server(char *dip);
u16  set_record_server(char *dip);
u16  x_search_server(char *dip, u16 dport);
u16  x_search_dst_server(u16 lport, char *dip, u16 *dport);
u16  x_set_server(char *dip, u16 dport);

u16  x_get_idle_port();
u16  x_set_idle_port(u16 dport);
u16  x_set_idle_ipport(char *dip, u16 dport);

#define NUM_ODD  0x01
#define NUM_EVEN 0x02
#define NUM_ANY  0x04

int  init_bind_port(u16 initport, u16 totalport);
u16  get_idle_bind_port(int num_flag);
int  set_idle_bind_port(u16 port);
void destroy_bind_port();

int init_segment_port(u16 base, int step, int count);
u16 get_idle_segment_port();
void free_idle_segment_port(u16 port);
void destroy_segment_port();

#endif
