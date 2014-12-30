#ifndef  __POOL_IP_H
#define  __POOL_IP_H

#include "common.h"
#include "toplist.h"

#define  N_USE       0x00
#define  Y_USE       0x01
#define  FILE_PATH   "/topconf/topvp/ippool.conf"

typedef struct IP_POOL {
    u32    lip;           // local listen ip from ip pool
    u32    dip;           // des visit ip from ip pool
    char   flag;          // 0-->ip no use; 1-->ip use
    SAI    vis_addr;      // client addr of only sign visit server
    struct list_head list;
} ip_pool;

typedef struct IPP_LIST {
    ip_pool         ippool;
    pthread_mutex_t ippmutex;
} ipp_list;

#define INIT_IPPOOL_LIST(ipplist) do { \
    INIT_LIST_HEAD(&(ipplist)->ippool.list); \
    pthread_mutex_init(&(ipplist)->ippmutex, NULL); \
} while (0)

#define __ipplist_add(ipplist, pnlist) do { \
    pthread_mutex_lock(&(ipplist)->ippmutex); \
    list_add_n(&((pnlist)->list), &((ipplist)->ippool.list)); \
    pthread_mutex_unlock(&(ipplist)->ippmutex); \
} while (0)

#define __ipplist_free(ipplist, pn, pos) do { \
    pthread_mutex_lock(&(ipplist)->ippmutex); \
    list_del(pos); \
    free(pn); \
    pthread_mutex_unlock(&(ipplist)->ippmutex); \
} while (0)

int  load_ip_pool();
int load_ip_pool2(const char *name);
void free_ip_pool();
void ippool_del_all();
void ipplist_print();
void ippool_rset_flag(SAI desaddr);

ip_pool * ippool_add(u32 lip, u32 dip);
ip_pool * ippool_search_by_desaddr(SAI desaddr);
ip_pool * ippool_search_idle_addr(SAI desaddr);
ip_pool * ippool_search_lip_pairs(u32 lip);
ip_pool * ippool_search_dip_pairs(u32 dip);

#define DESTROY_IPPOOL_LIST(ipplist) do { \
    ippool_del_all(); \
    pthread_mutex_destroy(&(ipplist)->ippmutex); \
} while (0)

#endif // ~ __POOL_IP_H
