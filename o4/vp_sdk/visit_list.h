#ifndef  __VISIT_LIST_H
#define  __VISIT_LIST_H

#include "common.h"
#include "toplist.h"
#include "vp_thread_setting.h"

typedef struct __cli_visit_list {
    u32    sip;    // source client ip
    u16    sport;  // source client port
    u32    lip;    // local video ip
    u16    lvport; // local video port 
    u32    dip;    // dest video ip
    u16    dvport; // dest video port
    u32    cliip;
    u16    cliport;
    u32    bind_video_ip;   // the ip need to bind port
    u16    bind_video_port; // bind port for tms or ums 
    int    sockfd;         /* for distribute */
    u16    vstream_tout;
    u32    platform_id;
    char   camera_id[32];
    char   visit_user[32];
    th_set tset;
    struct list_head list;
} clivlist;

typedef struct __visit_list {
    clivlist cvlist;
    pthread_mutex_t vmutex;
} vlist;

#define INIT_VISIT_LIST(pvlist) do { \
    INIT_LIST_HEAD(&(pvlist)->cvlist.list); \
    pthread_mutex_init(&(pvlist)->vmutex, NULL); \
} while (0)

#define __vlist_add(pvlist, pcvlist) do { \
    pthread_mutex_lock(&(pvlist)->vmutex); \
    list_add_n(&((pcvlist)->list), &((pvlist)->cvlist.list)); \
    pthread_mutex_unlock(&(pvlist)->vmutex); \
} while (0)

#define __vlist_free(pvlist, pn, pos) do { \
    pthread_mutex_lock(&(pvlist)->vmutex); \
    list_del(pos); \
    oss_free((void *)&pn); \
    pthread_mutex_unlock(&(pvlist)->vmutex); \
} while (0)

void vlist_del(vlist *pvlist, u32 cliip, u16 cliport);
void vlist_del_by_cip(vlist *pvlist, u32 cliip);
void vlist_del_all(vlist *pvlist);
void vlist_print(vlist *pvlist);

clivlist * vlist_add(vlist *pvlist, u32 cliip, u16 cliport);
clivlist * vlist_search(vlist *pvlist, u32 cliip, u16 cliport);
clivlist * vlist_search_by_cip(vlist *pvlist, u32 cliip);
clivlist * create_tuvs_smem(const char * psmid);

#define DESTROY_VISIT_LIST(pvlist) do { \
    vlist_del_all(pvlist); \
    pthread_mutex_destroy(&(pvlist)->vmutex); \
} while (0)

#endif // __VISIT_LIST
