/*
 *   @ useful: distribute video stream to more visit client.
 */
#ifndef __VP_DISTRIBUTE_H
#define __VP_DISTRIBUTE_H

#include "common.h"
#include "toplist.h"
#include "visit_list.h"
#include "flowcli.h"
#include "vp_pack.h"

typedef struct list_head lh;

#define  NODE_LEADER  0x00
#define  NODE_BEHIND  0x01

typedef struct video_way {
    u8   v_num;                  // client connect num
    u32  lip;                    // local server proxy ip
    u16  lport;                  // local server proxy port
    u32  dip;                    // dest video server ip or camera ip
    u16  dport;                  // dest video server ip or camera port
    char x_sign[32];             // camera id or device id or other
    char dt_id[32];              // distribute id auth process share video stream process
} v_way;

typedef struct video_visit_node {
    SAI cli_addr;
    int x_mark;                  // sign the first connect client
    int cli_sock;                // connect client socket useful tcp
    lh  list;
} vv_node;

/*
 *  dip and dport or x_sign
 *  only sign one video stream.
 *  the vvlist is empty
 *  when the dest server have too much.
 *  the vvlist is empty
 *  when use vp_vstcp or vp_vsudp process.
 */
typedef struct video_visit_server {
    v_way   vway;
    vv_node vvlist;
    lh      list;
} v_ser;

/*
 *  auth proxy process and
 *  video stream process share this struct.
 *  when auth process recv close cmd
 *  the auth process look online visit num,
 *  if the num eq 1 then send close cmd to server.
 */
typedef struct video_visit_list {
    v_ser               vser;
    pthread_mutex_t     vmutex;
    pthread_mutexattr_t vmuattr;
} vs_list;

#define dt_init(pvslist) do { \
    INIT_LIST_HEAD(&(pvslist)->vser.list); \
    pthread_mutexattr_init(&(pvslist)->vmuattr); \
    pthread_mutexattr_setpshared(&(pvslist)->vmuattr, PTHREAD_PROCESS_SHARED); \
    pthread_mutex_init(&(pvslist)->vmutex, &(pvslist)->vmuattr); \
    pthread_mutexattr_destroy(&(pvslist)->vmuattr); \
} while (0)

#define __vser_add_tail(pvslist, pser) do { \
    pthread_mutex_lock(&(pvslist)->vmutex); \
    list_add_tail(&(pser)->list, &(pvslist)->vser.list); \
    INIT_LIST_HEAD(&(pser)->vvlist.list); \
    pthread_mutex_unlock(&(pvslist)->vmutex); \
} while (0)

#define __vsnode_add_tail(pvslist, pser, pvvnode) do { \
    pthread_mutex_lock(&(pvslist)->vmutex); \
    list_add_tail(&(pvvnode)->list, &(pser)->vvlist.list); \
    pthread_mutex_unlock(&(pvslist)->vmutex); \
} while (0)

#define __vslist_del(pvslist, pn, pos) do { \
    pthread_mutex_lock(&(pvslist)->vmutex); \
    list_del(pos); \
    oss_free((void *)&pn); \
    pthread_mutex_unlock(&(pvslist)->vmutex); \
} while (0)

#define vser_getnum(pvslist, pser, num) do { \
    pthread_mutex_lock(&(pvslist)->vmutex); \
    num = pser->vway.v_num; \
    pthread_mutex_unlock(&(pvslist)->vmutex); \
} while (0)

#define vser_addnum(pvslist, pser) do { \
    pthread_mutex_lock(&(pvslist)->vmutex); \
    ++pser->vway.v_num; \
    pthread_mutex_unlock(&(pvslist)->vmutex); \
} while (0)

#define vser_lessnum(pvslist) do { \
    pthread_mutex_lock(&(pvslist)->vmutex); \
    pser->vway.v_num; \
    pthread_mutex_unlock(&(pvslist)->vmutex); \
} while (0)

#define init_vser_node(pser) do { \
    memset(&pser->vway, 0x00, sizeof(v_way)); \
    pser->vway.v_num = 0; \
} while (0)

int dt_recvx_x(vs_list *pvslist,
               int sockfd,
               SAI cli_addr,
               char *data_buf,
               int ret,
               v_ser *pser);

void dt_send_x(vs_list *pvslist,
               char *data_buf,
               clivlist *pcvn,
               int rx,
               int sockfd,
               v_ser *pser);

v_ser * vser_search(vs_list *pvslist,
                    u32 dip,
                    u16 port,
                    char *x_mark);

void vser_del(vs_list *pvslist,
              u32 dip,
              u16 port,
              char *x_mark);

v_ser * vser_add(vs_list *pvslist,
                 u32 dip,
                 u16 dport,
                 char *x_mark);

void lser_set(v_ser *pser, u32 lip, u16 lport);
void vser_del_all(vs_list *pvslist);

int  dt_empty(vs_list *pvslist);
void dt_quit(vs_list *pvslist);
void dt_print(vs_list *pvslist);

vs_list * create_dt_smem(const char * smid);
vs_list * get_dt_smem(const char * smid);

#endif // ~__VP_DISTRIBUTE_H
