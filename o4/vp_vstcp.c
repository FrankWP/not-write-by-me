#include "vpheader.h"

static   u16      g_vport;
static   pp_list *t_pplist;
static   bool     g_pport = false;
static   bool     g_distb = false;

static   char     g_times = 0;
static   char     psmid[32] = {0};
static   SAI      peer;
static   int      g_numconn = 0;
pthread_mutex_t   g_mutex = PTHREAD_MUTEX_INITIALIZER;

#define add_numconn() do { \
    pthread_mutex_lock(&g_mutex); \
    g_numconn += 1; \
    pthread_mutex_unlock(&g_mutex); \
} while (0)

#define del_numconn() do { \
    pthread_mutex_lock(&g_mutex); \
    g_numconn -= 1; \
    pthread_mutex_unlock(&g_mutex); \
} while (0)

void quit_system(int n)
{
    if (strlen(psmid) > 0)
        shm_unlink(psmid);
    if (g_pport) {
        pplist_set_flag(t_pplist, g_vport);
    }
    pthread_mutex_destroy(&g_mutex);

#if 0
    if (n != PF_DISMISSED)
        pf_away_home(); // away process family, so process home won't send signal to curent process's pid.
#endif

#if 0
    modmysql_close();
    pf_away_home(); // away process family, so process home won't send signal to curent process's pid.
#endif
    exit(n);
}

/*
   int count_flow(long bytes)
   {
   const static char FLOW_VAL[] = "flow_val";
   const static char FLOW_TIME[] = "flow_tm";
   const static int interval = 5;
   tdata *pflow = NULL;
   tdata *ptime = NULL;
   time_t tnow = time(0);
   time_t told = 0;
   long len = 0;

   if ((ptime = tp_get_data(FLOW_TIME)) == NULL)
   {
   tp_set_data(FLOW_TIME, (char*)&tnow, sizeof(tnow));
//logdbg_fmt("tnow: %ld", tnow);
told = tnow;
}
else 
{
memcpy(&told, ptime->data, ptime->len);
}

if ((pflow = tp_get_data(FLOW_VAL)) == NULL)
{
tp_set_data(FLOW_VAL, (char*)&len, sizeof(len));
}
else
{
memcpy(&len, pflow->data, pflow->len);
}

len += bytes;
tp_mod_data(FLOW_VAL, (char*)&len, sizeof(len));

if (tnow - told > interval)
{
logdbg_fmt("rate: %ld kB/s", len/interval/1024);
len = 0;
tp_mod_data(FLOW_VAL, (char*)&len, sizeof(len));
tp_mod_data(FLOW_TIME, (char*)&tnow, sizeof(tnow));
}

return len;
}
*/

int transceiver_pack(clivlist *pn, int operate, int rsock, int ssock, int *frm_cnt)
{
    int  rx;
    u32  ulen;
    char buf[BUF_SIZE];

    //struct timeval start;
    //struct timeval end;
    //int use;
#if 0
    int prio_ip_flg = 1;
    time_t prio_ip_tm = time(NULL);
#endif

    ulen = sizeof(peer);
    memset(buf, 0x00, BUF_SIZE);

    //gettimeofday(&start, NULL);
    if ((rx = recv(rsock, buf, BUF_SIZE, 0)) <= 0)
        return -1;
    //gettimeofday(&end, NULL);
    //use = 1000*1000*(end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec);
    //logdbg_fmt("recv %d bytes use time:%d", rx, use);
    //logdbg_fmt("speed %d bytes/usec", rx/use);

    /*
       if (operate == DO_REPLY)
       {
       const static char FLG_TIMES[] = "times";
       tdata *pdata = NULL;
       int n = 1;
       if ((pdata = tp_get_data(FLG_TIMES)) == NULL)
       tp_set_data(FLG_TIMES, (char*)&n, sizeof(n));
       else
       {
       memcpy(&n, pdata->data, pdata->len);
       ++n;
       tp_mod_data(FLG_TIMES, (char*)&n, sizeof(n));
       }
       if (n > 100)
       {
       count_flow(rx);
       return 0;
       }
    //return 0;
    }
    */

#if 0
    ip_can_through(&prio_ip_flg, pn->cliip, &prio_ip_tm);
    if (prio_ip_flg == 0)
    {
        loginf_out("服务器网络流量达到预定峰值，当前用户视频退出!");
        return -1;
    }

    if ((operate == DO_REPLY) && (frm_cnt != NULL) && g_frmp.frame_enable)
    {
        if (frame_run_count(frm_cnt))
        {
            if (!g_frmp.frame_modify_num)
                return 0;
            else if (Send(ssock, buf, rx, 0) < 0)
                return -1;
        }
    }
#endif

    //gettimeofday(&start, NULL);
    if (Send(ssock, buf, rx, MSG_NOSIGNAL) < 0)
        return -1;
    //gettimeofday(&end, NULL);
    //use = 1000*1000*(end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec);
    //logdbg_fmt("send %d bytes use time:%d", rx, use);

    if (operate == DO_REQST && g_times == 0) {
        getpeername(rsock, (struct sockaddr *)&peer, &ulen);
        g_times = 1;
    }

    if (operate == DO_REPLY && pn->platform_id > 0) {
        write_flow_value(pn->visit_user, ntohl(peer.sin_addr.s_addr),
                ntohs(peer.sin_port), pn->dip, pn->dvport,
                pn->camera_id, rx, pn->platform_id);
    }
    return 0;
}

static int init_uthtrans( pvp_uthtrans puthtrans, clivlist *pcvn)
{
    puthtrans->vphttp.src_ip = pcvn->sip;
    puthtrans->vphttp.src_port = pcvn->sport;
    puthtrans->vphttp.dip = pcvn->dip;
    puthtrans->vphttp.dport = pcvn->dvport;
    puthtrans->vphttp.bind_video_ip = pcvn->bind_video_ip;
    puthtrans->vphttp.bind_video_port = pcvn->bind_video_port;

    return 0;
}
void * __run_tcp_proxy(void * args)
{
    int            maxfd;
    int            svrsock;
    fd_set         rfds;
    clivlist     * pcvn;
    struct timeval tv;
    //SAI            cli_addr;
    int            frm_cnt = 1;
    vp_uthtrans     uthtrans;

#if 0
    const static time_t cert_ck_interval = 3;
    time_t         t_now = 0;
    time_t         t_old = 0;
    char           cliip[16] = {0};
#endif

    if ((pcvn = (clivlist *)args) == NULL)
        return NULL;

    if ((svrsock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
        goto __end;
    memset(&uthtrans, 0x00, sizeof(uthtrans));
    init_uthtrans(&uthtrans, pcvn);

#if 0
    if (tcp_connect(pcvn->sip, pcvn->sport, pcvn->dip, pcvn->dvport, &pcvn->tset, svrsock, 10) < 0)
        goto __end;
#endif

    
    if ( tcp_connect(svrsock, 5, &uthtrans) < 0 )
        goto __end;

    maxfd = (int)pcvn->sockfd > svrsock ? (int)pcvn->sockfd : svrsock;

    //cli_addr.sin_addr.s_addr = ntohl(pcvn->cliip);
    for (;;) {
        FD_ZERO(&rfds);
        FD_SET(svrsock, &rfds);
        FD_SET(pcvn->sockfd, &rfds);

        tv.tv_sec = pcvn->vstream_tout;
        tv.tv_usec = 0;

        if (Select(maxfd, &rfds, NULL, NULL, &tv) <= 0)
            break ;

        if (FD_ISSET(pcvn->sockfd, &rfds)) {
#if 0
            t_now = time(NULL);
            if (cert_is_enable() && ((t_now - t_old) > cert_ck_interval))
            {
                if ( ! test_user_cert(cli_addr))
                {
                    inet_ntop(AF_INET, &cli_addr.sin_addr, cliip, 15);
                    loginf_fmt("用户证书无效. IP:%s", cliip);
                    break;
                }
                t_old = t_now;
            }
#endif
            if (transceiver_pack(pcvn, DO_REQST, pcvn->sockfd, svrsock, NULL) < 0)
                break ;
        }
        if (FD_ISSET(svrsock, &rfds)) {
#if 0
            if (cert_is_enable() && ((t_now - t_old) > cert_ck_interval))
            {
                if ( ! test_user_cert(cli_addr))
                {
                    inet_ntop(AF_INET, &cli_addr.sin_addr, cliip, 15);
                    loginf_fmt("用户证书无效. IP:%s", cliip);
                    break;
                }
                t_old = t_now;
            }
#endif
            if (transceiver_pack(pcvn, DO_REPLY, svrsock, pcvn->sockfd, &frm_cnt) < 0)
                break ;
        }
    }
__end:
    free(pcvn);
    del_numconn();
    close_sock((int *)&pcvn->sockfd);
    close_sock(&svrsock);
    return NULL;
}

void __start_tcp_proxy(clivlist *pcvn)
{
    int         len;
    int         lsn_sock;
    int         connfd;
    int         thread_id;
    SAI         lisaddr;
    SAI         cliaddr;
    clivlist  * pn;
    pthread_t   thread_t;

    if ((lsn_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
        return ;

    init_sockaddr(&lisaddr, pcvn->lip, pcvn->lvport);

    if (Bind(lsn_sock, lisaddr, sizeof(lisaddr)) < 0)
        goto __end;

    if (Setsockopt(lsn_sock, SOL_SOCKET, SO_REUSEADDR) < 0)
        goto __end;

    listen(lsn_sock, 200);

    len = sizeof(cliaddr);

    for (;;) {
        connfd = noblock_accept(lsn_sock, (SA *)&cliaddr, len, pcvn->vstream_tout);
        if (connfd < 0)
            break ;
        if (connfd == 0) {
            if (g_numconn == 0)
                break ;
            continue ;
        }

        pn = (clivlist *)malloc(sizeof(clivlist));
        if (pn == NULL)
            break ;

        memcpy(pn, pcvn, sizeof(clivlist));
        pn->sockfd = connfd;
        pn->cliip = ntohl(cliaddr.sin_addr.s_addr);
        pn->cliport = ntohs(cliaddr.sin_port);
        add_numconn();

        thread_id = pthread_create(&thread_t, NULL, __run_tcp_proxy, (void *)pn);
        if (thread_id == 0)
            pthread_detach(thread_t);
    }
__end:
    close_sock(&lsn_sock);
}

/*
 *  @ argc:    must eq 3
 *  @ argv[0]: vp-vstcp
 *  @ argv[1]: platform id
 *  @ argv[2]: -pdn
 *  @ -p:      use pool port
 *  @ -d:      use distribute
 *  @ -n:      default
 */
int getarg(int argc, char * argv[])
{
    char * opt;

    int n = 0;
    for (; n < argc; ++n)
    {
        if (strcmp(argv[n], "-v") == 0)
        {
            printf("%s\n", MTP_VERSION_STR);
            exit(0);
        }
    }

    if (argc < 3) {
        syslog(LOG_ERR, "videostream process param error");
        return -1;
    }
    for (opt = argv[2]; *opt != '\0'; opt++) {
        if (*opt == 'p')
            g_pport = true;
        if (*opt == 'd')
            g_distb = true;
    }
    return 1;
}

int main(int argc, char *argv[])
{
    clivlist *pcvn = NULL;

    if (getarg(argc, argv) < 0)
        quit_system(DO_EXIT);

    signal(SIGTERM, quit_system);
    signal(SIGINT, quit_system);
    signal(SIGPIPE, SIG_IGN);

    if (__load_general_config() < 0)
        quit_system(DO_EXIT);
    if ((argc == 4) && (atoi(argv[3]) > 0))
        __gg.ferry_port = atoi(argv[3]);

#if 0
    if ( ! pf_init_member(quit_system, 0))
    {
        loginf_out("vstcp: init process family failed!");
        quit_system(DO_EXIT);
    }
#endif

    strcpy(psmid, argv[1]);
    if ((pcvn = create_tuvs_smem(psmid)) == NULL)
    {
        psmid[0] = '\0';
        quit_system(DO_EXIT);
    }

    if (g_pport) {
        t_pplist = create_pp_smem(PP_SMNAME);
        g_vport = pcvn->lvport;
    }
#if 0
    if ( ! modmysql_open(DB_NAME, 1))
    {
        loginf_out("数据库初始失败!");
    }
    else if (init_prio_ip_para(pcvn->platform_id, pcvn->dip) == -1)
    {
        loginf_out("优先级IP初始失败!");
    }

    load_user_cert();
    init_frame_paras();
#endif
    __start_tcp_proxy(pcvn);
    quit_system(DO_EXIT);
    return 0;
}

