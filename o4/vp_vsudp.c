#include "vpheader.h"

static   char     psmid[32] = {0};
static   u16      g_vport;
static   pp_list *u_pplist;
static   bool     g_pport = false;  // use port pool
static   bool     g_distb = false;  // use distribute
static   bool     g_ippool = false; // use ip pool

static void quit_system(int n)
{
    if (strlen(psmid) > 0)
        shm_unlink(psmid);
    if (g_pport)
        pplist_set_flag(u_pplist, g_vport);
#if 0
    if (n != PF_DISMISSED)
        pf_away_home(); // away process family, so process home won't send signal to curent process's pid.
#endif
    exit(n);
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

void response_dealwith(clivlist *pcvn, int lsn_sock, int svr_sock, SAI lsn_addr, SAI svr_addr)
{
    char           buf[BUF_SIZE];
    int            ret, maxfd, rx;
    fd_set         rfds;
    SAI            cli_addr;
    SAI            svr1_addr;
    socklen_t      clilen, svrlen;
    struct timeval tv;
    vp_uthtrans     uthtrans;
    vp_ferry_udp_req_t  req;

#if 0
    const static time_t cert_ck_interval = 3;
    int			   frm_cnt = 1;
    time_t		   t_now = 0;
    time_t		   t_old = 0;
    char		   cliip[16] = {0};
    int            prio_ip_flg = THROUGH;
    time_t         prio_ip_tm = time(NULL);
#endif

    memset(&uthtrans, 0x00, sizeof(uthtrans));
    init_uthtrans(&uthtrans, pcvn);

    clilen = sizeof(cli_addr);
    svrlen = sizeof(svr1_addr);

    maxfd = lsn_sock > svr_sock ? lsn_sock : svr_sock;

    for (;;) {
        FD_ZERO(&rfds);
        FD_SET(lsn_sock, &rfds);
        FD_SET(svr_sock, &rfds);

        if (pcvn->vstream_tout == (u16)-1)
        {
            if (Select(maxfd, &rfds, NULL, NULL, NULL) <= 0)
                break ;
        }
        else
        {
            tv.tv_sec = pcvn->vstream_tout;
            tv.tv_usec = 0;

            if (Select(maxfd, &rfds, NULL, NULL, &tv) <= 0)
                break ;
        }

        memset(buf, 0x00, BUF_SIZE);

        if (FD_ISSET(lsn_sock, &rfds)) 
        {
            rx = recvfrom(lsn_sock, buf + sizeof(req), BUF_SIZE - sizeof(req), 0, (SA *)&cli_addr, &clilen);
            if (rx <= 0)
                break ;
#if 0
            t_now = time(NULL);
            inet_ntop(AF_INET, &(cli_addr.sin_addr), cliip, 15);
            ip_can_through(&prio_ip_flg, cli_addr.sin_addr.s_addr, &prio_ip_tm);
            if (prio_ip_flg == 0)
            {
                loginf_fmt("服务器网络流量达到预定峰值，当前用户视频退出! IP:%s", cliip);
                break;
            }

            if (cert_is_enable() && ((t_now - t_old) > cert_ck_interval))
            {
                if ( ! test_user_cert(cli_addr))
                {
                    loginf_fmt("用户证书无效. IP:%s", cliip);
                    break;
                }
                t_old = t_now;
            }
#endif

            //if (g_pport)
            //ret = sendto(svr_sock, buf, rx, 0, (SA *)&svr_addr, sizeof(svr_addr));
            //else
            ret = x_sendto_xy(svr_sock, buf, rx + sizeof(req), 0, (SA *)&cli_addr, (SA *)&svr_addr, sizeof(svr_addr), &uthtrans.vphttp);
            if (ret <= 0)
                break ;
        }

        if (FD_ISSET(svr_sock, &rfds)) 
        {
            rx = recvfrom(svr_sock, buf, BUF_SIZE, 0, (SA *)&svr1_addr, &svrlen);
            if (rx <= 0)
                break ;
#if 0
            inet_ntop(AF_INET, &(cli_addr.sin_addr), cliip, 15);
            ip_can_through(&prio_ip_flg, cli_addr.sin_addr.s_addr, &prio_ip_tm);
            if (prio_ip_flg == 0)
            {
                loginf_fmt("服务器网络流量达到预定峰值，当前用户视频退出! IP:%s", cliip);
                break;
            }

            if (cert_is_enable() && ((t_now - t_old) > cert_ck_interval))
            {
                if ( ! test_user_cert(cli_addr))
                {
                    loginf_fmt("用户证书无效. IP:%s", cliip);
                    break;
                }
                t_old = t_now;
            }

            if (g_frmp.frame_enable && frame_run_count(&frm_cnt))
            {
                if ( ! g_frmp.frame_modify_flg)
                    continue;
                else
                {
                    ret = sendto(lsn_sock, buf, rx, 0, (SA *)&cli_addr, sizeof(cli_addr));
                    if (ret < 0)
                        break ;
                }
            }
#endif
            ret = sendto(lsn_sock, buf, rx, 0, (SA *)&cli_addr, sizeof(cli_addr));
            if (ret < 0)
                break ;
        }

        if (pcvn->platform_id > 0) {
            write_flow_value(pcvn->visit_user,
                    pcvn->cliip, ntohs(cli_addr.sin_port), pcvn->dip,
                    pcvn->dvport, pcvn->camera_id, rx, pcvn->platform_id);
        }
    }
    close_sock(&lsn_sock);
    close_sock(&svr_sock);
}

void * run_vs_proxy(void * arg)
{
    int        lsn_sock;
    int        svr_sock;
    SAI        lsn_addr;
    SAI        svr_addr;
    clivlist * pcvn;
    int len_zero_send_buffer = 0;
    int len_recv_buffer = __gg.sz_buffer;

    if ((pcvn = (clivlist *)arg) == NULL)
        return NULL;

    init_sockaddr(&lsn_addr, pcvn->lip, pcvn->lvport);
    init_sockaddr(&svr_addr, pcvn->dip, pcvn->dvport);

    lsn_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    svr_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (lsn_sock < 0 || svr_sock < 0)
        return NULL;

    if (Setsockopt(lsn_sock, SOL_SOCKET, SO_REUSEADDR) < 0
            || Setsockopt(svr_sock, SOL_SOCKET, SO_REUSEADDR) < 0)
        return NULL;

    if (Bind(lsn_sock, lsn_addr, sizeof(lsn_addr)) < 0)
        return NULL;
     
    if (setsockopt(lsn_sock, SOL_SOCKET, SO_SNDBUF, (char *)&len_zero_send_buffer, sizeof(int)) < 0)
    {
        close_sock(&lsn_sock);
        close_sock(&svr_sock);
        return NULL;
    } 
    if (setsockopt(lsn_sock, SOL_SOCKET, SO_RCVBUF, (char *)&len_recv_buffer, sizeof(int)) < 0)
    {
        close_sock(&lsn_sock);
        close_sock(&svr_sock);
        return NULL;
    }
 
    if (setsockopt(svr_sock, SOL_SOCKET, SO_SNDBUF, (char *)&len_zero_send_buffer, sizeof(int)) < 0)
    {
        close_sock(&lsn_sock);
        close_sock(&svr_sock);
        return NULL;
    }   
    if (setsockopt(svr_sock, SOL_SOCKET, SO_RCVBUF, (char *)&len_recv_buffer, sizeof(int)) < 0)
    {
        close_sock(&lsn_sock);
        close_sock(&svr_sock);
        return NULL;
    }

    response_dealwith(pcvn, lsn_sock, svr_sock, lsn_addr, svr_addr);
    return NULL;
}

/*
 *  @ argc:    must eq 3
 *  @ argv[0]: vp-vsudp
 *  @ argv[1]: platform id
 *  @ argv[2]: -pdn
 *  @ argv[3]: private dest port
 *  @ -p:      use pool port
 *  @ -d:      use distribute
 *  @ -i:      use ip pool
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
        syslog(LOG_ERR, "videostream process param error.");
        return -1;
    }
    for (opt = argv[2]; *opt != '\0'; opt++) {
        if (*opt == 'p')
            g_pport = true;
        if (*opt == 'd')
            g_distb = true;
        if (*opt == 'i')
            g_ippool = true;
    }
    return 1;
}

int main(int argc, char * argv[])
{
    int        td;
    pthread_t  pt;
    clivlist * pvstream;

    if (getarg(argc, argv) < 0)
        return -1;

    signal(SIGTERM, quit_system);
    signal(SIGINT, quit_system);
    signal(SIGPIPE, SIG_IGN);

    memcpy(psmid, argv[1], strlen(argv[1]));

    if (__load_general_config() < 0)
    {
        loginf_out("vsudp: load general config failed!");
        quit_system(DO_EXIT);
    }
    if ((argc == 4) && (atoi(argv[3]) > 0))
        __gg.ferry_port = atoi(argv[3]);

#if 0
    if ( ! pf_init_member(quit_system, 0))
    {
        loginf_out("vsudp: init process family failed!");
        quit_system(DO_EXIT);
    }
#endif

    if ((pvstream = create_tuvs_smem(psmid)) == NULL)
        quit_system(DO_EXIT);

    if (g_pport) {
        u_pplist = create_pp_smem(PP_SMNAME);
        g_vport = pvstream->lvport;
    }

#if 0
    load_user_cert();
    init_frame_paras();

    if ( ! modmysql_open(DB_NAME, 1))
    {
        loginf_out("数据库初始失败!");
    }
    else if (init_prio_ip_para(pvstream->platform_id, pvstream->lip) == -1)
    {
        loginf_out("优先级IP初始失败!");
    }
#endif

    td = pthread_create(&pt, NULL, run_vs_proxy, (void *)pvstream);
    if (td != 0)
        quit_system(DO_EXIT);

    pthread_join(pt, NULL);
    quit_system(DO_EXIT);
    return 0;
}
