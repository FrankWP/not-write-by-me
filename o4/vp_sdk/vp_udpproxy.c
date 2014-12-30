#include "common.h"
#include "vp_uthttp.h"
#include "vp_thread_setting.h"
#include "toplist.h"
#include "pool_port.h"
#include "vp_multi_protol.h"

#define EXIT_UDP_PROXY { \
    close_sock(&lsn_sock); \
    if (tset_is_flg_set(&puh->vphttp.tset, TSET_PPORT_FREE)) \
    x_set_idle_port(puh->vphttp.lport); \
    tset_clear(&puh->vphttp.tset); \
    oss_free(&puh); \
    return NULL; \
}

typedef struct UDP_PROXY_LIST {
    u32    hlen;               // http pack head len
    u32    blen;               // http pack boday len
    u32    tlen;               // http pcak total len
    char * reqst;              // reqst data buf
    int    svrsock;
    int    clisock;
    struct timeval tvlast;

    struct sockaddr_in cli_addr;
    struct sockaddr_in svr_addr;

    vp_uthttp vp_arg;

    struct list_head list;
} *pudpproxylist, udpproxylist;

const static char UDP_CONNECT_ACK[] = "ack ok";
const static int UDP_CONNECT_TIMES_TRY = 3;
const static int UDP_CONNECT_TIMEOUT = 3;

static udpproxylist *list_add_node(pvp_uthtrans puh, udpproxylist **udplist, SAI *cliaddr, 
        SAI *svraddr, int sockfd, int len)
{
    udpproxylist *pn = NULL;
    SAI           exit_addr;
    int len_zero_send_buffer = 0;
    int len_recv_buffer = __gg.sz_buffer;

    pn = (udpproxylist *)malloc(sizeof(udpproxylist));
    if (pn == NULL)
        return NULL;

    if ((pn->svrsock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        oss_free(&pn);
        return NULL;
    }

    if (setsockopt(pn->svrsock, SOL_SOCKET, SO_SNDBUF, (char *)&len_zero_send_buffer, sizeof(int)) < 0)
    {
        logdbg_out("list_add_node: 设置0发送缓冲大小失败!");
        close_sock(&pn->svrsock);
        oss_free(&pn);
        return NULL;
    }
    if (setsockopt(pn->svrsock, SOL_SOCKET, SO_RCVBUF, (char *)&len_recv_buffer, sizeof(int)) < 0)
    {
        logdbg_out("list_add_node: 设置接收缓冲大小失败!");
        close_sock(&pn->svrsock);
        oss_free(&pn);
        return NULL;
    }
    /*初始化pn*/
    memcpy(&pn->vp_arg, &puh->vphttp, sizeof(pn->vp_arg));
    pn->vp_arg.svr_sock = pn->svrsock;
    pn->vp_arg.cli_sock = sockfd;
    memcpy(&pn->vp_arg.cli_addr, cliaddr, len);
    memcpy(&pn->vp_arg.svr_addr, svraddr, sizeof(pn->vp_arg.svr_addr));

    // bind exit address
    if ((puh->vphttp.bind_video_ip != 0) || (puh->vphttp.bind_video_port != 0))
    {
        memset(&exit_addr, 0, sizeof(exit_addr));
        exit_addr.sin_family = AF_INET;
        exit_addr.sin_addr.s_addr = htonl(puh->vphttp.bind_video_ip);
        exit_addr.sin_port = htons(puh->vphttp.bind_video_port);

        if (Bind(pn->svrsock, exit_addr, sizeof(exit_addr)) < 0)
        {
            close_sock(&pn->svrsock);
            oss_free(&pn);
            return NULL;
        }
    }


    if (puh->do_socket != NULL)
    {
        if (puh->do_socket(&pn->vp_arg, pn->svrsock) < 0)
        {
            close_sock(&pn->svrsock);
            oss_free(&pn);
            return NULL;
        }
    }

    pn->tlen = 0;
    pn->reqst = NULL;
    pn->clisock = sockfd;
    gettimeofday(&pn->tvlast, NULL);
    memcpy(&pn->cli_addr, cliaddr, len);
    memcpy(&pn->svr_addr, svraddr, sizeof(pn->svr_addr));
    list_add_tail(&(pn->list), &((*udplist)->list));

    return pn;
}

static udpproxylist *list_search_cliaddr_node(udpproxylist *udplist, SAI *cliaddr)
{
    udpproxylist     *pn;
    struct list_head *pos;

    list_for_each(pos, &udplist->list){
        pn = list_entry(pos, udpproxylist, list);
        if (!memcmp(&pn->cli_addr, cliaddr, sizeof(pn->cli_addr)))
            return pn;
    }
    return NULL;
}

static udpproxylist *list_search_svrsock_node(udpproxylist *udplist, int sockfd)
{
    udpproxylist     *pn;
    struct list_head *pos;

    list_for_each(pos, &udplist->list){
        pn = list_entry(pos, udpproxylist, list);
        if (pn->svrsock == sockfd)
            return pn;
    }
    return NULL;
}

static void list_set_node(udpproxylist *pn)
{
    pn->hlen = 0;
    pn->blen = 0;
    pn->tlen = 0;
    oss_free(&(pn->reqst));

    gettimeofday(&pn->tvlast, NULL);
}

static void list_free_node(pvp_uthtrans ptrans, udpproxylist *pn, struct list_head *pos, int epfd, int *curfds)
{
    if (ptrans->do_close != NULL)
        ptrans->do_close(&ptrans->vphttp, pn->svrsock);

    list_del(pos);
    oss_free(&pn->reqst);
    epoll_ctl(epfd, EPOLL_CTL_DEL, pn->svrsock, NULL);
    close_sock(&pn->svrsock);
    oss_free(&pn);
    *curfds -= 1;
}

static void list_del_cliaddr_node(pvp_uthtrans ptrans, udpproxylist *udplist, SAI cliaddr, int epfd, int *curfds)
{
    udpproxylist     *pn;
    struct list_head *pos, *qn;

    list_for_each_safe(pos, qn, &udplist->list) {
        pn = list_entry(pos, udpproxylist, list);
        if (!memcmp(&pn->cli_addr, &cliaddr, sizeof(cliaddr))) {
            list_free_node(ptrans, pn, pos, epfd, curfds);
            return ;
        }
    }
}

static void list_del_svrsock_node(pvp_uthtrans ptrans, udpproxylist *udplist, int sockfd, int epfd, int *curfds)
{
    udpproxylist     *pn;
    struct list_head *pos, *qn;

    list_for_each_safe(pos, qn, &udplist->list) {
        pn = list_entry(pos, udpproxylist, list);
        if (pn->svrsock == sockfd) {
            list_free_node(ptrans, pn, pos, epfd, curfds);
            return ;
        }
    }
}

static void list_del_tout_node(pvp_uthtrans ptrans, udpproxylist *udplist, int session_tout, int epfd, int *curfds)
{
    int              tapart;
    udpproxylist     *pn;
    struct list_head *pos, *qn;
    struct timeval   tnow;

    gettimeofday(&tnow, NULL);
    list_for_each_safe(pos, qn, &udplist->list) {
        pn = list_entry(pos, udpproxylist, list);
        tapart = COUNTTOUT(tnow, pn->tvlast);
        if (tapart > session_tout)
            list_free_node(ptrans, pn, pos, epfd, curfds);
    }
}

static void list_del_all_node(pvp_uthtrans ptrans, udpproxylist *udplist, int epfd, int *curfds)
{
    udpproxylist     *pn;
    struct list_head *pos, *qn;

    list_for_each_safe(pos, qn, &udplist->list) {
        pn = list_entry(pos, udpproxylist, list);
        list_free_node(ptrans, pn, pos, epfd, curfds);
    }
}

static int insert_epoll_event(int epfd, int sockfd, int *curfds)
{
    struct epoll_event ev;

    ev.events = EPOLLIN /*| EPOLLET*/;
    ev.data.fd = sockfd;
    setnonblocking(sockfd);
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd, &ev) < 0) {
        syslog(LOG_INFO, "epoll add sockfd error: fd = %d", sockfd);
        return -1;
    }
    *curfds += 1;

    return 0;
}

static int tms_send_data(udpproxylist *pn, char *dbuf, u32 len, int side, vp_uthttp *pvp_arg)
{
    int ret;

    if (side == DO_REQST) 
    {
        ret = x_sendto_xy(pn->svrsock, dbuf, len,
                0, (SA*)&(pn->cli_addr), (SA *)&(pn->svr_addr), sizeof(pn->svr_addr), pvp_arg);
    } 
    else
    {
        ret = sendto(pn->clisock, dbuf, len,
                0, (SA *)&(pn->cli_addr), sizeof(pn->cli_addr));
    }
    if (ret < 0) {
       
        syslog(LOG_INFO, " tms_send_data error=[%d:%s] ", errno, strerror(errno));
        return -1;
    }

    return 1;
}

static int udp_ferry_send_data(udpproxylist *pn, char *dbuf, u32 len, int side, vp_uthttp *pvp_arg)
{
    int ret;
    vp_ferry_udp_req_t req;

    if (side == DO_REQST)
    {
        memcpy(&req, dbuf, sizeof(req));
        memset(&pn->svr_addr, 0x00, sizeof(pn->svr_addr));
        pn->svr_addr.sin_family = AF_INET;
        pn->svr_addr.sin_addr.s_addr = req.dip;
        pn->svr_addr.sin_port = req.dport;

        ret = sendto(pn->svrsock, dbuf + sizeof(req), len - sizeof(req), 0,
                (SA *)&(pn->svr_addr), sizeof(pn->svr_addr));
    }
    else 
    {
        ret = sendto(pn->clisock, dbuf, len,
                0, (SA *)&(pn->cli_addr), sizeof(pn->cli_addr));
    }
    if (ret < 0) {

        syslog(LOG_INFO, " udp_ferry_send_data error=[%d:%s]", errno, strerror(errno));
        return -1;
    }
    return 1;
}

/*
static int udp_accept(udpproxylist *pn)
{
    char ack_buf[sizeof(UDP_CONNECT_ACK)] = {0};
    SAI    peer;
    vp_ferry_udp_req_t  req;
    int nTried = UDP_CONNECT_TIMES_TRY;
    int ret = -1;
    socklen_t    len = 0;
    struct timeval tout;
    struct timeval tout_old;
    socklen_t tout_len = 0;
    int sockfd = -1;

    if (pn == NULL)
        return -1;

    //////////////////////////////////////////
    memset(&req, 0x00, sizeof(req));
    //init_sockaddr(&peer, __gg.peer_priv_addr, __gg.ferry_port);

    //req.sip = pn->cli_addr.sin_addr.s_addr;
    //req.sport = pn->cli_addr.sin_port;
    //req.dip = pn->svr_addr.sin_addr.s_addr;
    //req.dport = pn->svr_addr.sin_port;
    //req.bind_video_ip = htonl(pn->vp_arg.bind_video_ip);
    //req.bind_video_port = htons(pn->vp_arg.bind_video_port);

    len = sizeof(svr_addr);
    tout.tv_sec = UDP_CONNECT_TIMEOUT;  // Seconds Timeout
    tout.tv_usec = 0;  

    sockfd = pn->clisock;
    // get old socket timeout
    if (getsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tout_old, &tout_len) < 0)
    {
        logwar_out("udp connect get old socket timeout failed!");
        return -1;
    }
    // set socket timeout
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tout, sizeof(struct timeval)) < 0)
    {
        logwar_out("udp connect set socket timeout failed!");
        return -1;
    }

    while (nTried-- > 0)
    {
        if (recvfrom(sockfd, &req, sizeof(vp_ferry_udp_req_t), 0, (SA*)&(pn->cli_addr), &len) < 0)
        {
            if (errno == EAGAIN)
                continue;
            logwar_out("udp accept receive head failed!");
            break;
        }

        if (sendto(sockfd, &req, sizeof(vp_ferry_udp_req_t), 0, (SA*)&(pn->svr_addr), sizeof(pn->svr_addr)) < 0)
        {
            char str_ip[16] = {0};
            u32 cli_ip = pn->cli_addr.sin_addr.s_addr;
            cli_ip = ntohl(cli_ip);
            inet_ultoa(cli_ip, str_ip);
            puts(str_ip);

            logwar_fmt("error=[%d:%s]", errno, strerror(errno));
            break;
        }

        if (recvfrom(sockfd, ack_buf, sizeof(ack_buf), 0, (SA*)&(pn->svr_addr), sizeof(pn->svr_addr)) < 0)
        {
            char str_ip[16] = {0};
            u32 cli_ip = pn->cli_addr.sin_addr.s_addr;
            cli_ip = ntohl(cli_ip);
            inet_ultoa(cli_ip, str_ip);
            puts(str_ip);

            logwar_fmt("error=[%d:%s]", errno, strerror(errno));
            break;
        }
        ret = 1;
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tout_old, sizeof(struct timeval)) < 0)
    {
        logwar_out("udp connect recover socket timeout failed!");
        return -1;
    }

    return ret;
}
*/

/*
 * TMS与UMS之间，第一次通讯时，发送包头，告知vp-ferry，
 * 此会话数据的最终目的地是哪里,以及一些其他vp-ferry端可能会用到的信息
 */
/*
static int udp_connect(udpproxylist *pn)
{
    char ack_buf[sizeof(UDP_CONNECT_ACK)] = {0};
    SAI    peer;
    vp_ferry_udp_req_t  req;
    int nTried = UDP_CONNECT_TIMES_TRY;
    int ret = -1;
    socklen_t    len = 0;
    struct timeval tout;
    struct timeval tout_old;
    socklen_t tout_len = 0;
    int sockfd = -1;

    if (pn == NULL)
        return -1;

    //////////////////////////////////////////
    memset(&req, 0x00, sizeof(req));
    init_sockaddr(&peer, __gg.peer_priv_addr, __gg.ferry_port);

    req.sip = pn->cli_addr.sin_addr.s_addr;
    req.sport = pn->cli_addr.sin_port;
    req.dip = pn->svr_addr.sin_addr.s_addr;
    req.dport = pn->svr_addr.sin_port;
    req.bind_video_ip = htonl(pn->vp_arg.bind_video_ip);
    req.bind_video_port = htons(pn->vp_arg.bind_video_port);

    len = sizeof(SA);
    tout.tv_sec = UDP_CONNECT_TIMEOUT;  // Seconds Timeout
    tout.tv_usec = 0;  

    sockfd = pn->svrsock;

    if (getsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tout_old, &tout_len) < 0)
    {
        logwar_out("udp connect get old socket timeout failed!");
        return -1;
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tout, sizeof(struct timeval)) < 0)
    {
        logwar_out("udp connect set socket timeout failed!");
        return -1;
    }

    while (nTried-- > 0)
    {
        if (sendto(sockfd, &req, sizeof(vp_ferry_udp_req_t), 0, (SA*)&(pn->svr_addr), sizeof(pn->svr_addr)) < 0)
        {
            char str_ip[16] = {0};
            u32 cli_ip = pn->cli_addr.sin_addr.s_addr;
            cli_ip = ntohl(cli_ip);
            inet_ultoa(cli_ip, str_ip);
            puts(str_ip);

            logwar_fmt("error=[%d:%s]", errno, strerror(errno));
            break;
        }

        if (recvfrom(sockfd, ack_buf, sizeof(ack_buf), 0, &svr_addr, &len) < 0)
        {
            if (errno == EAGAIN)
                continue;
            logwar_out("udp connect receive ack failed!");
            break;
        }

        if (memcmp(ack_buf, UDP_CONNECT_ACK, sizeof(ack_buf)) == 0)
        {
            logwar_out("udp connect received invalud ack!");
            break;
        }

        if (sendto(sockfd, UDP_CONNECT_ACK, sizeof(UDP_CONNECT_ACK), 0, (SA*)&(pn->svr_addr), sizeof(pn->svr_addr)) < 0)
        {
            char str_ip[16] = {0};
            u32 cli_ip = pn->cli_addr.sin_addr.s_addr;
            cli_ip = ntohl(cli_ip);
            inet_ultoa(cli_ip, str_ip);
            puts(str_ip);

            logwar_fmt("error=[%d:%s]", errno, strerror(errno));
            break;
        }
        ret = 1;
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tout_old, sizeof(struct timeval)) < 0)
    {
        logwar_out("udp connect recover socket timeout failed!");
        return -1;
    }

    return ret;
}
*/

/*
 *  @ return:  -1--error; 0--have data read; 1--finish read
 *  @ side:    the operate of client request or reply
 *  @ careful: do not use strlen(buf), because have binary data
 */
static int udp_transceiver_data(pvp_uthtrans puh,
        udpproxylist **udplist, SAI *cli_addr,
        SAI *svraddr, int sockfd, int side, bool enable_chunked,
        int epfd, int *curfds, bool is_ferry, int *frm_cnt, char *buff_recv, u32 len_buff_recv )
{
    int nret = 0;
    int          ret = -1;
    int          retval;
    socklen_t    len;
    struct       sockaddr_in cliaddr;
    udpproxylist *pn = NULL;
    tset_arg     *ts_times = NULL;
    int          xsize = 0;
    char         *xbuf = NULL;
    char         *tmp_ptr = NULL;
    int         tmp_len = 0;
    vp_ferry_udp_req_t req;
    int (*udp_send_data)(udpproxylist *, char *, u32, int, vp_uthttp *) = NULL;

    udp_send_data = is_ferry ? udp_ferry_send_data : tms_send_data;

    len = sizeof(cliaddr);
    memset(&cliaddr, 0x00, len);

    if ( ( ! is_ferry) && (side == DO_REQST))
    {
        ret = recvfrom(sockfd, buff_recv + sizeof(req), len_buff_recv - sizeof(req), 0, (SA *)&cliaddr, &len);
    }
    else
    {
        ret = recvfrom(sockfd, buff_recv, len_buff_recv, 0, (SA *)&cliaddr, &len);
    }

    if (ret <= 0) 
    {
        return -1;
    }

    if (is_ferry && (side == DO_REQST))
    {
        tmp_ptr = buff_recv + sizeof(req);
        tmp_len = ret - sizeof(req);
    }
    else if (!is_ferry && (side == DO_REQST))
    {
        tmp_ptr = buff_recv + sizeof(req);
        tmp_len = ret;
    }
    else
    {
        tmp_ptr = buff_recv;
        tmp_len = ret;
    }

    ts_times = tset_fetch_arg(&puh->vphttp.tset, TSET_CONN_TIMES);
    if (side == DO_REQST)
    {
        if ((pn = list_search_cliaddr_node(*udplist, &cliaddr)) == NULL)
        {
            if (ts_times != NULL)
            {
                if (ts_times->n-- <= 0)
                    return -1;
            }

            if (is_ferry)
            {    
                memcpy(&req, buff_recv, sizeof(req));
                puh->vphttp.src_ip = ntohl(req.sip);
                puh->vphttp.src_port = ntohs(req.sport);
                puh->vphttp.dip = ntohl(req.dip);
                puh->vphttp.dport = ntohs(req.dport);
                puh->vphttp.bind_video_ip= ntohs(req.bind_video_ip);
                puh->vphttp.bind_video_port= ntohs(req.bind_video_port);
            }

            if ((pn = list_add_node(puh, udplist, &cliaddr, svraddr, sockfd, len)) == NULL)
                return -1;
            if (insert_epoll_event(epfd, pn->svrsock, curfds) < 0)
                return -1;
            if ( ! is_ferry)
            {
                pn->vp_arg.src_ip = ntohl(cliaddr.sin_addr.s_addr);
                pn->vp_arg.src_port = ntohs(cliaddr.sin_port);
            }
        }
        /*
         *            if ( is_ferry )
         *              udp_accept(pn);
         *            else
         *              udp_connect(pn);
         */

        if (puh->do_recv)
        {
            if (puh->do_recv(&pn->vp_arg, tmp_ptr, &tmp_len, DO_REQST) < 0)
                return -1;
        }
    }
    else
    {
        if ((pn = list_search_svrsock_node(*udplist, sockfd)) == NULL)
            return -1;
        if (puh->do_recv)
        {
            if (puh->do_recv(&pn->vp_arg, tmp_ptr, &tmp_len, DO_REPLY) < 0)
                return -1;
        }
    }

    if (side == DO_REQST)
    {
        ret = tmp_len + sizeof(req);
    }
    else
    {
        ret = tmp_len;
    }

    gettimeofday(&pn->tvlast, NULL);
    if (puh->vphttp.data_cache == N_CACHE) 
    {
        if (udp_send_data(pn, buff_recv, ret, side, &pn->vp_arg) < 0)
            return -1;
        goto __end;
    }

    if (side == DO_REQST)
    {
        xsize = sizeof(req);
        ret -= xsize;
    }

    if ( enable_chunked)
    {
        if ((retval = http_general_mode(&pn->reqst,
                        buff_recv + xsize, ret, &pn->tlen, &pn->hlen, &pn->blen)) <= 0)
        {
            return retval;
        }
    }
    else
    {
        if (oss_malloc(&(pn->reqst), ret + 1) < 0)
        {
            logdbg_fmt("malloc failed!(size:%d)", ret);
            return -1;
        }
        memcpy(pn->reqst, buff_recv + xsize, ret);
        pn->tlen = ret;
    }
    pn->reqst[pn->tlen] = 0x00;

    if  (side == DO_REQST && puh->do_request) 
    {
        if ((nret = puh->do_request(&pn->vp_arg, &(pn->reqst), &(pn->tlen))) <= 0)
        {
            list_set_node(pn);
            return -1;
        }
    }
    else if( side == DO_REPLY && puh->do_reply) 
    {
        if ((nret = puh->do_reply(&pn->vp_arg, &(pn->reqst), &(pn->tlen))) <= 0) 
        {
            list_set_node(pn);
            return -1;
        }
    }

    if (side == DO_REQST) 
    {
        if (oss_malloc(&xbuf, pn->tlen + xsize) < 0) 
        {
            list_set_node(pn);
            return -1;
        }
        memcpy(xbuf, buff_recv, xsize);
        memcpy(xbuf + xsize, pn->reqst, pn->tlen);
        oss_free(&(pn->reqst));
        pn->reqst = xbuf;
        pn->tlen += xsize;
    }

#if 0
    if ((frm_cnt != NULL) && (side == DO_REPLY) && g_frmp.frame_enable)
    {
        if (frame_run_count(frm_cnt))
        {
            if ( ! g_frmp.frame_modify_flg)
                return 0;
            else if (udp_send_data(pn, pn->reqst, pn->tlen, side) < 0)
                return -1;
        }
    }
#endif
    if (udp_send_data(pn, pn->reqst, pn->tlen, side, &pn->vp_arg) < 0) 
    {
        list_set_node(pn);
        return -1;
    }
__end:
    list_set_node(pn);
    return 1;
}

static void * __start_udp_proxy(void * arg, bool is_ferry)
{
    int    ret = -1;
    int    lsn_sock = -1;
    SAI    lsn_addr, cli_addr, svr_addr;
    int    i, epfd, efd, curfds = 0, nfds;
    struct epoll_event events[MAXEPOLLSIZE];
    int    frm_cnt = 1;
    bool   enable_chunked = false;
    char   buff_recv[BUF_SIZE] = {0};
    u32    len_buff_recv = sizeof(buff_recv);
    int len_zero_send_buffer = 0;
    int len_recv_buffer = __gg.sz_buffer;

    pvp_uthtrans puh = (pvp_uthtrans)arg;
    if (puh == NULL)
        return NULL;

    if ((lsn_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    {
        EXIT_UDP_PROXY;
    }

    if (setsockopt(lsn_sock, SOL_SOCKET, SO_SNDBUF, (char *)&len_zero_send_buffer, sizeof(int)) < 0)
    {
        logdbg_out("设置0发送缓冲大小失败!");
        EXIT_UDP_PROXY;
    }

    if (setsockopt(lsn_sock, SOL_SOCKET, SO_RCVBUF, (char *)&len_recv_buffer, sizeof(int)) < 0)
    {
        logdbg_out("设置接收缓冲大小失败!");
        EXIT_UDP_PROXY;
    }

    init_sockaddr(&lsn_addr, puh->vphttp.lip, puh->vphttp.lport);
    init_sockaddr(&svr_addr, puh->vphttp.dip, puh->vphttp.dport);

    if (Bind(lsn_sock, lsn_addr, sizeof(lsn_addr)) < 0) {
        EXIT_UDP_PROXY;
    }

    udpproxylist *udplist = (udpproxylist *)malloc(sizeof(udpproxylist));
    if (udplist == NULL) 
    {
        EXIT_UDP_PROXY;
    }

    INIT_LIST_HEAD(&udplist->list);

    epfd = epoll_create(MAXEPOLLSIZE);

    if (insert_epoll_event(epfd, lsn_sock, &curfds) < 0)
        goto __end;

    if (tset_is_flg_set(&puh->vphttp.tset, TSET_ENABLE_CHUNKED))
    {
        enable_chunked = true;
    }

    for (;;) 
    {
        nfds = epoll_wait(epfd, events, curfds, EPOLLWAITTIME);

        list_del_tout_node(puh, udplist, puh->vphttp.session_tout, epfd, &curfds);

        if (nfds <= 0)
        {
            continue ;
        }

        for (i = 0; i < nfds; ++i) 
        {
            efd = events[i].data.fd;

            if (efd == lsn_sock) 
            {
#if 0
                if (ip_can_through(&prio_ip_flg, puh->cliip, &prio_ip_tm) == -1)
                    break;
                if (prio_ip_flg == CLOSE)
                    break;
#endif
                ret = udp_transceiver_data(puh, &udplist, &cli_addr, &svr_addr, efd, DO_REQST, enable_chunked,
                        epfd, &curfds, is_ferry, NULL, buff_recv, len_buff_recv);
                if (ret < 0)
                    list_del_cliaddr_node(puh, udplist, cli_addr, epfd, &curfds);

            }
            else if (events[i].events & EPOLLIN) 
            {
                ret = udp_transceiver_data(puh, &udplist, &cli_addr, &svr_addr, efd, DO_REPLY, enable_chunked, 
                        epfd, &curfds, is_ferry, &frm_cnt, buff_recv, len_buff_recv);
                if (ret < 0)
                    list_del_svrsock_node(puh, udplist, efd, epfd, &curfds);
            }
        }
    }
__end:
    list_del_all_node(puh, udplist, epfd, &curfds);
    oss_free(&udplist);
    close(epfd);
    EXIT_UDP_PROXY;
}

static void * start_udp_proxy(void * arg)
{
    return __start_udp_proxy(arg, false);
}

static void * start_ferry_udp_proxy(void *arg)
{
    return __start_udp_proxy(arg, true);
}

static int __load_udp_proxy(pvp_uthtrans pu, int t_state, bool is_ferry)
{
    int       tret;
    pthread_t tid;
    tfunc_runproxy start_proxy = NULL;

    start_proxy = is_ferry ? start_ferry_udp_proxy : start_udp_proxy;

    puts("__load_udp_proxy");
    tret = pthread_create(&tid, NULL, start_proxy, (void *)pu);
    if (tret != 0)
        return -1;

    if (t_state == T_WAITING)
        pthread_join(tid, NULL);
    if (t_state == T_DETACH)
        pthread_detach(tid);
    return 1;
}

int load_udp_proxy(pvp_uthtrans pu, int t_state)
{
    return __load_udp_proxy(pu, t_state, false);
}

int load_ferry_udp_proxy(pvp_uthtrans pu, int t_state)
{
    return __load_udp_proxy(pu, t_state, true);
}
