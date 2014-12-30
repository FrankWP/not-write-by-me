/********************************************************
 *  create:     2011/12/13
 *  match file: vp_h3c.c of CLiaoNing
 *******************************************************/

#include "../vpheader.h"
#include "pm_proxy.h"

#define INITPORT   40000
#define TOTALPORT  600
#define H3C_VOD    "application/sdp"

static int run_proxy(char *cliport)
{
    clivlist *pn;
    char      psmid[32] = {0};
    clivlist *psmvn = NULL;
    char     *arg[4] = {NULL};

    if (oss_malloc(&pn, sizeof(clivlist)) < 0)
        return -1;

    pn->lvport = (u16)atoi(cliport);
    pn->dvport = pn->lvport;
    pn->lip = __gg.outer_addr;
    pn->dip = __gg.inner_priv_addr;
    pn->vstream_tout = 12;

    sprintf(psmid, "%d", get_sharemem_pid());

    if ((psmvn = create_tuvs_smem(psmid)) == NULL)
        return -1;

    memcpy(psmvn, pn, sizeof(clivlist));
    free(pn);

    arg[0] = (char*)V_UDP_PROXY;
    arg[1] = psmid;
    arg[2] = (char*)"-p";
    arg[3] = (char *)0;

    return start_vstream_proxy((char*)V_UDP_PROXY, arg);
}

int h3c_init()
{
    if (init_bind_port(INITPORT, TOTALPORT) < 0)
        return -1;
    return 1;
}

int h3c_socket(pvp_uthttp put, const int sockfd)
{
    u16 xport;
    SAI xaddr;
    int i = 0;

begin:
    if ((xport = get_idle_bind_port(NUM_EVEN)) <= 0) {
        syslog(LOG_INFO, "get idle bind port failed:[%d]", xport);
        return -1;
    }

    memset(&xaddr, 0x00, sizeof(xaddr));
    xaddr.sin_family = AF_INET;
    xaddr.sin_addr.s_addr = INADDR_ANY;
    xaddr.sin_port = htons(xport);

    if (bind(sockfd, (SA *)&xaddr, sizeof(xaddr)) < 0) {
        /* port conflict, try 10 times */
        if (++i > 20)
            return 1;
        goto begin;
    }
    return 1;
}

void h3c_quit()
{
    destroy_bind_port();
}

int x_run_proxy(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    void  *pret;
    char  cliport[8];

    /*
     *  o=H3C 0 0 IN IP4 172.16.1.11 # server_ip
     *  c=IN IP4 228.16.1.11  # client_ip
     *  m=video 10002 udp 105 # client_port
     */
    pret = memmem(*ut_buf, *pack_len, H3C_VOD, strlen(H3C_VOD));
    if (pret != NULL) {
        pret = (void *)strstr((char *)pret, "m=video");
        if (pret == NULL) {
            syslog(LOG_ERR, "transport protocol error:[H3C_GETPORT]");
            return -1;
        } else
            sscanf((char *)pret + 8, "%[0-9]", cliport);

        return run_proxy(cliport);
    }
    return 1;
}

int h3c_request(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    void   *pret = NULL;
    void   *pseq = NULL;

    pseq = memmem(*ut_buf, *pack_len, "CSeq:", 5);
    pret = memmem(*ut_buf, *pack_len, "SIP/2.0/UDP", strlen("SIP/2.0/UDP"));

    if (pret != NULL && pseq != NULL) {
        u16   rport;
        char  rip[16];
        char  cliip[16];
        char  cliport[8];
        char  saddr[32];
        char  daddr[32];
        SAI   laddr;
        socklen_t len;

        /* real video */
        if (strstr(*ut_buf, H3C_VOD) != NULL) {
            if (x_run_proxy(put, ut_buf, pack_len) < 0)
                return -1;
        }
        if (find_sip_addr(ut_buf, cliip, cliport) < 0)
            return -1;

        memset(&laddr, 0x00, sizeof(laddr));
        len = sizeof(laddr);

        if (getsockname(put->svr_sock, (struct sockaddr *)&laddr, &len) == -1)
            return -1;

        rport = ntohs(laddr.sin_port);
        inet_ultoa(__gg.outer_addr, rip);

        sprintf(saddr, "%s:%s", cliip, cliport);
        sprintf(daddr, "%s:%d", rip, rport);

        if (strstr(*ut_buf, saddr) != NULL) {
            if (strreply(ut_buf, saddr, daddr, REPLACE_ALL, pack_len) < 0)
                return -1;
        }
        if (strstr(*ut_buf, cliip) != NULL) {
            if (strreply(ut_buf, cliip, rip, REPLACE_ALL, pack_len) < 0)
                return -1;
        }
        update_content_len(ut_buf, pack_len);
    }
    return 1;
}

int setup_rtsp(pvp_uthttp put, char *ut_buf, int *pack_len)
{
    char *pdes;
    char  umsip[16];
    char  desip[16];
    u16   rport;
    char  cliport[16];
    char  xport[16];
    char *pbuf;

    inet_ultoa(__gg.outer_addr, umsip);

    if ((pdes = strstr(ut_buf, "destination=")) == NULL)
        return -1;
    sscanf(pdes + 12, "%[0-9.]", desip);

    if ((pdes = strstr(ut_buf, "client_port=")) == NULL)
        return -1;
    sscanf(pdes + 12, "%[^\r\n]", cliport);

    if ((rport = getsockport(put->svr_sock)) == 0)
        return -1;

    sprintf(xport, "%d-%d", rport, rport + 1);

    if (oss_malloc(&pbuf, *pack_len + 1) < 0)
        return -1;
    memcpy(pbuf, ut_buf, *pack_len);

    strreply(&pbuf, cliport, xport, REPLACE_ONE, (u32 *)pack_len);
    strreply(&pbuf, desip, umsip, REPLACE_ONE, (u32 *)pack_len);

    memcpy(ut_buf, pbuf, *pack_len);
    free(pbuf);
    return 1;
}

int reply_setup_rtsp(char *ut_buf)
{
    char *pret;
    char  cliport[8];

    if ((pret = strstr(ut_buf, "client_port=")) == NULL)
        return -1;
    sscanf(pret + 12, "%[^-]", cliport);

    return run_proxy(cliport);
}

/*
 *  @used for h3c web browser to request record resource.
 *  @used rtsp protocol and 554 port.
 */
int h3c_recv(pvp_uthttp put, char *ut_buf, int *pack_len, int direction)
{
    if (put->dport == 554) {
        // client request
        if (strstr(ut_buf, "SETUP rtsp://") != NULL) {
            if (setup_rtsp(put, ut_buf, pack_len) == -1) {
                syslog(LOG_ERR, "failed setup rtsp:[h3c_recv]");
                return -1;
            }
        }
        // server reply
        if (strstr(ut_buf, "source=") != NULL) {
            if (reply_setup_rtsp(ut_buf) == -1) {
                syslog(LOG_ERR, "failed reply setup rtsp:[h3c_recv]");
                return -1;
            }
        }
    }
    return 1;
}

int h3c_close(pvp_uthttp put, int sockfd)
{
    u16 xport;

    if ((xport = getsockport(put->svr_sock)) == 0)
        return -1;

    set_idle_bind_port(xport);
    return 1;
}

