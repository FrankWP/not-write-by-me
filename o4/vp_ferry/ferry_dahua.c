#include "../vpheader.h"
#include "pm_proxy.h"

#define PORT_AUTH1   9000
#define PORT_AUTH2   9100
#define PORT_HEARTBEAT 9200

#define FLG_HTTP        "POST http://"
#define FLG_XML_BODY      "<body>"
#define FLG_XML_IP      "<ip>"
#define FLG_XML_PORT    "<port>"
#define FLG_URLRTSP     "<url>rtsp://"
#define FLG_RTSP        "rtsp://"
#define FLG_SPORT       "server_port="
#define FLG_HEBET       "heartbeat"
#define FLG_CLI         "<Client>"
#define FLG_INF         "<Interface>"
#define FLG_IP          "<IP>"
#define FLG_PROG        "<Program>"
#define FLG_RTSPLI      "<RTSPListenInfo>"
#define FLG_DMZ_LIP     "<DMZListenInfo>"

//static char umsip[16];

int __dahua_init();
int rep_post_req_addr(pvp_uthttp put, char **ut_buf, u32 *pack_len);
void pre_vs_proxy(u32 lip, u32 dip, u16 vport, int tout);
void update_content_length(char **ut_buf, u32 *pack_len);

void update_content_length(char **ut_buf, u32 *pack_len)
{
    char *p;
    char olen[32];
    int  nlen;
    char slen[64];
    char dlen[64];

    p = strstr(*ut_buf, "Content-Length:");
    if (p == NULL)
        return ;

    sscanf(p + strlen("Content-Length: "), "%[^\r\n]", olen);

    p = strstr(*ut_buf, "\r\n\r\n");
    nlen = *pack_len - (p - *ut_buf) - 4;

    sprintf(slen, "Content-Length: %s", olen);
    sprintf(dlen, "Content-Length: %d", nlen);
    strreply(ut_buf, slen, dlen, REPLACE_ONE, pack_len);
}

/* replace body addr by flag <body> and <ip> */
int rep_body_ip_addr(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    puts("port 9000: replace request post addr");
    if ((memmem(*ut_buf, *pack_len, FLG_XML_BODY, sizeof(FLG_XML_BODY)-1) != NULL)
            && (memmem(*ut_buf, *pack_len, FLG_XML_IP, sizeof(FLG_XML_IP)-1) != NULL))
    {
        char *p_curr = (char*)memmem(*ut_buf, *pack_len, FLG_XML_IP, sizeof(FLG_XML_IP)-1);

        if (p_curr != NULL){
            char src_ip_addr[16] = {0};
            char dst_ip_addr[16] = {0};

            sscanf(p_curr+sizeof(FLG_XML_IP)-1, "%[^:]", src_ip_addr);
            if (strlen(src_ip_addr) == 0)
                return 1;

            inet_ultoa(put->dip, dst_ip_addr);

            memreplace_pos(NULL, NULL, ut_buf, pack_len, -1, src_ip_addr, strlen(src_ip_addr), dst_ip_addr, strlen(dst_ip_addr));
        }
    }

    update_content_length(ut_buf, pack_len);

    return 1;
}


/* replace post addr of dest port is 9000. */
int rep_post_req_addr(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    puts("port 9000: replace request post addr");

    char *p_curr = (char*)memmem(*ut_buf, *pack_len, FLG_HTTP, sizeof(FLG_HTTP)-1);

    if (p_curr != NULL){
        char src_ip_addr[16] = {0};
        char dst_ip_addr[16] = {0};

        sscanf(p_curr+sizeof(FLG_HTTP)-1, "%[^:]", src_ip_addr);
        if (strlen(src_ip_addr) == 0)
            return 1;

        inet_ultoa(put->dip, dst_ip_addr);

        memreplace_pos(NULL, NULL, ut_buf, pack_len, 1, src_ip_addr, strlen(src_ip_addr), dst_ip_addr, strlen(dst_ip_addr));
    }

    return 1;
}

int rep_cli_req_addr(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    puts("port 9000: replace request client addr");

    char *p_curr = (char*)memmem(*ut_buf, *pack_len, FLG_CLI, sizeof(FLG_CLI)-1);
    while (p_curr != NULL){
        char src_ip_addr[16] = {0};
        char dst_ip_addr[16] = {0};

        sscanf(p_curr+sizeof(FLG_CLI)-1, "%[^:]", src_ip_addr);
        inet_ultoa(put->dip, dst_ip_addr);

        memreplace_pos(NULL, NULL, ut_buf, pack_len, 1, src_ip_addr, strlen(src_ip_addr), dst_ip_addr, strlen(dst_ip_addr));

        p_curr = (char*)memmem(p_curr + sizeof(FLG_CLI) - 1, *pack_len - (p_curr - *ut_buf), FLG_CLI, sizeof(FLG_CLI)-1);
    }

    update_content_length(ut_buf, pack_len);

    return 1;
}

int rep_inf_addr(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    puts("port 9000: replace request interface addr");

    ip_pool *ipp;

    char *p_ip = NULL;
    char *p_curr = (char*)memmem(*ut_buf, *pack_len, FLG_INF, sizeof(FLG_INF)-1);
    while (p_curr != NULL){

        char src_ip_addr[16] = {0};
        char dst_ip_addr[16] = {0};

        p_ip = (char*)memmem(*ut_buf, *pack_len, FLG_IP, sizeof(FLG_IP)-1);
        if (p_ip != NULL) {
            sscanf(p_ip + sizeof(FLG_IP) - 1, "%[^<]", src_ip_addr);
            ipp = ippool_search_dip_pairs(inet_atoul(src_ip_addr));
            if (ipp != NULL) {
                inet_ultoa(ipp->lip, dst_ip_addr);
                memreplace_pos(p_ip, NULL, ut_buf, pack_len, 1, src_ip_addr, strlen(src_ip_addr), dst_ip_addr, strlen(dst_ip_addr));
            }
        }

        p_curr = (char*)memmem(p_curr + sizeof(FLG_INF) - 1, *pack_len - (p_curr - *ut_buf), FLG_INF, sizeof(FLG_INF)-1);
        p_ip = NULL;
    }

    update_content_length(ut_buf, pack_len);

    return 1;
}

int rep_prog_addr(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    puts("port 9000: replace request program addr");

    ip_pool *ipp;

    char *p_ip = NULL;
    char *p_rtsp_ip = NULL;
    char *p_dmz_lip = NULL;
    char *p_curr = (char*)memmem(*ut_buf, *pack_len, FLG_PROG, sizeof(FLG_PROG)-1);
    if (p_curr != NULL){

        char src_ip_addr[16] = {0};
        char dst_ip_addr[16] = {0};

        p_ip = (char*)memmem(p_curr, *pack_len - ( p_curr - *ut_buf ), FLG_IP, sizeof(FLG_IP)-1);
        if (p_ip != NULL) {
            sscanf(p_ip + sizeof(FLG_IP) - 1, "%[^<]", src_ip_addr);
            ipp = ippool_search_dip_pairs(inet_atoul(src_ip_addr));
            if (ipp != NULL) {
                inet_ultoa(ipp->lip, dst_ip_addr);
                memreplace_pos(p_ip, NULL, ut_buf, pack_len, 1, src_ip_addr, strlen(src_ip_addr), dst_ip_addr, strlen(dst_ip_addr));
            }
        }

        p_rtsp_ip = (char*)memmem(p_curr, *pack_len - ( p_curr - *ut_buf ), FLG_RTSPLI, sizeof(FLG_RTSPLI)-1);
        if (p_rtsp_ip != NULL) {
            sscanf(p_rtsp_ip + sizeof(FLG_RTSPLI) - 1, "%[^:]", src_ip_addr);
            ipp = ippool_search_dip_pairs(inet_atoul(src_ip_addr));
            if (ipp != NULL) {
                inet_ultoa(ipp->lip, dst_ip_addr);
                memreplace_pos(p_ip, NULL, ut_buf, pack_len, 1, src_ip_addr, strlen(src_ip_addr), dst_ip_addr, strlen(dst_ip_addr));
            }
        }

        p_dmz_lip = (char*)memmem(p_curr, *pack_len - ( p_curr - *ut_buf ), FLG_DMZ_LIP, sizeof(FLG_DMZ_LIP)-1);
        if (p_dmz_lip != NULL) {
            sscanf(p_dmz_lip + sizeof(FLG_DMZ_LIP) - 1, "%[^:]", src_ip_addr);
            ipp = ippool_search_dip_pairs(inet_atoul(src_ip_addr));
            if (ipp != NULL) {
                inet_ultoa(ipp->lip, dst_ip_addr);
                memreplace_pos(p_ip, NULL, ut_buf, pack_len, 1, src_ip_addr, strlen(src_ip_addr), dst_ip_addr, strlen(dst_ip_addr));
            }
        }
    }

    update_content_length(ut_buf, pack_len);

    return 1;
}

int rep_body_rtsp_addr(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{

    if ((memmem(*ut_buf, *pack_len, FLG_XML_BODY, sizeof(FLG_XML_BODY)-1) != NULL)
            && (memmem(*ut_buf, *pack_len, FLG_RTSP, sizeof(FLG_RTSP)-1) != NULL))
    {
        char *p_curr = (char*)memmem(*ut_buf, *pack_len, FLG_RTSP, sizeof(FLG_RTSP)-1);

        if (p_curr != NULL) {
            char src_ip_addr[16] = {0};
            char dst_ip_addr[16] = {0};

            sscanf(p_curr+sizeof(FLG_RTSP)-1, "%[^:]", src_ip_addr);
            inet_ultoa(put->dip, dst_ip_addr);

            memreplace_pos(NULL, NULL, ut_buf, pack_len, 1, src_ip_addr, strlen(src_ip_addr), dst_ip_addr, strlen(dst_ip_addr));
        }
    }

    return 1;
}


int prs_carema_url_pkg(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    puts("port 9000: start 9100");

    ip_pool *ipp;
    u16 cport;
    char sip[32] = {0};
    char dip[32] = {0};
    char s_cport[16] = {0};

    /* only for replace */
    char *p_ip = (char*)memmem(*ut_buf, *pack_len, FLG_URLRTSP, sizeof(FLG_URLRTSP)-1);
    sscanf(p_ip+sizeof(FLG_URLRTSP)-1, "%[^:]", sip);
    char *p_port = p_ip+sizeof(FLG_URLRTSP)-1+strlen(sip)+1;
    sscanf(p_port, "%[^/]", s_cport);
    cport = (u16)atoi(s_cport);

    /* search by dvr server ip */
    ipp = ippool_search_dip_pairs(put->src_ip);
    if (ipp == NULL) {
        loginf_out("no idle ip at ippool");
        return -1;
    }

    inet_ultoa(ipp->lip, dip);
    memreplace_pos(NULL, NULL, ut_buf, pack_len, -1, sip, strlen(sip), dip, strlen(dip));

    pre_vs_proxy(ipp->lip, ipp->lip, cport, 60*10);

    return 1;
}

//ip_pool * ippool_search_ip_pairs(u32 lip)

/* replace <ip> with tms ip by client ip, and send to client ip*/
/* ipp lip: tmsip cliip*/

void pre_vs_proxy(u32 lip, u32 dip, u16 vport, int tout)
{
    vp_uthtrans *pauth = NULL;
    if (oss_malloc(&pauth, sizeof(vp_uthtrans)) < 0)
        return;

    pauth->vphttp.lip = lip;
    pauth->vphttp.lport = vport;
    pauth->vphttp.dip = dip;
    pauth->vphttp.dport = vport;
    pauth->vphttp.session_tout = tout;
    pauth->vphttp.platform_id = 0;

    pauth->do_recv = NULL;
    pauth->do_request = __dahua_request;
    pauth->do_reply = __dahua_reply;
    pauth->do_close = NULL;
    pauth->vphttp.data_cache = Y_CACHE;

    load_tcp_proxy(pauth, T_DETACH);
}

int __dahua_init()
{
    if (load_ip_pool() < 0) {
        loginf_out("ferry dahua init: load ip pool failed.");
        return -1;
    }

    return 1;
}

int __dahua_socket(pvp_uthttp put, int sockfd)
{
    if ((__gg.local_priv_addr & 0xff ) == 0){
    }
    else{
        SAI xaddr;
        ip_pool *ipp;
        memset(&xaddr, 0x00, sizeof(xaddr));

        ipp = ippool_search_dip_pairs(put->src_ip);
        if (ipp == NULL) {
            loginf_out("no idle ip at ippool");
                return -1;
        }

        xaddr.sin_family = AF_INET;
        xaddr.sin_addr.s_addr = htonl(ipp->lip);
        //xaddr.sin_port = htons(put->src_port);
        xaddr.sin_port = 0;
        Setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR);

        char localip[32] = {0};
        inet_ultoa(ipp->lip, localip);
        printf("__dahua_socket: bind ip [%s] port [%d] \n", localip, xaddr.sin_port);

        if (bind(sockfd, (SA *)&xaddr, sizeof(xaddr)) < 0)
        {
            char localip[32] = {0};
            inet_ultoa(ipp->lip, localip);
            loginf_fmt("__dahua_socket: bind ip [%s] port [%d] random failed\n", localip, xaddr.sin_port);
            return -1;
        }
    }

    return 1;
}

int __dahua_recv(pvp_uthttp put, char *ut_buf, int *pack_len, int direction)
{
    return 1;
}

int __dahua_request(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{

#if 1
    /* port 9000 replace outer three video ip to inner three float ip and replace umsip to inner addr */
    if (put->dport == PORT_AUTH1) {
        /* replace addr by flag "POST http://" */
        /* replace outer three ip to inner */
        if (rep_post_req_addr(put, ut_buf, pack_len) < 0)
            return -1;
#if 0
        /* replace addr by flag "<Client>" and <IP> */
        /* replace umsip to inner */
        if (rep_cli_req_addr(put, ut_buf, pack_len) < 0)
            return -1;

        /* replace addr by flag "<Interface>" and "<IP>" */
        /* replace outer three ip to inner */
        if (rep_inf_addr(put, ut_buf, pack_len) < 0)
            return -1;

        /* replace addr by flag "<Program>" and "<IP>" and "<RTSPListenInfo>" and "<DMZListenInfo>"*/
        /* replace outer three ip to inner */
        if (rep_prog_addr(put, ut_buf, pack_len) < 0)
            return -1;

        /* replace addr by flag "<body>" and "<ip>" */
        /* replace outer three ip to inner */
        if (rep_body_ip_addr(put, ut_buf, pack_len) < 0)
            return -1;

        /* replace addr by flag "<body>" and "rtsp://"  */
        /* replace outer three ip to inner */
        if (rep_body_rtsp_addr(put, ut_buf, pack_len) < 0)
            return -1;

#endif
    }

#endif

    return 1;
}

int __dahua_reply(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    return 1;
}

int __dahua_close(pvp_uthttp put, int sockfd)
{
    return 1;
}

void __dahua_quit()
{
    free_ip_pool();
    return;
}

