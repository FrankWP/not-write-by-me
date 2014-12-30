#include "../vpheader.h"
#include "pm_proxy.h"

#define CLI_IP         "<MonitorIp>"
#define CLI_PORT       "<ClientRtpPort>"
#define SD_MEDSER_PORT 17999

static ip_pool *get_idle_ip(pvp_uthttp put)
{
    ip_pool *ipp = NULL;

    ipp = ippool_search_by_desaddr(put->cli_addr);
    if (ipp == NULL) {
        ipp = ippool_search_idle_addr(put->cli_addr);
        if (ipp == NULL) {
            syslog(LOG_INFO, "no idle ip at ippool.");
            return ipp;
        }
    }
    return ipp;
}

static int run_proxy(u16 nlport, u32 nlip, u32 ndip)
{
    clivlist *pn = NULL;

    if (oss_malloc(&pn, sizeof(clivlist)) < 0)
        return -1;

    pn->lvport = nlport;
    pn->dvport = nlport;
    pn->lip = nlip;
    pn->dip = ndip;
    pn->vstream_tout = 24;

    __start_vs_udp_proxy(pn, __gg.ferry_port, 0);
    free(pn);

    return 1;
}

int __sandun_init()
{
    return load_ip_pool();
}

void __sandun_quit()
{
    free_ip_pool();
    return ;
}

int __sandun_reply(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    /*
       void *pret;

       ser_ip = memmem(*ut_buf, *pack_len, "<RequesterIP>", strlen("<RequesterIP>"));
       if (ser_ip != NULL) {
       sscanf((char *)ser_ip + strlen("<RequesterIP>"), "%[^<]", cli_ip);

       if (memreplace_pos(NULL, NULL, ut_buf, pack_len,
       1, cli_ip, strlen(cli_ip), sip, strlen(sip)) < 0)
       return -1;

       blen = *pack_len - 30;
       memcpy(*ut_buf + 26, &blen, sizeof(blen));
       blen += 18;
       memcpy(*ut_buf + 4, &blen, sizeof(blen));
       memcpy(*ut_buf + 8, &blen, sizeof(blen));
       }*/
    return 1;
}

int __sandun_request(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    u32       netcliip;
    u32       hostcliip;
    u16       videoport;
    u32       netouterip;
    ip_pool  *ipp = NULL;

    /*
     *  play video.
     *  ac 13 6e 62 f9 07 00 00 00 00 00 00.
     */
    if (put->dport == SD_MEDSER_PORT && *pack_len == 12) {
        memcpy(&netcliip, *ut_buf, sizeof(netcliip));

        videoport = (u_char)(*ut_buf)[4] + (u_char)(*ut_buf)[5]*256 + 8000;
        hostcliip = ntohl(netcliip);

        if ((ipp = get_idle_ip(put)) == NULL)
            return -1;

        netouterip = htonl(ipp->lip);
        memcpy(*ut_buf, &netouterip, sizeof(netouterip)); // replace ip head

        return run_proxy(videoport, ipp->lip, hostcliip);
    }

    /*
     *  for hd dvr camera.
     *  <MonitorIp>172.19.110.98</MonitorIp>
     *  <ClientRtpPort>10002</ClientRtpPort>
     */
    char  cli_ip[16];
    char  cli_port[8];
    char  sip[16];
    void  *ser_ip = NULL;
    void  *ser_port = NULL;
    u16   blen;

    ser_ip = memmem(*ut_buf, *pack_len, CLI_IP, strlen(CLI_IP));
    ser_port = memmem(*ut_buf, *pack_len, CLI_PORT, strlen(CLI_PORT));

    if (ser_ip != NULL && ser_port != NULL) {
        sscanf((char *)ser_ip + strlen(CLI_IP), "%[^<]", cli_ip);
        sscanf((char *)ser_port + strlen(CLI_PORT), "%[^<]", cli_port);

        videoport = (u16)atoi(cli_port);
        hostcliip = inet_atoul(cli_ip);

        if ((ipp = get_idle_ip(put)) == NULL)
            return -1;

        //inet_ultoa(ipp->lip, sip);
        inet_ultoa(__gg.outer_addr, sip);
        if (memreplace_pos(NULL, NULL, ut_buf, pack_len,
                    1, cli_ip, strlen(cli_ip), sip, strlen(sip)) < 0)
            return -1;

        blen = *pack_len - 30;
        memcpy(*ut_buf + 26, &blen, sizeof(blen));
        blen += 18;
        memcpy(*ut_buf + 4, &blen, sizeof(blen));
        memcpy(*ut_buf + 8, &blen, sizeof(blen));

        return run_proxy(videoport, __gg.outer_addr, hostcliip);
    }

    /*
       inet_ultoa(__gg.outer_addr, sip);

       ser_ip = memmem(*ut_buf, *pack_len, "<RequesterIP>", strlen("<RequesterIP>"));
       if (ser_ip != NULL) {
       sscanf((char *)ser_ip + strlen("<RequesterIP>"), "%[^<]", cli_ip);

       if (memreplace_pos(NULL, NULL, ut_buf, pack_len,
       1, cli_ip, strlen(cli_ip), sip, strlen(sip)) < 0)
       return -1;

       blen = *pack_len - 30;
       memcpy(*ut_buf + 26, &blen, sizeof(blen));
       blen += 18;
       memcpy(*ut_buf + 4, &blen, sizeof(blen));
       memcpy(*ut_buf + 8, &blen, sizeof(blen));
       }

       ser_ip = memmem(*ut_buf, *pack_len, "<UserIPAddr>", strlen("<UserIPAddr>"));
       if (ser_ip != NULL) {
       sscanf((char *)ser_ip + strlen("<UserIPAddr>"), "%[^<]", cli_ip);

       if (memreplace_pos(NULL, NULL, ut_buf, pack_len,
       1, cli_ip, strlen(cli_ip), sip, strlen(sip)) < 0)
       return -1;

       blen = *pack_len - 30;
       memcpy(*ut_buf + 26, &blen, sizeof(blen));
       blen += 18;
       memcpy(*ut_buf + 4, &blen, sizeof(blen));
       memcpy(*ut_buf + 8, &blen, sizeof(blen));
       }

       ser_ip = memmem(*ut_buf, *pack_len, "<MonitorIp>", strlen("<MonitorIp>"));
       if (ser_ip != NULL) {
       sscanf((char *)ser_ip + strlen("<MonitorIp>"), "%[^<]", cli_ip);

       if (memreplace_pos(NULL, NULL, ut_buf, pack_len,
       1, cli_ip, strlen(cli_ip), sip, strlen(sip)) < 0)
       return -1;

       blen = *pack_len - 30;
       memcpy(*ut_buf + 26, &blen, sizeof(blen));
       blen += 18;
       memcpy(*ut_buf + 4, &blen, sizeof(blen));
       memcpy(*ut_buf + 8, &blen, sizeof(blen));
       }*/
    return 1;
}

int __sandun_close(pvp_uthttp put, int sockfd)
{
    ip_pool *ipp = NULL;

    ipp = ippool_search_by_desaddr(put->cli_addr);
    if (ipp != NULL)
        ippool_rset_flag(put->cli_addr);

    return 1;
}
