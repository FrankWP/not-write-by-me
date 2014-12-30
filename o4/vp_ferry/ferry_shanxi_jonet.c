#include "../vpheader.h"
#include "pm_proxy.h"

enum e_ports
{
    L_APORT = 0,
    D_APORT,
    L_VPORT,
    D_VPORT,
    PORTS_TOTAL,
};

const static char FLG_INVITE[] = "INVITE sip";
const static char FLG_INIP[] = "IN IP4 ";
const static char FLG_MAUDIO[] = "m=audio ";
const static char FLG_MVIDEO[] = "m=video ";
const static char FLG_OK[] = "SIP/2.0 200 OK";
const static char FLG_CALLID[] = "Call-ID: ";

int jonet_init(const char *parg)
{
    if (load_portpool() < 0)
    {
        logwar_out("load port pool failed!");
        return -1;
    }
    return 1;
}

void jonet_quit()
{
    destroy_portpool();
}

int jonet_socket(pvp_uthttp put, int sockfd)
{
    return 1;
}

int jonet_recv(pvp_uthttp put, char *ut_buf, int *pack_len, int direction)
{
    return 1;
}

int jonet_replace_contact(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    char *ptr = NULL;
    char lip[16] = {0};
    char dip[16] = {0};

    //printf("----ums replace sip:%s ------>to sip:%s\n", lip, dip);
    const static char FLG_CONTACT[] = "\r\nContact: ";
    u32 host_lip = 0;
    if ((ptr = strnstr(*ut_buf, FLG_CONTACT, *pack_len, true)) != NULL)
    {
        printf("find contace flag!\n");
        ptr += sizeof(FLG_CONTACT)-1;
        if ((ptr = strnstr(ptr, "@", *pack_len - (ptr-*ut_buf), true)) == NULL)
            return -1;
        ptr += sizeof("@")-1;

        sscanf(ptr, "%[^:]", lip);
        host_lip = inet_atoul(lip);
        printf("replacce contact ip:%s\n", lip);

        if (host_lip == put->src_ip)    // client 
            inet_ultoa(__gg.outer_addr, dip);       //ums
        else if (host_lip == __gg.outer_addr)
            inet_ultoa(put->src_ip, dip);
        else if (host_lip == put->dip)
            inet_ultoa(__gg.inner_addr, dip);
        else if (host_lip == __gg.inner_addr)
            inet_ultoa(put->dip, dip);

        printf("sip:%s\n", lip);
        printf("dip:%s\n", dip);
        int nreplace = 0;
        if ((nreplace= strreplace_pos(ptr,NULL, ut_buf, lip,dip, 1, pack_len)) < 0)
            return -1;
        printf("nreplace:%d\n", nreplace);
        update_content_len(ut_buf, pack_len);
    }

    return 1;
}

int do_jonet_replace_content(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    const static char FLG_CONTACT[] = "\r\nContact:";
    char r_src[64] = {0};
    char r_dst[64] = {0};
    char cli_ip[16] = {0};
    char ums_ip[16] = {0};
    char cli_port[8] = {0};
    //char ums_port[8] = {0};
    char *ptr = NULL;
    char *p_cliport = NULL;
    SAI   laddr;
    socklen_t len = sizeof(laddr);

    if (-1 == getsockname(put->svr_sock, (struct sockaddr *)&laddr, &len))
    {
        logdbg_out("replace contact: get sockname failed!!");
        return -1;
    }
    //inet_ultoa(ntohs(laddr.sin_port), ums_port);

    if ((ptr = (char*)memmem(*ut_buf, *pack_len, FLG_CONTACT, sizeof(FLG_CONTACT)-1)) == NULL)
        return 1;
    if ((ptr = (char*)memmem(ptr, *pack_len - (ptr - *ut_buf), "@", 1)) == NULL)
        return 1;
    ptr += 1;

    if ((p_cliport = (char*)memmem(ptr, *pack_len - (ptr - *ut_buf), ":", 1)) == NULL)
    {
        logdbg_out("replace contact: cannot find port falg!");
        return -1;
    }
    p_cliport += 1;
    sscanf(p_cliport, "%[0-9]", cli_port);

    inet_ultoa(put->src_ip, cli_ip);
    inet_ultoa(__gg.outer_addr, ums_ip);
    // replace client ip to ums ip
    sprintf(r_src, "%s:%s", cli_ip, cli_port);
    //sprintf(r_dst, "%s:%s", ums_ip, ums_port);
    sprintf(r_dst, "%s:%d", ums_ip, ntohs(laddr.sin_port));
    strreplace_pos(ptr,ptr + 32, ut_buf, r_src,r_dst, 1, pack_len);

    return 1;
}

int do_sip_sdp(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    int ports[PORTS_TOTAL] = {0};
    gldata *gdata = NULL;
    char call_id[40] = {0};
    char r_src[64] = {0};
    char r_dst[64] = {0};
    char lip[16] = {0};
    char dip[16] = {0};
    //char cli_ip[16] = {0};
    char dst_audio_port[8] = {0};
    char dst_video_port[8] = {0};
    char *pIp = NULL;
    char *pAudioPort = NULL;
    char *pVideoPort = NULL;
    char *pCallId = NULL;
    u16 laudio = (u16)-1;
    u16 lvideo = (u16)-1;

    //const static char FLG_INVITE[] = "INVITE sip";
    if (memcmp(*ut_buf, FLG_INVITE, sizeof(FLG_INVITE)-1) != 0)
        return 1;

    // get call id
    if ((pCallId = (char*)memmem(*ut_buf, *pack_len, FLG_CALLID, sizeof(FLG_CALLID)-1)) == NULL)
        return -1;
    pCallId += sizeof(FLG_CALLID)-1;

    // get dest address
    if ((pIp = (char*)memmem(*ut_buf, *pack_len, FLG_INIP, sizeof(FLG_INIP)-1)) == NULL)
        return 1;
    pIp += sizeof(FLG_INIP)-1;
    // audio port
    if ((pAudioPort = (char*)memmem(*ut_buf, *pack_len, FLG_MAUDIO, sizeof(FLG_MAUDIO)-1)) != NULL)
        pAudioPort += sizeof(FLG_MAUDIO)-1;
    // video port
    if ((pVideoPort = (char*)memmem(*ut_buf, *pack_len, FLG_MVIDEO, sizeof(FLG_MVIDEO)-1)) != NULL)
        pVideoPort += sizeof(FLG_MVIDEO)-1;

    sscanf(pIp, "%[0-9.]", dip);
    memcpy(call_id, pCallId, 32);
    if (pAudioPort != NULL)
        sscanf(pAudioPort, "%[0-9]", dst_audio_port);
    if (pVideoPort != NULL)
        sscanf(pVideoPort, "%[0-9]", dst_video_port);

    puts("----------------- FERRY REQUEST ----------------");
    puts(*ut_buf);

    inet_ultoa(__gg.outer_addr, lip);
    // replace ip
    sprintf(r_src, "%s%s", FLG_INIP, dip);
    sprintf(r_dst, "%s%s", FLG_INIP, lip);
    strreplace_pos(NULL,NULL, ut_buf, r_src,r_dst, -1, pack_len);

    if ( (gdata = gl_get_data(call_id)) == NULL)
    {
        if (dst_audio_port[0] != '\0')
        {
            // get local audio port
            if ((laudio = pplist_getidle_port_x()) == 0)
            {
                logwar_out("get idle port failed!");
                return -1;
            }
            ports[L_APORT] = laudio;
            ports[D_APORT] = atoi(dst_audio_port);
        }
        if (dst_video_port[0] != '\0')
        {
            // get local video port
            if ((lvideo = pplist_getidle_port_x()) == 0)
            {
                logwar_out("get idle port failed!");
                return -1;
            }
            ports[L_VPORT] = lvideo;
            ports[D_VPORT] = atoi(dst_video_port);
        }

        if ( ! gl_set_data(call_id, (char*)ports, sizeof(ports)))
        {
            logwar_out("do_sdp_sdp: remember failed!");
            return -1;
        }
    }
    else
    {
        memcpy(ports, gdata->data, gdata->len);
        gl_rm_data(call_id);

        if (run_vs_udp_proxy(__gg.outer_addr, put->src_ip, ports[L_APORT], ports[D_APORT], 0, put->session_tout, __gg.ferry_port) < 0)
        {
            logwar_out("sdp start audio proxy failed!");
            return -1;
        }
        if (run_vs_udp_proxy(__gg.outer_addr, put->src_ip, ports[L_VPORT], ports[D_VPORT], 0, put->session_tout, __gg.ferry_port) < 0)
        {
            logwar_out("sdp start video proxy failed!");
            return -1;
        }
    }
    // start audio proxy
    sprintf(r_src, "%s%s", FLG_MAUDIO, dst_audio_port);
    sprintf(r_dst, "%s%d", FLG_MAUDIO, ports[L_APORT]);
    strreplace_pos(NULL,NULL, ut_buf, r_src,r_dst, 1, pack_len);

    sprintf(r_src, "%s%s", FLG_MVIDEO, dst_video_port);
    sprintf(r_dst, "%s%d", FLG_MVIDEO, ports[L_VPORT]);
    strreplace_pos(NULL,NULL, ut_buf, r_src,r_dst, 1, pack_len);
       
    update_content_len(ut_buf, pack_len);

    puts(*ut_buf);
    puts("=======================================");

    return 1;
}

int jonet_request(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    if (put->dport != 5060)
        return 1;
    if (*pack_len < 50)
        return 1;

    //const static char FLG_REGISTER[] = "REGISTER sip:";
    //const static char FLG_OK[] = "SIP/2.0 200 OK";
    const static char FLG_INVITE[] = "INVITE sip:";

    do_jonet_replace_content(put, ut_buf, pack_len);
    if (memcmp(*ut_buf, "REGISTER", sizeof("REGISTER")-1) == 0)
        return 1;
    if (memcmp(*ut_buf, "BYE", sizeof("BYE")-1) == 0)
        return 1;

    if (memcmp(*ut_buf, FLG_INVITE, sizeof(FLG_INVITE)-1) == 0)
        return do_sip_sdp(put, ut_buf, pack_len);

    return 1;
}

int jonet_reply(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    return 1;
}

int jonet_close(pvp_uthttp put, int sockfd)
{
    return 1;
}

int do_sip_ok(pvp_uthttp put, char **ut_buf, u32 *pack_len, int direction)
{
    char cli_ip[16] = {0};
    char l_ip[16] = {0};
    char lip[16] = {0};
    char audio_ip[16] = {0};
    char audio_port[8] = {0};
    char *pAudioIp = NULL;
    char *pAudioPort = NULL;
    u16  audio_lport = 0;
    char r_src[64] = {0};
    char r_dst[64] = {0};

    puts("-- do_sip_ok --");

    //const static char FLG_OK[] = "SIP/2.0 200 OK";
    if (memcmp(*ut_buf, FLG_OK, sizeof(FLG_OK)-1) != 0)
        return 1;
    
    inet_ultoa(put->src_ip, cli_ip);
    inet_ultoa(__gg.outer_addr, l_ip);
    strreplace(ut_buf, cli_ip,l_ip, -1, pack_len);

    // get audio ip and port
    if ((pAudioIp = (char*)memmem(*ut_buf, *pack_len, FLG_INIP, sizeof(FLG_INIP)-1)) == NULL)
        return 1;
    pAudioIp += sizeof(FLG_INIP)-1;
    if ((pAudioPort = (char*)memmem(*ut_buf, *pack_len, FLG_MAUDIO, sizeof(FLG_MAUDIO)-1)) == NULL)
        return 1;
    pAudioPort += sizeof(FLG_MAUDIO)-1;

    sscanf(pAudioIp, "%[0-9.]", audio_ip);
    sscanf(pAudioPort, "%[0-9]", audio_port);

    // get local audio port
    if ((audio_lport = pplist_getidle_port_x()) == 0)
    {
        logwar_out("get idle audio port failed!");
        return -1;
    }

    // replace audio address 
    // eth0 ip
    inet_ultoa(__gg.outer_addr, lip);
    // replace ip
    sprintf(r_src, "%s%s", FLG_INIP, audio_ip);
    sprintf(r_dst, "%s%s", FLG_INIP, lip);
    strreplace_pos(NULL,NULL, ut_buf, r_src,r_dst, -1, pack_len);

    // replace port
    sprintf(r_src, "%s%s", FLG_MAUDIO, audio_port);
    sprintf(r_dst, "%s%d", FLG_MAUDIO, audio_lport);
    strreplace_pos(NULL,NULL, ut_buf, r_src,r_dst, -1, pack_len);

    update_content_len(ut_buf, pack_len);

    //if (__start_media_proxy(V_UDP_PROXY, __gg.outer_addr, inet_atoul(audio_ip), audio_lport, atoi(audio_port), put->session_tout, __gg.ferry_port) < 0)
    if (run_vs_udp_proxy(__gg.outer_addr, inet_atoul(audio_ip), audio_lport, atoi(audio_port), 0, put->session_tout, __gg.ferry_port) < 0)
    {
        logwar_out("200 ok start audio proxy failed!");
        return -1;
    }
 
    puts(*ut_buf);
    puts("=======================================");
  
    return 1;
}

