#include "../vpheader.h"
#include "pm_proxy.h"

static char g_ums_ip[16] = {0};
static gldata *gdata = NULL;

const static char FLG_CICODE[] = "<CamIndexCode>";

int hik_fcg_init();
int hik_fcg_request(pvp_uthttp put, char **ut_buf, u32 *pack_len);

int hik_fcg_init()
{
    if ( ! load_portpool())
    {
        logwar_out("load port pool failed!");
        return -1;
    }
    inet_ultoa(__gg.outer_addr, g_ums_ip);

    return 1;
}

void hik_fcg_quit()
{
    destroy_portpool();
}

static int run_vs_tcp_proxy(u32 lip, u32 dip, u16 lport, u16 dport, u16 bport, int pmid, int tout, int ferry_port)
{
    int ret = -1;
    clivlist *pcvn = NULL;
    oss_malloc(&pcvn, sizeof(clivlist));
    if (pcvn == NULL)
        return -1;

    pcvn->lip = lip;
    pcvn->dip = dip;
    pcvn->lvport = lport;
    pcvn->dvport = dport;
    pcvn->bind_video_port = bport;
    pcvn->platform_id = pmid;
    pcvn->vstream_tout = tout;

    printf("run_vs_tcp_proxy: ferry_port:%d\n", ferry_port);
    ret = __start_vs_tcp_proxy(pcvn, true, ferry_port);
    oss_free(&pcvn);

    return ret;
}

static int run_vs_udp_proxy(u32 lip, u32 dip, u16 lport, u16 dport, u16 bport, int pmid, int tout, int ferry_port)
{
    int ret = -1;
    clivlist *pcvn = NULL;
    oss_malloc(&pcvn, sizeof(clivlist));
    if (pcvn == NULL)
        return -1;

    pcvn->lip = lip;
    pcvn->dip = dip;
    pcvn->lvport = lport;
    pcvn->dvport = dport;
    pcvn->bind_video_port = bport;
    pcvn->platform_id = pmid;
    pcvn->vstream_tout = tout;

    printf("run_vs_tcp_proxy: ferry_port:%d\n", ferry_port);
    ret = __start_vs_udp_proxy(pcvn, true, ferry_port);
    oss_free(&pcvn);

    return ret;
}


// for cascade 
int do_cascade_request(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    const static char FLG_IP[] = "<Route ip=\"";
    const static char FLG_PORT[] = "port=\"";
    //const static char FLG_LINK_TYPE_UDP[] = "link=\"UDP\"";
    const static char FLG_LINK_TYPE_TCP[] = "link=\"TCP\"";
    const static int OFFSET_LEN_PKG = 6;
    int link_type = P_UDP_PROXY;
    char *ptr = NULL;
    char dip[16] = {0};
    char dport[8] = {0};
    char r_src[64] = {0};
    char r_dst[64] = {0};
    char bindport[8] = {0};
    u16 lport = 0;
    u16 len_pkg = 0;

    char camindexcode[20] = {0};
    if ((ptr = (char*)memmem(*ut_buf, *pack_len, FLG_CICODE, sizeof(FLG_CICODE)-1)) == NULL)
        return 1;
    ptr += sizeof(FLG_CICODE)-1;
    sscanf(ptr, "%[0-9]", camindexcode);

    if ((ptr = (char*)memmem(*ut_buf, *pack_len, FLG_IP, sizeof(FLG_IP)-1)) == NULL)
        return 1;
    ptr += sizeof(FLG_IP)-1;
    sscanf(ptr, "%[0-9.]", dip);

    if ((ptr = (char*)memmem(*ut_buf, *pack_len, FLG_PORT, sizeof(FLG_PORT)-1)) == NULL)
        return 1;
    ptr += sizeof(FLG_PORT)-1;
    sscanf(ptr, "%[^\"]", dport);

    if (memmem(*ut_buf, *pack_len, FLG_LINK_TYPE_TCP, sizeof(FLG_LINK_TYPE_TCP)-1) != NULL)
        link_type = P_TCP_PROXY;

    if ((lport = pplist_getidle_port_x()) == 0)
    {
        logwar_out("get idle port failed!");
        return -1;
    }

    sprintf(bindport, "%d", lport);
    gl_set_data(camindexcode, bindport, sizeof(bindport));

    if (link_type == P_TCP_PROXY)
        //run_vs_tcp_proxy(put->lip, inet_atoul(dip), lport, atoi(dport), put->session_tout, __gg.ferry_port);
        run_vs_tcp_proxy(__gg.outer_addr, inet_atoul(dip), lport, atoi(dport), lport, 0, put->session_tout, __gg.ferry_port);
    else
        //run_vs_udp_proxy(put->lip, inet_atoul(dip), lport, atoi(dport), put->session_tout, __gg.ferry_port);
        run_vs_udp_proxy(__gg.outer_addr, inet_atoul(dip), lport, atoi(dport), lport, 0, put->session_tout, __gg.ferry_port);

    //puts("1 --  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
    //t_disbuf(*ut_buf, *pack_len);

    // replace ip
    sprintf(r_src, "%s%s", FLG_IP, dip);
    sprintf(r_dst, "%s%s", FLG_IP, g_ums_ip);
    //puts(r_src);
    //puts(r_dst);
    //puts("2 --  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
    //strreplace_pos(ut_buf, r_src,r_dst, 1, pack_len);
    strreplace_pos(NULL,NULL, ut_buf, r_src, r_dst, 1, pack_len);
    // replace port
    sprintf(r_src, "%s%s", FLG_PORT, dport);
    sprintf(r_dst, "%s%d", FLG_PORT, lport);
    //puts(r_src);
    //puts(r_dst);
    //puts("3 --  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
    //strreplace(ut_buf, r_src,r_dst, 1, pack_len);
    strreplace_pos(NULL, NULL, ut_buf, r_src, r_dst, 1, pack_len);

    // update pkg len
    memcpy(&len_pkg, *ut_buf + OFFSET_LEN_PKG, 2);
    printf("len_pkg_old:%d\n", ntohs(len_pkg));

    len_pkg = (u16)*pack_len;
    printf("len_pkg:%d\n", len_pkg);
    len_pkg = htons(len_pkg);
    memcpy(*ut_buf + OFFSET_LEN_PKG, &len_pkg, 2);

    t_disbuf(*ut_buf, *pack_len);
    puts("4 --  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");

    return 1;
}

int do_cascade_reply(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    //const static char FLG_IP[] = "<Route ip=\"";
    const static char FLG_PORT[] = "port=\"";
    //const static char FLG_LINK_TYPE_TCP[] = "link=\"TCP\"";
    const static int OFFSET_LEN_PKG = 6;
    //int link_type = P_UDP_PROXY;
    char *ptr = NULL;
    //char dip[16] = {0};
    char dport[8] = {0};
    char r_src[64] = {0};
    char r_dst[64] = {0};
    char bindport[8] = {0};
    //u16 lport = 0;
    u16 len_pkg = 0;

    if ((ptr = (char*)memmem(*ut_buf, *pack_len, FLG_PORT, sizeof(FLG_PORT)-1)) == NULL)
        return 1;
    ptr += sizeof(FLG_PORT)-1;
    sscanf(ptr, "%[^\"]", dport);

     char camindexcode[20] = {0};
    if ((ptr = (char*)memmem(*ut_buf, *pack_len, FLG_CICODE, sizeof(FLG_CICODE)-1)) == NULL)
        return 1;

    ptr += sizeof(FLG_CICODE)-1;
    sscanf(ptr, "%[0-9]", camindexcode);

    if ( (gdata = gl_get_data(camindexcode)) == NULL)
        return 1;
    
    memcpy(bindport, gdata->data, gdata->len);
    gl_rm_data(camindexcode);
    
    printf("camindexcode:%s bindport:%s desport:%s", camindexcode, bindport, dport);

    sprintf(r_src, "%s%s", FLG_PORT, dport);
    sprintf(r_dst, "%s%s", FLG_PORT, bindport);
    strreplace_pos(NULL, NULL, ut_buf, r_src, r_dst, 1, pack_len);

    // update pkg len
    memcpy(&len_pkg, *ut_buf + OFFSET_LEN_PKG, 2);
    printf("len_pkg_old:%d\n", ntohs(len_pkg));

    len_pkg = (u16)*pack_len;
    printf("len_pkg:%d\n", len_pkg);
    len_pkg = htons(len_pkg);
    memcpy(*ut_buf + OFFSET_LEN_PKG, &len_pkg, 2);

    t_disbuf(*ut_buf, *pack_len);

    return 1;
}


int hik_fcg_request(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    const static char FLG_HIK_PROTO[] = "HKP$";
    u16 lport_stream = 0;
    u16 lport_heartbeat = 0;
    u16 dport_stream = 0;
    u16 dport_heartbeat = 0;
    char sip[16] = {0};
    char dip[16] = {0};
    u16 len_pkg = 0;

    if (put->dport == 80)
        return 1;
    if (put->dport == 7100)
    {
        if (memcmp(*ut_buf, FLG_HIK_PROTO, sizeof(FLG_HIK_PROTO)-1) == 0)
        {
            memcpy(&len_pkg, *ut_buf + 6, 2);
            len_pkg = ntohs(len_pkg);
            printf("len_pkg:%d, pack_len:%d\n", len_pkg, *pack_len);
            if (len_pkg > *pack_len)
            {
                recv_tail(put->cli_sock, len_pkg - *pack_len, ut_buf, pack_len);
                puts("-- x 2");
            }
            puts("------------------------------------------------------");
            t_disbuf(*ut_buf, *pack_len);
            return do_cascade_request(put, ut_buf, pack_len);
        }
        return 1;
    }

    if (*pack_len != 16 * 7 +4)
        return 1;

    inet_ultoa(put->src_ip, sip);
    inet_ultoa(__gg.outer_addr, dip);

    if (memcmp(*ut_buf + 16 * 3, sip, 16) == 0)
    {
        memcpy(*ut_buf + 16 * 3, dip, 16);
        memcpy((void*)&dport_stream, *ut_buf + *pack_len - 4, 2);
        dport_stream = ntohs(dport_stream);
        dport_heartbeat = dport_stream + 1;

        if (pplist_getidle_port2(&lport_stream, &lport_heartbeat) == 0)
        {
            logdbg_out("get idle port failed!");
            return -1;
        }
        printf("lport_stream:%d\n", lport_stream);
        printf("dport_stream:%d\n", dport_stream);

        if (run_vs_udp_proxy(__gg.outer_addr, put->src_ip, lport_stream, dport_stream, 0, put->session_tout, __gg.ferry_port) < 0)
            return -1;
        if (run_vs_udp_proxy(__gg.outer_addr, put->src_ip, lport_heartbeat, dport_heartbeat, 0, put->session_tout, __gg.ferry_port) < 0)
            return -1;

        // replace stream port
        lport_stream = htons(lport_stream);
        memcpy(*ut_buf + *pack_len - 4, &lport_stream, 2);
    }

	return 1;
}

int hik_fcg_reply(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    const static char FLG_HIK_PROTO[] = "HKP$";
    u16 len_pkg = 0;

    if (put->dport == 7100)
    {
        if (memcmp(*ut_buf, FLG_HIK_PROTO, sizeof(FLG_HIK_PROTO)-1) == 0)
        {
            memcpy(&len_pkg, *ut_buf + 6, 2);
            len_pkg = ntohs(len_pkg);
            if (len_pkg > *pack_len)
            {
                recv_tail(put->svr_sock, len_pkg - *pack_len, ut_buf, pack_len);
            }
            puts("------------------------------------------------------");
            t_disbuf(*ut_buf, *pack_len);
            return do_cascade_reply(put, ut_buf, pack_len);
        }
        return 1;
    }

    return 1;
}

