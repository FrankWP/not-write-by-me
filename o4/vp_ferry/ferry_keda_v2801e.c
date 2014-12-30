#include "../vpheader.h"
#include "pm_proxy.h"

static char g_value[C_TOTAL][32] = {{0}};
static char g_ums_ip[16] = {0};
static char g_cascade_ip[16] = {0};
static int g_pmid = 0;
static char g_pmid_str[16] = {0};
static int __keda2801e_1722_reply(pvp_uthttp put, char **ut_buf, u32 *pack_len);
static int  __keda2801e_1722_socket(pvp_uthttp put, int sockfd);
static int  __keda2801e_1722_close(pvp_uthttp put, int sockfd);

int __keda2801e_init(const char *parg)
{
    if (g_pm.proxy_type == P_UDP_PROXY)
        return 1;

    if (parg == NULL)
        return -1;

    // save platform id
    strncpy(g_pmid_str, parg, sizeof(g_pmid_str)-1);
    g_pmid = atoi(parg);

    // load config
    if (load_proxy_config("keda_2801e.conf", g_pmid, PROXY_VIDEO_SERVER, g_value) < 0)
        return -1;

    modmysql_open(DB_NAME, 3);

    if (load_portpool() < 0)
    {
        logdbg_out("加载端口池失败！");
        return -1;
    }

	//inet_ultoa(__gg.outer_addr, g_ums_ip);
	//inet_ultoa(__gg.inner_addr, g_cascade_ip);
    strcpy(g_ums_ip, g_value[L_AUTHIP]);
    strcpy(g_cascade_ip, g_value[D_AUTHIP]);

    vp_uthtrans *p1722 = NULL;

    if (oss_malloc(&p1722, sizeof(vp_uthtrans)) < 0)
        return -1;
    set_trans_arg(p1722, g_pmid, g_pm.time_out, 0,
            inet_atoul(g_value[L_AUTHIP]), 1722, inet_atoul(g_value[D_AUTHIP]), 1722,
            __keda2801e_1722_socket, NULL, NULL, __keda2801e_1722_reply, __keda2801e_1722_close);
    tset_enable_proto_ums_server(&p1722->vphttp.tset, TYPE_OSP);
    load_tcp_proxy(p1722, T_DETACH);

    load_tcp_proxy_simple_n(T_DETACH, g_pmid, g_pm.time_out, 0,
            inet_atoul(g_value[L_AUTHIP]), 30000, inet_atoul(g_value[D_AUTHIP]), 30000,
            NULL, NULL, NULL, NULL, NULL);
    //load_tcp_proxy_simple_n(T_DETACH, 0, g_pm.time_out, 0, __gg.outer_addr, 1722, __gg.inner_addr, 1722,
            //NULL, NULL, NULL, NULL, NULL);
    //load_tcp_proxy_simple_n(T_DETACH, 0, g_pm.time_out, 0, __gg.outer_addr, 30000, __gg.inner_addr, 30000,
            //NULL, NULL, NULL, NULL, NULL);
   
    return 1;
}

void __keda2801e_quit()
{
    user_clear_online();
    destroy_portpool();
    modmysql_close();
    return;
}

/*
 * 处理点播视频信令
 */
static int __keda2801e_play(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    /*
     0000  00 00 00 00 00 00 00 0f - 00 2e 00 0a 00 2e ff fc    ................
     0010  00 00 02 23 00 6b 0c 5d - b1 0b 00 00 00 00 00 00    ...#.k.]........
     0020  00 00 77 5d b1 0b 00 14 - cf 27 01 78 9c 63 60 60    ..w].....'.x.c``
     0030  48 30 35 35 34 32 30 37 - 30 34 80 03 43 43 08 c7    H055420704..CC..
     0040  08 4c 32 40 15 20 01 13 - b0 2a 03 a8 1e 06 06 26    .L2@. ...*.....&
     0050  86 92 15 77 18 20 e0 34 - 94 66 20 68 2e c3 7f 10    ...w. .4.f h....
     0060  c0 34 dd 08 6e 32 58 d9 - ff ff 0c 0c 73 1c 98 19    .4..n2X.....s...
     0070  18 b8 b6 2a 44 cf 71 c8 - 4e 4d 49 4c ce cf 65 c0    ...*D.q.NMIL..e.
     0080  09 b2 c8 b7 19 dd 5f ff - 41 3e 03 da 0c 00 54 53    ......_.A>....TS
     0090  3b 5f ** ** ** ** ** ** - ** ** ** ** ** ** ** **    ;_
     -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
     0000  00 00 00 60 35 35 31 32 - 30 37 30 31 30 30 30 30    ...`551207010000
     0010  30 30 30 30 30 30 31 31 - 31 30 30 30 30 30 32 30    0000001110000020
     0020  30 30 30 30 00 35 35 31 - 32 30 37 30 30 30 30 30    0000.55120700000
     0030  30 30 30 30 30 30 30 34 - 30 30 30 30 31 30 30 31    0000000400001001
     0040  30 30 30 30 30 00 00 02 - 00 74 a8 dc 00 00 00 00    00000....t......
     0050  00 00 00 cb 00 00 00 00 - 00 00 00 00 35 35 31 32    ............5512
     0060  30 37 30 31 30 30 30 30 - 30 30 30 30 30 30 31 31    0701000000000011
     0070  31 30 30 30 30 30 32 30 - 30 30 30 30 00 00 ff ff    100000200000....
     0080  ff ff ff 35 35 31 32 30 - 37 30 30 30 30 30 30 30    ...5512070000000
     0090  30 30 30 30 30 32 31 30 - 30 31 30 30 30 30 30 30    0000021001000000
     00a0  30 30 30 00 ff ff 00 00 - 9c 40 03 00 00 0a b5 20    000......@..... 
     00b0  5b 9c 40 6b 65 64 61 63 - 6f 6d 00 00 00 00 00 00    [.@kedacom......
     00c0  00 00 00 00 00 00 00 00 - 00 00 00 00 00 00 00 00    ................
     00d0  00 00 00 00 6a 00 35 35 - 31 32 30 37 30 31 30 30    ....j.5512070100
     00e0  30 30 30 30 30 30 30 30 - 31 31 31 30 30 30 30 30    0000000011100000
     00f0  32 30 30 30 30 30 00 00 - ff ff ff ff ff 35 35 31    200000.......551
     0100  32 30 37 30 30 30 30 30 - 30 30 30 30 30 30 30 34    2070000000000004
     0110  30 30 30 30 31 30 30 31 - 30 30 30 30 30 00 00 ff    0000100100000...
     0120  00 02 00 74 03 00 00 ** - ** ** ** ** ** ** ** **    ...t...
     */

    const static u32 OFFSET_CLIENT_IP = 10 * 16 + 13;
    const static u16 OFFSET_CLIENT_PORT = 10 * 16 + 13 + 4;
    u32 inet_lip = 0;
    u32 inet_dip = 0;
    u16 inet_lport = 0;
    u16 inet_dport = 0;
    u16 host_lport1 = 0;
    u16 host_lport2 = 0; // +2 的端口，可能是用于是音频

    memcpy(&inet_dip, *ut_buf + OFFSET_CLIENT_IP, 4);
    /*
    if (memcmp(*ut_buf + OFFSET_CLIENT_IP, &inet_dip, 4) != 0)
        return 1;
        */
    // 获取信令中原有端口
    memcpy(&inet_dport, *ut_buf + OFFSET_CLIENT_PORT, 2);

    // 从端口池中获取端口
    if (pplist_getidle_port2_step(&host_lport1, &host_lport2, 2) <= 0)
    {
        logdbg_out("点播视频时，从端口池内获取端口失败！");
        return 1;   // 如果返回-1，当前连接会被断开，级联状态也会被断开
    }

    // 将内网服务器的IP，换成UMS的IP
    inet_lip = htonl(put->lip);
    inet_lport = htons(host_lport1);
    memcpy(*ut_buf + OFFSET_CLIENT_IP, &inet_lip, 4);
    // 将内网服务器的视频端口，换成UMS开启的视频端口
    memcpy(*ut_buf + OFFSET_CLIENT_PORT, &inet_lport, 2);

    // 开启视频代理
    clivlist *pcvn = NULL;
    oss_malloc(&pcvn, sizeof(clivlist));
    if (pcvn == NULL)
        return -1;

    //pcvn->lip = __gg.outer_addr;
    //pcvn->dip = __gg.inner_addr;
    pcvn->lip = put->lip;
    pcvn->dip = ntohl(inet_dip);
    pcvn->lvport = host_lport1;
    pcvn->dvport = ntohs(inet_dport);
    pcvn->platform_id = put->platform_id;
    pcvn->vstream_tout = put->session_tout;
    strncpy(pcvn->visit_user, put->login_user, sizeof(pcvn->visit_user)-1);
    get_virtual_cameraid(pcvn->camera_id);

    __start_vs_udp_proxy(pcvn, false, __gg.ferry_port + 1);

    pcvn->lvport = host_lport2;
    pcvn->dvport = host_lport2;
    __start_vs_udp_proxy(pcvn, false, __gg.ferry_port + 1);
    oss_free(&pcvn);

    /*
    run_vs_udp_proxy(__gg.outer_addr, __gg.inner_addr, ntohs(inet_cli_port), ntohs(inet_cli_port), g_pmid, 12, __gg.ferry_port + 1);
    // 开启视频代理 + 2的端口(可能是音频)
    run_vs_udp_proxy(__gg.outer_addr, __gg.inner_addr, ntohs(inet_cli_port) + 2, ntohs(inet_cli_port) + 2, g_pmid, 12, __gg.ferry_port + 1);
    */

    return 1;
}

static int  __keda2801e_1722_socket(pvp_uthttp put, int sockfd)
{
    char cli_ip[16] = {0};
    char uname[16] = {0};
    // 使用下级平台的ip地址，做为在线用户名
    inet_ultoa(put->src_ip, cli_ip);
    strncpy(uname, cli_ip, sizeof(uname)-1);
    strncpy(put->login_user, uname, sizeof(put->login_user)-1);

    user_online(uname, cli_ip, g_pmid_str);

    return 1;
}

static int  __keda2801e_1722_close(pvp_uthttp put, int sockfd)
{
    char cli_ip[16] = {0};
    char uname[16] = {0};
    // 使用下级平台的ip地址，做为在线用户名
    inet_ultoa(put->src_ip, cli_ip);
    strncpy(uname, cli_ip, sizeof(uname)-1);

    user_offline(uname, cli_ip, g_pmid_str);

    return 1;
}

/*
 * 下级平台会主动连接上级平台的1722端口
 */
static int __keda2801e_1722_reply(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    const static u32 LEN_OSP_HEAD = 39;
    const static u32 OFFSET_LEN_UNCOMPRESS = LEN_OSP_HEAD + 2;
    u16 len_uncompress_host = 0;

    if (*pack_len <= LEN_OSP_HEAD)
        return 1;
    if (*pack_len < OFFSET_LEN_UNCOMPRESS)
        return 1;
    memcpy(&len_uncompress_host, *ut_buf + OFFSET_LEN_UNCOMPRESS, 2);
    //printf("len uncompress: %d\n", len_uncompress_host);
    //t_disbuf(&len_uncompress_host, 2);
    // 如果解压后长度为\x01\x27，很可能是点播视频的信令 
    // 如果解压后长度为\x02\x39，很可能是点播录像的信令 
    if ((memcmp(&len_uncompress_host, "\x27\x01", 2) == 0) ||
        (memcmp(&len_uncompress_host, "\x39\x02", 2) == 0))
    {
        process_keda_comp_protocol(put, ut_buf, pack_len, __keda2801e_play);
    }

    return 1;
}

