#include "../vpheader.h"
#include "pm_proxy.h"

int zhongxing_henan_init(const char *parg)
{
    if (is_tms())
        return 1;

    if (load_portpool() < 0)
        return -1;
    
    return 1;
}

void zhongxing_henan_quit()
{
    if (is_tms())
        return;
    destroy_portpool();
}

int zhongxing_henan_request(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    // <targetIPAddr>10.110.1.37</targetIPAddr><targetPort>10000</targetPort>
    //
    const static char FLG_CLIIP[] = "<targetIPAddr>";
    const static char FLG_CLIPORT[] = "<targetPort>";
    char *ptr = NULL;
    char cli_ip[16] = {0};
    char cli_port[16] = {0};
    char ums_ip[16] = {0};
    char r_src[64] = {0};
    char r_dst[64] = {0};
    int lvport = 0;

    // get client ip
    if ((ptr = (char*)memmem(*ut_buf, *pack_len, FLG_CLIIP, sizeof(FLG_CLIIP)-1)) == NULL)
        return 1;
    ptr += sizeof(FLG_CLIIP)-1;
    sscanf(ptr, "%[^<]", cli_ip);
    // get client port
    if ((ptr = (char*)memmem(*ut_buf, *pack_len, FLG_CLIPORT, sizeof(FLG_CLIPORT)-1)) == NULL)
        return 1;
    ptr += sizeof(FLG_CLIPORT)-1;
    sscanf(ptr, "%[^<]", cli_port);

    printf("cli ip:%s, cli port:%s\n", cli_ip, cli_port);
 
    if ((lvport = pplist_getidle_port()) == 0)
    {
        loginf_out("get idle port failed!");
        return -1;
    }

    inet_ultoa(__gg.outer_addr, ums_ip); 

    // replace ip
    sprintf(r_src, "%s%s", FLG_CLIIP, cli_ip);
    sprintf(r_dst, "%s%s", FLG_CLIIP, ums_ip);
    strreplace_pos(NULL,NULL, ut_buf, r_src,r_dst, 1, pack_len);

    // replace port
    sprintf(r_src, "%s%s", FLG_CLIPORT, cli_port);
    sprintf(r_dst, "%s%d", FLG_CLIPORT, lvport);
    strreplace_pos(NULL,NULL, ut_buf, r_src,r_dst, 1, pack_len);

    update_content_len(ut_buf, pack_len);

    int nret = 1;
    if (run_vs_udp_proxy(__gg.outer_addr, inet_atoul(cli_ip), lvport, atoi(cli_port), 0, put->session_tout, __gg.ferry_port) < 0)
        nret = -1;

	return nret;
}

int zhongxing_socket(pvp_uthttp put, int sockfd)
{
    SAI  xaddr;
    memset(&xaddr, 0x00, sizeof(xaddr));

    xaddr.sin_family = AF_INET;
    xaddr.sin_addr.s_addr = 0; //INADDR_ANY;
    xaddr.sin_port = put->src_port;
    Setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR);

    if (bind(sockfd, (SA *)&xaddr, sizeof(xaddr)) < 0){
        loginf_fmt("__keda_socket: bind port [%d] failed!\n", xaddr.sin_port);
        return -1;
    }

    run_vs_udp_proxy(__gg.outer_addr, put->src_ip, put->src_port + 1, put->src_port + 1, 0, 12, __gg.ferry_port);

    return 1;
}

