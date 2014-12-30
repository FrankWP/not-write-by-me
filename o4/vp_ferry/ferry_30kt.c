#include "../vpheader.h"
#include "pm_proxy.h"

int __30kt_init(const char *parg)
{
    if (load_portpool() < 0) 
	{
        logwar_out("ferry 30kt init: load pool port failed.");
        return -1;
    }

    return 1;
}

void __30kt_quit()
{
    destroy_portpool();
    pf_destroy_home();
}

int __30kt_request(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    const static u32  LEN_HEAD = 33;
    const static u32  LEN_PROTO_IP = 65;
    const static u32  LEN_PROTO_PORT = 62;
    const static char FLG_IP[] = "\x01\x01";
    const static char FLG_PORT[] = "\x02\x01";
    u32 inet_client_ip = 0;
    u16 inet_client_port = 0;
    u32 inet_ums_ip = 0;
    u16 ums_port = 0;
    pid_t pf_member_pid = 0;

    if (*pack_len < LEN_HEAD + 2)
        return 1;

    if (*pack_len == LEN_PROTO_IP)
    {
        if (memcmp(*ut_buf + LEN_HEAD, FLG_IP, sizeof(FLG_IP)-1) != 0)
            return 1;
        inet_client_ip = htonl(put->src_ip);
        if (memcmp(*ut_buf + *pack_len - 4, &inet_client_ip, 4) == 0)
        {
            inet_ums_ip = htonl(__gg.outer_addr);
            memcpy(*ut_buf + *pack_len - 4, &inet_ums_ip, 4);
        }
    }
    else if (*pack_len == LEN_PROTO_PORT)
    {
        if (memcmp(*ut_buf + LEN_HEAD, FLG_PORT, sizeof(FLG_PORT)-1) != 0)
            return 1;
        memcpy(&inet_client_port, *ut_buf + *pack_len - 2, 2);
        if ((ums_port = pplist_getidle_port_x()) == 0)
        {
            logerr_out("get idle port failed!");
            return -1;
        }

        //if (run_vs_udp_proxy(__gg.outer_addr, put->src_ip, ums_port, ntohs(inet_client_port), put->session_tout, __gg.ferry_port) < 0)
        if ((pf_member_pid = run_vs_udp_proxy(__gg.outer_addr, put->src_ip, 
                        ums_port, inet_client_port, 0, put->session_tout, __gg.ferry_port)) < 0)
        {
            logerr_out("run udp proxy failed!");
            return -1;
        }
		pf_add_member(pf_member_pid);
        // replace port
        //ums_port = ums_port;
        memcpy(*ut_buf + *pack_len - 2, &ums_port, 2);
    }

	return 1;
}


