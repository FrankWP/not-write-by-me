#include "../vpheader.h"
#include "pm_proxy.h"

int  __amplesky_ctrl_reply(pvp_uthttp put, char **ut_buf, u32 *pack_len);
char *__amplesky_replace_oneproto_uplen(char **ut_buf, u32 *pack_len, char *pos, char *src, char *dst);
void __run_amplesky_udp_proxy(pvp_uthttp put, char **ut_buf, u32 *pack_len);

int __amplesky_init()
{
    if (load_portpool() < 0) 
	{
        logwar_out("ferry amplesky init:load pool port failed.");
        return -1;
    }
    init_record_server();

    return 1;
}

void __amplesky_quit()
{
    destroy_portpool();
}

int __amplesky_request(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
	const static char CTL_PORT[] = "D_CTRL_P=";
	const static char CTL_IP[] = "D_IP=";
	char ctrl_ip[32] = {0};
	char ctrl_port[16] = {0};
	char *posIP = NULL;
	char *posPort = NULL;
    int lsn_port = 0;
	char str_outer_addr[32] = {0};
	char s_buf[64] = {0};
	char d_buf[64] = {0};

	if (((posIP = strnstr(*ut_buf, CTL_IP, *pack_len, true)) != NULL) &&
		((posPort = strnstr(*ut_buf, CTL_PORT, *pack_len, true)) != NULL))
	{
		if (sscanf(posIP + sizeof(CTL_IP)-1, "%[^:]", ctrl_ip) == EOF)
		{
			logwar_out("ip not found!");
			return 1;
		}
		if (sscanf(posPort + sizeof(CTL_PORT)-1, "%[^:]", ctrl_port) == EOF)
		{
			logwar_out("port not found!");
			return 1;
		}
        if ((lsn_port = x_search_server(ctrl_ip, atoi(ctrl_port))) == 0)
        {
            if ((lsn_port = x_set_server(ctrl_ip, atoi(ctrl_port))) == 0)
            {
                logwar_out("get idle port failed!");
                return -1;
            }
            // start proxy 
            load_tcp_proxy_simple_n(T_DETACH, 0, put->session_tout, 0,
                __gg.outer_addr,lsn_port, inet_atoul(ctrl_ip),atoi(ctrl_port),
                NULL,NULL,NULL,__amplesky_ctrl_reply,NULL);
        }
       	
        inet_ultoa(__gg.outer_addr, str_outer_addr);
        sprintf(s_buf, "%s%s", CTL_IP, ctrl_ip);
        sprintf(d_buf, "%s%s", CTL_IP, str_outer_addr);
		__amplesky_replace_allproto_uplen(ut_buf, pack_len, s_buf, d_buf);

        sprintf(s_buf, "%s%s", CTL_PORT, ctrl_port);
        sprintf(d_buf, "%s%d", CTL_PORT, lsn_port);
		__amplesky_replace_allproto_uplen(ut_buf, pack_len, s_buf, d_buf);
	}

	return 1;
}

int __amplesky_ctrl_reply(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
	const static char VS_UDP_P[] = "UDP_PORT=";
	if (strnstr(*ut_buf, VS_UDP_P, *pack_len, true) != NULL) {
		__run_amplesky_udp_proxy(put, ut_buf, pack_len);
    }
	return 1;
}

char *__amplesky_replace_oneproto_uplen(char **ut_buf, u32 *pack_len, char *pos, char *src, char *dst)
{
	const static int NLEN_SZ = 5;
    char new_len_buf[8] = {0};
	char msg_len[16] = {0};
	int old_pack_len = *pack_len;
	int n_msg_len = 0;
	char *pNextProto = NULL;
	int pos_offset = 0;

	if (pos == NULL)
		return NULL;
	pos_offset = pos - *ut_buf;

	memcpy(msg_len, pos, NLEN_SZ);
	n_msg_len = atoi(msg_len); 
	pNextProto = pos + n_msg_len + NLEN_SZ;

	strreplace_pos(pos, pNextProto, ut_buf, src, dst, -1, pack_len);
	pos = *ut_buf + pos_offset;

    n_msg_len += *pack_len - old_pack_len;
	sprintf(new_len_buf, "%05d", n_msg_len);
	memcpy(pos, new_len_buf, NLEN_SZ);

	pNextProto = (*ut_buf + pos_offset) + n_msg_len + NLEN_SZ;
	if (pNextProto + 1 >= *ut_buf + *pack_len)
		pNextProto = NULL;

	return pNextProto;
}

void __amplesky_replace_allproto_uplen(char **ut_buf, u32 *pack_len, char *src, char *dst)
{
	char *pos = *ut_buf;
	do
	{
		pos = __amplesky_replace_oneproto_uplen(ut_buf, pack_len, pos, src, dst);
	}while (pos != NULL);
}

void __run_amplesky_udp_proxy(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
	const static char VS_UDP_P[] = "UDP_PORT=";
	char *pos = NULL;
	char udp_port[16] = {0};
	u16 lp_video = 0;
	char s_buf[64] = {0};
	char d_buf[64] = {0};

	if ((pos = strnstr(*ut_buf, VS_UDP_P, *pack_len, true)) != NULL)
	{
		if (sscanf(pos + sizeof(VS_UDP_P)-1, "%[^:]", udp_port) == EOF)
		{
			logwar_out("get udp port failed!");
			return;
		}

		if ((lp_video = pplist_getidle_port()) == 0)
		{
			logwar_out("get video idle port failed!");
			return;
		}

		sprintf(s_buf, "%s%s", VS_UDP_P, udp_port);
		sprintf(d_buf, "%s%d", VS_UDP_P, lp_video);
		__amplesky_replace_allproto_uplen(ut_buf, pack_len, s_buf, d_buf);

        run_vs_udp_proxy(__gg.outer_addr, put->dip, lp_video, atoi(udp_port), 0,  put->session_tout, __gg.ferry_port);
	}
}

