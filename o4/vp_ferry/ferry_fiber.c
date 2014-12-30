#include "../vpheader.h"
#include "pm_proxy.h"

#define VS_INVITE "INVITE sip:"
#define VS_EXPIRES "expires=0"

static void get_string_val(char *s,char *b,char *e,char *result)
{
	char *p1;
	char *p2;

	p1 = strstr(s,b);
	if (p1 != NULL){
		p1 = p1 + strlen(b);
		p2 = strstr(p1,e);
		if (p2 != NULL){
			memcpy(result,p1,p2-p1);
			result[p2-p1] = 0;
		}else{
			result[0] = 0;
		}
	} else
		result[0] = 0;
}

static void update_content_length(char **ut_buf, u32 *pack_len)
{
	int  nlen;
	char olen[20];
	char *pcrlfcrlf;

	get_string_val(*ut_buf, (char*)"Content-Length: ", (char*)"\r\n", olen);

	pcrlfcrlf = strnstr(*ut_buf, "\r\n\r\n", *pack_len, true);
	if (pcrlfcrlf != NULL) {
		char len1[256];
		char len2[256];
		nlen = strlen(*ut_buf) - (pcrlfcrlf - *ut_buf) - 4;
		sprintf(len1, "Content-Length: %s\r\n", olen);
		sprintf(len2, "Content-Length: %d\r\n", nlen);
		strreplace(ut_buf, len1, len2, REPLACE_ALL, pack_len);
	}
}

static int request_video_info(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
	char      *p =NULL;
	char      s[32]={0};
	char      vsrcip[32] = {0};
	char      vsrcport[8] ={0};


	p = strnstr(*ut_buf, "c=IN", *pack_len, true); // c=IN IP4 10.18.13.79
	if (p != NULL)
		sscanf(p + 9, "%[^\r\n]", vsrcip);

	p = strnstr(*ut_buf, "m=video", *pack_len, true); // m=video 26828 RTP/AVP 99
	if (p != NULL)
		sscanf(p + 8, "%[^' ']", vsrcport);

	run_vs_udp_proxy(__gg.inner_addr, inet_atoul(vsrcip), atoi(vsrcport), atoi(vsrcport), 0, put->session_tout, __gg.ferry_port);
	run_vs_udp_proxy(__gg.inner_addr, inet_atoul(vsrcip), atoi(vsrcport)+1, atoi(vsrcport)+1, 0, put->session_tout, __gg.ferry_port);

	inet_ultoa(__gg.inner_addr, s);
	strreplace(ut_buf, vsrcip, s, REPLACE_ALL, pack_len);
	update_content_length(ut_buf, pack_len);
	return 1;
}


int __fiber_init(const char *parg)
{
	if (g_pm.proxy_type == P_UDP_PROXY)
	{
		if (load_ip_pool() < 0)
		{
			logwar_out("ferry keda init: init ip pool failed!");
			return -1;
		}
	}

	return 1;
}

int __fiber_socket(pvp_uthttp put, int sockfd)
{
	if (5060 == put->dport)
	{
		SAI  xaddr;
		ip_pool *ipp = NULL;
		memset(&xaddr, 0x00, sizeof(xaddr));

		ipp = ippool_search_by_desaddr(put->cli_addr);
	
		if (ipp == NULL)
			ipp = ippool_search_idle_addr(put->cli_addr);
        syslog(LOG_INFO, "get a ip %s at ippool.",inet_ultoa(ipp->lip,NULL));

		if (ipp == NULL) {
			syslog(LOG_INFO, "no idle ip at ippool.");
			return -1;
		}

		xaddr.sin_family = AF_INET;
		xaddr.sin_addr.s_addr = htonl(ipp->lip); //INADDR_ANY;
		xaddr.sin_port = htons(5060);
		Setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR);

		if (bind(sockfd, (SA *)&xaddr, sizeof(xaddr)) < 0){
			char localip[32] = {0};
			inet_ultoa(ipp->lip, localip);
			loginf_fmt("__keda_socket: bind ip [%s] port [%d] random failed!\n", localip, xaddr.sin_port);
			return -1;
		}
	}
	return 1;
}

int __fiber_request(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
	if (strnstr(*ut_buf,VS_INVITE,*pack_len, true) != NULL)
	{
		request_video_info(put,ut_buf, pack_len);
	}

	return 1;
}

int __fiber_reply(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
	if (strnstr(*ut_buf,VS_EXPIRES,*pack_len, true) != NULL)
	{
		ip_pool *ipp = NULL;

		ipp = ippool_search_by_desaddr(put->cli_addr);
		if (ipp != NULL)
        {
			ippool_rset_flag(put->cli_addr);
            syslog(LOG_INFO, "free a ip %s at ippool.",inet_ultoa(ipp->lip,NULL));
        }
	}
	return 1;
}

int __fiber_close(pvp_uthttp put, int sockfd)
{
	ip_pool *ipp = NULL;

    ipp = ippool_search_by_desaddr(put->cli_addr);
    if (ipp != NULL)
      ippool_rset_flag(put->cli_addr);

	return 1;
}
