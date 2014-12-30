#include "common.h"
#include "vp_uthttp.h"
#include "pool_port.h"

#include "vp_local_tcpclient.h"

static void * __start_local_tcpclient(void * arg)
{
    SAI ser_addr;
    SAI cli_addr;
    int cli_sock = -1;
	struct timeval tout;
	char buf[32] = {0};
	vp_local_client lc;

	char *pSend = NULL;
	char *pRecv = NULL;
	int  nSend = 0;
	int  nRecvBuf = 0;
	int  nRecv = 0;

	if (arg == NULL)
		return NULL;
	memcpy(&lc, arg, sizeof(lc));
	oss_free(&arg);

	puts("-- 1");
    if ((cli_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
	{
		logdbg_out("Start local tcp client: create socket failed!");
		return NULL;
	}

	puts("-- 2");
    if (Setsockopt(cli_sock, SOL_SOCKET, SO_REUSEADDR) < 0)
	{
		logdbg_out("Start local tcp client: set socket reuse failed!");
		close(cli_sock);
		return NULL;
	}

	// set server address
	init_sockaddr(&ser_addr, lc.args.dip, lc.args.dport);

	puts("-- 3");
	// set client address
	if ((lc.args.lip != 0) || (lc.args.lport != 0))
	{
		init_sockaddr(&cli_addr, lc.args.lip, lc.args.lport);
		if (Bind(cli_sock, cli_addr, sizeof(cli_addr)) < 0)
		{
			logdbg_fmt("Start local tcp client: bind socket to %s:%d failed!", inet_ultoa(lc.args.lip, buf), lc.args.lport);
			close(cli_sock);
			return NULL;
		}
	}

	puts("-- 4");
	tout.tv_sec = lc.args.session_tout;  // Seconds Timeout
	tout.tv_usec = 0;  
	if (setsockopt(cli_sock, SOL_SOCKET, SO_RCVTIMEO, &tout,sizeof(struct timeval)) < 0)
	{
		logdbg_out("Start local tcp client: set connect timeout failed!");
		close(cli_sock);
		return NULL;
	}

	puts("-- 5");
	if (Connect(cli_sock, (struct sockaddr*)&ser_addr, sizeof(ser_addr), 5) < 0)
	{
		logdbg_fmt("Start local tcp client: connect %s:%d failed!", inet_ultoa(lc.args.lip, buf), lc.args.lport);
		close(cli_sock);
		return NULL;
	}

	puts("-- 6");
	if (lc.do_connect != NULL)
	{
		if (lc.do_connect(&(lc.args), &pSend, &nSend) <= 0)
		{
			close(cli_sock);
			return NULL;
		}
		if (Send(cli_sock, pSend, nSend, MSG_NOSIGNAL) <= 0)
		{
			close(cli_sock);
			return NULL;
		}
	}
	puts("-- 7");
	// int  (* do_process_recv)(pvp_local_client_args *pclient_args, char **ppreply, int *preply_len);
	nRecvBuf = BUF_SIZE;
	//if (pRecv = (char*)malloc(BUF_SIZE);
	if (oss_malloc(&pRecv, nRecvBuf) < 0)
	{
		logdbg_out("Start local tcp client: malloc receive buffer failed!");
		close(cli_sock);
		return NULL;
	}

	char *pTmp = NULL;
	while (true)
	{
		if (nRecvBuf < BUF_SIZE)
		{
			if ((pTmp = (char*)realloc(pRecv, BUF_SIZE)) == NULL)
			{
				logdbg_out("Start local tcp client: realloc buffer failed!");
				break;
			}
			pRecv = pTmp;
			nRecvBuf = BUF_SIZE;
		}

		if ((nRecv = Recv(cli_sock, pRecv, nRecvBuf, 0)) <= 0)
		{
			if (nRecv < 0)
				logdbg_out("Start local tcp client: receive failed!");
			break;
		}

		if (lc.do_process_recv != NULL)
		{
			if (lc.do_process_recv(&lc.args, &pRecv, &nRecv, &nRecvBuf) < 0)
				break;
		}
	}

    close_sock(&cli_sock);

    return NULL;
}

int load_local_tcpclient(vp_local_client *pclient, int t_state)
{
    int        tret = -1;
    pthread_t  tid;

    tret = pthread_create(&tid, NULL, __start_local_tcpclient, (void *)pclient);
    if (tret != 0)
        return -1;

    if (t_state == T_WAITING)
        pthread_join(tid, NULL);
    if (t_state == T_DETACH)
        pthread_detach(tid);

    return 1;
}


