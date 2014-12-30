#ifndef	_VP_LOCAL_TCPCLIENT_H_
#define	_VP_LOCAL_TCPCLIENT_H_

typedef struct VP_LOCAL_CLIENT_ARGS 
{
    u32  lip;               // local ip
    u32  dip;               // visit des ip
    u16  lport;             // local port
    u16  dport;             // visit des port
    u16  session_tout;      // connect or receive time out

}vp_local_client_args;

typedef struct VP_LOCAL_CLIENT
{
	vp_local_client_args args;

	int  (* do_connect)(vp_local_client_args *pclient_args, char **ppsend, int *psend_len);	// this will be called once, when succeed to connect to server
	int  (* do_process_recv)(vp_local_client_args *pclient_args, char **ppreply, int *preply_len, int *pbuf_len);
}vp_local_client;

int load_local_tcpclient(vp_local_client *pclient, int t_state);

#endif	//	_VP_LOCAL_TCPCLIENT_H_

