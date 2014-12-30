#ifndef	_VP_LOCAL_TCPSERVER_H_
#define _VP_LOCAL_TCPSERVER_H_

#define	LSERVER_ENDSESSION	-1
#define	LSERVER_RECVNEXT	-2
#define	LSERVER_REPLY		1

int load_local_tcpserver(pvp_uthtrans pt, int t_state);

#endif // _VP_LOCAL_TCPSERVER_H_
