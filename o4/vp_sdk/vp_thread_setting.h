#ifndef __THREAD_SETTING_H_
#define __THREAD_SETTING_H_

#include "common.h"

#define  MAKE8BYTES(_4low,_4high)	(((uint64_t)(_4low)) | (((uint64_t)(_4high)) << sizeof(uint32_t)*8))
#define  LOW4BYTES(_8byte)			((uint32_t)((_8byte) & 0x00000000FFFFFFFF))
#define  HIGH4BYTES(_8byte)			((uint32_t)(((_8byte) & 0xFFFFFFFF00000000) >> sizeof(uint32_t)*8))
/*
typedef struct __sdk_request_reply
{
    int(*func_request_receiver)(int sockfd, void *put, char **pkg, u32 *len_pkg, SA *src_addr, socklen_t *addrlen);
    int(*func_reply_receiver)(int sockfd, void *put, char **pkg, u32 *len_pkg, SA *src_addr, socklen_t *addrlen);
}sdk_request_reply;
*/

typedef enum __e_flg_tset
{
	TSET_DEF_NONE		= 0,		// nothing special to do.
	TSET_CONN_TIMES		= 1 << 0,	// just accept connect by given times. def: keep listening.
	TSET_LSN_TOUT_EXIT	= 1 << 1,	// exit thread when listen time is out. 
	TSET_PPORT_FREE		= 1 << 2,	// free pool port. def: not using pool port, so neend't to free.
	TSET_ENABLE_CHUNKED = 1 << 3,	// enable http chunked mode
//	TSET_USE_PROTO_RECEIVER = 1 << 4,	// receive one protocol once in sdk
    TSET_USE_PROTO_TMS_CLIENT= 1 << 4,//received from client by tms 
    TSET_USE_PROTO_TMS_SERVER= 1 << 5,//received from ums by tms 
    TSET_USE_PROTO_UMS_CLIENT= 1 << 6,//received from tms by ums 
    TSET_USE_PROTO_UMS_SERVER= 1 << 7,//received from outer server by ums 

	TSET_MAX_COUNT  = (uint64_t)(~0),	// this can makes me large as 64 bits.
}e_flg_tset;

typedef struct __tset_arg
{
	e_flg_tset flg;	// flag for finding me.

	void    *ptr;  // pointer argument
	int64_t	n;		// integer argument

	struct __tset_arg *next;
}tset_arg;

typedef struct __thread_setting
{
	uint64_t	flg;		// thread setting.
	tset_arg	*targ;		// arguments of thread setting
}th_set;

bool tset_set(th_set *tset, e_flg_tset flg, bool has_arg, void *arg_ptr, int64_t arg_n);
tset_arg *tset_fetch_arg(th_set *tset, e_flg_tset flg);
void tset_rm(th_set *tset, e_flg_tset flg);
bool tset_is_flg_set(th_set *tset, e_flg_tset flg);
void tset_clear(th_set *tset);

////// 
// simple thread setting functions.

void tset_none(th_set *tset);
void tset_conn_times(th_set *tset, int times);
void tset_port_free(th_set *tset);
void tset_thread_tout(th_set *tset, time_t tout);
void tset_enable_chunked(th_set *tset);
void tset_disable_chunked(th_set *tset);
//void tset_enable_proto_receiver(th_set *tset, sdk_request_reply *srr);
void tset_enable_proto_tms_client(th_set *tset, int type);
void tset_enable_proto_tms_server(th_set *tset, int type);
void tset_enable_proto_ums_client(th_set *tset, int type);
void tset_enable_proto_ums_server(th_set *tset, int type);

#endif	// __THREAD_SETTING_H_

