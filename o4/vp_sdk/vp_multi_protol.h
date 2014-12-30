#ifndef VP_MULTI_PROTOL_H
#define VP_MULTI_PROTOL_H

#include "config.h"
#define OSP_HEAD_LEN 39
#define OSP_START_POS 20


enum protocal_type{
	TYPE_NONE,
	TYPE_HTTP,
	TYPE_OSP,
	TYPE_SIP,
	TYPE_RTSP,
};


typedef int(*DO_RECEIVER_T)(int sockfd, void *put, char **pkg, u32 *len_pkg, SA*src_addr, socklen_t *addrlen);


DO_RECEIVER_T reply_receiver_multiprotocal(int type);
DO_RECEIVER_T request_receiver_multiprotocal(int type);

#endif //VP_MULTI_PROTOL_H
