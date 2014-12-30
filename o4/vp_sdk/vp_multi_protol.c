#include "../vpheader.h"

int do_reply_receiver_http(int sockfd, void *void_put, char **pkg, u32 *len_pkg, SA *src_addr, socklen_t *addrlen)
{	
	const static char FLG_HTTP_HEAD_END[] = "\r\n\r\n";
	u32 body_len= 0;
	int ret = -1;
	char *phead = NULL;
	char *pbody = NULL;
    u32 head_len = 0;

	if ((ret = recv_until_flag(sockfd, FLG_HTTP_HEAD_END, sizeof(FLG_HTTP_HEAD_END)-1, &phead, &head_len)) < 0)
    {
        logwar_out("recv_until_flag is failed!\n");
		return -1;
    }
	
    body_len = get_content_len_http(phead, *len_pkg);
    
    oss_malloc(&pbody, body_len+1);
	if (Recvn(sockfd, pbody, body_len) != body_len)
	{
		logwar_out("Recvn body length is failed!\n");
		return -1;	
	}
    oss_malloc(pkg,head_len+body_len+1);
	memcpy(*pkg, phead, head_len);
	memcpy(*pkg+head_len, pbody, body_len);
	*len_pkg = head_len+ body_len;

	oss_free(&phead);
	oss_free(&pbody);
	return 1; 
}

int do_request_receiver_osp(int sockfd, void *put, char **pkg, u32 *len_pkg,SA *src_addr, socklen_t *addrlen )
{

	int head_len = OSP_HEAD_LEN;
	int start_pos = OSP_START_POS;
    int body_len = 0;
	char *phead = NULL;
	char *pbody = NULL;

	oss_malloc(&phead, head_len+1);
	if (Recvn(sockfd, phead, head_len) != OSP_HEAD_LEN)
	{
		logwar_out("Recvn OSP_HEAD_LEN is failed!\n");
		return -1;	
	}

	body_len = get_content_len_osp(phead, start_pos);

	oss_malloc(&pbody, body_len+1);
	if (Recvn(sockfd, pbody, body_len) != body_len)
	{
		logwar_out("Recvn body length is failed!\n");
		return -1;	
	}
    
	oss_malloc(pkg,head_len+body_len+1);
	memcpy(*pkg, phead, head_len);
	memcpy(*pkg+head_len, pbody, body_len);
	*len_pkg = head_len+ body_len;

	oss_free(&phead);
	oss_free(&pbody);

	return 1; 
}

int do_reply_receiver_osp(int sockfd, void *put, char **pkg, u32 *len_pkg,SA *src_addr, socklen_t *addrlen )
{

	int head_len = OSP_HEAD_LEN;
	int start_pos = OSP_START_POS;
    int body_len = 0;
    char *phead = NULL;
	char *pbody = NULL;

	oss_malloc(&phead, head_len+1);
	if (Recvn(sockfd, phead, head_len) != OSP_HEAD_LEN)
	{
		logwar_out("Recvn OSP_HEAD_LEN is failed!\n");
		return -1;	
	}

	body_len = get_content_len_osp(phead, start_pos);

	oss_malloc(&pbody, body_len+1);
	if (Recvn(sockfd, pbody, body_len) != body_len)
	{
		logwar_out("Recvn body length is failed!\n");
		return -1;	
	}

	oss_malloc(pkg,head_len+body_len+1);
	memcpy(*pkg, phead, head_len);
	memcpy(*pkg+head_len, pbody, body_len);
	*len_pkg = head_len+ body_len;

	oss_free(&phead);
	oss_free(&pbody);

	return 1;
}

DO_RECEIVER_T reply_receiver_multiprotocal(int type)
{

    DO_RECEIVER_T do_reply_receiver;
	
	switch(type)
	{
		case TYPE_HTTP: 	
			do_reply_receiver = do_reply_receiver_http;
			break;
		case TYPE_OSP:
			do_reply_receiver = do_reply_receiver_osp;
			break;
		default:
			do_reply_receiver = NULL;
	}
	return do_reply_receiver;
}

DO_RECEIVER_T request_receiver_multiprotocal(int type)
{
    DO_RECEIVER_T do_request_receiver;
	switch(type)
	{
		case TYPE_HTTP:
			do_request_receiver = NULL;// do_request_receiver_http;
			break;
		case TYPE_OSP:
			do_request_receiver = do_request_receiver_osp;
			break;
		default:
			do_request_receiver = NULL;
	}
	return do_request_receiver;
}
