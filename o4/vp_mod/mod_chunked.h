#ifndef _MOD_CHUMKED_H_
#define _MOD_CHUMKED_H_

typedef struct _modchunked_t
{
    char *http_head;
    char *data_chunked;
    u32  len_http_head;
    u32  len_chunked;
    // 
    u32  len_current_block_left;
    u32  len_current_block;

    int  sock_recv;
    int  sock_send;
}modchunked_t;

bool modchunked_test(char *data, u32 len);
bool modchunked_init(modchunked_t *chkd, int sock_recv, int sock_send, char *pdata, u32 len_data);
bool modchunked_cache_chunked(modchunked_t *chkd);
bool modchunked_split_send(modchunked_t *chkd, int len_split);
bool modchunked_end(modchunked_t *chkd);
//char *modchunked_peel(char *pchunked, u32 len_chunked, u32 *len_data);
char *modchunked_peel(char *pchunked, u32 len_chunked, u32 *len_data, u32 *len_block_left);


#endif  //  _MOD_CHUMKED_H_

