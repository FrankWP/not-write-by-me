#include "../vpheader.h"
#include "mod_chunked.h"

const static char FLG_HTTP[] = "HTTP/";
const static char FLG_CHUNKED_MODE[] = "Transfer-Encoding: chunked";
const static char FLG_CHUNKED_SPLIT[] = "\r\n\r\n";
const static char FLG_HTTP_NEWLINE[] = "\r\n";
//const static char FLG_CHUNKED_END[] = "\r\n\r\n0\r\n\r\n";
const static char FLG_CHUNKED_END[] = "\r\n0\r\n\r\n";

bool modchunked_test(char *data, u32 len)
{
    if (len < sizeof(FLG_HTTP) + sizeof(FLG_CHUNKED_MODE))
        return false;

    if (memcmp(data, FLG_HTTP, sizeof(FLG_HTTP)-1) != 0)
        return false;
    if (memmem(data, len, FLG_CHUNKED_MODE, sizeof(FLG_CHUNKED_MODE)-1) == NULL)
        return false;
    if (memmem(data, len, FLG_CHUNKED_SPLIT, sizeof(FLG_CHUNKED_SPLIT)-1) == NULL)
        return false;

    return true;
}

bool modchunked_init(modchunked_t *chkd, int sock_recv, int sock_send, char *pdata, u32 len_data)
{
    char *ptr = NULL;

    if ((chkd == NULL) ||
            (sock_recv == -1) ||
            (sock_send == -1) ||
            (pdata == NULL) ||
            (len_data == 0))
        return false;

    memset(chkd, 0, sizeof(modchunked_t));

    if ((ptr = (char*)memmem(pdata, len_data, FLG_CHUNKED_SPLIT, sizeof(FLG_CHUNKED_SPLIT)-1)) == NULL)
    {
        logwar_out("modchunked_init: find chunked split flag error!");
        return false;
    }
    ptr += sizeof(FLG_CHUNKED_SPLIT)-1;
    // calculate http head length
    chkd->len_http_head = ptr - pdata;
    // malloc memory for saving http head
    oss_malloc(&chkd->http_head, chkd->len_http_head);
    // save http head
    memcpy(chkd->http_head, pdata, chkd->len_http_head);

    u32 len_ck = 0;
    u32 len_left = 0;
    char *p = modchunked_peel(ptr, len_data - chkd->len_http_head, &len_ck, &len_left);
    chkd->data_chunked = p;
    chkd->len_chunked = len_ck;
    chkd->len_current_block_left = len_left;

    //printf("data_chunked:%s\nlen_chunked:%d, len_left:%d\n", p, len_ck, len_left);
  
    chkd->sock_recv = sock_recv;
    chkd->sock_send = sock_send;

    return true;
}

/*
int replace_chunked_data(int sockfd, char **data, u32 *len_data, char *from, int len_from, char *to, int len_to, int times)
{
    const static char FLG_HTTP_HEAD[] = "HTTP/1.1 ";
    const static char FLG_CHUNKED[] = "Transfer-Encoding: chunked";
    const static char FLG_HTTP_NEWLINE[] = "\r\n";
    const static char FLG_CHUNKED_SPLIT[] = "\r\n\r\n";
    //const static char FLG_CHUNKED_END[] = "\r\n\r\n0\r\n\r\n";
    const static char FLG_CHUNKED_END[] = "\r\n0\r\n\r\n";
    char *ptr = NULL;
    char *tmp = NULL;
    int ret = 0;
    int len_http_head = 0;
    char str_len_chunked_data[8] = {0};

    char *chunked_data = NULL;
    u32 len_chunked_data = 0;
    int len_chunked_block = 0;
    int len_chunked_current_block_left = 0;

    if (strnstr(*data, FLG_HTTP_HEAD, *len_data, false) == NULL)
        return 1;
    if (strnstr(*data, FLG_CHUNKED, *len_data, false) == NULL)
        return 1;

    if ((ptr = (char*)memmem(*data, *len_data, FLG_CHUNKED_SPLIT, sizeof(FLG_CHUNKED_SPLIT)-1)) == NULL)
        return 1;
    ptr += sizeof(FLG_CHUNKED_SPLIT)-1;
    sscanf(ptr, "%x\r\n", &len_chunked_block);
    // save http head length
    len_http_head = ptr - *data;

    if ((ptr = (char*)memmem(ptr, *len_data - (ptr - *data), FLG_HTTP_NEWLINE, sizeof(FLG_HTTP_NEWLINE)-1)) == NULL)
        return -1;
    // usually \r\n\r\ne21\r\n
    ptr += sizeof(FLG_HTTP_NEWLINE)-1;
    // sometimes \r\n\r\ne21\r\n\r\n
    if (memcmp(ptr, FLG_HTTP_NEWLINE, sizeof(FLG_HTTP_NEWLINE)-1) == 0)
        ptr += sizeof(FLG_HTTP_NEWLINE)-1; // "ptr" now pointing to chunked data who is fallowing chunked length
    if (len_chunked_block == 0)
        return 1;

    len_chunked_current_block_left = len_chunked_block - (*len_data - (ptr - *data));
    // get chunked block out
    while (len_chunked_current_block_left < 0)
    {
        if ((tmp = (char*)realloc(chunked_data, len_chunked_data + len_chunked_block)) == NULL)
        {
            oss_free(&chunked_data);
            logwar_out("realloc chunked memory failed 1!");
            return -1;
        }
        chunked_data = tmp;
        memcpy(chunked_data + len_chunked_data, ptr, len_chunked_block);
        len_chunked_data += len_chunked_block;
        ptr += len_chunked_block; 

        if (memcmp(ptr, FLG_HTTP_NEWLINE, sizeof(FLG_HTTP_NEWLINE)-1) == 0)
            ptr += sizeof(FLG_HTTP_NEWLINE)-1;

        sscanf(ptr, "%x\r\n", &len_chunked_block);
        // 8 is enough, not have to very far
        if ((ptr = (char*)memmem(ptr, 8, FLG_HTTP_NEWLINE, sizeof(FLG_HTTP_NEWLINE)-1)) == NULL)
        {
            logwar_out("find new line flag failed!");
            return -1;
        }
        ptr += sizeof(FLG_HTTP_NEWLINE)-1;
        if (memcmp(ptr, FLG_HTTP_NEWLINE, sizeof(FLG_HTTP_NEWLINE)-1) == 0)
            ptr += sizeof(FLG_HTTP_NEWLINE)-1;
        len_chunked_current_block_left = len_chunked_block - (*len_data - (ptr - *data));
    }

    // prepare first chunked data 
    if ((tmp = (char*)realloc(chunked_data, len_chunked_data + len_chunked_block)) == NULL)
    {
        oss_free(&chunked_data);
        logwar_out("realloc chunked memory failed 2!");
        return -1;
    }
    chunked_data = tmp;

    memcpy(chunked_data + len_chunked_data, ptr, *len_data - (ptr - *data));
    len_chunked_data += *len_data - (ptr - *data);

    while (true)
    {
        // data not received complate.
        if (len_chunked_current_block_left > 0)
        {
            //int offset = len_chunked_data;
            // receive chunked data and a flowing chunked data that not large than sizeof 
            // chunked end
            if ((ret = recv_tail(sockfd, len_chunked_current_block_left, &chunked_data, &len_chunked_data)) < 0)
            {
                oss_free(&chunked_data);
                logwar_out("recv chunked failed!");
                printf("len_chunked_current_block_left:%d\n", len_chunked_current_block_left);
                return -1;
            }
            else if (ret == 0)
            {
                printf("len_chunked_current_block_left:%d\n", len_chunked_current_block_left);
                break;
            }
            //t_disbuf(chunked_data + offset, len_chunked_current_block_left);
            len_chunked_current_block_left = 0;
            //puts("- 1 ------------------------------------------");
        }
        else if (len_chunked_current_block_left == 0)
        {
            if ((len_chunked_block = read_next_block_len(sockfd)) < 0)
            {
                logwar_out("receive next block head failed!");
                oss_free(&chunked_data);
                return -1;
            }
            if (len_chunked_block == 0)
            {
                printf("zero!!\n");
                break;
            }
            len_chunked_current_block_left = len_chunked_block;
            //printf("next len:%x, %d\n", len_chunked_block,len_chunked_block);
        }
        else //if (len_chunked_current_block_left < 0)
        {
            logwar_out("error!!!");
            oss_free(&chunked_data);
            return -1;
        }
    }

    // replace data
    memreplace_pos(NULL,NULL, &chunked_data,&len_chunked_data, times, from,len_from, to,len_to);

    printf("len_chunked_data:%x\n", len_chunked_data);
    t_disbuf(chunked_data, len_chunked_data);
    puts("-------------------------------------------------------------------------------");

    ///////////////////////////////////////////////////////////
    // copy chunked data to http
    // //////////////////////////////////////////////////////

    // calculate new buffer size
    sprintf(str_len_chunked_data, "%x", len_chunked_data);
    *len_data = len_http_head + 
                strlen(str_len_chunked_data) + 
                //sizeof(FLG_HTTP_NEWLINE)-1 +
                sizeof(FLG_CHUNKED_SPLIT)-1 +
                len_chunked_data + 
                sizeof(FLG_CHUNKED_END)-1;
    // realloc http buffer
    if ((ptr = (char*)realloc(*data, *len_data)) == NULL)
    {
        oss_free(&chunked_data);
        return -1;
    }
    *data = ptr;
    ptr = *data + len_http_head;
    // copy chunked length
    memcpy(ptr, str_len_chunked_data, strlen(str_len_chunked_data));
    ptr += strlen(str_len_chunked_data);

    // add a newline flag
    //memcpy(ptr, FLG_HTTP_NEWLINE, sizeof(FLG_HTTP_NEWLINE)-1);
    //ptr += sizeof(FLG_HTTP_NEWLINE)-1;
    memcpy(ptr, FLG_CHUNKED_SPLIT, sizeof(FLG_CHUNKED_SPLIT)-1);
    ptr += sizeof(FLG_CHUNKED_SPLIT)-1;

    // copy chunked data 
    memcpy(ptr, chunked_data, len_chunked_data);
    ptr += len_chunked_data;

    // add end flag
    memcpy(ptr, FLG_CHUNKED_END, sizeof(FLG_CHUNKED_END)-1);
    t_disbuf(*data, *len_data);

    // free temp buffer
    oss_free(&chunked_data);

    return 1;
}
*/

static char *modchunked_skip_split(char *ptr)
{
    if (ptr != NULL)
    {
        // usually \r\n\r\ne21\r\n
        //ptr += sizeof(FLG_HTTP_NEWLINE)-1;
        if (memcmp(ptr, FLG_HTTP_NEWLINE, sizeof(FLG_HTTP_NEWLINE)-1) == 0)
            ptr += sizeof(FLG_HTTP_NEWLINE)-1; 
        // sometimes \r\n\r\ne21\r\n\r\n
        if (memcmp(ptr, FLG_HTTP_NEWLINE, sizeof(FLG_HTTP_NEWLINE)-1) == 0)
            ptr += sizeof(FLG_HTTP_NEWLINE)-1; 
        // "ptr" now pointing to chunked data who is fallowing chunked length
    }
    return ptr;
}

//////////////////////////////////////////////////////
// return value: new memory saving peeled data
char *modchunked_peel(char *pchunked, u32 len_chunked, u32 *len_data, u32 *len_block_left)
{
    bool bRes = true;
    char *ptr = NULL;
    char *tmp = NULL;
    int len_chunked_current_block = 0;
    int len_chunked_current_block_left = 0;
    char *chunked_data = NULL;
    u32 len_chunked_data = 0;

    ptr = pchunked;
    do 
    {
        // get first chunked block length
        sscanf(ptr, "%x\r\n", &len_chunked_current_block);
        // printf("len_chunked_current_block:%d\n", len_chunked_current_block);
        // chunked data size is zero, means ending
        if (len_chunked_current_block == 0)
        {
            puts("----   current block zero size !! -------");
            len_chunked_current_block_left = 0;
            break;
        }

        if ((ptr = (char*)memmem(ptr, 8/*8 is enough, not have to very far*/, FLG_HTTP_NEWLINE, sizeof(FLG_HTTP_NEWLINE)-1)) == NULL)
        {
            logwar_out("modchunked_peel: find new line flag failed!");
            bRes = false;
            break;
        }
        ptr = modchunked_skip_split(ptr);
        //         
        len_chunked_current_block_left = len_chunked_current_block - (len_chunked - (ptr - pchunked));
        if (len_chunked_current_block_left < 0)
        { // there are more block data, get current block and ready to get next block
            //if ((tmp = (char*)realloc(chunked_data, len_chunked_data + len_chunked_current_block)) == NULL)
            if ((tmp = (char*)realloc(chunked_data, len_chunked_data + (len_chunked - (ptr - pchunked)))) == NULL)
            {
                logwar_out("modchunked_peel: realloc chunked memory failed 1!");
                bRes = false;
                break;
            }
            chunked_data = tmp;
            memcpy(chunked_data + len_chunked_data, ptr, len_chunked_current_block);
            len_chunked_data += len_chunked_current_block;
            ptr += len_chunked_current_block; 

            // skip chunked block tail
            if (memcmp(ptr, FLG_HTTP_NEWLINE, sizeof(FLG_HTTP_NEWLINE)-1) == 0)
                ptr += sizeof(FLG_HTTP_NEWLINE)-1;
        }
    } while (len_chunked_current_block_left < 0);

    if ( ! bRes)
    {
        oss_free(&chunked_data);
        *len_data = 0;
        return NULL;
    }

    if (len_chunked_current_block_left > 0)
    {
        if ((tmp = (char*)realloc(chunked_data, len_chunked_data + (len_chunked - (ptr - pchunked)))) == NULL)
        {
            oss_free(&chunked_data);
            printf("len_chunked_data:%d, len_chunked:%d, ptr:%p, chunked_data:%p\n", len_chunked_data, len_chunked, ptr, pchunked); 
            logwar_fmt("modchunked_peel: realloc chunked memory failed 2(size:%lu)!", len_chunked_data + (len_chunked - (ptr - pchunked)));
            return false;
        }
        chunked_data = tmp;

        // do not change the order
        memcpy(chunked_data + len_chunked_data, ptr, len_chunked - (ptr - pchunked));
        len_chunked_data += len_chunked - (ptr - pchunked);
    }

    *len_data = len_chunked_data;
    *len_block_left = len_chunked_current_block_left;

    return chunked_data;
}

/*
static bool modchunked_prepare_first_chunked(modchunked_t *chkd)
{
    if (chkd == NULL)
    {
        logwar_out("modchunked_prepare_first_chunked: arg error!");
        return false;
    }

    bool bRes = false;
    char *ptr = NULL;
    char *tmp = NULL;
    int len_chunked_current_block = 0;
    int len_chunked_current_block_left = 0;
    char *chunked_data = NULL;
    u32 len_chunked_data = 0;

    char *data = chkd->pdata;
    //char *psplit = chkd->pchunked_split_flg;
    u32 len_data = chkd->len_data;

    if ((ptr = psplit) == NULL)
    {
        logwar_out("modchunked_prepare_first_chunked: NULL chunked split flag pointer!");
        return false;
    }
    
    // get chunked block out
    bRes = true;
    do 
    {
        // get first chunked block length
        sscanf(ptr, "%x\r\n", &len_chunked_current_block);
        printf("len_chunked_current_block:%d\n", len_chunked_current_block);
        // chunked data size is zero 
        if (len_chunked_current_block == 0)
            break;

        if ((ptr = (char*)memmem(ptr, 8/8 is enough, not have to very far/, FLG_HTTP_NEWLINE, sizeof(FLG_HTTP_NEWLINE)-1)) == NULL)
        {
            logwar_out("modchunked_prepare_first_chunked: find new line flag failed!");
            break;
        }
        // usually \r\n\r\ne21\r\n
        ptr += sizeof(FLG_HTTP_NEWLINE)-1;
        // sometimes \r\n\r\ne21\r\n\r\n
        if (memcmp(ptr, FLG_HTTP_NEWLINE, sizeof(FLG_HTTP_NEWLINE)-1) == 0)
            ptr += sizeof(FLG_HTTP_NEWLINE)-1; 
        // "ptr" now pointing to chunked data who is fallowing chunked length
        
        len_chunked_current_block_left = len_chunked_current_block - (len_data - (ptr - data));
        if (len_chunked_current_block_left < 0)
        { // there are more block data, get current block and ready to get next block
            if ((tmp = (char*)realloc(chunked_data, len_chunked_data + len_chunked_current_block)) == NULL)
            {
                logwar_out("modchunked_prepare_first_chunked: realloc chunked memory failed 1!");
                bRes = false;
                break;
            }
            chunked_data = tmp;
            memcpy(chunked_data + len_chunked_data, ptr, len_chunked_current_block);
            len_chunked_data += len_chunked_current_block;
            ptr += len_chunked_current_block; 

            // skip chunked block tail
            if (memcmp(ptr, FLG_HTTP_NEWLINE, sizeof(FLG_HTTP_NEWLINE)-1) == 0)
                ptr += sizeof(FLG_HTTP_NEWLINE)-1;
        }
    } while (len_chunked_current_block_left < 0);

    if ( ! bRes)
    {
        oss_free(&chunked_data);
        return false;
    }

    if (len_chunked_data > 0)
    {
        if ((tmp = (char*)realloc(chunked_data, len_chunked_data + (len_data - (ptr - data)))) == NULL)
        {
            oss_free(&chunked_data);
            logwar_out("modchunked_prepare_first_chunked: realloc chunked memory failed 2!");
            return false;
        }
        chunked_data = tmp;

        // do not change the order
        memcpy(chunked_data + len_chunked_data, ptr, len_data - (ptr - data));
        len_chunked_data += len_data - (ptr - data);
    }

    // set data
    chkd->data_chunked = chunked_data;
    chkd->len_chunked = len_chunked_data;
    chkd->offset_current_block = ptr - psplit;
    chkd->len_current_block = len_chunked_current_block;

    if (len_chunked_data > 0)
        t_disbuf(chunked_data, len_chunked_data);
    printf("len_chunked_data:%d, %x\n", len_chunked_data, len_chunked_data);
    printf("len_current_block:%d, %x\n", len_chunked_current_block, len_chunked_current_block);
    printf("offset_block:%d, %x\n", chkd->offset_current_block, chkd->offset_current_block);

    return true;
}
*/

int read_next_block_len(int sockfd)
{
    int len_next_block = 0;
    int ret = 0;
    char tmp[32] = {0};
    char *ptr = tmp;

    while (ptr < tmp + sizeof(tmp))
    {
        if ((ret = Recv(sockfd, ptr, 1, 0)) <= 0)
            break;
        if (memmem(tmp, sizeof(tmp), "\r\n", sizeof("\r\n")-1) != NULL)
        {
            if (memcmp(tmp, "\r\n", 2) == 0)
            {
                ptr = tmp;
                continue;
            }
            break; 
        }
        ++ptr;
    }
    if (ptr == tmp + sizeof(tmp))
        return -1;

    sscanf(tmp, "%x\r\n", &len_next_block);
    if (len_next_block == 0)
        ret = Recv(sockfd, ptr + 1, 2, 0);
    //printf("temp\n");
    //t_disbuf(tmp, sizeof(tmp));
    
    return len_next_block;
}

bool modchunked_cache_chunked(modchunked_t *chkd)
{
    if (chkd == NULL)
    {
        logwar_out("modchunked_cache_chunked: arg error!");
        return false;
    }

    bool bRes = false;
    int ret = 0;
    int len_chunked_block = 0;
    int len_chunked_current_block_left = chkd->len_current_block_left;
    int sockfd = -1;
    char *chunked_data = chkd->data_chunked;
    u32 len_chunked_data = chkd->len_chunked;

    // process chunked data that has already been received.
    if (chkd->len_chunked == 0)
        return true;
    sockfd = chkd->sock_recv;
    chunked_data = chkd->data_chunked;
    len_chunked_data = chkd->len_chunked;
    len_chunked_block = chkd->len_current_block;

    while (true)
    {
        // data not received complate.
        if (len_chunked_current_block_left > 0)
        {
            //int offset_tmp = len_chunked_data + len_chunked_current_block_left - len_chunked_block;
            printf("current block left:%d\n", len_chunked_current_block_left);
            printf("len chunked block:%d\n", len_chunked_block);
            // receive chunked data and a flowing chunked data that not large than sizeof chunked end
            if ((ret = recv_tail(sockfd, len_chunked_current_block_left, &chunked_data, &len_chunked_data)) < 0)
            {
                logwar_out("recv chunked failed!");
                printf("modchunked_cache_chunked: len_chunked_current_block_left:%d\n", len_chunked_current_block_left);
                break;
            }
            else if (ret == 0)
            {
                printf("modchunked_cache_chunked: len_chunked_current_block_left:%d\n", len_chunked_current_block_left);
                break;
            }
            //t_disbuf(chunked_data + offset_tmp, len_chunked_block);
            //t_disbuf(chunked_data, len_chunked_data);
            //t_disbuf(chunked_data, len_chunked_data);
            len_chunked_current_block_left = 0;
        }
        else if (len_chunked_current_block_left == 0)
        {
            if ((len_chunked_block = read_next_block_len(sockfd)) < 0)
            {
                logwar_out("modchunked_cache_chunked: receive next block head failed!");
                break;
            }
            if (len_chunked_block == 0)
            {
                printf("zero!!\n");
                bRes = true;
                break;
            }
            printf("-------- next block len ------------\n");
            printf("%d\n", len_chunked_block);
            len_chunked_current_block_left = len_chunked_block;
        }
        else //if (len_chunked_current_block_left < 0)
        {
            logwar_out("error!!!");
            break;
        }
    }

    if ( ! bRes)
    {
        oss_free(&chunked_data);
        return false;
    }

    // set data
    chkd->data_chunked = chunked_data;
    chkd->len_chunked = len_chunked_data;

    return true;
}

bool modchunked_cache(modchunked_t *chkd)
{
    if (chkd == NULL)
    {
        logwar_out("modchunked_cache: arg error!");
        return false;
    }

    if ( ! modchunked_cache_chunked(chkd))
        return false;

    return true;
}

bool modchunked_send_chunkedlength(modchunked_t *chkd, int len)
{
    char str_length[32] = {0};
    
    sprintf(str_length, "%x\r\n", len);
    if ( Send(chkd->sock_send, str_length, strlen(str_length), 0) < 0)
        return false;

    return true;
}

bool modchunked_send_chunked_blockend(modchunked_t *chkd)
{
    if ( Send(chkd->sock_send, FLG_HTTP_NEWLINE, sizeof(FLG_HTTP_NEWLINE)-1, 0) < 0)
        return false;

    return true;
}

bool modchunked_split_send(modchunked_t *chkd, int len_split)
{
    if ((chkd == NULL) || (len_split < 0))
    {
        logwar_out("modchunked_split_send: arg error!");
        return false;
    }

    char *ptr = chkd->data_chunked;
    int len_left = chkd->len_chunked;
    // send http head
    if ( Send(chkd->sock_send, chkd->http_head, chkd->len_http_head, 0) < 0)
        return false;

    if (len_split == 0)
        len_split = chkd->len_chunked;
    
    while (len_left > 0)
    {
        if (len_left < len_split)
            len_split = len_left;

        if ( ! modchunked_send_chunkedlength(chkd, len_split))
            return false;
        if ( Send(chkd->sock_send, ptr, len_split, 0) < 0)
            return false;
        ptr += len_split;
        if ( ! modchunked_send_chunked_blockend(chkd))
            return false;
        len_left -= len_split;
    }

    // send \r\n0\r\n\r\n
    //if ( ! modchunked_send_chunked_blockend(chkd))
        //return false;
    // send 0\r\n\r\n
    if ( ! modchunked_send_chunkedlength(chkd, 0))
        return false;
    if ( ! modchunked_send_chunked_blockend(chkd))
        return false;
    //if ( ! modchunked_send_chunked_blockend(chkd))
        //return false;

    return true;
}

bool modchunked_end(modchunked_t *chkd)
{
    if (chkd == NULL)
        return false;
    oss_free(&chkd->http_head);
    oss_free(&chkd->data_chunked);
    memset(chkd, 0, sizeof(modchunked_t));

    return true;
}



