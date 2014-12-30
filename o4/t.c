/*
 *  @describe: keda v2800
 *  @date: 
 */

#include "vpheader.h"

const static int LEN_PROTO_HEAD = 39;
const static int OFFSET_LEN_MSG = 20;

int process_keda_uncompress(pvp_uthttp put, unsigned char **pUncompress, u16 *uncompress_len)
{
    //const static char FLG_ADDR[] = "http://";
    puts("--------- UNCOMPRESS !! -------------------------------------------");
    //t_disbuf(*pUncompress, *uncompress_len);

    return 1;
}

int process_keda_one_protocol(char **pOneProto, u32 *len_one_proto)
{
    puts("----------- ONE PROTOCOL ---------------");
    t_disbuf(*pOneProto, *len_one_proto);
    puts("-- -- -- -- -- -- -- -- -- -- -- -- -- -- --");
    //const static char FLG_COMP[] = "\x02\x23";
    u16 inet_len_msg_compress = 0;
    //u16 host_len_msg_compress = 0;
    u16 len_msg_uncompress = 0;
    unsigned long host_len_msg_compress_l = 0;
    unsigned long len_msg_uncompress_l = 0;
    unsigned char *pUncompress = NULL;
    unsigned char *ptr = NULL;
    //puts("process_keda_one_protocol: 1");
    //if (memcmp(*pOneProto + 18, FLG_COMP, sizeof(FLG_COMP)-1) != 0)
        //return 1;
    //puts("process_keda_one_protocol: 2");
    memcpy(&inet_len_msg_compress, *pOneProto + OFFSET_LEN_MSG, 2);
    host_len_msg_compress_l = ntohs(inet_len_msg_compress) - 4;
    //puts("process_keda_one_protocol: 3");
    //inet_len_msg_compress = htons(ntohs(inet_len_msg_compress) - 4);
    //len_msg_compress_l = ntohs(inet_len_msg_compress) - 4;
    memcpy(&len_msg_uncompress, *pOneProto + 41, 2);
    len_msg_uncompress_l = len_msg_uncompress;
    //printf("len_msg_uncompress:%d\n", len_msg_uncompress);

    //puts("process_keda_one_protocol: 4");
    if (oss_malloc(&pUncompress, len_msg_uncompress) < 0)
    {
        logerr_out("malloc uncompress memory failed!");
        return -1;
    }

    //puts("process_keda_one_protocol: 5");
    ptr = (unsigned char*)(*pOneProto + LEN_PROTO_HEAD + 4);
    //puts("--------- before uncompress -----------");
    //t_disbuf(ptr, len_msg_compress_l);
	if (zdecompress(ptr,host_len_msg_compress_l, pUncompress, &len_msg_uncompress_l) < 0)
    {
        oss_free(&pUncompress);
        puts("-------------------------------------------------");
        t_disbuf(ptr, host_len_msg_compress_l);
        logerr_out("uncompress failed!");
        return 1;
    }

    //puts("process_keda_one_protocol: 6");
    //printf("uncompress len:%ld\n", len_msg_uncompress_l);
    //puts("-------- uncompress ----------------------------------------");
    t_disbuf(pUncompress, len_msg_uncompress_l);

    //if (process_keda_uncompress(put, &pUncompress, &len_msg_uncompress) < 0)
    //{
        //oss_free(&pUncompress);
        //logerr_out("process keda uncompress failed!");
        //return -1;
    //}

    //puts("process_keda_one_protocol: 7");
    // ReCompress
    unsigned char *pNewCompress = NULL;
    unsigned long len_new_compress = len_msg_uncompress + 128; // sometimes compress data is larger than that uncompress.
    if (oss_malloc(&pNewCompress, len_new_compress) < 0)
    {
        logerr_fmt("malloc failed! size:%lu", len_new_compress);
        return -1;
    }
    if (zcompress(pUncompress,len_msg_uncompress_l, pNewCompress,&len_new_compress) < 0)
    {
        printf("pUn:%p, len_un:%lu, pNew:%p, len_new:%lu\n", pUncompress, len_msg_uncompress_l, pNewCompress,len_new_compress);
        oss_free(&pUncompress);
        oss_free(&pNewCompress);
        logerr_out("compress failed!");
        exit(-1);
        return -1;
    }
    //puts("process_keda_one_protocol: 8");
    //puts("------------ new compress ----------------------------");
    //t_disbuf(pNewCompress, len_new_compress);

    // update data
    if ((ptr = (unsigned char*)realloc(*pOneProto, LEN_PROTO_HEAD + 4 + len_new_compress)) == NULL)
    {
        oss_free(&pUncompress);
        oss_free(&pNewCompress);
        logerr_out("realloc failed!");
        return -1;
    }
    //puts("process_keda_one_protocol: 9");
    *pOneProto= (char*)ptr;
    *len_one_proto = LEN_PROTO_HEAD + 4 + len_new_compress;

    memcpy(*pOneProto + LEN_PROTO_HEAD + 4, pNewCompress, len_new_compress);
    len_new_compress += 4;
    u16 inet_len_new_compress = htons(len_new_compress);
    memcpy(*pOneProto + 20, &inet_len_new_compress, 2);

    //puts("process_keda_one_protocol: 10");
    //puts("-------- new data -----------");
    //t_disbuf((unsigned char*)*ut_buf, *pack_len);
    
    oss_free(&pUncompress);
    oss_free(&pNewCompress);

    //puts("process_keda_one_protocol: 11");
    return 1;
}

int recv_keda_complete_protocol(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    int len_msg_compress = 0;
    char *ptr = *ut_buf;
    int len_left = *pack_len;

    do 
    {
        if (len_left < LEN_PROTO_HEAD)
        {
            if (recv_tail(put->svr_sock, LEN_PROTO_HEAD - (*pack_len - (ptr - *ut_buf)), ut_buf, pack_len) <= 0)
                return -1;
            memcpy(&len_msg_compress, ptr + OFFSET_LEN_MSG, sizeof(len_msg_compress));
            len_msg_compress = ntohs(len_msg_compress);
            if (recv_tail(put->svr_sock, len_msg_compress, ut_buf, pack_len) <= 0)
                return -1;
            // receive ok, break the loop
            break;
        }

        memcpy(&len_msg_compress, ptr + OFFSET_LEN_MSG, sizeof(len_msg_compress));
        len_msg_compress = ntohs(len_msg_compress);

        if ((len_left -= (LEN_PROTO_HEAD + len_msg_compress)) == 0)
            break;
        else if (len_left > 0)
            ptr += (LEN_PROTO_HEAD + len_msg_compress);
        else // if (len_left < 0)
        {
            if (recv_tail(put->svr_sock, -len_left, ut_buf, pack_len) <= 0)
                return -1;
            break;
        }
    } while (true);

    return 1;
}

int process_keda_protocol(char **ut_buf, u32 *pack_len)
{
    char *ptr_one_proto = *ut_buf;
    u16  len_one_proto = 0;
    u16  len_msg = 0;
    char *ptr_keda_proto = NULL;
    u32  len_keda_proto = 0;
    puts("------------------ Source Data --------------------------------------");
    t_disbuf(*ut_buf, *pack_len);
    puts("---------------------------------------------------------------------");

    do
    {
        //ptr_one_proto = ptr_one_proto + len_last_proto;
        memcpy(&len_msg, ptr_one_proto + OFFSET_LEN_MSG, 2);
        len_msg = ntohs(len_msg);
        len_one_proto = len_msg + LEN_PROTO_HEAD;

        //printf("len_protocol: %d\n", len_one_proto);
        len_keda_proto = len_one_proto;
        oss_malloc(&ptr_keda_proto, len_keda_proto);
        memcpy(ptr_keda_proto, ptr_one_proto, len_keda_proto);

        //sleep (1);
        if (process_keda_one_protocol(&ptr_keda_proto, &len_keda_proto) < 0)
            return -1;
        //puts("KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKkk");
        //t_disbuf(ptr_keda_proto, len_keda_proto);
        //puts("--------------------------------------");

        oss_free(&ptr_keda_proto);
        len_keda_proto = 0;

        ptr_one_proto += len_one_proto;
    } while (ptr_one_proto < *ut_buf + *pack_len);
    oss_free(ut_buf);
    *pack_len = 0;

    return 1; 
}

int str2hex(char **str, u32 *len_str)
{
    if ((str == NULL) || (*str == NULL) || (len_str == NULL))
    {
        printf("str2hex: arg error! %p, %p, %p\n", str, *str, len_str);
        return -1;
    }
    if ((*len_str % 2) != 0)
    {
        printf("str2hex: length error!\n");
        return -1;
    }

    u32 len_hex = *len_str/2;
    char *pHex = NULL;
    char hex = 0;
    u32 i = 0;
    char tmp[4] = {0};
    char *ptr = NULL;

    oss_malloc(&pHex, len_hex);

    ptr = pHex;
    for (i = 0; i < len_hex; ++i)
    {
        memset(tmp, 0, sizeof(tmp));
        memcpy(tmp, *str + i * 2, 2);
        hex = Hex2Int(tmp);
        memcpy(ptr, &hex, 1);
        ++ptr;
    }

    oss_free(str);
    *str = pHex;
    *len_str = len_hex;

    return 1;
}

/////////////////
int main(int argc, char *argv[])
{

    char *buf = NULL;
    size_t len_buf = 0;

    if (argc < 2)
    {
        printf("Usage: %s filename\n", argv[0]);
        return -1;
    }

    if ( ! t_read_full_file(argv[1], &buf, &len_buf, 0))
    {
        printf("read file \"%s\" failed!\n", argv[1]);
        return -1;
    }
    len_buf -= 1;
    //t_disbuf(buf, len_buf);

    if (str2hex(&buf, (u32*)&len_buf) < 0)
    {
        printf("string to hex failed!\n");
        return -1;
    }
    
    if ( ! process_keda_protocol(&buf, (u32*)&len_buf))
    {
        puts("process keda failed!");
        return -1;
    }
    free(buf);
    buf = NULL;

    return 0;
}

