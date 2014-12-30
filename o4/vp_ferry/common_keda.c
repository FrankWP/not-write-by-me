#include "common_keda.h"

int __kd_ga_video_proxy(u32 lip, u32 dip, u16 l_base_port, u16 d_base_port, int count_proxy, int step, u16 tout)
{
    int     times;
    pid_t   pf_member_ids[PROXY_COUNT] = {0};
    char    flg[32] = {0};

    /* real video */
    for (times=0; times < count_proxy; times++)
    {
        if ((pf_member_ids[times] = run_vs_udp_proxy(lip, dip, l_base_port, d_base_port, 0, tout, __gg.ferry_port)) > 0)
        {
            pf_add_member(pf_member_ids[times]);
            printf("add member: %u\n", pf_member_ids[times]);
        }
        else
        {
            logwar_out("run vp-vsudp failed!\n");
        }
        l_base_port += step;
        d_base_port += step;
    }

    sprintf(flg, "%lu", pthread_self());
    tp_set_data(flg, (char*)(void*)pf_member_ids, sizeof(pid_t) * PROXY_COUNT);

    return 1;
}

int process_keda_comp_protocol(pvp_uthttp put, char **ut_buf, u32 *pack_len, mtp_call_back func_process_data)
//int process_keda_comp_protocol(pvp_uthttp put, char **ut_buf, u32 *pack_len, int direction)
{
    const static char FLG_COMP[] = "\x02\x23";
    const static char FLG_RECORD[] = "\x78\xc0";
    const static int len_head = 39;
    const static int offset_msg_comp_len = 20;
    u16 inet_len_msg_compress = 0;
    u16 len_msg_uncompress = 0;
    unsigned long len_msg_compress_l = 0;
    unsigned long len_msg_uncompress_l = 0;
    unsigned char *pUncompress = NULL;
    unsigned char *ptr = NULL;
    int start_record = 0;

    //puts("------------- originality -----------------------------------");
    //t_disbuf((unsigned char*)*ut_buf, *pack_len);

    // check compress 
    if (memcmp(*ut_buf + 18, FLG_COMP, sizeof(FLG_COMP)-1) != 0)
	{
		//puts("-----------------------------");
        return 1;	// data is not compressed
	}

    if (memcmp(*ut_buf + 39, FLG_RECORD, sizeof(FLG_RECORD)-1) != 0)
        start_record = 1;

    memcpy(&inet_len_msg_compress, *ut_buf + offset_msg_comp_len, 2);
    inet_len_msg_compress = htons(ntohs(inet_len_msg_compress) - 4);

    memcpy(&len_msg_uncompress, *ut_buf + 41, 2);
    //printf("len uncom 1: %d\n", len_msg_uncompress);
    if (oss_malloc(&pUncompress, len_msg_uncompress) < 0)
    {
        logdbg_out("malloc uncompress memory failed!");
        return -1;
    }

    len_msg_uncompress_l = len_msg_uncompress;
    len_msg_compress_l = ntohs(inet_len_msg_compress);
    ptr = (unsigned char*)(*ut_buf + len_head + 4);
    //puts("--------- before uncompress -----------");
    //t_disbuf(ptr, len_msg_compress_l);
    if (zdecompress(ptr,len_msg_compress_l, pUncompress, &len_msg_uncompress_l) < 0)
    {
        oss_free(&pUncompress);
        logdbg_out("uncompress failed!");
        return 1;
    }

    printf("uncompress len:%ld\n", len_msg_uncompress_l);
    puts("-------- uncompress ----------------------------------------");
    t_disbuf(pUncompress, len_msg_uncompress_l);

    if (func_process_data != NULL)
        func_process_data(put, (char**)&pUncompress, (u32*)&len_msg_uncompress_l);
    // -------------- PROCESS UNCOMPRESS DATA -------------------
    /*
    if (direction == DO_REQST)
        replace_cascade_addr(put, (char**)&pUncompress, (u32*)&len_msg_uncompress_l);
    else
    {
        replace_video_stream_addr(put, (char**)&pUncompress, (u32*)&len_msg_uncompress_l);
        if (start_record)
            replace_record_addr(put, (char**)&pUncompress, (u32*)&len_msg_uncompress_l);
    }
    */
    
    // ReCompress
    unsigned char *pNewCompress = NULL;
    unsigned long len_new_compress = len_msg_uncompress + 128; // sometimes compress data is larger than that uncompress.
    oss_malloc(&pNewCompress, len_new_compress);    
    if (zcompress(pUncompress,len_msg_uncompress_l, pNewCompress,&len_new_compress) < 0)
    {
        oss_free(&pUncompress);
        oss_free(&pNewCompress);
        logdbg_out("compress failed!");
        return -1;
    }
    //puts("------------ new compress ----------------------------");
    //t_disbuf(pNewCompress, len_new_compress);

    // update data
    if ((ptr = (unsigned char*)realloc(*ut_buf, len_head + 4 + len_new_compress)) == NULL)
    {
        oss_free(&pUncompress);
        oss_free(&pNewCompress);
        logdbg_out("realloc failed!");
        return -1;
    }
    *ut_buf = (char*)ptr;
    *pack_len = len_head + 4 + len_new_compress;
    memcpy(*ut_buf + len_head + 4, pNewCompress, len_new_compress);
    len_new_compress += 4;
    u16 inet_len_new_compress = htons(len_new_compress);
    memcpy(*ut_buf + offset_msg_comp_len, &inet_len_new_compress, 2);

    //puts("-------- new data -----------");
    //t_disbuf((unsigned char*)*ut_buf, *pack_len);

    oss_free(&pUncompress);
    oss_free(&pNewCompress);

	return 1;
}

