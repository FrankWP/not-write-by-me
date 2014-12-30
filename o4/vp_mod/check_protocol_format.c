#include "../vpheader.h"
#include "check_protocol_format.h"

int
load_transport_format_filter()
{
	query_conf *pconf = NULL;
	query_conf *pctrl = NULL;
	char cfg_path[256] = {0};
	char *val = NULL;
    int nval = 0;
    int flag = E_TFORMAT_NONE;

	sprintf(cfg_path, "%s/%s", "/topconf/topvp", "transformat.conf");
    
	if ((pconf = load_configuration(cfg_path)) == NULL)
	{
        logwar_out("Load protocol control config file failed!");
        return E_TFORMAT_ERROR;
	}

	if ((pctrl = find_label(pconf, (char*)"id")) == NULL)
	{
		free_configuration(&pconf);
		logwar_out("Find transport format id failed!");
		return E_TFORMAT_ERROR;
	}

    if ((val = get_value_from_label(pctrl, (char*)"rtp")) != NULL)
        nval = atoi(val);
    if (nval > 0)
        flag |= E_TFORMAT_RTP;

    if ((val = get_value_from_label(pctrl, (char*)"all")) != NULL)
        nval = atoi(val);
    if (nval > 0)
        flag |= E_TFORMAT_ALL;

	free_configuration(&pconf);

    return flag;
}

int
match_rtph(rtpheader *sample, rtpheader *data)
{
    if ((sample == NULL) || (data == NULL))
        return 0;

    int interval = data->timestamp - sample->timestamp;

    if ( (sample->version != data->version) ||
         (sample->ssrc != data->ssrc) ||
         (sample->sequence_n != data->sequence_n - 1))
    {
        return 0;
    }

    if (interval < 0)
        return 0;

	/*
    if ((sample->time_interval > 0) &&
        (interval != sample->time_interval))
    {
        return 0;
    }
	*/

    return 1;
}

int
set_rtpheader(char *buf, rtpheader *prtph)
{
    if ((buf == NULL) || (prtph == NULL))
        return 0;

    prtph->version = (buf[0] & 0xc0) >> 6; 
    prtph->is_padding = (buf[0] & 0x20) >> 5;
    prtph->is_extend = (buf[0] & 0x10) >> 4;
    prtph->num_csrc = (buf[0] & 0x0f);

    prtph->mark = (buf[1] & 0x80) >> 7;
    prtph->ptype = (buf[1] & 0x7f);

    prtph->sequence_n = htons(*(uint16_t*)(buf+2));
    prtph->timestamp = htonl(*(uint32_t*)(buf+4));
    prtph->ssrc = ntohl(*(uint32_t*)(buf+8));

    //prtph->time_interval = 0;
    
    return 1;
}

void
dis_header(rtpheader *h)
{
    if (h == NULL)
        return;
 
    printf("version:%02x\n", h->version);
    printf("is_padding:%02x\n", h->is_padding);
    printf("is_extend:%02x\n", h->is_extend);
    printf("num_csrc:%02x\n", h->num_csrc);
    printf("mark:%02x\n", h->mark);
    printf("ptype:%02x\n", h->ptype);
    printf("sequence_n:%02x, %u\n", h->sequence_n, h->sequence_n);
    printf("timestamp:%02x, %u\n", h->timestamp, h->timestamp);
    printf("ssrc:%02x, %u\n", h->ssrc, h->ssrc);
   //printf("time interval:%d\n", h->time_interval);
}

/*
int
sample_rtph(char *buf, int sz_buf, rtpheader *h)
{
    if ((buf == NULL) || (h == NULL) || (sz_buf <= 0))
        return 0;

    int res = 0;
    char *ptr = buf;
    int i = 0;
    rtpheader last;
    rtpheader tmp;

    set_rtpheader(ptr, h);
    set_rtpheader(ptr, &last);
    i = sizeof(rtpheader) + h->num_csrc * 4;
    ptr += i;

    for (; i < sz_buf; ++i)
    {
		loginf_out("1");
        set_rtpheader(ptr+i, &tmp);
        if (match_rtph(&last, &tmp))
        {
		loginf_out("2");
            last.time_interval = tmp.timestamp - last.timestamp;
            if (last.time_interval == 0)
            {
		loginf_out("3");
                last.sequence_n += 1;
                continue;
            }
            else if (last.time_interval > 0)
            {
		loginf_out("4");
                h->time_interval = last.time_interval;
                res = 1;
                break;
            }
		loginf_out("5");
            last.time_interval = 0;
        }
    }

    return res;
}
*/

int
sample_rtph(char *buf, int sz_buf, rtpheader *h)
{
    if ((buf == NULL) || (h == NULL) || (sz_buf <= 0))
        return 0;

    int res = 0;
    char *ptr = buf;
    //char *ptr_tmp = NULL;
    int i = 0;
    int hsz = 0;
    rtpheader last;
    rtpheader tmp;

    set_rtpheader(ptr, h);
    set_rtpheader(ptr, &last);
    hsz = sizeof(rtpheader) + h->num_csrc * 4;
    ptr += hsz;
    //ptr_tmp = ptr;

    i = hsz;
    for (; i < sz_buf; )
    {
        //set_rtpheader(ptr_tmp, &tmp);
        set_rtpheader(ptr, &tmp);
        if (match_rtph(&last, &tmp))
        {
            memcpy(&last, &tmp, sizeof(rtpheader));
            hsz = sizeof(rtpheader) + h->num_csrc * 4;
            //ptr = ptr_tmp + hsz;

            i += hsz;
            ptr += hsz;
            continue;
        }
        
        ++i;
     //   ++ptr_tmp;
        ++ptr;
    }

	if (i == sz_buf)
		res = 1;
	//loginf_fmt("--- i:%d, sz:%d ---", i,sz_buf);

    return res;
}


/*
int
fetch_data(char *buf, int sz_buf, rtpheader *h, FILE *pf)
{
    if ((buf == NULL) || (h == NULL) || (sz_buf <= 0) || (pf == NULL))
        return 0;

    int res = 0;
    char *ptr = buf;
    char *ptr_tmp = NULL;
    int i = 0;
    int hsz = 0;
    rtpheader last;
    rtpheader tmp;

    set_rtpheader(ptr, h);
    set_rtpheader(ptr, &last);
    hsz = sizeof(rtpheader) + h->num_csrc * 4;
    ptr += hsz;
    ptr_tmp = ptr;

    int flag = 0;
    i = hsz;
    for (; i < sz_buf; )
    {
        set_rtpheader(ptr_tmp, &tmp);
        if (match_rtph(&last, &tmp))
        {
            fwrite(ptr, ptr_tmp - ptr, 1, pf);
            //printf("mark:%02x, ptype:%02x\n", last.mark, last.ptype);

//            if (last.mark == 1) 
 //               ++flag;
  //          else if (flag == 1)
//                ++flag;

//            const int n = 2;
//            write_file_order(ptr, ptr_tmp-ptr, (flag == n));
//            if (flag == n)
//                flag = 0;
            memcpy(&last, &tmp, sizeof(rtpheader));

            hsz = sizeof(rtpheader) + h->num_csrc * 4;
            ptr = ptr_tmp + hsz;

            i += hsz;
            ptr_tmp += hsz;
            continue;
        }
        
        ++i;
        ++ptr_tmp;
    }

    return res;
}
*/

/*
int
main(int argc,  char **argv)
{
	if (argc != 3)
	{
		printf("Usage: %s rtpFile videoName\n", argv[0]);
		return -1;
	}
	size_t fsz = 0;
	char *fbuf = NULL;
	char *frpath = argv[1];
    char *fwpath = argv[2];
	char *ptr = NULL;

	if ( ! read_full_file(frpath, &fbuf, &fsz, 0) )
		return -1;

    ptr = fbuf;
    rtpheader rtp_header;

    //if ( ! sample_rtph(ptr, fsz, &rtp_header))
    //{
        //printf("sample rtp header failed!\n");
        //free(fbuf);
        //return -1;
    //}

    FILE *pf = fopen(fwpath, "wb");
    if (pf == NULL)
    {
        printf("open file %s failed!\n", fwpath);
        free(fbuf);
        return -1;
    }

    set_rtpheader(ptr, &rtp_header);
    fetch_data(ptr, fsz, &rtp_header, pf);

    fclose(pf);

	return 0;
}
*/

