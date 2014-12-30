#ifndef _CHECK_PROTOCOL_FORMAT_H_
#define _CHECK_PROTOCOL_FORMAT_H_

typedef struct _rtpheader
{
	unsigned char version:2;
	unsigned char is_padding:1;
	unsigned char is_extend:1;
	unsigned char num_csrc:4;
	unsigned char mark:1;
	unsigned char ptype:7;
	uint16_t sequence_n;
	uint32_t timestamp;
    uint32_t ssrc;

//    int time_interval;
}rtpheader;

typedef enum e_trans_format
{
    E_TFORMAT_NONE = 0,
    E_TFORMAT_RTP = 1,
    E_TFORMAT_ALL = 2,
    
    E_TFORMAT_ERROR = 4
}eTransFormat;

int load_transport_format_filter();

int match_rtph(rtpheader *sample, rtpheader *data);
int set_rtpheader(char *buf, rtpheader *prtph);
int sample_rtph(char *buf, int sz_buf, rtpheader *h);
void dis_header(rtpheader *h);

#endif // _CHECK_PROTOCOL_FORMAT_H_

