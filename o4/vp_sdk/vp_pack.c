#include "vp_pack.h"

/* wuhan fiber
 * client send get video stream reqst at heart thread
 */

enum __e_mode __mode;

char wh_vget[] = {
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    0x39 };

/* reply heart info at heart thread */

char wh_hreply[32];

/* client send close video stream reqst */

char wh_vcclose[] = {
    0x81, 0xcb, 0x00, 0x07, 0x55, 0x96, 0x31, 0x30 };

/* server reply close video stream cmd */

char wh_vsclose[] = {
    0x80, 0xcb, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xf8, 0x6d, 0x65, 0x64, 0x69, 0x61, 0x20, 0x64,
    0x69, 0x73, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63,
    0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

/*
 *  parse cmd type, request or close or other.
 *  send reply info to request client.
 */
int parse_reqst_cmd(int sockfd,
                    SAI cli_addr,
                    char *data_buf)
{
    /*
    if (data_buf == "close") {
        send close ack info to reqst client
        //send_close();
       return DT_CLOSE_CONNECT;
    }

    if (data_buf == "reqst_video") {
        //send close ack info to reqst client
        //send_reqst();
        return DT_REQST_VIDEO;
    }
    return DT_SEND;*/
    return 1;
}
