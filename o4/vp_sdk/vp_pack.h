#ifndef __VP_PACK_H
#define __VP_PACK_H

#include "common.h"
enum __e_mode{
    DT_ERROR = -1,
    DT_NOSEND,
    DT_SEND,
    DT_REQST_VIDEO,
    DT_CLOSE_CONNECT,
    DT_QUIT
};

extern enum __e_mode __mode;

int parse_reqst_cmd(int sockfd, SAI cli_addr, char *data_buf);

#endif // ~__VP_PACK_H
