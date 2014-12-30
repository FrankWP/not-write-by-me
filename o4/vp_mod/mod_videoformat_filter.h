#ifndef _MOD_VIDEOFORMAT_FILTER_H_
#define _MOD_VIDEOFORMAT_FILTER_H_

typedef enum _e_videoformat
{
    EVF_NONE    = 0,
    EVF_H264    = 1
}e_vf;

bool mod_vf_filter_init();
e_vf mod_vf_filter_gettype(char *pkg, int len_pkg);
bool mod_vf_filter_check(e_vf videoformat);

#endif  // _MOD_VIDEOFORMAT_FILTER_H_

