#include "../vpheader.h"

typedef struct _videoformat_t
{
    char type_string[32];
    int  type_n;
}videoformat_t;

videoformat_t videoformats[] = 
{
    {"h264_flag=", EVF_H264}
};

static int g_vf = 0;

bool mod_vf_filter_init()
{
    char  value[8];
    char  buf[1024];
    FILE *pf = NULL;
    char *pret = NULL;

    // video format filter
    if ((pf = fopen("/topconf/topvp/flowformat.conf", "r")) == NULL)
        return false;
    fread(buf, sizeof(buf) - 1, 1, pf);
    fclose(pf);

    u32 i = 0;
    for (; i < sizeof(videoformats)/sizeof(videoformat_t); ++i)
    {
        if ((pret = strstr(buf, videoformats[i].type_string)) == NULL)
            break;
        sscanf(pret + strlen(videoformats[i].type_string), "%[0-9]", value);
        if (atoi(value) != 0)
        {
            g_vf |= videoformats[i].type_n;
            printf("vf filter: white list %s\n", videoformats[i].type_string);
        }
    }

    if (i != sizeof(videoformats)/sizeof(videoformat_t))
    {
        g_vf = 0;
        return false;
    }

    return true;
}

e_vf mod_vf_filter_gettype(char *pkg, int len_pkg)
{
    e_vf video_format = EVF_NONE;
    video_format = EVF_H264;
    return video_format;
}

//bool mod_vf_filter_check(char *pkg, int len_pkg)
bool mod_vf_filter_check(e_vf videoformat)
{
    //bool bRes = false;
    //return bRes;
    return ((g_vf & videoformat) == videoformat);
}

