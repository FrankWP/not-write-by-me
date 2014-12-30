#include "../vpheader.h"
#include "pm_proxy.h"

/*
 *  TODO:
 *  @date: 2012.8.13
 *  @introduce: there are three parts need to be replaced:REGISTER, INVITE and ACK.
 *  @steps: 
 *      
 *      1. REGISTER:    replace flag:   a. Register head
 *                                      b. Contact
 *                                      c. Authorization uri
 *      
 *      2. INVITE:      replace flag:   a. Invite head
 *                                      b. Contact
 *                                      c. o=... 0 0 IN IP4 (client ip)
 *                                      d. c=IN IP4 (client ip)
 *                                      e. m=video (client port) 
 *
 *      3. ACK          replace flag:   a. Ack head
 *                                      b. o=... 0 0 IN IP4 (server ip)
 *                                      c. c=IN IP4 (server ip)
 *                                      d. m=video (server port)
 *
 *      For the time being, we can only write several functions to replace the ip and port in the
 *      example which appears in the book of nanyang_h3c_hik. In real work, more things needs to be done.
 *
 * */


#define F_REG "REGISTER"
#define F_INV "INVITE"
#define F_ACK "ACK"
#define F_CTC "Contact"

#define SIPPORT     "5061"
#define SIP_OK      "SIP/2.0 200 OK"
#define IS_TMS      (__gg.host_side == HOST_SIDE_INNER ? 1 : 0)
#define SDP_SIGN    "application/sdp"

static int run_vs_proxy(pvp_uthttp put, u32 lip, u16 lport, u32 dip, u16 dport)
{
    char      psmid[32] = {0};
    clivlist *psm = NULL;
    char     *arg[5] = {NULL};

    sprintf(psmid, "%d", get_sharemem_pid());

    if (NULL == (psm = create_tuvs_smem(psmid)))
        return -1;

    /*Proxy address*/
    psm->lip = lip;
    psm->lvport = lport;
    psm->dip = dip;
    psm->dvport = dport;
    psm->vstream_tout = 60;

    arg[0] = (char*)V_UDP_PROXY;
    arg[1] = psmid;
    arg[2] = (char *)"-i";
    arg[3] = (char *)"30024";
    arg[4] = 0;

    start_vstream_proxy((char *)V_UDP_PROXY, arg);

    return 1;
}

/****************************************************************
 *Parse sdp content ,replace ip and port,start video stream proxy.
 ****************************************************************/
#define F_INIP      "IN IP4 "
static int parse_sdp(pvp_uthttp put, char **ut_buf, u32 *pack_len, int direction)
{
    char    fip[16] = {0};  /*ferry ip*/
    char    *pstr = NULL;
    char    sport[8] = {0};    /*Source port*/
    //int     cport = 0;
    char    cli_ip[16] = {0};
    char    *p_rep_invite = NULL;

    if(IS_TMS){
        inet_ultoa(__gg.inner_addr, fip);
    }else{
        inet_ultoa(__gg.outer_addr, fip);
    }

    if(strncmp(*ut_buf, "INVITE", strlen("INVITE")) == 0){
        /*INVITE*/
        if (direction == DO_REQST) {
            p_rep_invite = (char*)memmem(*ut_buf, *pack_len, F_INIP, sizeof(F_INIP) - 1); 
            if (p_rep_invite != NULL) 
            {
                sscanf(p_rep_invite + sizeof(F_INIP) - 1, "%[0-9.]", cli_ip);
                memreplace_pos(p_rep_invite, NULL, ut_buf, pack_len, -1, cli_ip, strlen(cli_ip), fip, strlen(fip));

                /*Find upper video stream port*/
                if((pstr = strstr(*ut_buf, "m=video")) != NULL)
                    sscanf(pstr + 8, "%[0-9]", sport);

                update_content_len(ut_buf, pack_len);    

                printf("BBBBBBBBBBBBBBBBBB   sip:%s dip:%s port:%d\n", cli_ip, fip, atoi(sport));
                run_vs_proxy(put, inet_atoul(fip) ,atoi(sport), inet_atoul(cli_ip), atoi(sport));
            }
        }
    }

    return 1;
}

/*********************************************************
 *Replace ip and ip:port
 ********************************************************/
#define MSG_HED     "MESSAGE sip:"
#define MSG_VIA     "Via: SIP/2.0/UDP "
#define MSG_FROM    "From: <sip:"
#define MSG_TO      "To: <sip:"
static int replace_addr(pvp_uthttp put, char **ut_buf, u32 *pack_len, int direction)
{
    char  lip[16] = {0};
    char  dip[16] = {0};
    char  cip[16] = {0};
    char  fip[16] = {0};  /*ferry ip*/

    //char  *p_rep_message = NULL;

    if(IS_TMS){
        inet_ultoa(__gg.outer_addr, lip);
        inet_ultoa(__gg.inner_addr, fip);

    }else{
        inet_ultoa(__gg.inner_addr,lip);
        inet_ultoa(__gg.outer_addr,fip);
    }

    inet_ultoa(put->dip, dip);
    inet_ultoa(put->src_ip, cip);

    //char fip[] = "172.16.2.150";

    if(DO_REQST == direction){

        //printf("in request replace ----> cip:%s fip:%s lip:%s dip:%s\n", cip, fip, lip, dip);

        //REPLACE----------------1
        /*  
            p_rep_message = (char*)memmem(*ut_buf, *pack_len, MSG_HED, sizeof(MSG_HED)-1); 
            if (p_rep_message != NULL) 
            {
            memreplace_pos(p_rep_message, NULL, ut_buf, pack_len, 1, lip, strlen(lip), dip, strlen(dip));
            }

        //REPLACE----------------2
        p_rep_message = (char*)memmem(*ut_buf, *pack_len, MSG_VIA, sizeof(MSG_VIA)-1); 
        if (p_rep_message != NULL) 
        {
        memreplace_pos(p_rep_message, NULL, ut_buf, pack_len, 1, cip, strlen(cip), fip, strlen(fip));
        }

        //REPLACE----------------3
        p_rep_message = (char*)memmem(*ut_buf, *pack_len, MSG_FROM, sizeof(MSG_FROM)-1); 
        if (p_rep_message != NULL) 
        {
        memreplace_pos(p_rep_message, NULL, ut_buf, pack_len, 1, cip, strlen(cip), fip, strlen(fip));
        }

        //REPLACE----------------4
        p_rep_message = (char*)memmem(*ut_buf, *pack_len, MSG_TO, sizeof(MSG_TO)-1); 
        if (p_rep_message != NULL) 
        {
        memreplace_pos(p_rep_message, NULL, ut_buf, pack_len, 1, lip, strlen(lip), dip, strlen(dip));
        }
        */

        /*  Replace client ip with ferry ip.*/
        if(-1 == strreplace(ut_buf, cip, fip, REPLACE_ALL, pack_len))
            return -1;

        /*Replace local ip with server ip.*/
        if(-1 == strreplace(ut_buf, lip, dip, REPLACE_ALL, pack_len))
            return -1;

        /*Update content-length*/
        update_content_len(ut_buf, pack_len);
    }
    else if(DO_REPLY == direction) {

        //printf("in reply replace ----> cip:%s fip:%s lip:%s, dip:%s\n", cip, fip, lip, dip);

        /*Replace server ip with local ip.*/
        if(-1 == strreplace(ut_buf, dip, lip, REPLACE_ALL, pack_len))
            return -1;

        /*Replace client ferry ip with client ip.*/
        if(-1 == strreplace(ut_buf, fip, cip, REPLACE_ALL, pack_len))
            return -1;

        /*Update content-length*/
        update_content_len(ut_buf, pack_len);
    }

    return 1;
}

static int parse_sip(pvp_uthttp put, char **ut_buf, u32 *pack_len, int direction)
{
    /*Replace address*/
    if(replace_addr(put, ut_buf, pack_len, direction) == -1)
        return -1;

    if(strcasestr(*ut_buf, SDP_SIGN) != NULL) {
        if (parse_sdp(put, ut_buf, pack_len, DO_REQST) == -1)
            return -1;
    }

    return 1;
}

int __nanyang_h3c_hik_init(const char *parg)
{
    return 1;
}

void __nanyang_h3c_hik_quit()
{
    return;
}

int __nanyang_h3c_hik_recv(pvp_uthttp put, char *ut_buf, int *pack_len, int direction)
{
    return 1;
}

int __nanyang_h3c_hik_socket(pvp_uthttp put, int sockfd)
{
    if (IS_TMS){
        SAI xaddr;
        memset(&xaddr, 0x00, sizeof(xaddr));
        xaddr.sin_family = AF_INET;
        //xaddr.sin_addr.s_addr = htonl(__gg.outer_addr);
        xaddr.sin_addr.s_addr = htonl(__gg.inner_addr);
        //xaddr.sin_port = htons(put->src_port);
        xaddr.sin_port = 0;
        Setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR);

        char localip[32] = {0};
        inet_ultoa(__gg.inner_addr, localip);
        printf("__nanyang_socket: bind ip [%s] port [%d] \n", localip, xaddr.sin_port);

        if (bind(sockfd, (SA *)&xaddr, sizeof(xaddr)) < 0)
        {
            char localip[32] = {0};
            inet_ultoa(__gg.inner_addr, localip);
            loginf_fmt("__nanyang_socket: bind ip [%s] port [%d] random failed\n", localip, xaddr.sin_port);
            return -1;
        }
    }
    else{
        /*  
        SAI xaddr;
        memset(&xaddr, 0x00, sizeof(xaddr));
        xaddr.sin_family = AF_INET;
        //xaddr.sin_addr.s_addr = htonl(__gg.outer_addr);
        xaddr.sin_addr.s_addr = htonl(__gg.outer_addr);
        //xaddr.sin_port = htons(put->src_port);
        xaddr.sin_port = 0;
        Setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR);

        char localip[32] = {0};
        inet_ultoa(__gg.outer_addr, localip);
        printf("__nanyang_socket: bind ip [%s] port [%d] \n", localip, xaddr.sin_port);

        if (bind(sockfd, (SA *)&xaddr, sizeof(xaddr)) < 0)
        {
            char localip[32] = {0};
            inet_ultoa(__gg.outer_addr, localip);
            loginf_fmt("__nanyang_socket: bind ip [%s] port [%d] random failed\n", localip, xaddr.sin_port);
            return -1;
        }
        */
    }

    return 1;
}

int __nanyang_h3c_hik_request(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    //puts("NY--REQUEST------------------------------------");
    if (parse_sip(put, ut_buf, pack_len, DO_REQST) < 0)
        return -1;

    return 1;
}

int __nanyang_h3c_hik_reply(pvp_uthttp put, char **ut_buf, u32 *pack_len)
{
    //puts("NY--REPLY------------------------------------");
    if (parse_sip(put, ut_buf, pack_len, DO_REPLY) < 0)
        return -1;

    return 1;
}

int __nanyang_h3c_hik_close(pvp_uthttp put, int sockfd)
{
    return 1;
}

