/********************************************************
 *  create:     2012/05/23
 *  match file: vp_h3c_fs.c of CLiaoNing
 *******************************************************/

#include "../vpheader.h"
#include "pm_proxy.h"

#define INITPORT   40000
#define TOTALPORT  600
#define SDP_SIGN   "application/sdp"
#define IS_TMS        __gg.host_side == HOST_SIDE_INNER ? 1 : 0

/***********************************************************************
 *  *Replace string
 *   ***********************************************************************/
static int mem_replace(char **ppbuf, char *sbuf, char *dbuf, int times, u32 *pack_len)
{
  return memreplace_pos(NULL, NULL, ppbuf, pack_len, times, sbuf, strlen(sbuf), dbuf, strlen(dbuf));
}

/****************************************************
 * Set up video stream proxy
 ****************************************************/
static int run_vs_proxy(u32 lsn_ip,  u16 lsn_port,
                        u32 serv_ip, u16 serv_port,
                        u32 bind_ip, u16 bind_port
                        )
{
  char      psmid[32] = {0};
  clivlist *psm = NULL;
  char     *arg[4] = {NULL};

  sprintf(psmid, "%d", get_sharemem_pid());

  if (NULL == (psm = create_tuvs_smem(psmid)))
    return -1;

  psm->lip = lsn_ip;
  psm->lvport = lsn_port;
  psm->dip = serv_ip;
  psm->dvport = serv_port;
  psm->cliip = bind_ip;
  psm->cliport = bind_port;
  psm->vstream_tout = 600;
printf("%s:%d\n",inet_ultoa(lsn_ip,NULL),lsn_port);
printf("%s:%d\n",inet_ultoa(serv_ip,NULL),serv_port);
printf("%s:%d\n",inet_ultoa(bind_ip,NULL),bind_port);
  arg[0] = (char*)V_UDP_PROXY;
  arg[1] = psmid;
  arg[2] = (char *)"-p";
  arg[3] = (char *)0;

  start_vstream_proxy((char *)V_UDP_PROXY, arg);

  return 1;
}

/*******************************************
 * Unused
 ******************************************/
int h3c_fs_init()
{
    if (init_bind_port(INITPORT, TOTALPORT) < 0)
        return -1;
    return 1;
}

/*******************************************
 * Unused
 ******************************************/
void h3c_fs_quit()
{
    destroy_bind_port();
}

/************************************************************
 *SIP address replace
 ***********************************************************/
static int sip_reqst_addr(pvp_uthttp put, char **ppbuf, u32 *pack_len)
{ 
  u16   rport;
  char  rip[16];
  char  cip[16];
  char  cport[8];
  char  saddr[32];
  char  daddr[32];
  SAI   laddr;
  socklen_t len;
  
  /*Replace client address (ip:port and ip) with 
   * UMS corresponding address connecting with SIP server*/
  if (find_sip_addr(ppbuf, cip, cport) < 0)
    return -1;
  
  memset(&laddr, 0x00, sizeof(laddr));
  len = sizeof(laddr);
  if (-1 == getsockname(put->svr_sock, (struct sockaddr *)&laddr, &len))
    return -1;

  rport = ntohs(laddr.sin_port);
  inet_ultoa(__gg.outer_addr,rip);

  if (-1 == mem_replace(ppbuf, cip, rip, REPLACE_ALL, pack_len))
    return -1;
  
  sprintf(saddr, "%s:%s", rip, cport);
  sprintf(daddr, "%s:%d", rip, rport);
  if (-1 == mem_replace(ppbuf, saddr, daddr, REPLACE_ALL, pack_len))
    return -1;
      
  /*Replace server ip*/
  inet_ultoa(__gg.inner_addr,saddr);
  inet_ultoa(put->dip,daddr);
  if (-1 == mem_replace(ppbuf, saddr, daddr, REPLACE_ALL, pack_len))
      return -1;
 
  update_content_len(ppbuf, pack_len);
  return 1;
}

/************************************************************
 *SIP request (port:5060)
 ***********************************************************/
static int sip_request(pvp_uthttp put, char **ppbuf, u32 *pack_len)
{ 
  char *pstr;
  char vport[8];
  u32  lsn_ip;
  u32  con_ip;

  /*Replace client address with ums address.*/
  if(-1 == sip_reqst_addr(put,ppbuf,pack_len))
    return -1;

  /*200 OK for INVITE,
    Start a proxy for video stream*/
  if ((NULL != strstr(*ppbuf,"200 OK")) 
      && (NULL != strstr(*ppbuf, SDP_SIGN))) {
    if (NULL == (pstr = strstr(*ppbuf, "m=video"))) {
      syslog(LOG_ERR, "transport protocol error:[H3C_GETPORT]");
      return -1;
    } else{
      sscanf((char *)pstr + 8, "%[0-9]", vport);
    }

    if(IS_TMS){
      lsn_ip = __gg.inner_addr;
      con_ip = __gg.outer_priv_addr;
    }else{
      lsn_ip = __gg.outer_addr;
      con_ip = __gg.inner_priv_addr;
    }
    /*Start video stream proxy*/
    if(-1 ==  run_vs_proxy(lsn_ip, atoi(vport),
                           con_ip, atoi(vport),
                           0,0))
      return -1;
    
  }
 
  return 1;
}

/************************************************************
 *RTSP request (port:554)
 ***********************************************************/
static int rtsp_request(pvp_uthttp put, char **ppbuf, u32 *pack_len)
{ 
  char  ums_ip[16];
  char  cli_addr[32];
  char  ums_addr[32];
  SAI   loc_addr;
  socklen_t addr_len;

  /*Replace client port with ums port*/ 
  addr_len = sizeof(loc_addr);
  if(-1 == getsockname(put->svr_sock, 
                       (struct sockaddr *)&loc_addr, 
                       &addr_len)){

    syslog(LOG_ERR,"%s:%d:getsocket:%s",__FILE__,__LINE__,strerror(errno));
  }else{
    sprintf(cli_addr,"%s:0",ums_ip);
    sprintf(ums_addr,"%s:%d",inet_ultoa(__gg.outer_addr,NULL),loc_addr.sin_port);
    mem_replace(ppbuf, cli_addr, ums_addr, REPLACE_ALL, (u32 *)pack_len);
  }

  /*Replace tms ip with server ip*/
  mem_replace(ppbuf, 
          inet_ultoa(__gg.inner_addr,NULL), 
          inet_ultoa(put->dip,NULL),
          REPLACE_ALL, pack_len);

  return 1;
}

/****************************************************************
 *RTSP reply(port:554)
 ****************************************************************/
static int rtsp_reply(pvp_uthttp put, char **ppbuf, u32 *pack_len)
{
  char *pstr;
  char cli_port[8];
  char serv_port[8];

  /*Set up video stream proxy*/
  if ((NULL != strstr(*ppbuf, "destination="))
       && (NULL != strstr(*ppbuf, "client_port="))
       && (NULL != strstr(*ppbuf,"server_port="))){

    pstr = strstr(*ppbuf, "client_port=");
    sscanf(pstr + strlen("client_port="), "%[^-]", cli_port);

    pstr = strstr(*ppbuf, "server_port=");
    sscanf(pstr + strlen("server_port"), "%[^-]", serv_port);

    if(-1 == run_vs_proxy(__gg.outer_addr, atoi(cli_port),
                          __gg.outer_priv_addr, atoi(cli_port),
                          0,0)){
      return -1;
    }
  }
  
  return 1;

  /*char *pstr;
  char  cli_port[8];

  Set up video stream proxy
  if (NULL != (pstr = strstr(*ppbuf, "client_port="))){
    sscanf(pstr + 12, "%[^-]", cli_port);
    
    return run_vs_proxy(__gg.outer_addr,atoi(cli_port),
                        INADDR_ANY,0,
                        __gg.inner_priv_addr,atoi(cli_port));
  }
    
  return 1;*/
}

/**********************************************************
 *Do reply
 *********************************************************/
int h3c_fs_reply(pvp_uthttp put, char **ppbuf, u32 *pack_len)
{
  int rtn = 1;

  switch(put->dport){
    case 554:
      rtn = rtsp_reply(put, ppbuf, pack_len);
      break;

    default:
      break;
  }

  return rtn;
}

/*************************************************************
 * Do request
 *************************************************************/
int h3c_fs_request(pvp_uthttp put, char **ppbuf, u32 *pack_len)
{ 
  int rtn = 1;

  switch(put->dport){
  
   case 5060:
      rtn = sip_request(put, ppbuf, pack_len);
      break;
   
    case 554:
      rtn = rtsp_request(put, ppbuf, pack_len);
      break;
    
    default:
      break;
  }
  
  return rtn;
}


/**********************************************************
 *Do scoket
 *********************************************************/
 int h3c_fs_socket(pvp_uthttp put, const int sockfd)
 {
  u16 xport;
  SAI xaddr;
  int i;
   
  for(i = 0; i <= 21; i++){
    if ((xport = get_idle_bind_port(NUM_EVEN)) <= 0) {
      syslog(LOG_INFO, "get idle bind port failed:[%d]", xport);
      return -1;
    }
    memset(&xaddr, 0x00, sizeof(xaddr));
    xaddr.sin_family = AF_INET;
    xaddr.sin_addr.s_addr = INADDR_ANY;
    xaddr.sin_port = htons(xport);
    if (bind(sockfd, (SA *)&xaddr, sizeof(xaddr)) < 0) 
      break;  
  }

  return 1;
}

/**********************************************************
 *Do close
 *********************************************************/
int h3c_fs_close(pvp_uthttp put, int sockfd)
{
    u16 xport;

    if ((xport = getsockport(put->svr_sock)) == 0)
        return -1;

    set_idle_bind_port(xport);
    return 1;
}

/**********************************************************
 *Do receive
 *********************************************************/
int h3c_fs_recv(pvp_uthttp put, char *ut_buf, int *pack_len, int direction)
{
  char  *pbuf;
  int   rtn = 1;

  if (oss_malloc(&pbuf, *pack_len + 1) < 0)
    return -1;
  memcpy(pbuf, ut_buf, *pack_len);
  if(DO_REQST == direction){

    switch(put->dport){

      case 554:
        //rtn = rtsp_request(put, &pbuf, (u32 *)pack_len);
        break;
     }

  }else if (DO_REPLY == direction) {
  
    switch(put->dport){
      case 554:
        //rtn = rtsp_reply(put, &pbuf,(u32 *)pack_len);
        break;

      default:
        break;
    }
  }

  memcpy(ut_buf, pbuf, *pack_len);
  free(pbuf);
  return rtn;
}

  
