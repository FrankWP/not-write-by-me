#include "common.h"
#include "config.h"
#include "net_ospf.h"

/* flag */
static PROCESS_T *g_sig_data = NULL;
static int g_sig_pid = 0;

/*************************************************************************************** 
 *   Name: net_master_signal_handler
 *   Desc: Signal callback function, Free the resource and exit the program.
 *  Input: 
 *	       @sig - signal type
 * Output: -
 * Return: int, 0 on success; -1 on error 
 * Others: Called by signal catch
 ***************************************************************************************/
void net_master_signal_handler(int sig)
{
	int stat = 0;
	int pid  = 0;
	
	switch (sig) {
		case SIGUSR2:	
			/* Tell slave quit byself */
			kill(g_sig_pid, SIGUSR2);
			LOGD("Program exiting...\n");
			break;

		case SIGCHLD:	
			while ( (pid = waitpid( -1, &stat, WNOHANG)) > 0 ) {
				usleep(1);
				LOGD("Master: waiting slave\n");

				if ( pid == g_sig_pid ) {
					LOGD("Master: quit\n");	
				}
			}

			if ( g_sig_data ) {
				
				/* Close socket */
				if ( g_sig_data->raw_fd > 0 ) {
					close(g_sig_data->raw_fd);
				}

				/* Free memory */
				if ( g_sig_data->ip_packet ) {
					free(g_sig_data->ip_packet);
					g_sig_data->ip_packet = NULL;
				}

				/* Stop capturing */
				if ( g_sig_data->device ) {
					pcap_close(g_sig_data->device);
				}
			}
			exit(SUCCESS);

		case SIGUSR1:	
			break;

		default:	
			break;
	}		
}

/*************************************************************************************** 
 *   Name: net_slave_signal_handler
 *   Desc: Signal callback function, Free the resource and exit the program.
 *  Input: 
 *	       @sig - signal type
 * Output: -
 * Return: int, 0 on success; -1 on error 
 * Others: Called by signal catch
 ***************************************************************************************/
void net_slave_signal_handler(int sig)
{
	switch (sig) {
		case SIGUSR2:	
			LOGD("Slave: Get signal, quit\n");

			if ( g_sig_data ) {

				/* Close socket */
				if ( g_sig_data->raw_fd > 0 ) {
					close(g_sig_data->raw_fd);
				}

				/* Free memory */
				if ( g_sig_data->ip_packet ) {
					free(g_sig_data->ip_packet);
					g_sig_data->ip_packet = NULL;
				}

				/* Stop capturing */
				if ( g_sig_data->device ) {
					pcap_close(g_sig_data->device);
				}
			}
			exit(SUCCESS);

		default:
			break;
	}
}

/*************************************************************************************** 
 *   Name: net_packet_ospf_parse
 *   Desc: Parse the ospf packet buffer
 *  Input: 
 *         @packet  - capture buffer
 *         @packlen - capture length
 * Output: -
 * Return: int, 0 on success; -1 on error 
 * Others: -
 ***************************************************************************************/
int net_packet_ospf_parse(int net_ip, const U8 *packet, int packlen)
{
//	static int cnt = 0;
	struct iphdr *iph  = NULL;
	struct libnet_ospf_hdr *ospf_hdr = NULL; 

	if ( !packet ) {
		goto _E1;
	}

	iph = (struct iphdr*)(packet + LIBNET_ETH_H);
	if (4 != iph->version) {
		LOGW("Not ipv4 packet\n");
		goto _E1;
	}

	if ( net_ip != iph->saddr ) {
		goto _E1;
	}

	ospf_hdr = (struct libnet_ospf_hdr*)(packet + LIBNET_ETH_H + LIBNET_IPV4_H);

	LOGD("+- Protocol type:  OSPF\n");

	/* L1~L2 */
	LOGD("|- Packet length: %d\n", packlen);
	LOGD("|- MAC Dst:        %02x:%02x:%02x:%02x:%02x:%02x\n",
			packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]); 
	LOGD("|- MAC Src:        %02x:%02x:%02x:%02x:%02x:%02x\n",
			packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);

	/* L3 */
	LOGD("|-      IP Source: "); ip_net_display((void*)&iph->saddr);
	LOGD("|-      IP Destin: "); ip_net_display((void*)&iph->daddr);
	LOGD("|-      IP Length: %u Bytes\n", iph->tot_len >> 8);
	LOGD("|- OSPF    Length: %u Bytes\n", ospf_hdr->ospf_len >> 8);

	switch ( ospf_hdr->ospf_type ) {
		case 1:
			LOGD("|-           type: HELLO Packet\n");
			break;

		case 2:	
			LOGD("|-           type: DD ( Database Description Packet )\n");
			break;

		case 3:	
			LOGD("|-           type: LSR ( Link State Request Packet )\n");
			break;

		case 4:	
			LOGD("|-           type: LSU ( Link State Update Packet )\n");
			break;

		case 5:	
			LOGD("|-           type: LSAck ( Link State Acknowledgment Packet )\n");
			break;

		default:	
			break;
	}

	LOGD("|- OSPF v%d\n", ospf_hdr->ospf_v); 
	LOGD("|- OSPF router id: "); ip_net_display((void*)&ospf_hdr->ospf_rtr_id);
	LOGD("|- OSPF area     : "); ip_net_display((void*)&ospf_hdr->ospf_area_id);
	LOGD("+-------------------------------------------------\n");

	goto _S0;

_E1:
	return FAILURE;

_S0:
	return SUCCESS;

}

/*************************************************************************************** 
 *   Name: net_packet_ospf_forward
 *   Desc: forward ip packet to destination address
 *  Input: 
 *         @pdata   - forward buffer
 *         @packet  - capture buffer
 *         @packlen - capture buffer length
 * Output: -
 * Return: int, 0 on success; -1 on error 
 * Others: -
 ***************************************************************************************/
int net_packet_ospf_forward(PROCESS_T *pdata, const U8 *packet, int packlen)
{
	int ret = FAILURE;
	int ip_packlen = 0;
	struct iphdr *iph_forward = NULL,
				 *iph_capture = NULL;

	if ( !pdata || !pdata->ip_packet || !packet ) {
		goto _E1;
	}

	/* Reset the buffer */
	memset(pdata->ip_packet, 0, 1500);

	iph_capture = (struct iphdr *)(packet + LIBNET_ETH_H);
	iph_forward = (struct iphdr *)pdata->ip_packet;
	ip_packlen  = packlen - LIBNET_ETH_H;

	/* Fill ip head */
	iph_forward->ihl      = iph_capture->ihl;
	iph_forward->version  = iph_capture->version;
	iph_forward->tos      = iph_capture->tos;	
	iph_forward->tot_len  = ip_packlen;	
	iph_forward->frag_off = 0;	                       /* no fragment */
	iph_forward->ttl      = iph_capture->ttl;	
	iph_forward->protocol = IPPROTO_OSPF;	           /* 89 */
	iph_forward->check    = 0;                         /* not needed in iphdr */	
	iph_forward->saddr    = htonl(pdata->lcl_ip);
	
	if ( ALLSPFRouters == iph_capture->daddr || 
		 ALLDRouters == iph_capture->daddr ) {
		iph_forward->daddr = iph_capture->daddr;
	}
	else {
		iph_forward->daddr = htonl(pdata->dst_ip);
	}

	/* Fill payload */
	memcpy((void *)iph_forward + LIBNET_IPV4_H,
		   (void *)iph_capture + LIBNET_IPV4_H,
		   ip_packlen);

	/* Recount check */
	iph_forward->check = csum((unsigned short *)iph_forward, ip_packlen);
	
	/* Send ip packet */
	ret = sendto(pdata->raw_fd, iph_forward, ip_packlen, 0,
			(struct sockaddr *)&pdata->raw_sin, sizeof(struct sockaddr));

	if ( ret != ip_packlen ) {
		LOGE("Send fail, %d bytes written\n", ret);
		goto _E1;
	}

	LOGD("+-           From: "); ip_host_display((void*)&pdata->lcl_ip);
	LOGD("|-             To: "); ip_net_display((void*)&iph_forward->daddr);
	LOGD("+-           Send: %d bytes\n", ret); 
	LOGD("+-------------------------------------------------\n");

	goto _S0;

_E1:
	return FAILURE;

_S0:
	return SUCCESS;
}

/*************************************************************************************** 
 *   Name: net_packet_capture_callback
 *   Desc: Callback function for handler the packet forward.
 *  Input: 
 *         @arg    - common program data struct
 *         @pkthdr - packet type  
 *         @packet - packet payload
 * Output: -
 * Return: - 
 * Others: -
 ***************************************************************************************/
void net_packet_capture_callback(U8 *arg, const struct pcap_pkthdr *pkthdr, const U8 *packet)
{
	int ret = FAILURE;
	struct iphdr *iph = NULL;
	PROCESS_T *pdata  = NULL;

	if ( !arg || !pkthdr || !packet ) {
		goto _E1;
	}

	pdata = (PROCESS_T *)arg;

	/* Skip mac header and ip type */
	iph = (struct iphdr *)(packet + 14);

	switch (iph->protocol) {
		case IPPROTO_RAW:	
		case IPPROTO_PIM:	
		case IPPROTO_MTP:	
			LOGD("get\n");
			break;

		case IPPROTO_OSPF:	
			ret = net_packet_ospf_parse(pdata->net_ip, packet, pkthdr->len);
			if ( SUCCESS != ret ) {
				goto _E1;
			}

			ret = net_packet_ospf_forward(pdata, packet, pkthdr->len);
			if ( SUCCESS != ret ) {
				LOGW("net_packet_ospf_forward error\n");
				goto _E1;
			}
			break;

		default:	
			break;
	}
	goto _S0;

_E1:
	return;
_S0:
	return;

}

/*************************************************************************************** 
 *   Name: net_master_process
 *   Desc: Forward IP packet from bhlcard interface to net.
 *  Input: 
 *         @pinst - common program data struct
 * Output: -
 * Return: - 
 * Others: -
 ***************************************************************************************/
void net_master_process(INSTANCE_T *pinst)
{
	int ret = FAILURE;

	char errbuf[PCAP_ERRBUF_SIZE] = {0}; 
	PROCESS_T prc_data            = {0};
	g_sig_data = &prc_data;

	if ( !pinst ) {
		LOGW("Input null\n");
		goto _E1;
	}

	/* Master signal handler */
	signal(SIGPIPE, SIG_IGN);
	signal(SIGCHLD, net_master_signal_handler);
	signal(SIGTERM, net_master_signal_handler);
	signal(SIGINT,  net_master_signal_handler);
	signal(SIGUSR1, net_master_signal_handler);
	signal(SIGUSR2, net_master_signal_handler);

	/* Master set source and destination addresses */

	ret = strncasecmp(pinst->host, OUTSIDE, strlen(pinst->host));
	if ( !ret ) {
		prc_data.src_ip = pinst->com_cfg.sis_in_ip;
		prc_data.net_ip = htonl(pinst->com_cfg.sis_in_ip);
	}
	else {
		prc_data.src_ip = pinst->com_cfg.sis_out_ip;
		prc_data.net_ip = htonl(pinst->com_cfg.sis_out_ip);
	}

	prc_data.lcl_ip = pinst->rt_cfg.rt_dst_ip;
	prc_data.dst_ip = pinst->rt_cfg.rt_src_ip;
	memcpy(prc_data.src_if, pinst->com_cfg.sis_if, SIZE_NAME);

	LOGD("Master: Set source address:"); ip_host_display((void*)&prc_data.src_ip);
	LOGD("Master: Set local  address:"); ip_host_display((void*)&prc_data.lcl_ip);
	LOGD("Master: Set destin address:"); ip_host_display((void*)&prc_data.dst_ip);

	/* alloc the forward ip packet buffer */
	prc_data.ip_packet = (U8 *)malloc(sizeof(U8) * 1500);
	if ( !prc_data.ip_packet ) {
		LOGE("malloc\n");
		goto _E1;
	}

	/* init row socket */
	prc_data.raw_fd = init_rawsock(IPPROTO_OSPF);
	if ( prc_data.raw_fd < 0 ) {
		LOGE("Create rawsock error\n");
		goto _E2;
	}
	
	memset(&prc_data.raw_sin, 0, sizeof(struct sockaddr_in));
	prc_data.raw_sin.sin_family      = AF_INET;
	prc_data.raw_sin.sin_addr.s_addr = htonl(prc_data.dst_ip);

	/* Open a device, wait until a packet arrives */
	prc_data.device = pcap_open_live(prc_data.src_if, MAX_PKT_SIZE, 1, 0, errbuf);  
	if ( !prc_data.device ) {
		LOGW("open device %s error [%s]\n", prc_data.src_if, errbuf);
		goto _E3;
	}

	/* Wait loop forever */
	pcap_loop(prc_data.device, -1, net_packet_capture_callback, (void*)&prc_data);

	pcap_close(prc_data.device);

	close(prc_data.raw_fd);

	free(prc_data.ip_packet);
	prc_data.ip_packet = NULL;

	goto _S0;

_E3:
	close(prc_data.raw_fd);

_E2:
	free(prc_data.ip_packet);
	prc_data.ip_packet = NULL;

_E1:
	return;

_S0:
	return;
}

/*************************************************************************************** 
 *   Name: net_slave_process
 *   Desc: Forward IP packet from net interface to bhlcard.
 *  Input:
 *         @pinst - common program data struct
 * Output: -
 * Return: - 
 * Others: -
 ***************************************************************************************/
void net_slave_process(INSTANCE_T *pinst)
{
	int ret = FAILURE;

	char errbuf[PCAP_ERRBUF_SIZE] = {0}; 
	PROCESS_T prc_data            = {0};
	g_sig_data = &prc_data;

	if ( !pinst ) {
		LOGW("Input null\n");
		goto _E1;
	}

	/* slave signal handler */
	signal(SIGPIPE, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);
	signal(SIGTERM, net_slave_signal_handler);
	signal(SIGINT,  net_slave_signal_handler);
	signal(SIGUSR1, net_slave_signal_handler);
	signal(SIGUSR2, net_slave_signal_handler);

	/* Slaver set source and destination addresses */
	ret = strncasecmp(pinst->host, OUTSIDE, strlen(pinst->host));
	if ( !ret ) {
		prc_data.lcl_ip = pinst->com_cfg.sis_out_ip;
		prc_data.dst_ip = pinst->com_cfg.sis_in_ip;
	}
	else {
		prc_data.lcl_ip = pinst->com_cfg.sis_in_ip;
		prc_data.dst_ip = pinst->com_cfg.sis_out_ip;
	}

	prc_data.src_ip = pinst->rt_cfg.rt_src_ip;
	prc_data.net_ip = htonl(pinst->rt_cfg.rt_src_ip);
	memcpy(prc_data.src_if, pinst->rt_cfg.rt_if, SIZE_NAME);

	LOGD(" Slave: Set source address:"); ip_host_display((void*)&prc_data.src_ip);
	LOGD(" Slave: Set local  address:"); ip_host_display((void*)&prc_data.lcl_ip);
	LOGD(" Slave: Set destin address:"); ip_host_display((void*)&prc_data.dst_ip);

	/* alloc the forward ip packet buffer */
	prc_data.ip_packet = (U8 *)malloc(sizeof(U8) * 1500);
	if ( !prc_data.ip_packet ) {
		LOGE("malloc\n");
		goto _E1;
	}

	/* init row socket */
	prc_data.raw_fd = init_rawsock(IPPROTO_OSPF);
	if ( prc_data.raw_fd < 0 ) {
		LOGE("Create rawsock error\n");
		goto _E2;
	}
	
	memset(&prc_data.raw_sin, 0, sizeof(struct sockaddr_in));
	prc_data.raw_sin.sin_family      = AF_INET;
	prc_data.raw_sin.sin_addr.s_addr = htonl(prc_data.dst_ip);

	/* Open a device, wait until a packet arrives */
	prc_data.device = pcap_open_live(prc_data.src_if, MAX_PKT_SIZE, 1, 0, errbuf);  
	if ( !prc_data.device ) {
		LOGW("open device %s error [%s]\n", prc_data.src_if, errbuf);
		goto _E3;
	}

	/* Wait loop forever */
	pcap_loop(prc_data.device, -1, net_packet_capture_callback, (void*)&prc_data);

	pcap_close(prc_data.device);

	close(prc_data.raw_fd);

	free(prc_data.ip_packet);
	prc_data.ip_packet = NULL;

	goto _S0;

_E3:
	close(prc_data.raw_fd);

_E2:
	free(prc_data.ip_packet);
	prc_data.ip_packet = NULL;
_E1:
	return;
_S0:
	free(prc_data.ip_packet);
	prc_data.ip_packet = NULL;
	return;
}

/*************************************************************************************** 
 *   Name: main
 *   Desc: Main entrance of program.
 *  Input: -
 * Output: -
 * Return: int, 0 on success; -1 on error 
 * Others: -
 ***************************************************************************************/
int main(int argc, char *argv[])
{
	/* Common data */
	int ret = FAILURE;	
	int pid = 0;
	char *cfg_file = CFG_FILE;

	INSTANCE_T inst; 
	memset(&inst, 0, sizeof(INSTANCE_T));


	if ( argc > 2 ) {
		printf("Usage: %s [ configure ]\n", argv[0]);
		goto _E1;
	}
	else if ( argc == 2 ){
		cfg_file = argv[1];
	}

#ifdef LOG_ERROR
	printf("LOG ERROR   message open\n");
#endif

#ifdef LOG_WARNING
	printf("LOG WARNING message open\n");
#endif

#ifdef LOG_DEBUG
	printf("LOG DEBUG   message open\n");
#endif

#ifdef LOG_NOTICE
	printf("LOG NOTICE  message open\n");
#endif

	/* Singleton pattern */
	ret = x_getpid(PID_FILE);
	if (!ret) {
		LOGW("PID file exist, Check if process already running, exit.\n");
		goto _E1;
	}

	ret = x_writepid(PID_FILE);
	if (FAILURE == ret) {
		goto _E1;
	}

#if 0
	/* Run as daemon process */
	ret = daemon_init();
	if (ret < 0) {
		goto _E1;
	}
#endif

	/* Read configure */
	ret = cfg_load(cfg_file, CFG_COM_TASK, (void*)&inst.com_cfg);
	if (SUCCESS != ret) {
		LOGW("Load session:%s from file:%s fail", CFG_COM_TASK, cfg_file);
		goto _E1;
	}

	ret = cfg_load(cfg_file, CFG_RT_TASK, (void*)&inst.rt_cfg);
	if (SUCCESS != ret) {
		LOGW("Load session:%s from file:%s fail", CFG_RT_TASK, cfg_file);
		goto _E1;
	}

	/* Get hostname */
	ret = gethostname(inst.host, SIZE_NAME);
	if ( ret < 0 ) {
		LOGE("Get hostname failure\n");
		goto _E1;
	}

	pid = fork();
	if ( -1 == pid ) {
		goto _E1;
	}
	else if ( 0 == pid ) {
		/* Slave: forward packet from net to sis */
		net_slave_process(&inst);
		goto _S0;
	}
	else {
		g_sig_pid = pid;
		/* Master: forward packet from sis to net */
		net_master_process(&inst);
		goto _S0;
	}

_E1:
	return FAILURE;
_S0:
	return SUCCESS;
}
