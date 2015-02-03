#include "common.h"

/*************************************************************************************** 
 *   Name: x_getpid
 *   Desc: Check process status
 *  Input:
 *         @pid - process id 
 * Output: -
 * Return: int, 0 on success; -1 on error 
 *         -1 - pid file not exist and process not start;
 *          0 - pid file exist and process already running
 * Others: -
 ***************************************************************************************/
int x_getpid(const char *pid)
{
	int ret;

	if (!(ret = access(pid, F_OK)))
		fprintf(stderr, "pid file already exist.\n");

	return ret;
}

/*************************************************************************************** 
 *   Name: x_writepid
 *   Desc: Save the main process id for convenience killing.
 *  Input: 
 *         @pid - process id 
 * Output: -
 * Return: int, 0 on success; -1 on error 
 * Others: -
 ***************************************************************************************/
int x_writepid(const char *pid)
{
	FILE  *fp;
	char   proid[8];

	if ((fp = fopen(pid, "w+")) == NULL)
		return -1;

	snprintf(proid, sizeof(proid) - 1, "%d", getpid());
	if (fwrite(proid, strlen(proid), 1, fp) == 0) {
		remove(pid);
		fclose(fp);
		return -1;
	}
	fclose(fp);
	return 0;
}

/*************************************************************************************** 
 *   Name: ip_aton
 *   Desc: converts  the Internet host address cp from the standard numbers-and-dots 
 *         notation into binary data and stores it in the int.
 *  Input: 
 *         @sip - standard numbers-and-dots ipv4 address
 * Output: -
 * Return: int, 0 on success; -1 on error 
 * Others: -
 ***************************************************************************************/
int ip_aton(char *sip)
{
	int ix = 0;
	int rv = 0;
	int val[4] = {0};

	if (sip == NULL) {
		return 0;
	}

	sscanf(sip, "%d.%d.%d.%d", &val[0], &val[1], &val[2], &val[3]);

	do {
		rv <<= 8;
		rv |= val[ix] & 0xff;
	} while (++ix < 4);

	return rv;
}

/*************************************************************************************** 
 *   Name: ip_ntoa
 *   Desc: converts  the Internet host address cp from the standard numbers-and-dots 
 *         notation into binary data and stores it in the structure that char points to.
 *  Input: 
 *         @sip  - network byte order address
 * Output: 
 *         @rvip - standard numbers-and-dots ipv4 address
 * Return: int, 0 on success; -1 on error 
 * Others: -
 ***************************************************************************************/
char *ip_ntoa(int sip, char *rvip)
{
	if (rvip == NULL) {
		return rvip;
	}

	sprintf(rvip, "%d.%d.%d.%d",
			sip >> 24&0xff, sip >> 16&0xff,
			sip >> 8&0xff, sip&0xff);

	return rvip;
}

/*************************************************************************************** 
 *   Name: daemon_init
 *   Desc: detach themselves from the controlling terminal and run in the background 
 *         as system daemons
 *  Input: -
 * Output: -
 * Return: int, 0 on success; -1 on error 
 * Others: -
 ***************************************************************************************/
int daemon_init()
{
//	int		i;
	pid_t	pid;

	if ((pid = fork()) < 0)
		return -1;
	else if (pid)
		exit(0);

	if (setsid() < 0)		/* become session leader */
		return -1;

	chdir("/");				/* change working directory */

#if 0
	for (i = 0; i < 3; i++)
		close(i);
#endif

	return pid;
}

/*************************************************************************************** 
 *   Name: csum
 *   Desc: ip header check
 *  Input:
 *         @buffer - check buffer
 *         @size   - buffer size 
 * Output: 
 * Return: int, 0 on success; -1 on error 
 * Others: -
 ***************************************************************************************/
unsigned short csum(unsigned short *buffer, int size)
{
	unsigned long cksum = 0;

	while (size > 1) {
		cksum += *buffer++;
		size -= sizeof(unsigned short);
	}

	if (size)
		cksum += *(char *)buffer;

	/* 32 bite change to 16 bite */
	while (cksum>>16) {
		cksum = (cksum>>16) + (cksum & 0xffff);
	}

	return (unsigned short)(~cksum);
}

/*************************************************************************************** 
 *   Name: init_rawsock
 *   Desc: creat the raw socket
 *  Input: 
 *         @protocol - protocol type
 * Output: - 
 * Return: int, sd on success; -1 on error 
 * Others: -
 ***************************************************************************************/
int init_rawsock(int protocol)
{
	int s, ret, op = 1;

	s = socket(AF_INET, SOCK_RAW, protocol);
	if (s < 0) {
		fprintf(stderr, "error: socket() %s\n", strerror(errno));
		return -1;
	}

	/* tell system to fill ip header */
	ret = setsockopt(s, IPPROTO_IP, IP_HDRINCL, &op, sizeof(op));
	if (ret < 0) {
		close(s);
		fprintf(stderr, "error: setsockopt() %s\n", strerror(errno));
		return -1;
	}

	return s;
}

/*************************************************************************************** 
 *   Name: output_hex
 *   Desc: Print hex
 *  Input: 
 *         @buff - debug string
 *         @len  - string len
 * Output: -
 * Return: int, 0 on success; -1 on error 
 * Others: -
 ***************************************************************************************/
void output_hex(unsigned char *buff, int len)
{
	int ix;  

	for (ix = 0; ix < len; ix++) {  
		printf(" %02x", buff[ix]);  

		if ((ix + 1) % 16 == 0)  
			printf("\n");  
	}  
	printf("\n\n");  
}

/*************************************************************************************** 
 *   Name: ip_net_display
 *   Desc: 
 *  Input: 
 * Output: 
 * Return: int, 0 on success; -1 on error 
 * Others: -
 ***************************************************************************************/
void ip_net_display(void *paddr)
{
	char *sip = NULL;
	int ip = -1;

	memcpy((void *)&ip, (void*)paddr, sizeof(int));

	sip = (char *)calloc(1, sizeof(char) * 16);
	if (!sip) {
		return;
	}

	sprintf(sip, "%d.%d.%d.%d", 
			ip & 0xff, ip>>8 & 0xff,
			ip>>16 & 0xff , ip>>24 & 0xff);
	printf("%s\n", sip);

	free(sip);
	sip = NULL;
	return;
}

/*************************************************************************************** 
 *   Name: ip_host_display
 *   Desc: 
 *  Input: 
 * Output: 
 * Return: int, 0 on success; -1 on error 
 * Others: -
 ***************************************************************************************/
void ip_host_display(void *paddr)
{
	char *sip = NULL;
	int ip = -1;

	memcpy((void *)&ip, (void*)paddr, sizeof(int));

	sip = (char *)calloc(1, sizeof(char) * 16);
	if (!sip) {
		return;
	}

	sprintf(sip, "%d.%d.%d.%d", 
			ip>>24 & 0xff, ip>>16 & 0xff,
			ip>>8 & 0xff , ip & 0xff);
	printf("%s\n", sip);

	free(sip);
	sip = NULL;
	return;
}
