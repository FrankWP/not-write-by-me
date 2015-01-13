#include<netinet/in.h>              
#include<sys/types.h>              
#include<sys/socket.h>            
#include<stdio.h>               
#include<stdlib.h>             
#include<string.h>            
#include <unistd.h>
#include <stdarg.h>
#include <getopt.h>
#include <errno.h>
#include <syslog.h>
#include <fcntl.h>
#include <ctype.h>
#include <signal.h>
#include <dlfcn.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/ioctl.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>

#define LENGTH_OF_LISTEN_QUEUE     20  
#define BUFFER_SIZE                4096

typedef enum{
	TRUE = 1,
	true = 1,
	FALSE = 0,
	false = 0
}BOOL, bool;
#define MAXFD						0x64
pid_t create_daemon()
{
	int i;
	pid_t pid;

	if ((pid = fork()) != 0)
		return pid;

	if (setsid() < 0)
		return -1;

	printf("create: %d\n", pid);
	for(i=0; i<MAXFD; i++)
		close(i);

	chdir("/");
	open("/dev/null", STDIN_FILENO);
	open("/dev/null", STDOUT_FILENO);
	open("/dev/null", STDERR_FILENO);

	return pid;
}

int main(int argc, char **argv)  
{  
	int opt = -1;
	int optIdx = -1;
	bool daemon = true;

	struct option opts[] =
	{
		{"debug", no_argument, NULL, 'd'}
	};

	while ((opt = getopt_long(argc, argv, "d", opts, &optIdx)) != -1)
	{
		switch (opt) {
			case 'd':
				daemon = false;
				break;
		}
	}

	pid_t d_pid = create_daemon();
	printf("d_pid:%d\n", d_pid);
	if (daemon && (d_pid != 0))
	{
		printf("create deamon failed");
		return 0;
	}


   return 0;  
}
  
