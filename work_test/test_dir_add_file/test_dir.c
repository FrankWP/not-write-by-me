#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <setjmp.h>
#include <errno.h>
#include <stdlib.h>

int touch_sync_directory(char *path)
{
	char *p = rindex(path, '/');
	*p = '\0';

	char dir_name[256];
	strcpy(dir_name, path);
	int i, len = strlen(dir_name);
	printf("%s\n", dir_name);
	
	char flag = '/';
	if (dir_name[len-1] != flag)
		strcat(dir_name, "/");

	len = strlen(dir_name);

	for(i=1; i<len; i++)
	{
		if (dir_name[i] == flag)
		{
			dir_name[i] = 0;
			if (access(dir_name, W_OK) !=0)
			{
				if (mkdir(dir_name, 0777) == -1)
				{
					perror("mkdir error!");
					return -1;
				}
			}
			dir_name[i] = flag;
		}
	}

	return 1;
}

int main(int argc, char **argv)
{
	char buf[] = "/root/a1/a2/a3/a4";

	if (create_directory(buf) < 0)
		return -1;

	return 0;
}




