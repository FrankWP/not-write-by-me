#include <stdio.h>
#include <stdlib.h>
#include <errno.h> 
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/types.h>
#define MAXBUF 1024
int main(int argc, char **argv)
{
	int sockfd, new_fd;
	socklen_t len;
	struct sockaddr_in my_addr, their_addr;
	unsigned int myport, lisnum;
	char buf[MAXBUF + 1];
	fd_set rfds;
	struct timeval tv;
	int retval, maxfd = -1;
	if (argv[1])
		myport = atoi(argv[1]);
	else
		myport = 7838;

	if (argv[2])
		lisnum = atoi(argv[2]);
	else
		lisnum = 2;

	if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
		perror("socket");
		exit(1);
	}

	bzero(&my_addr, sizeof(my_addr));
	my_addr.sin_family = PF_INET;
	my_addr.sin_port = htons(myport);

	if (argv[3])
		my_addr.sin_addr.s_addr = inet_addr(argv[3]);
	else
		my_addr.sin_addr.s_addr = INADDR_ANY;

	if (bind(sockfd, (struct sockaddr *) &my_addr, sizeof(struct sockaddr))== -1) 
	{
		perror("bind");
		exit(1);
	}

	if (listen(sockfd, lisnum) == -1) 
	{
		perror("listen");
		exit(1);
	}

	while (1) {
		printf
			("\n----等待新的连接到来开始新一轮聊天……\n");
		len = sizeof(struct sockaddr);
		if ((new_fd = accept(sockfd, (struct sockaddr *) &their_addr,&len)) == -1) 
		{
			perror("accept");
			exit(errno);
		} 
		else
		{	
			printf("server: got connection from %s, port %d, socket %d\n",
					inet_ntoa(their_addr.sin_addr),
					ntohs(their_addr.sin_port), new_fd);
		}
		printf
			("\n准备就绪，可以开始聊天了……直接输入消息回车即可发信息给对方\n");

		while (1) {
			FD_ZERO(&rfds);
			FD_SET(0, &rfds);
			maxfd = 0;
			FD_SET(new_fd, &rfds);
			if (new_fd > maxfd)
				maxfd = new_fd;
			tv.tv_sec = 1;
			tv.tv_usec = 0;
			retval = select(maxfd + 1, &rfds, NULL, NULL, &tv);
			if (retval == -1) {
				printf("将退出，select出错！ %s", strerror(errno));
				break;
			} else if (retval == 0) {
				continue;
			} else {
				if (FD_ISSET(0, &rfds)) {
					bzero(buf, MAXBUF + 1);
					fgets(buf, MAXBUF, stdin);
					if (!strncasecmp(buf, "quit", 4)) {
						printf("自己请求终止聊天！\n");
						break;
					}

					len = send(new_fd, buf, strlen(buf) - 1, 0);
					if (len > 0)
						printf
							("消息:%s\t发送成功，共发送了%d个字节！\n",
							 buf, len);
					else {
						printf
							("消息'%s'发送失败！错误代码是%d，错误信息是'%s'\n",
							 buf, errno, strerror(errno));
						break;
					}
				}

				if (FD_ISSET(new_fd, &rfds)) {
					bzero(buf, MAXBUF + 1);
					len = recv(new_fd, buf, MAXBUF, 0);
					if (len > 0)
						printf
							("接收消息成功:'%s'，共%d个字节的数据\n",
							 buf, len);
					else {
						if (len < 0)
							printf
								("消息接收失败！错误代码是%d，错误信息是'%s'\n",
								 errno, strerror(errno));
						else
							printf("对方退出了，聊天终止\n");
						break;
					}
				}
			}
		}
		close(new_fd);
		printf("还要和其它连接聊天吗？(no->退出)");
		fflush(stdout);
		bzero(buf, MAXBUF + 1);
		fgets(buf, MAXBUF, stdin);
		if (!strncasecmp(buf, "no", 2)) {
			printf("终止聊天！\n");
			break;
		}
	}
	close(sockfd);
	return 0;
}

