#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <resolv.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>

#define MAXBUF 1024
int main(int argc, char **argv)
{
	int sockfd, len;
	struct sockaddr_in dest;
	char buffer[MAXBUF + 1];
	fd_set rfds;
	struct timeval tv;
	int retval, maxfd = -1;
	if (argc != 3) {
		printf("参数格式错误！正确用法如下：\n\t\t%s IP地址 端口\n\t比如:\t%s 127.0.0.1 80\n此程序用来从某个 IP 地址的服务器某个端口接收最多 MAXBUF 个字节的消息",
				argv[0], argv[0]);
		exit(0);
	}

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("Socket");
		exit(errno);
	}
	bzero(&dest, sizeof(dest));
	dest.sin_family = AF_INET;
	dest.sin_port = htons(atoi(argv[2]));
	if (inet_aton(argv[1], (struct in_addr *) &dest.sin_addr.s_addr) == 0) {
		perror(argv[1]);
		exit(errno);
	}

	if (connect(sockfd, (struct sockaddr *) &dest, sizeof(dest)) != 0) {
		perror("Connect ");
		exit(errno);
	}

	printf
		("\n准备就绪，可以开始聊天了……直接输入消息回车即可发信息给对方\n");

	while (1) {
		FD_ZERO(&rfds);
		FD_SET(0, &rfds);
		maxfd = 0;
		FD_SET(sockfd, &rfds);
		if (sockfd > maxfd)
			maxfd = sockfd;
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		retval = select(maxfd + 1, &rfds, NULL, NULL, &tv);
		if (retval == -1) {
			printf("将退出，select出错！ %s", strerror(errno));
			break;
		} else if (retval == 0) {
			continue;
		} else {
			if (FD_ISSET(sockfd, &rfds)) {
				bzero(buffer, MAXBUF + 1);
				len = recv(sockfd, buffer, MAXBUF, 0);
				if (len > 0)
					printf("接收消息成功:'%s'，共%d个字节的数据\n",
							buffer, len);
				else {
					if (len < 0)
						printf("消息接收失败！错误代码是%d，错误信息是'%s'\n",
								errno, strerror(errno));
					else
						printf("对方退出了，聊天终止！\n");
					break;
				}
			}

			if (FD_ISSET(0, &rfds)) {
				bzero(buffer, MAXBUF + 1);
				fgets(buffer, MAXBUF, stdin);
				if (!strncasecmp(buffer, "quit", 4)) {
					printf("自己请求终止聊天！\n");
					break;
				}
				len = send(sockfd, buffer, strlen(buffer) - 1, 0);
				if (len < 0) {
					printf("消息'%s'发送失败！错误代码是%d，错误信息是'%s'\n",
							buffer, errno, strerror(errno));
					break;
				} else
					printf
						("消息：%s\t发送成功，共发送了%d个字节！\n",
						 buffer, len);
			}
		}
	}
	close(sockfd);
	return 0;

}

