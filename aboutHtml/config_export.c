/*
* Copyright (c) 2004 ,北京京泰网络科技有限公司
* All rights reserved.
*
* 文件名称：config_export.c
* 所属项目：GAP
* 概    述：导出系统配置文件
*
* 当前版本：1.0
* 作    者：童兆丰
* 完成日期：2004.10.14
*/

/*
#include  "company.h"					//公司信息
#include  "bhlnet_fixed.h"				//京泰网络公司的固定值
#include  "<project>_fixed.h"				//项目的信息和固定值
*/
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>
#include <fcntl.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>


/*宏定义*/

#define TMP_PATH	"/usr/local/hawk/web/cgi-bin/download"
#define SHELL_PATH	"/usr/local/hawk/web/cgi-bin/script"

#define BUFSIZE				1024

#define true 1
#define false 0


void display(char *msg)
{
	printf("Content-Type: %s\n\n", "text/html");
	printf("<HTML><HEAD><script language=javascript src=\"/timeout.js\"></script></head>");
	printf("<body background=\"icons/bg01.gif\"><br><center><H2>导出系统配置</H2><P></center>");
	printf("<HR width=60%><p><p><center>");
	printf("%s\n\n", msg);
	printf("<p><p><HR width=60%><center>");
	printf("</FORM></BODY><HEAD><META HTTP-EQUIV=\"PRAGMA\" CONTENT=\"NO-CACHE\"></HEAD></HTML>	");
	
}

char *trim(char *s, char *b) {
	char *p, *p1;
	char *blank;

	p = s;

	if (b == NULL)
		blank = " ";
	else
		blank = b;

	while ((p[0]) && strchr(blank, p[0])) {
		p++;
	}
	if (p>s) {
		p1 = s;
		while (*p) {
			p1[0] = *p;
			p1++;
			p++;
		}
		*p1=0;
	} else
		p1=s+strlen(s);

	p1--;
	while ((p1>s) && strchr(blank, *p1))
		*p1-- = 0;
	return s;
}

int main (void)
{
	int	read_len;
	char	buf[BUFSIZE + 1];
	char	cmd[BUFSIZE];
	char	name[BUFSIZE];
	char	fullname[BUFSIZE];
	char	*tar_file = NULL;
	char	*shell = NULL;
	char	*gap_path = NULL;
	
	int	i = 0;
	FILE	*fp = NULL;

	gap_path = getenv("QUERY_STRING");

	wlog("/root/log", gap_path);
			
	tar_file = strchr(gap_path, '&');
	
	tar_file++;
	tar_file += strlen("file=");
	i = 0;
	while((tar_file[i] != '&') && (tar_file[i] != ' ') && (tar_file[i] != '\0') && (tar_file[i] != '\r') && (tar_file[i] != '\n'))
	{
		i++;
	}
	tar_file[i] = '\0';

	shell = gap_path + strlen("item=");
	i = 0;
	while((shell[i] != '&') && (shell[i] != ' ') && (shell[i] != '\0') && (shell[i] != '\r') && (shell[i] != '\n'))
	{
		i++;
	}
	shell[i] = '\0';
	if ( strcmp(shell,"config_export") != 0 )
	{
		display("非法使用CGI程序");
	}

	memset(cmd, 0, sizeof(cmd));
	snprintf(cmd, sizeof(cmd)-1, "%s/%s %s/%s > /dev/null", SHELL_PATH, shell, TMP_PATH, tar_file);
	///apache/cgi-bin/script/config_export /apache/cgi-bin/download/gap-cfg
	system(cmd);
	
	memset(cmd, 0, sizeof(cmd));	
	sprintf(cmd, "%s/%s", TMP_PATH, tar_file);
	
	fp = fopen(cmd, "r");
	if(fp == NULL)
	{
		display("备份配置错误");
		return false;
	}else{
		memset(name, 0, sizeof(name));
		fgets(name,sizeof(name)-1,fp);
	
	}

	fclose(fp);
	
	memset(fullname, 0, sizeof(fullname));
	snprintf(fullname,sizeof(fullname)-1,"%s/%s",TMP_PATH,name);
	
	fp = fopen(trim(fullname," \r\n\t"), "rb");
	if(fp == NULL)
	{
		display("备份配置错误");
		return false;
	}
	
	printf("Content-Disposition: attachment; filename=%s\r\n", name);
		
	memset(buf, 0, sizeof(buf));
	while((read_len = fread(buf, sizeof(char), BUFSIZE, fp)) > 0)
	{
		fwrite(buf,sizeof(char),  read_len, stdout);
	}
	unlink(cmd);
	unlink(trim(fullname," \r\n\t"));
	return true;
}
