#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <malloc.h>
#include <time.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "webadmin.h"

/**
*       从系统配置文件中获取登陆失败次数和操作该次数后禁止登陆的时间间隔
*/
int getLimit(char *file,int* try_num,int* timeout,int* limit)
{
     int ret = -1;
     FILE *pf = fopen(file,"r");
     if(pf)
     {
             char buf[1024];
             while(fgets(buf,sizeof(buf),pf))
            {
                     char *p = strchr(buf,'=');
                    if(p==NULL)
                         p = strchr(buf,' ');
                     if(p==NULL)
                         p = strchr(buf,'\t');
                     if(p)
                     {
                         *p++ = 0;
                         if((strcmp(buf,"try_num")==0)&&(try_num))
                             *try_num = atoi(p);
                         else if((strcmp(buf,"lock_time")==0)&&(limit))
                             *limit = atoi(p);
                         else if((strcmp(buf,"timeout")==0)&&(timeout))
                             *timeout=atoi(p);
                     }
             }
            fclose(pf);
             ret = 0;
     }
      return ret;
}

/***************************************************
/	获取操作结果字符信息
/***************************************************/
char * getResaultMsg(int ret,char *msg)
{
	static char Msg[512];
	int i;
	char *MsgError[]={
		"操作成功",
		"获取菜单信息失败",
		"非法用户",
		"错误的用户口令",
		"不能打开用户文件",
		"网页中没有指定的变量",
		"包含非法数值字符",
		"用户己经存在",
		"用户不存在",
		"打开临时文件出错",
		"打开菜单文件出错",
		"打开访问权限文件出错",
		"菜单资源不存在",
		"菜单资源已经存在",
		"无效的资源",
		"无效的资源ID",
		"无效的父资源ID",
		"无效的菜单项",
		"非法的用户名或口令",
		"非法的用户名数据",
		"写打开会（认证）话文件失败",
		"读打开会（认证）话文件失败",
		"有其它人员使用您的账号登陆了",
		"非法连接,有其它人员使用您的账号登陆了",
		"超时",
		"没有文件名",
		"内存分配失败",
		"字段太多",
		"没有主键",
		"读打开文件失败",
		"写打开文件失败",
		"已经有相同的主键值",
		"没有找到该记录",
		"非法的口令数据",
		"两个口令不相等",
		"有子菜单，不能删除",
		"非法的表号",
		"不能获取菜单信息",
		"无访问权限",
		"没有要获取的变量名",
		"网页中的变量的数值太小",
		"网页中的变量的数值太大",
		"没有要读取的变量名",
		"不能获取该变量的值",
		"",
		"非法的XML文件",
		"没有给出XML根节点名",
		"没有给出XML记录节点名",
		"没有给出XML记录主键名",
		"没有给出XML记录主键值",
		"没有给出XML文件名",
		"空的XML文件",
		"错误的XML文件",
		"该XML记录中没有字段",
		"没有找到XML记录",
		"没有给出字段名",
		"没有给出字段值",
		"错误的口令",
		"启动指令失败",
		"启动失败",
		"停止失败",
		"重启失败",
		"非法的参数",
		"不知道的返回值",
		"程序已经运行",
		"程序没有运行",
		"缺少CGI程序名",
		"没有找到指定的属性记录",
		"缺少回调函数",
		"缺少加密密钥",
		"错误的节点路径",
		"操作结束",
		"没有任何数据",
		"该功能暂时未实现",
		"没有给出xml节点路径",
		"非法ip地址",
		"非法email地址",
		"非法掩码",
		"非法目录或文件名",
		"非法字符",
		"超出范围[0-59]",
		"超出范围[0-59]",
		"超出范围[0-23]",
		"备份文件已经存在,请先下载后删除后,再重新备份!",
		"备份失败",
		"非法的网卡MAC地址",
		"非法网络掩码",
		"IP和其掩码不符",
		"成功",
		"失败",
		"未知",
		NULL};
		
	if (ret<=0)
	{
		int len;
		i=ret*(-1);
		len = sizeof(MsgError)/sizeof(char*);
		if (i>len)
			i = (-1)*NO_KNOW_RESAULT;
	}
	else
	{
		i = (-1)*NO_KNOW_RESAULT;
	}
	if (msg)
	{
		if (strlen(MsgError[i]))
			snprintf(Msg,512,"%s %s",MsgError[i],msg);
		else
			return msg;
	}
	else
		return MsgError[i];			
	return Msg;
}
/***********************************************************************
/	base64编码
/***********************************************************************/
int Base64Encode(unsigned char *inbuf, int size, unsigned char *outbuf)
{
	char CODETABLE[65]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	// 算法
	// 3个8比特， 转换成4个6比特，并对应到码表
	// 如果长度不是3的被数，以0补齐，并将这部分编成=号
	// 例如 剩下1个字节，则需要补2个=号， 剩下2个字节，则只需要补1个=号
	int  bits=0;    //
	int  i=0;
	int  j=0;
	short remain=0;
	short mask[10]= {0,1,3,7,15,31,63,127,255,512};
	for(i=0;i<size;)
	{
		if( bits < 6 )
		{
			remain <<= 8;
			remain |= inbuf[i];
			bits+=8;
			i++;
		}
		// 移出一个6位
		// 目前remain保存了bits位
		outbuf[j++] = CODETABLE[ remain>>(bits-6) ];
		remain = remain&mask[bits-6];
		bits-=6;
	}
	
	if( bits == 6 )
	{
		outbuf[j++] = CODETABLE[ remain ];
	}
	else if( bits== 2 )
	{
		remain <<= 4;
		outbuf[j++] = CODETABLE[ remain ];
		outbuf[j++] = '=';
		outbuf[j++] = '=';
	}
	else if( bits == 4 )
	{
		remain <<= 2;
		outbuf[j++] = CODETABLE[ remain ];
		outbuf[j++] = '=';
	}
	else
	{
		//printf("Base64 Encode error.\n");
		return -1;
	}
	
	return j;
}
/***********************************************************************
/	base64解码
/***********************************************************************/
int Base64Decode(unsigned char *inbuf, int size, unsigned char *outbuf)
{
	int bits=0;
	int i=0;
	int j=0;
	short remain=0;
	char  c;
	int  cut=0;
	short mask[10]= {0,1,3,7,15,31,63,127,255,512};
	
	for(i=0;i<size;i++)
	{
		c = inbuf[i];
		if( (c>='A')&&(c<='Z') ) c-='A';
		else if( (c>='a')&&(c<='z') )  c = c-'a'+26;
		else if( (c>='0')&&(c<='9') )  c = c-'0'+52;
		else if( c == '+' ) c = 62;
		else if( c == '/' ) c = 63;
		else if( c == '=' ) { c = 0; cut++; }
		
		// 处理 c
		remain <<= 6;
		bits+=6;
		remain|=c;
		if( bits>=8 )
		{
			outbuf[j++] = remain>>(bits-8);
			remain &= mask[bits-8];
			bits-=8;
		}
	}
	
	j-=cut;
	if( bits != 0 ) 
	{
		//printf("Decode error.\n");
		return -1;
	}
	
	return j;
}

/***************************************************
/	Url编码
/***************************************************/
char *UrlEncode(char *data)
{
  char *hex = "0123456789ABCDEF";
  unsigned char *i, *j, *code;
  int   inc;

  for (inc=0, i=data; *i!='\0'; i++)
    if (!isalnum(*i))
      inc += 2;
  
  if (!(code = (char*)malloc(strlen(data)+inc+1)))
    return NULL;
  
  for (j=code, i=data; *i!='\0'; i++, j++)
  {
      if (*i == ' ')
		*j = '+';
      else if (!isalnum(*i))
	  {
	  	*j++ = '%';
	  	*j++ = hex[*i/16];
	  	*j   = hex[*i%16];
	  }
      else
		*j = *i;
  }
  *j = '\0';
  return code;
}

/****************************************************************
 *
 *  Function: mSplit()
 *
 *  Purpose: Splits a string into tokens non-destructively.
 *
 *  Parameters:
 *      char *str => the string to be split
 *      char *sep => a string of token seperaters
 *      int max_strs => how many tokens should be returned
 *      int *toks => place to store the number of tokens found in str
 *      char meta => the "escape metacharacter", treat the character
 *                   after this character as a literal and "escape" a
 *                   seperator
 *
 *  Returns:	
 *      2D char array with one token per "row" of the returned
 *      array.
 *					将str分解为字段数组返回
 ****************************************************************/
char **mSplit(	char *str, 			// 要分解的字符串
				char *sep, 			// 分隔符字符串
				int max_strs, 		// 应该返回的字符数目
				int *toks, 			// 实际分解的字符数目
				char meta			// str中的转意字符
			 )
{
    char **retstr;      /* 2D array which is returned to caller */
    char *idx;          /* index pointer into str */
    char *end;          /* ptr to end of str */
    char *sep_end;      /* ptr to end of seperator string */
    char *sep_idx;      /* index ptr into seperator string */
    int len = 0;        /* length of current token string */
    int curr_str = 0;       /* current index into the 2D return array */
    char last_char = (char) 0xFF;
	int k;

    *toks = 0;
    if (!str) 
		return NULL;


    sep_end = sep + strlen(sep);
    end = str + strlen(str);

    //
    //	删除尾部空格
    //
    while(isspace((int) *(end - 1)) && ((end - 1) >= str))
        *(--end) = '\0';

    sep_idx = sep;
    idx = str;
	//
	//	分配指针数组
	//
    if((retstr = (char **) malloc((sizeof(char **) * max_strs))) == NULL)
        return NULL;


    max_strs--;

    while(idx < end)
    {
        while(sep_idx < sep_end)
        {
            //
            //	判断是否分割符
            //
            if((*idx == *sep_idx) && (last_char != meta))
            {
                if(len > 0)
                {
                    if(curr_str <= max_strs)
                    {
                        //
                        //	分配内存。
                        //
                        if((retstr[curr_str] = (char *) malloc((sizeof(char) * len) + 1)) == NULL)
                        {
                            for(k=0;k<curr_str;k++);
                            	free(retstr[k]);
                            free(retstr);
                            return NULL;
                        }
						//
						//	复制字段数据
						//	
                        memcpy(retstr[curr_str], (idx - len), len);
                        retstr[curr_str][len] = 0;
                        len = 0;
                        curr_str++;
                        last_char = *idx;
                        idx++;
                    }
                    //
                    //	判断是否超过了指定的字段数
                    //
                    if(curr_str >= max_strs)
                    {
                        while(isspace((int) *idx))
                            idx++;
						//
						// 将剩余的数据全部符给最后一个字段。
						//
                        len = end - idx;

                        if((retstr[curr_str] = (char *) malloc((sizeof(char) * len) + 1)) == NULL)
                        {
                            for(k=0;k<curr_str;k++);
                            	free(retstr[k]);
                            free(retstr);
                            return NULL;
                        }

                        memcpy(retstr[curr_str], idx, len);
                        retstr[curr_str][len] = 0;

                        *toks = curr_str + 1;

                        return retstr;
                    }
                }
                else
                {
                    //
                    //	空的字段，丢掉。
                    //
                    last_char = *idx;
                    idx++;
                    sep_idx = sep;
                    len = 0;
                }
            }
            else
            {
                //
                //	不等于当前分割符，使用下一个分割符进行判断。
                //
                sep_idx++;
            }
        }

        sep_idx = sep;
        //
        //	记录当前字段数据长度
        //
        len++;
        last_char = *idx;
        idx++;
    }
    if(len > 0)
    {

        if((retstr[curr_str] = (char *) malloc((sizeof(char) * len) + 1)) == NULL)
		{
            for(k=0;k<curr_str;k++);
            	free(retstr[k]);
            free(retstr);
            return NULL;
		}
        memcpy(retstr[curr_str], (idx - len), len);
        retstr[curr_str][len] = 0;
        *toks = curr_str + 1;
    }

    return retstr;
}
/***********************************************************************
/  设置Cookie
/	name: cookie名字
/	value: cookie的值
/  expirehour: 多少小时后，cookie失效. 0表示当前会话结束后, cookie失效
/***********************************************************************/
void  setCookie(char *name, char  *value, int  expire)
{
	time_t  now;
	struct tm  *gmtm;

	//
	//	判断数据的有效性
	//
	if (!name)
		return;

	if (expire<=0)
	{
		//
		//	设置cookie
		//
		fprintf(stdout,"Set-Cookie: %s=%s\n", name, value);
	}
	else 
	{
		time(&now);
		//
		//	设置超时时间
		//
		now += 60*expire;
		gmtm=gmtime(&now);
		fprintf(stdout,"Set-Cookie: %s=%s;expires=%d, %d-%d-%d %d:%d:%d GMT\n",
		        name, value,
		        gmtm->tm_wday,
		        gmtm->tm_mday, gmtm->tm_mon, gmtm->tm_year,
		        gmtm->tm_hour, gmtm->tm_min, gmtm->tm_sec );

	}
	fflush(stdout);
}
/*********************************************************
/	获取cookie的值
/*********************************************************/
char * getCookie(char* name)
{
	char *cookies;
	char **toks;
	char *ret=NULL;
    int num_toks,i;
	cookies = getenv("HTTP_COOKIE");
	if (cookies)
	{
		//
		//	分解字段
		//
		toks = mSplit(cookies, ";", 20, &num_toks, '\\');
		if (toks)
		{
			for(i=0 ; i< num_toks ; i++)
			{
				char **nameValue;
				int  num;
				
				if (ret == NULL)
				{
					nameValue = mSplit(toks[i], "= \t", 2, &num, '\\');
					if ((num == 2) && nameValue && (strcmp(nameValue[0],name)==0))
					{
						ret = nameValue[1];
						free(nameValue[0]);
					}
					else
					{
						free(nameValue[0]);
						free(nameValue[1]);
					}
					free(nameValue);
				}
				free(toks[i]);
			}
			free(toks);
		}
	}
	return ret;
}

/****************************************************************
*   获取开机时间
*****************************************************************/
time_t getUptime(void)
{
     int fd;
     fd = open("/proc/uptime",O_RDONLY);
     if (fd != -1)
     {
         char buf[64];
         unsigned long sec,usec;
         memset(buf,0,64);
         read(fd,buf,64);
         sscanf(buf,"%u.%u",&sec,&usec);
         close(fd);
         return sec;
     }
     return 0;
}


/*****************************************************************
/	设置认证文件。
/*****************************************************************/
int setSession(char *name,unsigned int userId,unsigned int *ram)
{
	FILE *pf;
	time_t now;
	char session[100];

	if (name==NULL)
		return INVALID_USER_NAME;
	
	snprintf(session,100,"%s%s",SESSION_DIR,name);
	pf = fopen(session,"w");
	
	if (pf == NULL)
		return OPEN_SESSION_WRITE_FALSE;

	time(&now);		// 获取当前时间
	
	srand((unsigned)now);
	*ram = rand() ;
	fprintf(pf,"%s\t%ld\t%ld\t%ld",name,now,*ram,userId);
	fclose(pf);
	return OK;
}
/*****************************************************
/	判断用户信息，是否在有效期内。
/*****************************************************/
int getSession(char *name,unsigned int *userId,unsigned int *ram)
{
	FILE *pf;
	time_t now;
	char session[100];
	char buf[STD_BUF];
    char **toks;
    int num_toks;
	int ret = OK;

	if ((name == NULL)||(strlen(name)==0))
		return INVALID_USER_NAME;
	
	sprintf(session,"%s%s",SESSION_DIR,name);
	pf = fopen(session,"r");
	
	if (pf == NULL)
		return OPEN_SESSION_READ_FALSE;

	if (fgets(buf, STD_BUF, pf) != NULL)
	{
		int k;
		time(&now);		// 获取当前时间
		//
		//	分解字段
		//
		toks = mSplit(buf, "\t", 5, &num_toks, 0);
		if (num_toks == 4)
		{
			
			//
			//	判断用户名
			//
			if (strcmp(name,toks[0]))
			{
				ret = INVALID_USER;
			}
			else if (*ram != (unsigned int )atoi(toks[2]))
			{
				ret = INVALID_SESSION;
			}
			else if (now > (atoi(toks[1])+HTTP_TIME_OUT+5))
				ret = TIME_OUT;
			else
			{
				*userId = atoi(toks[3]);	// 获取用户id
			}
		}
		else
		{
			
			ret = SESSION_FILE_BAD;
		}
		for (k=0;k<num_toks;k++)
			free(toks[k]);
		free(toks);
	}
	fclose(pf);
	//
	//	验证失败
	//
	if (ret != OK)
		return ret;
	//
	//	认证通过后重新设置随机数和有效期
	//
	sprintf(session,"%s%s",SESSION_DIR,name);
	pf = fopen(session,"w");
	
	if (pf == NULL)
		return OPEN_SESSION_WRITE_FALSE;

	//srand((unsigned)now);
	//*ram = rand(); 
	fprintf(pf,"%s\t%ld\t%ld\t%ld",name,now,*ram,*userId);
	fclose(pf);
	return OK;
}
/*****************************************************************
/	生成页面程序
/*****************************************************************/
int generateUpdate(int keyIndex,		//主键字段序号
				   char*key,			//主键值
				   int numField,		//字段数目
				   char **FieldProperty,//字段显示属性数组
				   char **FieldTitle,	//字段标题数组
				   char *configName,	// 配置文件名
				   char *operate,		// 操作
				   char *Title)			// 标题
{
	int ret ;
	int i;
    char **FieldValue=NULL;	//字段值数组

	//
	//	获取一个记录的各个字段
	//
	ret = getFieldValue(keyIndex,key,numField,&FieldValue,configName,"=\t ");
	if (ret)
	{
		//
		//	获取数据失败
		//
		printf("获取数据失败");
		return ret;
	}
	//
	//	生成页面
	//
	if (HTTP_TIME_OUT>0)
		printf("<HTML><HEAD><title>安全隔离与信息交换系统 -- 系统管理</title>"
			"<meta http-equiv=\"refresh\" content=\"%d;URL=/timeout.html\"></head>"
			"</HEAD><body background=\"/icons/bg01.gif\"><br><center><H2>%s</H2><P></center>"
			"<FORM name=\"request\" action=\"/cgi-bin/%s.cgi\" method=POST>"
			"<P><P><HR width=90%><br><table align=center>",HTTP_TIME_OUT,Title,operate);
	else
		printf("<HTML><HEAD><title>安全隔离与信息交换系统 -- 系统管理</title>"
			"</HEAD><body background=\"/icons/bg01.gif\"><br><center><H2>%s</H2><P></center>"
			"<FORM name=\"request\" action=\"/cgi-bin/%s.cgi\" method=POST>"
			"<P><P><HR width=90%><br><table align=center>",Title,operate);
	
	for(i=0;i<numField;i++)
	{
		char varName[100];
		sprintf(varName,"field%d",i);
		
		if ((strcmp(FieldProperty[i],"显示")==0)&&(FieldTitle[i]))
		{		
			//if (strcmp(operate,"delRecord")==0)
				printf("<tr><td>");
				DisplayEncodeHttp(FieldTitle[i]);
				printf("</td><td><input type=\"text\" READONLY name=\"");
				DisplayEncodeHttp(varName);
				printf("\" value=\"");
				DisplayEncodeHttp(FieldValue[i]);
				printf("\" size=20 MAXLENGTH=48></td></tr>");
				/*	将数据中的 & ; " <> 字符进行编码后输出。
				printf("<tr><td>%s</td><td><input type=\"text\" READONLY name=%s "
					" value=%s size=20 MAXLENGTH=48></td></tr>",FieldTitle[i],varName,FieldValue[i]); */
		}
		else if ((strcmp(FieldProperty[i],"修改")==0)&&(FieldTitle[i]))
		{
			//printf("<tr><td>%s</td><td><input type=\"text\" name=%s value=%s size=20 MAXLENGTH=48></td></tr>",FieldTitle[i],varName,FieldValue[i]);
			printf("<tr><td>");
			DisplayEncodeHttp(FieldTitle[i]);
			printf("</td><td><input type=\"text\" name=\"");
			DisplayEncodeHttp(varName);
			printf("\" value=\"");
			DisplayEncodeHttp(FieldValue[i]);
			printf("\" size=20 MAXLENGTH=48></td></tr>");
		}
	}
	printf("<input type=hidden name=numField value=%d>",numField);
	printf("<input type=hidden name=configFile value=%s>",configName);
	printf("<input type=hidden name=KeyIndex value=%d >",keyIndex);
	printf("<input type=hidden name=KeyIndex value=%d >",keyIndex);
	if (strcmp(operate,"delRecord")==0)
	{
		printf("</TABLE><P><P>");
		printf("<HR width=90%><center><input TYPE=\"checkbox\" name=IsDelete>是否删除&nbsp;&nbsp;&nbsp;<input type=\"submit\" value=\"发送确认\"></FORM></BODY></HTML>");
	}
	else if (strcmp(operate,"updateRecord")==0)
	{
		printf("</TABLE><P><P>");
		printf("<HR width=90%><center><input type=\"submit\" value=\"提   交\"></FORM></BODY></HTML>");
	}
	//
	//	释放分配的资源
	//
	if (FieldValue)
	{
		for(i=0;i<numField;i++)
			if (FieldValue[i]) free(FieldValue[i]);
		free(FieldValue);
	}
	return OK;
}

/*************************************************************
/	显示操作信息给用户。
/*************************************************************/
typedef struct {
  char *var;
  char *val;
} pair_t;

typedef struct {
  int     size;
  pair_t *pair;
} form_t;
char USER_NAME[100];
extern form_t form;

void dispOperateInfo(char * level,int error,char *msg)
{
	char *msg_file = NULL;
	char *p=NULL;
	//
	//	记录日志
	//
	if (logEnable)
		log(LOG_FILE_NAME,&form,"%s\t%s\t%s",USER_NAME,progName,getResaultMsg(error,msg));
	else
		log(LOG_FILE_NAME,NULL,"%s\t%s\t%s",USER_NAME,progName,getResaultMsg(error,msg));
	
	if ((error == NO_DISP_OK_MSG)||(error == NO_DISP_FALSE_MSG)||(error == NO_DISP_MSG))
	{
		//
		//	只记录日志
		//
		return ;	
	}
	//
	//	显示标题
	//

	/* delete by hugeyang 2003.03.29 
	printf("<HTML><body background=\"/icons/bg01.gif\"><br><center>"
		"<H2>操 作 信 息</H2><P></center><HR width=50%s><BR><P><center>","%");
	*/ //delete end 
	
	printf("<html>\n<head>\n<link href=\"/icons/all.css\" rel=\"stylesheet\" type=\"text/css\">\n<meta http-equiv=\"refresh\" content=\"290;URL=/timeout.html\"></head>\n<body background=\"/icons/bg01.gif\"><br><center>"
		"<table border=\"0\" cellpadding=\"0\" cellspacing=\"0\" style=\"border-collapse: collapse\" bordercolor=\"#111111\" width=\"60%\" id=\"AutoNumber1\" height=\"72\">"
		"<tr><td width=\"13%\" height=\"102\" rowspan=\"4\"></td><td width=\"78%\" height=\"67\" colspan=\"3\"><H2 align=\"center\">操 作 信 息</H2></td><td width=\"9%\" height=\"102\" rowspan=\"4\"></td></tr>"
  		"<tr><td width=\"78%\" height=\"10\" colspan=\"3\"><HR width=\"100%\"><p></td></tr>"
		"<tr><td width=\"18%\" height=\"24\"><p align=\"right\">");


	//提示显示分为三个图标文件　路径：/icons  成功：msg_success.gif   错误失败： msg_error.gif  提示：msg_info.gif
		
	if(level)
	{
		p = strchr(level,':');
		if (p)
			*p++ = 0;
		if (strcasecmp(level,"error")==0)
		{
			msg_file = "msg_error.gif";
		}
		else if(strcasecmp(level,"ok")==0)
		{
			msg_file = "msg_success.gif";
		}
		else
		{
			msg_file = "msg_info.gif";	
		}
	}
	else
	{
		msg_file = "msg_info.gif";		
	}
	if (msg) 
	{
		if (error==NO_MESSAGE)
			printf("<img border=\"0\" src=\"/icons/%s\" width=\"40\" height=\"40\"></td>",msg_file);
		else
			printf("</td>");
		printf("<td width=\"40%\" height=\"24\" align=\"center\">");
		printf(msg);
		printf("</p></td><td width=\"20%\" height=\"24\"></td></tr><td width=\"18%\" height=\"24\"><p align=\"right\">");
	}
	if (error == NO_MESSAGE)
	{
		// delete by hgy 2003.04.03 printf("</center><Br><center><HR width=50%s></body></HTML>","%");
		printf ("<tr><td></td><td width=\"78%\" height=\"1\" colspan=\"3\"> &nbsp;<HR width=100%></td></tr></table></center><BR><P><p><Br></p>");
		if (p)
			printf(p);
		printf("</body></HTML>");
		return ;
	}
	
	printf("<img border=\"0\" src=\"/icons/%s\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\" ><p align=\"center\">",msg_file);
	printf("%s</p></td><td width=\"20%\" height=\"24\"></td></tr>",getResaultMsg(error,msg));


/*	
	switch (error)
	{
		case OK:
			printf("<img border=\"0\" src=\"/icons/msg_success.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("操作成功</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case GET_MENU_FALSE:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("获取菜单信息失败</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case INVALID_USER:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("非法用户</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case ERR_PASSWORD:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("错误的用户口令</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case OPEN_USER_FILE_FALSE:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("不能打开用户文件</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case NO_FOUND:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("网页中没有指定的变量</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;			
		case IS_LETTER:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("包含非法数值字符</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;			

		case USER_EXIST:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("用户己经存在</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case USER_NO_EXIST:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("用户不存在</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case OPEN_TEMP_FILE_FALSE:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("打开临时文件出错</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case OPEN_MENU_FILE_FALSE:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("打开菜单文件出错</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case OPEN_ACCESS_FILE_FALSE:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("打开访问权限文件出错</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case RESOURCE_NO_EXIST:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("菜单资源不存在</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case RESOURCE_EXIST:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("菜单资源已经存在</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case INVALID_RESOURCE:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("无效的资源</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case INVALID_RESOURCE_ID:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("无效的资源ID</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case INVALID_RESOURCE_FATHER:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("无效的父资源ID</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case INVALID_RESOURCE_ITEM:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("无效的菜单项</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case INVALID_USER_OR_PASS:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("非法的用户名或口令</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case INVALID_USER_NAME:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("非法的用户名数据</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case OPEN_SESSION_WRITE_FALSE:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("写打开会（认证）话文件失败</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case OPEN_SESSION_READ_FALSE:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("读打开会（认证）话文件失败</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case SESSION_FILE_BAD:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("SSEION 文件被破坏了</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case TIME_OUT:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("超时!  ");
			printf("<a href=\"/index.html\" target=_top><font color=\"#0000FF\">重新登陆</font></a></p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case NO_FILE_NAME:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("没有文件名</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case MALLOC_FALSE:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("内存分配失败</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case TOO_FIELD:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("字段太多</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case NO_KEY:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("没有主键</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case OPEN_FILE_READ_FALSE:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("读打开文件失败</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case OPEN_FILE_WRITE_FALSE:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("写打开文件失败</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case KEY_EXIST:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("已经有相同的主键值</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case NO_FIND_RECORD:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("没有找到该记录</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case INVALID_PASS_DATA:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("非法的口令数据</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case PASS_NO_SAME:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("两个口令不相等</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case HAVE_SUN_INTEM:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("有子菜单，不能删除</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case INVALID_ID:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("非法编号</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case GET_MENU_INFO_FALSE:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("不能获取菜单信息</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case NO_VARIABE:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("网页中没有要获取的变量名</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case NO_ACCESS_RIGHT:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("无访问权限</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		
		case TOO_SMALL:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("网页中的变量的数值太小</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case TOO_BIG:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("网页中的变量的数值太大</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case NO_VARIABLE_NAME:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("没有给出变量名</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case NO_GET_VALUE:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("不能获取该变量的值</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case XML_INVALID_FILE:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("非法的XML文件</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case XML_NO_ROOT_NAME:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("没有给出XML根节点名</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case XML_NO_RECORD_NAME:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("没有给出XML记录节点名</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case XML_NO_KEY_NAME:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("没有给出XML记录主键名</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case XML_NO_KEY_VALUE:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("没有给出XML记录主键值</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case XML_NO_NAME:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("没有给出XML文件名</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case XML_EMPTY:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("空的XML文件</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case XML_INVALID_ROOT:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("错误的XML文件</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case XML_NO_FIELD:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("该XML记录中没有字段</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case XML_NO_FIND_RECORD:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("没有找到XML记录</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case XML_NO_FIELDS_NAME:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("没有给出字段名</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case XML_NO_FIELDS_VALUE:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("没有给出字段值</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case INVALID_PASSWORD:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("错误的口令!  ");
			printf("<a href=\"/index.html\" target=_top><font color=\"#0000FF\">重新登陆</font></a></p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case INVALID_SESSION:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("非法连接!  ");
			printf("<a href=\"/index.html\" target=_top><font color=\"#0000FF\">重新登陆</font></a></p></td><td width=\"20%\" height=\"24\"></td></tr>");

			break;
		case EXEC_FAULT:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("启动指令失败</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case START_FAULT:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("启动失败</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case STOP_FAULT:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("停止失败</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case RESTART_FAULT:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("重启失败</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case INVALID_ARG:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("非法的参数</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case NO_KNOW_RESAULT:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("不知道的返回值</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case IS_RUNNING:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("程序已经运行</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case NO_RUNNING:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("程序没有运行</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case XML_NO_CGI:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("缺少CGI程序名</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case XML_NO_PROPERTY:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("没有找到指定的属性记录</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case XML_NO_FOUNCTION:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("缺少回调函数</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case NO_ENCRYPT_KEY:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("缺少加密密钥</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case XML_NODE_PATH:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("错误的节点路径</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case OPERATE_OVER:
			printf("<img border=\"0\" src=\"/icons/msg_success.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("操作结束</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case NO_CONTENT:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("没有任何数据</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case NO_REALIZATION:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("该功能暂时未实现</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case XML_NO_PATH:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("没有给出xml节点路径</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case INVALID_IP:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("非法ip地址</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case INVALID_EMAIL:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("非法email地址</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case INVALID_MARK:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("非法掩码</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case INVALID_PATH:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("非法目录或文件名</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case INVLID_LETTER:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("包含非法字符</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case INVALID_HOUR:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("超出范围[0-23]</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case INVALID_MINUTE:
		case INVALID_SECOND:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("超出范围[0-59]</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case BACK_FILE_EXIST:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("备份文件已经存在<p>请先下载后删除<P>再重新备份!</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case BACK_FALSE:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("备份失败!</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case INVALID_NET_MAC:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("非法的网卡MAC地址!</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case INVALID_MASK:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("非法网络掩码!</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case INVALID_MASK_IP:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("IP和其掩码不符!</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		default:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("错误编号=%d</p></td><td width=\"20%\" height=\"24\"></td></tr>",error);
	} */
	if (msg)
		printf ("<tr><td></td><td width=\"78%\" height=\"1\" colspan=\"3\"> &nbsp;<HR width=100%></td></tr></table></center><BR><P><p><Br></p>");
	else
		printf ("<tr><td width=\"78%\" height=\"1\" colspan=\"3\"> &nbsp;<HR width=100%></td></tr></table></center><BR><P><p><Br></p>");
	if (p)
		printf(p);
	printf("</body></HTML>");
	//printf("</center><Br><center><HR width=50%s></body></HTML>","%");
}
