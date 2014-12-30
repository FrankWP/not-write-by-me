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
*       ��ϵͳ�����ļ��л�ȡ��½ʧ�ܴ����Ͳ����ô������ֹ��½��ʱ����
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
/	��ȡ��������ַ���Ϣ
/***************************************************/
char * getResaultMsg(int ret,char *msg)
{
	static char Msg[512];
	int i;
	char *MsgError[]={
		"�����ɹ�",
		"��ȡ�˵���Ϣʧ��",
		"�Ƿ��û�",
		"������û�����",
		"���ܴ��û��ļ�",
		"��ҳ��û��ָ���ı���",
		"�����Ƿ���ֵ�ַ�",
		"�û���������",
		"�û�������",
		"����ʱ�ļ�����",
		"�򿪲˵��ļ�����",
		"�򿪷���Ȩ���ļ�����",
		"�˵���Դ������",
		"�˵���Դ�Ѿ�����",
		"��Ч����Դ",
		"��Ч����ԴID",
		"��Ч�ĸ���ԴID",
		"��Ч�Ĳ˵���",
		"�Ƿ����û��������",
		"�Ƿ����û�������",
		"д�򿪻ᣨ��֤�����ļ�ʧ��",
		"���򿪻ᣨ��֤�����ļ�ʧ��",
		"��������Աʹ�������˺ŵ�½��",
		"�Ƿ�����,��������Աʹ�������˺ŵ�½��",
		"��ʱ",
		"û���ļ���",
		"�ڴ����ʧ��",
		"�ֶ�̫��",
		"û������",
		"�����ļ�ʧ��",
		"д���ļ�ʧ��",
		"�Ѿ�����ͬ������ֵ",
		"û���ҵ��ü�¼",
		"�Ƿ��Ŀ�������",
		"����������",
		"���Ӳ˵�������ɾ��",
		"�Ƿ��ı��",
		"���ܻ�ȡ�˵���Ϣ",
		"�޷���Ȩ��",
		"û��Ҫ��ȡ�ı�����",
		"��ҳ�еı�������ֵ̫С",
		"��ҳ�еı�������ֵ̫��",
		"û��Ҫ��ȡ�ı�����",
		"���ܻ�ȡ�ñ�����ֵ",
		"",
		"�Ƿ���XML�ļ�",
		"û�и���XML���ڵ���",
		"û�и���XML��¼�ڵ���",
		"û�и���XML��¼������",
		"û�и���XML��¼����ֵ",
		"û�и���XML�ļ���",
		"�յ�XML�ļ�",
		"�����XML�ļ�",
		"��XML��¼��û���ֶ�",
		"û���ҵ�XML��¼",
		"û�и����ֶ���",
		"û�и����ֶ�ֵ",
		"����Ŀ���",
		"����ָ��ʧ��",
		"����ʧ��",
		"ֹͣʧ��",
		"����ʧ��",
		"�Ƿ��Ĳ���",
		"��֪���ķ���ֵ",
		"�����Ѿ�����",
		"����û������",
		"ȱ��CGI������",
		"û���ҵ�ָ�������Լ�¼",
		"ȱ�ٻص�����",
		"ȱ�ټ�����Կ",
		"����Ľڵ�·��",
		"��������",
		"û���κ�����",
		"�ù�����ʱδʵ��",
		"û�и���xml�ڵ�·��",
		"�Ƿ�ip��ַ",
		"�Ƿ�email��ַ",
		"�Ƿ�����",
		"�Ƿ�Ŀ¼���ļ���",
		"�Ƿ��ַ�",
		"������Χ[0-59]",
		"������Χ[0-59]",
		"������Χ[0-23]",
		"�����ļ��Ѿ�����,�������غ�ɾ����,�����±���!",
		"����ʧ��",
		"�Ƿ�������MAC��ַ",
		"�Ƿ���������",
		"IP�������벻��",
		"�ɹ�",
		"ʧ��",
		"δ֪",
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
/	base64����
/***********************************************************************/
int Base64Encode(unsigned char *inbuf, int size, unsigned char *outbuf)
{
	char CODETABLE[65]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	// �㷨
	// 3��8���أ� ת����4��6���أ�����Ӧ�����
	// ������Ȳ���3�ı�������0���룬�����ⲿ�ֱ��=��
	// ���� ʣ��1���ֽڣ�����Ҫ��2��=�ţ� ʣ��2���ֽڣ���ֻ��Ҫ��1��=��
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
		// �Ƴ�һ��6λ
		// Ŀǰremain������bitsλ
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
/	base64����
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
		
		// ���� c
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
/	Url����
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
 *					��str�ֽ�Ϊ�ֶ����鷵��
 ****************************************************************/
char **mSplit(	char *str, 			// Ҫ�ֽ���ַ���
				char *sep, 			// �ָ����ַ���
				int max_strs, 		// Ӧ�÷��ص��ַ���Ŀ
				int *toks, 			// ʵ�ʷֽ���ַ���Ŀ
				char meta			// str�е�ת���ַ�
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
    //	ɾ��β���ո�
    //
    while(isspace((int) *(end - 1)) && ((end - 1) >= str))
        *(--end) = '\0';

    sep_idx = sep;
    idx = str;
	//
	//	����ָ������
	//
    if((retstr = (char **) malloc((sizeof(char **) * max_strs))) == NULL)
        return NULL;


    max_strs--;

    while(idx < end)
    {
        while(sep_idx < sep_end)
        {
            //
            //	�ж��Ƿ�ָ��
            //
            if((*idx == *sep_idx) && (last_char != meta))
            {
                if(len > 0)
                {
                    if(curr_str <= max_strs)
                    {
                        //
                        //	�����ڴ档
                        //
                        if((retstr[curr_str] = (char *) malloc((sizeof(char) * len) + 1)) == NULL)
                        {
                            for(k=0;k<curr_str;k++);
                            	free(retstr[k]);
                            free(retstr);
                            return NULL;
                        }
						//
						//	�����ֶ�����
						//	
                        memcpy(retstr[curr_str], (idx - len), len);
                        retstr[curr_str][len] = 0;
                        len = 0;
                        curr_str++;
                        last_char = *idx;
                        idx++;
                    }
                    //
                    //	�ж��Ƿ񳬹���ָ�����ֶ���
                    //
                    if(curr_str >= max_strs)
                    {
                        while(isspace((int) *idx))
                            idx++;
						//
						// ��ʣ�������ȫ���������һ���ֶΡ�
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
                    //	�յ��ֶΣ�������
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
                //	�����ڵ�ǰ�ָ����ʹ����һ���ָ�������жϡ�
                //
                sep_idx++;
            }
        }

        sep_idx = sep;
        //
        //	��¼��ǰ�ֶ����ݳ���
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
/  ����Cookie
/	name: cookie����
/	value: cookie��ֵ
/  expirehour: ����Сʱ��cookieʧЧ. 0��ʾ��ǰ�Ự������, cookieʧЧ
/***********************************************************************/
void  setCookie(char *name, char  *value, int  expire)
{
	time_t  now;
	struct tm  *gmtm;

	//
	//	�ж����ݵ���Ч��
	//
	if (!name)
		return;

	if (expire<=0)
	{
		//
		//	����cookie
		//
		fprintf(stdout,"Set-Cookie: %s=%s\n", name, value);
	}
	else 
	{
		time(&now);
		//
		//	���ó�ʱʱ��
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
/	��ȡcookie��ֵ
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
		//	�ֽ��ֶ�
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
*   ��ȡ����ʱ��
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
/	������֤�ļ���
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

	time(&now);		// ��ȡ��ǰʱ��
	
	srand((unsigned)now);
	*ram = rand() ;
	fprintf(pf,"%s\t%ld\t%ld\t%ld",name,now,*ram,userId);
	fclose(pf);
	return OK;
}
/*****************************************************
/	�ж��û���Ϣ���Ƿ�����Ч���ڡ�
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
		time(&now);		// ��ȡ��ǰʱ��
		//
		//	�ֽ��ֶ�
		//
		toks = mSplit(buf, "\t", 5, &num_toks, 0);
		if (num_toks == 4)
		{
			
			//
			//	�ж��û���
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
				*userId = atoi(toks[3]);	// ��ȡ�û�id
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
	//	��֤ʧ��
	//
	if (ret != OK)
		return ret;
	//
	//	��֤ͨ���������������������Ч��
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
/	����ҳ�����
/*****************************************************************/
int generateUpdate(int keyIndex,		//�����ֶ����
				   char*key,			//����ֵ
				   int numField,		//�ֶ���Ŀ
				   char **FieldProperty,//�ֶ���ʾ��������
				   char **FieldTitle,	//�ֶα�������
				   char *configName,	// �����ļ���
				   char *operate,		// ����
				   char *Title)			// ����
{
	int ret ;
	int i;
    char **FieldValue=NULL;	//�ֶ�ֵ����

	//
	//	��ȡһ����¼�ĸ����ֶ�
	//
	ret = getFieldValue(keyIndex,key,numField,&FieldValue,configName,"=\t ");
	if (ret)
	{
		//
		//	��ȡ����ʧ��
		//
		printf("��ȡ����ʧ��");
		return ret;
	}
	//
	//	����ҳ��
	//
	if (HTTP_TIME_OUT>0)
		printf("<HTML><HEAD><title>��ȫ��������Ϣ����ϵͳ -- ϵͳ����</title>"
			"<meta http-equiv=\"refresh\" content=\"%d;URL=/timeout.html\"></head>"
			"</HEAD><body background=\"/icons/bg01.gif\"><br><center><H2>%s</H2><P></center>"
			"<FORM name=\"request\" action=\"/cgi-bin/%s.cgi\" method=POST>"
			"<P><P><HR width=90%><br><table align=center>",HTTP_TIME_OUT,Title,operate);
	else
		printf("<HTML><HEAD><title>��ȫ��������Ϣ����ϵͳ -- ϵͳ����</title>"
			"</HEAD><body background=\"/icons/bg01.gif\"><br><center><H2>%s</H2><P></center>"
			"<FORM name=\"request\" action=\"/cgi-bin/%s.cgi\" method=POST>"
			"<P><P><HR width=90%><br><table align=center>",Title,operate);
	
	for(i=0;i<numField;i++)
	{
		char varName[100];
		sprintf(varName,"field%d",i);
		
		if ((strcmp(FieldProperty[i],"��ʾ")==0)&&(FieldTitle[i]))
		{		
			//if (strcmp(operate,"delRecord")==0)
				printf("<tr><td>");
				DisplayEncodeHttp(FieldTitle[i]);
				printf("</td><td><input type=\"text\" READONLY name=\"");
				DisplayEncodeHttp(varName);
				printf("\" value=\"");
				DisplayEncodeHttp(FieldValue[i]);
				printf("\" size=20 MAXLENGTH=48></td></tr>");
				/*	�������е� & ; " <> �ַ����б���������
				printf("<tr><td>%s</td><td><input type=\"text\" READONLY name=%s "
					" value=%s size=20 MAXLENGTH=48></td></tr>",FieldTitle[i],varName,FieldValue[i]); */
		}
		else if ((strcmp(FieldProperty[i],"�޸�")==0)&&(FieldTitle[i]))
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
		printf("<HR width=90%><center><input TYPE=\"checkbox\" name=IsDelete>�Ƿ�ɾ��&nbsp;&nbsp;&nbsp;<input type=\"submit\" value=\"����ȷ��\"></FORM></BODY></HTML>");
	}
	else if (strcmp(operate,"updateRecord")==0)
	{
		printf("</TABLE><P><P>");
		printf("<HR width=90%><center><input type=\"submit\" value=\"��   ��\"></FORM></BODY></HTML>");
	}
	//
	//	�ͷŷ������Դ
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
/	��ʾ������Ϣ���û���
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
	//	��¼��־
	//
	if (logEnable)
		log(LOG_FILE_NAME,&form,"%s\t%s\t%s",USER_NAME,progName,getResaultMsg(error,msg));
	else
		log(LOG_FILE_NAME,NULL,"%s\t%s\t%s",USER_NAME,progName,getResaultMsg(error,msg));
	
	if ((error == NO_DISP_OK_MSG)||(error == NO_DISP_FALSE_MSG)||(error == NO_DISP_MSG))
	{
		//
		//	ֻ��¼��־
		//
		return ;	
	}
	//
	//	��ʾ����
	//

	/* delete by hugeyang 2003.03.29 
	printf("<HTML><body background=\"/icons/bg01.gif\"><br><center>"
		"<H2>�� �� �� Ϣ</H2><P></center><HR width=50%s><BR><P><center>","%");
	*/ //delete end 
	
	printf("<html>\n<head>\n<link href=\"/icons/all.css\" rel=\"stylesheet\" type=\"text/css\">\n<meta http-equiv=\"refresh\" content=\"290;URL=/timeout.html\"></head>\n<body background=\"/icons/bg01.gif\"><br><center>"
		"<table border=\"0\" cellpadding=\"0\" cellspacing=\"0\" style=\"border-collapse: collapse\" bordercolor=\"#111111\" width=\"60%\" id=\"AutoNumber1\" height=\"72\">"
		"<tr><td width=\"13%\" height=\"102\" rowspan=\"4\"></td><td width=\"78%\" height=\"67\" colspan=\"3\"><H2 align=\"center\">�� �� �� Ϣ</H2></td><td width=\"9%\" height=\"102\" rowspan=\"4\"></td></tr>"
  		"<tr><td width=\"78%\" height=\"10\" colspan=\"3\"><HR width=\"100%\"><p></td></tr>"
		"<tr><td width=\"18%\" height=\"24\"><p align=\"right\">");


	//��ʾ��ʾ��Ϊ����ͼ���ļ���·����/icons  �ɹ���msg_success.gif   ����ʧ�ܣ� msg_error.gif  ��ʾ��msg_info.gif
		
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
			printf("�����ɹ�</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case GET_MENU_FALSE:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("��ȡ�˵���Ϣʧ��</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case INVALID_USER:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("�Ƿ��û�</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case ERR_PASSWORD:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("������û�����</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case OPEN_USER_FILE_FALSE:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("���ܴ��û��ļ�</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case NO_FOUND:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("��ҳ��û��ָ���ı���</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;			
		case IS_LETTER:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("�����Ƿ���ֵ�ַ�</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;			

		case USER_EXIST:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("�û���������</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case USER_NO_EXIST:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("�û�������</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case OPEN_TEMP_FILE_FALSE:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("����ʱ�ļ�����</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case OPEN_MENU_FILE_FALSE:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("�򿪲˵��ļ�����</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case OPEN_ACCESS_FILE_FALSE:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("�򿪷���Ȩ���ļ�����</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case RESOURCE_NO_EXIST:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("�˵���Դ������</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case RESOURCE_EXIST:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("�˵���Դ�Ѿ�����</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case INVALID_RESOURCE:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("��Ч����Դ</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case INVALID_RESOURCE_ID:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("��Ч����ԴID</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case INVALID_RESOURCE_FATHER:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("��Ч�ĸ���ԴID</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case INVALID_RESOURCE_ITEM:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("��Ч�Ĳ˵���</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case INVALID_USER_OR_PASS:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("�Ƿ����û��������</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case INVALID_USER_NAME:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("�Ƿ����û�������</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case OPEN_SESSION_WRITE_FALSE:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("д�򿪻ᣨ��֤�����ļ�ʧ��</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case OPEN_SESSION_READ_FALSE:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("���򿪻ᣨ��֤�����ļ�ʧ��</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case SESSION_FILE_BAD:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("SSEION �ļ����ƻ���</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case TIME_OUT:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("��ʱ!  ");
			printf("<a href=\"/index.html\" target=_top><font color=\"#0000FF\">���µ�½</font></a></p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case NO_FILE_NAME:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("û���ļ���</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case MALLOC_FALSE:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("�ڴ����ʧ��</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case TOO_FIELD:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("�ֶ�̫��</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case NO_KEY:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("û������</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case OPEN_FILE_READ_FALSE:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("�����ļ�ʧ��</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case OPEN_FILE_WRITE_FALSE:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("д���ļ�ʧ��</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case KEY_EXIST:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("�Ѿ�����ͬ������ֵ</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case NO_FIND_RECORD:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("û���ҵ��ü�¼</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case INVALID_PASS_DATA:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("�Ƿ��Ŀ�������</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case PASS_NO_SAME:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("����������</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case HAVE_SUN_INTEM:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("���Ӳ˵�������ɾ��</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case INVALID_ID:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("�Ƿ����</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case GET_MENU_INFO_FALSE:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("���ܻ�ȡ�˵���Ϣ</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case NO_VARIABE:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("��ҳ��û��Ҫ��ȡ�ı�����</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case NO_ACCESS_RIGHT:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("�޷���Ȩ��</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		
		case TOO_SMALL:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("��ҳ�еı�������ֵ̫С</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case TOO_BIG:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("��ҳ�еı�������ֵ̫��</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case NO_VARIABLE_NAME:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("û�и���������</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case NO_GET_VALUE:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("���ܻ�ȡ�ñ�����ֵ</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case XML_INVALID_FILE:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("�Ƿ���XML�ļ�</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case XML_NO_ROOT_NAME:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("û�и���XML���ڵ���</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case XML_NO_RECORD_NAME:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("û�и���XML��¼�ڵ���</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case XML_NO_KEY_NAME:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("û�и���XML��¼������</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case XML_NO_KEY_VALUE:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("û�и���XML��¼����ֵ</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case XML_NO_NAME:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("û�и���XML�ļ���</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case XML_EMPTY:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("�յ�XML�ļ�</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case XML_INVALID_ROOT:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("�����XML�ļ�</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case XML_NO_FIELD:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("��XML��¼��û���ֶ�</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case XML_NO_FIND_RECORD:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("û���ҵ�XML��¼</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case XML_NO_FIELDS_NAME:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("û�и����ֶ���</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case XML_NO_FIELDS_VALUE:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("û�и����ֶ�ֵ</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case INVALID_PASSWORD:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("����Ŀ���!  ");
			printf("<a href=\"/index.html\" target=_top><font color=\"#0000FF\">���µ�½</font></a></p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case INVALID_SESSION:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("�Ƿ�����!  ");
			printf("<a href=\"/index.html\" target=_top><font color=\"#0000FF\">���µ�½</font></a></p></td><td width=\"20%\" height=\"24\"></td></tr>");

			break;
		case EXEC_FAULT:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("����ָ��ʧ��</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case START_FAULT:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("����ʧ��</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case STOP_FAULT:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("ֹͣʧ��</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case RESTART_FAULT:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("����ʧ��</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case INVALID_ARG:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("�Ƿ��Ĳ���</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case NO_KNOW_RESAULT:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("��֪���ķ���ֵ</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case IS_RUNNING:
			printf("<img border=\"0\" src=\"/icons/msg_error.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("�����Ѿ�����</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case NO_RUNNING:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("����û������</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case XML_NO_CGI:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("ȱ��CGI������</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case XML_NO_PROPERTY:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("û���ҵ�ָ�������Լ�¼</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case XML_NO_FOUNCTION:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("ȱ�ٻص�����</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case NO_ENCRYPT_KEY:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("ȱ�ټ�����Կ</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case XML_NODE_PATH:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("����Ľڵ�·��</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case OPERATE_OVER:
			printf("<img border=\"0\" src=\"/icons/msg_success.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("��������</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case NO_CONTENT:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("û���κ�����</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case NO_REALIZATION:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("�ù�����ʱδʵ��</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case XML_NO_PATH:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("û�и���xml�ڵ�·��</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case INVALID_IP:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("�Ƿ�ip��ַ</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case INVALID_EMAIL:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("�Ƿ�email��ַ</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case INVALID_MARK:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("�Ƿ�����</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case INVALID_PATH:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("�Ƿ�Ŀ¼���ļ���</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case INVLID_LETTER:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("�����Ƿ��ַ�</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case INVALID_HOUR:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("������Χ[0-23]</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case INVALID_MINUTE:
		case INVALID_SECOND:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("������Χ[0-59]</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case BACK_FILE_EXIST:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("�����ļ��Ѿ�����<p>�������غ�ɾ��<P>�����±���!</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case BACK_FALSE:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("����ʧ��!</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case INVALID_NET_MAC:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("�Ƿ�������MAC��ַ!</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case INVALID_MASK:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("�Ƿ���������!</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		case INVALID_MASK_IP:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("IP�������벻��!</p></td><td width=\"20%\" height=\"24\"></td></tr>");
			break;
		default:
			printf("<img border=\"0\" src=\"/icons/msg_info.gif\" width=\"40\" height=\"40\"></td><td width=\"40%\" height=\"24\"><p align=\"center\">");
			printf("������=%d</p></td><td width=\"20%\" height=\"24\"></td></tr>",error);
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
