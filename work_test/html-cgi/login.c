#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <time.h>

#include "webadmin.h"
#include "cgi.h"

char *cgiDebug="save=wttdebug";
char *progName="login";
int logEnable = 0;
int getLimit(char *file,int* try_num,int * timeout,int* limit);
int cgiMain (void)
{
	FILE *pf = NULL ;
	char *userName;
	char *password;
	char *dev;
	char *cent;
	char *clientCert=NULL;
	char session[512];
	USER_INFO userInfo;
	int haveUser = 0;
	int ram;
	int ret;
	int fail = 0;
	time_t timeout = -1;
	
	memset(&userInfo,0,sizeof(USER_INFO));
	clientCert = getenv("SSL_CLIENT_CERT");
	if (clientCert==NULL)
	{
		memset(&userInfo,0,sizeof(USER_INFO));
		ret = cgiGetString(&userName,1,20,"userName");
		
		if (ret)
		{
			cgiHeaderContent("text/html");
			dispOperateInfo(NULL,ret,"�û���");
			return 0;
		}
		ret = cgiGetString(&password,1,20,"userPassword");
		if (ret)
		{
			cgiHeaderContent("text/html");
			dispOperateInfo(NULL,ret,"����");
			return 0;
		}
		if (1)
		{
			//
			// �жϸ��û��Ƿ�����
			//
			FILE *pf;
			time_t now;
			int try_num=3;
			int limit_time =600;
			char session[100];
			snprintf(session,100,"%s%s",SESSION_DIR,userName);
			pf = fopen(session,"r");
			if (pf)
			{
				char **toks;
	    		int num_toks;
	     		
				char buf[STD_BUF];
				if (fgets(buf, STD_BUF, pf) != NULL)
				{
					int i;
					toks = mSplit(buf, "\t", 5, &num_toks, 0);
					if (num_toks==2)
					{
						fail = atoi(toks[0]);
						timeout = (time_t)atoi(toks[1]);
					}
					for(i=0;i<num_toks;i++)
						free(toks[i]);
					free(toks);
				}
				fclose(pf);	
			}
			//time(&now);
			now=getUptime();
                        getLimit("/apache/cgi-bin/conf/system.conf",&try_num,NULL,&limit_time);
                        if ((fail>=try_num)&&(now < timeout + limit_time))
                        {
                             cgiHeaderContent("text/html");
                             cgiPrintf("<script language=\"javascript\"> history.back();</script>");
                             //cgiPrintf("time = %d",now);
                             return OK;
                         }
		}
		//
		//	�ж��û��ĺϷ���
		//
		if (IsValidUser(userName , password, &userInfo))
		{
			int haveUser(USER_INFO *);
			//
			//	�Ƿ��û�
			//
			//cgiLoad("../htdocs/index.html");
			cgiHeaderContent("text/html");
			cgiPrintf("<script language=\"javascript\"> history.back();</script>");
			//
			//	�ж��û��Ƿ����
			//
			userInfo.name = userName;
			if (haveUser(&userInfo))
			{
				FILE *pf;
				time_t now;
				char session[100];
				snprintf(session,100,"%s%s",SESSION_DIR,userName);
				pf = fopen(session,"w");
				if (pf == NULL)
					return OK;
	
				time(&now);		// ��ȡ��ǰʱ��
                                now=getUptime();
				fprintf(pf,"%d\t%ld",++fail,now);
				fclose(pf);
			}
			return OK;
		}
	}
	else
	{

		//
		//	�ж�֤��������Ƿ��ǺϷ��û�
		//
		ret = IsValidUserByCert(clientCert,&userInfo);
		if (ret)
		{
			cgiHeaderContent("text/html");
			//dispOperateInfo(NULL,ret,NULL);
                        cgiPrintf("<script language=\"javascript\"> history.back();</script>");
			return OK;			
		}
	}
	
	ret = user_passwd_limit_time_detect(userName);	
	if(ret < 0)
	{
		//�û������ѹ���
		return 0;
	}
	
	ret = setSession(userInfo.name,userInfo.id,(unsigned int*)&ram);
	if (ret != OK)
	{
		//
		//	��¼session����
		//
		cgiHeaderContent("text/html");
		dispOperateInfo(NULL,ret,NULL);
		return OK;
	}
	//
	//	����cookie
	//
	setCookie("userName",userInfo.name,0);
	snprintf(session,512,"%d",ram);
	setCookie("sessid",session,0);
	setCookie("menuid","10000",0);		// ���ò˵�id
	cgiHeaderContent("text/html");

/*
	cgiPrintf("<HTML>\n");
	cgiPrintf("<frameset rows=\"40,*\" framespacing=0 noresize name=\"home\">");
	cgiPrintf("<FRAME name=\"hmoeTile\" src=\"/home.html\" border=1 marginwidth=0 marginheight=0 noresize>");
	cgiPrintf("<FRAME name=\"worktop\" src=\"/cgi-bin/mainwork.cgi?userName=%s&sessid=%d\" border=1 marginwidth=0 marginheight=0 noresize>",userName,ram);
	cgiPrintf("</frameset>\n</html>\n"); 
*/
	//
	//	����һ���û��ļ���
	//


	//
	//	��ȡ���ķ����豸��
	/*
	dev = cgiFormGetVal("dev");
	cent = cgiFormGetVal("cent");
	if ((dev==NULL) || (cent==NULL) || strlen(dev)==0 || atoi(cent)<1 || atoi(cent)>99)
	{
		if (dev && strlen(dev)) free(dev);
		if (cent && strlen(cent)) free(cent);
		dev = NULL;
		cent = NULL;
	}*/
	//
	//	��ȡҪ�����ļ�����������ļ����ڣ���ʾҪ������־���غ�ɾ��
	//
	dev = cgiFormGetVal("testFileName");
	if (dev==NULL || strlen(dev)==0)
		dev = NULL;	
	//
	//	����sesion
	//
	sprintf(session,"../htdocs/login/%s.html",userInfo.name);
	pf = fopen(session,"w");
	if (pf)
	{
/*  delete by hugeyang 2003.03.25 
		fprintf(pf,"<HTML>\n");
		fprintf(pf,"<frameset rows=\"100,*\" framespacing=0 noresize name=\"home\">");
		fprintf(pf,"<FRAME name=\"hmoeTile\" src=\"/home.html\" border=0 marginwidth=0 marginheight=0 noresize>");
		fprintf(pf,"<FRAME name=\"worktop\" src=\"/cgi-bin/mainwork.cgi?userName=%s&sessid=%d\" border=0 marginwidth=0 marginheight=0 noresize>",userName,ram);
		fprintf(pf,"</frameset>\n</html>\n"); 
		fclose(pf);

*/ 
//update by hugeyang 

		fprintf(pf,"<HTML>\n");
		fprintf(pf,"<frameset rows=\"90,*\" framespacing=0 frameborder=0 border=0 name=\"home\">");
		fprintf(pf,"<FRAME name=\"hmoeTile\" src=\"/home.html\" border=0 marginwidth=0 marginheight=0 scrolling=no noresize>");		
		if (dev)
		{
			fprintf(pf,"<FRAME name=\"worktop\" src=\"/cgi-bin/mainwork.cgi?userName=%s&testFileName=%s&sessid=%d\" border=0 marginwidth=0 marginheight=0 noresize>",userName,dev,ram);
		}
		else
		{
			fprintf(pf,"<FRAME name=\"worktop\" src=\"/cgi-bin/mainwork.cgi?userName=%s&sessid=%d\" border=0 marginwidth=0 marginheight=0 noresize>",userName,ram);
		}
		fprintf(pf,"</frameset>\n</html>\n"); 
		
		fclose(pf);

//update end

		//
		//	�������������ɵ�ҳ����
		//
		sprintf(session,"/login/%s.html",userInfo.name);
		cgiPrintf("<html><body><head><META HTTP-EQUIV=\"REFRESH\" CONTENT=\"0; URL=%s\"></head></body></html>",session); 
	}
	else
	{
		dispOperateInfo(NULL,OPEN_TEMP_FILE_FALSE,NULL);
	}
	if (userName)	free(userName);
  	if (password)	free(password);
	return 0;
}

