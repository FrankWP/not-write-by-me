#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <sys/stat.h>
#include <gnome-xml/libxml/xmlmemory.h>
#include <gnome-xml/libxml/parser.h>
#include <gnome-xml/libxml/tree.h>
#include "webadmin.h"
#include "cgi.h"

char *cgiDebug;//="SAVE=wttdebug";
char *progName="backup";
int logEnable = 1;
/********************************************
/	������־
/********************************************/
int cgiMain (void)
{
	int ret = OK;
	char name[512];
	char cmd[1024];
	char *keyName=NULL;
	char *ErrMsg = NULL;
	char *fileName=NULL;
	char *backName=NULL;
	char *p = NULL;
	char *directory= NULL;
	char *confFile=NULL;
	char *title=NULL;
	struct stat buf	;
	xmlDocPtr doc;
	xmlNodePtr pNode,pRoot;
  	//
	//	��֤�û�,���һ�ȡ�û���
	//
	ret = authentication(NULL,NULL);
	cgiHeaderContent("text/html");
	if (ret)
	{
		//
		//	��֤ʧ��
		//
		goto exit;
	}
	//
	//	��ȡ�����ļ���
	//
	ErrMsg = "propertyFile";
	ret = cgiGetString(&confFile,2,255,ErrMsg);
	if(ret)
		goto exit;	
	//
	//	��ȡҪʹ�õ����Լ�¼����
	//
	ErrMsg = "keyName";
	ret = cgiGetString(&keyName,1,255,ErrMsg);
	if (ret)
		goto exit;
	ErrMsg = NULL;
	//
	//	���������ļ��л�ȡcgi����
	//
	doc = xmlParseFile(confFile);
	if (NULL == doc)
	{
		ret = NO_MESSAGE;
		ErrMsg="û�д������ļ�<p>��û�������ļ�";
		goto exit;
	}
	//
	//	��ȡ���ڵ�
	//
	pRoot = xmlDocGetRootElement(doc);
	if (NULL == pRoot)
	{
		xmlFreeDoc(doc);
		ret = NO_MESSAGE;
		ErrMsg="�յ������ļ�";
		goto exit;
	}
	pNode = pRoot->xmlChildrenNode;
	//
	//	����ʹ�õ�������
	//
	while(pNode)
	{
		if (xmlStrcmp(pNode->name,"conf")==0)
		{
			xmlChar * keyValue = NULL;
			//
			//	����ʹ�õ����Լ�¼
			//
			keyValue = xmlGetProp(pNode,"name");
			if (xmlStrcmp(keyValue,(const xmlChar*)keyName)==0)
			{
				break;
			}
			xmlFree(keyValue);
		}
		pNode = pNode->next;
	}
	if (NULL == pNode)
	{
		xmlFreeDoc(doc);
		doc=NULL;
		ret = NO_MESSAGE;
		ErrMsg="û���ҵ�ָ����������";
		goto exit;
	}
	title = xmlGetProp(pNode,"title");
	if (strcmp(keyName,"systemLog")==0)
	{
		//
		//	ϵͳ��־�����֡�
		//
		time_t cur_time;
		struct tm *myTime;
		int i;
	 	cur_time = time(NULL);
		myTime = localtime(&cur_time);
		xmlFreeDoc(doc);
		doc = NULL;
		for(i=1;i<32;i++)
		{
			sprintf(name,"%s.%d",LOG_FILE_NAME,i);
			ret =  stat(name,&buf);
			if ((ret)||(buf.st_mode & S_IFDIR))
				continue;
			break;
		}
		if (i>=32)
		{
			cgiPrintf("<HTML><HEAD><meta http-equiv=\"refresh\" content=\"290;URL=/timeout.html\"></head></HEAD>"
				"<body background=\"/icons/bg01.gif\"><br><center><H2>%s</H2><P></center>"
				"<P><P><HR width=60%><br>"
				"<table align=center><tr><td>û�м�¼��־</td></tr></TABLE><P><P><HR width=60%><center></BODY></HTML>",title);
			dispOperateInfo(NULL,NO_DISP_MSG,"û�м�¼��־");
			return 0;		
		}
		//
		// ���ɱ����ļ���
		//
		//snprintf(name,512,"../../htdocs/login/webadminLog.%d-%d-%d.tar.gz",myTime->tm_year+1900,myTime->tm_mon+1,myTime->tm_mday);
		snprintf(name,512,"../download/webadminLog.%d-%d-%d.tar.gz",myTime->tm_year+1900,myTime->tm_mon+1,myTime->tm_mday);
		snprintf(cmd,1024,"cd ./log ; tar -zcf %s sysLog.*",name);

		if (system(cmd)==-1)
			ret = EXEC_FAULT;
		else
		{
			//sprintf(name,"../htdocs/login/webadminLog.%d-%d-%d.tar.gz",myTime->tm_year+1900,myTime->tm_mon+1,myTime->tm_mday);
			sprintf(name,"./download/webadminLog.%d-%d-%d.tar.gz",myTime->tm_year+1900,myTime->tm_mon+1,myTime->tm_mday);
			ret =  stat(name,&buf);
			if (ret)
			{
				ret = BACK_FALSE;	
			}
			else
			{
				//sprintf(name,"/login/webadminLog.%d-%d-%d.tar.gz",myTime->tm_year+1900,myTime->tm_mon+1,myTime->tm_mday);
				sprintf(name,"webadminLog.%d-%d-%d.tar.gz",myTime->tm_year+1900,myTime->tm_mon+1,myTime->tm_mday);
				//sprintf(cmd,"�� <font size =\"14\" color=blue><a href=%s color=red>����</a> </font>�����Ʊ��档",name);
				sprintf(cmd,"�� <font size =\"14\" color=blue><a href=/cgi-bin/download.cgi?downloadFile=%s color=red>����</a> </font>�����Ʊ��档",name);
				cgiPrintf("<HTML><head><link href=\"/icons/all.css\" >"
					"<meta http-equiv=\"refresh\" content=\"290;URL=/timeout.html\"></head>"
					"<BODY background=\"/icons/bg01.gif\"><br><center><H2>����%s</H2><P></center>"
					"<P><HR width=60%><br><center>%s",title,cmd);
				cgiPrintf("<br><HR width=60%></body></html>");
				dispOperateInfo(NULL,NO_DISP_OK_MSG,NULL);
				return 0;
			}
		}
		goto exit;
	}	
	fileName = xmlGetProp(pNode,"fileName");
	if (fileName)
	{
		ret =  stat(fileName,&buf);
		if ((ret)||(buf.st_mode & S_IFDIR))
		{
			ret = NO_MESSAGE;
			ErrMsg="��־�ļ�������";
			goto exit;
		}
	}
	backName = xmlGetProp(pNode,"backName");
	if ((backName==NULL)||(strlen(backName)==0))
	{
		ret = NO_MESSAGE;
		ErrMsg = "û�и��������ļ���";
		goto exit;	
	}
	directory = xmlGetProp(pNode,"directory");
	xmlFree(doc);
	doc = NULL;
	//
	//	��ȡ��־���ڵ�Ŀ¼
	//
	strncpy(name,fileName,512);
	p=strrchr(name,'/');
	if (p)
	{
		*p=0;
		//
		// ���ɱ����ļ���
		//
		if (directory)
			snprintf(cmd,1023,"cd %s ; tar -zcf %s.tar.gz %s %s",name,backName,p+1,directory);
		else
			snprintf(cmd,1023,"cd %s ; tar -zcf %s.tar.gz %s",name,backName,p+1);
		
	}
	else
	{
		if (directory)
			snprintf(cmd,1023,"tar -zcf %s.tar.gz %s %s",backName,fileName,directory);
		else
			snprintf(cmd,1023,"tar -zcf %s.tar.gz %s",backName,fileName);
	}
	if (system(cmd)==-1)
		ret = EXEC_FAULT;
	else
	{
		sprintf(name,"%s.tar.gz",backName);
		ret =  stat(name,&buf);
		if (ret)
		{
			ret = BACK_FALSE;
		}
		else
		{
			p=strrchr(backName,'/');
			if (p)
				p++;
			else
				p = backName;
			//snprintf(name,512,"/%s.tar.gz",p);
			snprintf(name,512,"%s.tar.gz",p);
			//snprintf(cmd,1023,"�� <font size =\"14\" color=blue><a href=%s color=red>����</a> </font>�����Ʊ��档",name);
			snprintf(cmd,1023,"�� <font size =\"14\" color=blue><a href=/cgi-bin/download.cgi?downloadFile=%s color=red>����</a> </font>�����Ʊ��档",name);
			cgiPrintf("<HTML><head><link href=\"/icons/all.css\" >"
				"<meta http-equiv=\"refresh\" content=\"290;URL=/timeout.html\"></head>"
				"<BODY background=\"/icons/bg01.gif\"><br><center><H2>����%s</H2><P></center>"
				"<P><HR width=60%><br><center>%s",title,cmd);
			cgiPrintf("<br><HR width=60%></body></html>");			
			snprintf(cmd,1024,"%s",fileName);
			dispOperateInfo(NULL,NO_DISP_MSG,cmd);
			return 0;
		}
	}
exit:
	if (doc) 	xmlFree(doc);
	if (fileName) free(fileName);
	if (backName) free(backName);
	if (directory) free(directory);
	dispOperateInfo(NULL,ret,ErrMsg);
	return ret;
}

