#include <malloc.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h> 
#include <memory.h>
#include <stdio.h> 
#include <sys/stat.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <openssl/md5.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include "webadmin.h"
#include "cgi.h"
#ifdef _cpluspus
extern "c" {
#endif
/***************************************************************
/	����
/***************************************************************/
static int lock_fd = -1;
void lock(void)
{
	static struct flock lock_it;
	int rc;
	if (strlen(LOCK_NAME))
		lock_fd = open(LOCK_NAME,O_CREAT|O_WRONLY , S_IWUSR|S_IRUSR);
	else
		return ;
		
	if (lock_fd)
	{
		lock_it.l_type = F_WRLCK;
		lock_it.l_whence = SEEK_SET;
		lock_it.l_start = 0;
		lock_it.l_len = 0;
		while((rc == fcntl(lock_fd,F_SETLKW,&lock_it)) < 0 )
		{
			if (errno == EINTR)
				continue;
			else
				//
				//	��������.
				//
				return ;
		}
	}
}
/*********************************************
/	����
/*********************************************/
void unlock(void)
{
	static struct flock unlock_it;
	if (lock_fd)
	{
		unlock_it.l_type = F_UNLCK;
		unlock_it.l_whence = SEEK_SET;
		unlock_it.l_start = 0;
		unlock_it.l_len = 0;
		fcntl(lock_fd,F_SETLKW,&unlock_it);
		close(lock_fd);
	}
}

typedef struct {
  char *var;
  char *val;
} pair_t;

typedef struct {
  int     size;
  pair_t *pair;
} form_t;

char userName[40];
#define SEM_WEBADMIN_LOG_NAME "/webadmin/sysLog"
/**************************************************************
/	��¼������־,�Զ���β����ӻ��з�
/**************************************************************/
void log(char *filename,form_t *form,char *fmt,...)
{
  	FILE *pf = NULL;
  	va_list argp;
	time_t cur_time;
	struct tm *myTime;
  	
  	cur_time = time(NULL);
  	myTime = localtime(&cur_time);
 	if (filename)
  	{
  		char name[512];
  		sprintf(name,"%s.%d",filename,myTime->tm_mday);
  		//
  		//	����
  		//
		lock();
		pf = fopen(name,"a");
  	}
  	if (pf == NULL)
  		return ;
  	//
  	//	��ʾ��־ʱ��
  	// 
  	fprintf(pf,"%d.%d.%d-%d:%d:%d\t",myTime->tm_year+1900,myTime->tm_mon+1,myTime->tm_mday,
  		myTime->tm_hour,myTime->tm_min,myTime->tm_sec);
  	va_start(argp, fmt);
  	vfprintf(pf, fmt, argp);
  	va_end(argp);
  	//
  	//	��¼�����������.
  	//
  	if (form && form->size)
  	{
  		int cnt;
  		for(cnt=0; cnt<form->size; cnt++)
  		{
  			char *var;
  			char *val;
  			int r=0;
  			int l=0;
  			int lenVar = (strlen(form->pair[cnt].var)*4)/3+8;
  			int lenVal = (strlen(form->pair[cnt].val)*4)/3+8;
  			
  			var = (char*)malloc(lenVar);
  			if (var)
  			{ 
  				memset(var,0,lenVar);
  				if (Base64Encode(form->pair[cnt].var,strlen(form->pair[cnt].var),var)<0)
  				{
  					free(var);
  					var = form->pair[cnt].var;
  				}
  				else
  				{
  					r =1;
  				}
  			}
  			else
  				var = form->pair[cnt].var;
  				
  			val = (char*)malloc(lenVal);
  			
  			if (val)
  			{
  				memset(val,0,lenVal);
  				if (Base64Encode(form->pair[cnt].val,strlen(form->pair[cnt].val),val)<0)
  				{
  					free(val);
  					var = form->pair[cnt].val;
  				}
  				else
  					l = 1;
  			}
  			else
  				var = form->pair[cnt].val;
  				
  			if (cnt)
  				fprintf(pf,"&%s*%s",var,val);
  			else
  				fprintf(pf,"\t%s*%s",var,val);
  			
  			if (r)
  				free(var);
  			if (l)
  				free(val);
  		}
  	}
  	fflush(pf);
  	fprintf(pf,"\n");
  	if (pf != stdout)
  		fclose(pf);
	//
	//	����
	//
	unlock();
}
/*****************************************************
/	��ȡ�û�������Դ
/*****************************************************/
int getUserResorce(char *user,USER_INFO *userInfo)
{
	FILE *pf ;
	char buf[STD_BUF];
	int k;
	int ret =ERR_PASSWORD ;
	
	if (NULL == user) return INVALID_USER;
	pf = fopen(USER_FILE,"r");
	if (pf)
	{
		while((fgets(buf, STD_BUF, pf)) != NULL)	
		{
		    char *index = buf;
		    //
		    // ȥ���հ׷�
		    //
		    while(*index == ' ' || *index == '\t')
            	index++;
            //
            //	ע���У�����ȥ�������ַ���#���͡�;����ʼ����Ϊע���С�
            //
            if((*index != '#') && (*index != 0x0a) && (*index != ';') && (index != NULL))
            {
            	char **toks;
            	int num_toks;
            	//
            	//	�ֽ��ֶ�
            	//
            	toks = mSplit(index, " \t", 6, &num_toks, 0);
            	if ((num_toks >2 )&&(strcmp(toks[1],user)==0))
            	{
					ret = OK;
            		if (userInfo)
            		{
	            		//
	            		//	�����û�id
	            		//
	            		userInfo->id = (unsigned int)atoi(toks[0]);
	            		//
	            		//	�����û���
	            		//
	            		if (userInfo->name)
	            			free(userInfo->name);
	            		userInfo->name = toks[1];
	            		//
	            		//	����email��ַ
	            		if (userInfo->email)
	            			free(userInfo->email);
	            		
	            		if (num_toks > 3)
	            			userInfo->email = toks[3];
	            		else
	            			userInfo->email = NULL;
	            			
	            		if (userInfo->resource)
	            			free(userInfo->resource);

	            		userInfo->resource = NULL;
	            		userInfo->resourceNum = 0;
						//
						//	��ȡ�û�������Դ
						//
						getResource(userInfo);            			
	            		//
	            		//	�ͷſ���ժҪ��id�ֶ�ռ�õ��ڴ档
	            		//
	            		free(toks[2]);
	            		free(toks[0]);
						free(toks);
						fclose(pf);
						return ret;
	            	}
        			//
        			//	�ͷ�mSplit������ڴ�
        			//
        			for(k=0;k<num_toks;k++)
						free(toks[k]);
        			free(toks);
					return ret;
            	}
        		//
        		//	�ͷ�mSplit������ڴ�
        		//
        		for(k=0;k<num_toks;k++)
					free(toks[k]);
        		free(toks);
            }
		}
		fclose(pf);
		return INVALID_USER;
	}
	return OPEN_USER_FILE_FALSE;
}
/**************************************************************
/	�ж��û��Ƿ��ܹ�����ָ������Դ
/**************************************************************/
int IsAccessRight(unsigned int userId,unsigned int menuId)
{
	FILE *pf ;
	char buf[STD_BUF];
	int ret = NO_ACCESS_RIGHT;

	//
	//	����˵��Ŵ���1000 ��Ϊ�κ��˾���ʹ�á�
	//
	if (menuId > 1000)
		return OK;

	pf = fopen(ACCESS_FILE,"r");	// �򿪷��ʿ����ļ���
	if (pf)
	{
		while((ret != OK) && (fgets(buf, STD_BUF, pf) != NULL))
		{
		    char * index = buf;
		    //
		    // ȥ���հ׷�
		    //
		    while(*index == ' ' || *index == '\t')
            	index++;
            //
            //	ע���У�����ȥ�������ַ���#���͡�;����ʼ����Ϊע���С�
            //
            if((*index != '#') && (*index != 0x0a) && (*index != ';') && (index != NULL))
            {
            	char **toks;
            	unsigned int id;
            	int num_toks;
		       	int k;
				
				id = (unsigned int )atoi(index);	// ��ȡ�û�id�ֶ���ֵ
				if (id == userId)
				{
	            	//
	            	//	�ֽ��ֶ�
	            	//
	            	toks = mSplit(index, " \t", 3, &num_toks, 0);
	            	if (num_toks == 2)
	            	{
						if ((unsigned int)atoi(toks[1])==menuId)
							ret = OK;
					}
        			//
        			//	�ͷ�mSplit������ڴ�
        			//
        			for(k=0;k<num_toks;k++)
        				free(toks[k]);
        			free(toks);
            	}
            }
		}
		fclose(pf);
	}
	return ret;
}
/**************************************************************
/	��ȡ�û�ʹ�õ���Դ��
/	���ʿ����ļ��ṹ��
/					�û�id		��Դid
/**************************************************************/
void getResource(USER_INFO* userInfo)
{
	FILE *pf ;
	char buf[STD_BUF];
	unsigned int Maxnum = 20;

	if (userInfo == NULL)
		return ;
	//
	//	���û���Դ��������ڴ�
	//
	if (userInfo->resource)
		free(userInfo->resource);
	
	userInfo->resource = (unsigned int *)malloc(Maxnum*(sizeof(unsigned int)));
	if (userInfo->resource == NULL)
		return ;
	userInfo->resourceNum = 0 ;
	memset(userInfo->resource,0,Maxnum*(sizeof(unsigned int)));
	pf = fopen(ACCESS_FILE,"r");	// �򿪷��ʿ����ļ���

	if (pf)
	{
		while((fgets(buf, STD_BUF, pf)) != NULL)
		{
		    char * index = buf;
		    //
		    // ȥ���հ׷�
		    //
		    while(*index == ' ' || *index == '\t')
            	index++;
            //
            //	ע���У�����ȥ�������ַ���#���͡�;����ʼ����Ϊע���С�
            //
            if((*index != '#') && (*index != 0x0a) && (*index != ';') && (index != NULL))
            {
            	char **toks;
            	unsigned int id;
            	int num_toks;
		       	int k;
				
				id = (unsigned int )atoi(index);	// ��ȡ�û�id�ֶ���ֵ
				if (id == userInfo->id)
				{
	            	//
	            	//	�ֽ��ֶ�
	            	//
	            	toks = mSplit(index, " \t", 3, &num_toks, 0);
	            	if (num_toks == 2)
	            	{
						if (userInfo->resourceNum == Maxnum)
						{
							unsigned int *p;
							p = (unsigned int *) realloc(userInfo->resource,(Maxnum+10)*sizeof(unsigned int*));
							if (p==NULL)
							{
								for(k=0;k<num_toks;k++)
			        				free(toks[k]);
			        			free(toks);
								break;
							}
							Maxnum += 10 ;
							userInfo->resource = p ;								
						}
						//
						//	������Դid
						//
						userInfo->resource[userInfo->resourceNum++] = (unsigned int ) atoi (toks[1]);
						
	            	}
        			//
        			//	�ͷ�mSplit������ڴ�
        			//
        			for(k=0;k<num_toks;k++)
        				free(toks[k]);
        			free(toks);
            	}
            }
		}
		fclose(pf);
	}
	if (userInfo->resourceNum == 0)
	{
		free(userInfo->resource);
		userInfo->resource = NULL;
	}
}
/**************************************************************
/	�ж��û��Ƿ����,��������ڣ�����userInfo->id=0���򽫸�ֵ
/	�Զ�����һ��û��ʹ�õ�id�š�
/**************************************************************/
int haveUser(USER_INFO *userInfo)
{
	char buf[STD_BUF];
	int ret = FALSE ;
	FILE *pf;
	int userId = 1;

	if ((NULL == userInfo)||(userInfo->name == NULL)) return INVALID_USER;

	//
	//	���û������ļ�
	//
	pf = fopen(USER_FILE,"r");
	if (pf)
	{
		while(fgets(buf, STD_BUF, pf) != NULL)
		{
		    char *index = buf;
		    //
		    // ȥ���հ׷�
		    //
		    while(*index == ' ' || *index == '\t')
				index++;
            //
            //	ע���У�����ȥ�������ַ���#���͡�;����ʼ����Ϊע���С�
            //
            if((*index != '#') && (*index != 0x0a) && (*index != ';') && (index != NULL))
            {
            	char **toks;
            	int num_toks,i;
            	//
            	//	�ֽ��ֶ�
            	//
            	toks = mSplit(index, " \t", 6, &num_toks, 0);
            	if (num_toks > 2)
				{
					int id ;

					id = atoi(toks[0]);
					//
					//	���������û�id��.
					//
					if (userId < id)
						userId = id;
					//
					//	�ж��û��Ƿ����
					//
					if (strcmp(toks[1],userInfo->name) == 0 )
					{
						userInfo->id = id ;
						ret = TRUE;
					}
				}
				for (i=0;i<num_toks;i++)
					free(toks[i]);
				free(toks);
			}
		}
		fclose(pf);
	}
	if ((ret == FALSE)&&(userInfo->id==0))
		userInfo->id = userId+1 ;
	return ret;
}
/**************************************************************
/	��֤�������û��Ƿ���ϵͳ�Ϸ����û��������û���Ϣ��
/	�û���Ϣ�ļ��ṹ��
/		�û�id	�û���	����ժҪ	email��ַ
/**************************************************************/
extern form_t form;
int IsValidUser(char *user , char *pass, USER_INFO* userInfo)
{
	FILE *pf ;
	char buf[STD_BUF];
	int k;
	int ret = ERR_PASSWORD;
	char *clientIP = cgiEnv.remoteAddr;
		
	if (NULL == user)
	{
	 	ret = INVALID_USER;
	 	goto exit;
	}
	pf = fopen(USER_FILE,"r");
	if (pf)
	{
		while((fgets(buf, STD_BUF, pf)) != NULL)	
		{
		    char *index = buf;
		    //
		    // ȥ���հ׷�
		    //
		    while(*index == ' ' || *index == '\t')
            	index++;
            //
            //	ע���У�����ȥ�������ַ���#���͡�;����ʼ����Ϊע���С�
            //
            if((*index != '#') && (*index != 0x0a) && (*index != ';') && (index != NULL))
            {
            	char **toks;
            	int num_toks;
            	//
            	//	�ֽ��ֶ�
            	//
            	toks = mSplit(index, " \t", 6, &num_toks, 0);
            	if ((num_toks >2 )&&(strcmp(toks[1],user)==0))
            	{
					int i;
            		MD5_CTX c;
            		unsigned char md[16];
					char buf[16*2];
            		//
            		//	��������ժҪ
            		//
            		MD5_Init(&c);
            		MD5_Update(&c,pass,strlen(pass));
            		MD5_Final(md,&c);
            		memset(&c,0,sizeof(c));
            		//
            		//	��ժҪת��Ϊʮ�������ַ�
            		//
					for (i=0; i<16; i++)
						sprintf(buf+(i*2),"%02x",md[i]);
					//
					//	�жϿ����Ƿ���ȷ��
					//
            		if (strcmp(toks[2],(const char*)buf)==0) 
            		{
	            		ret = OK;
            			if (userInfo)
            			{
	            			//
	            			//	�����û�id
	            			//
	            			userInfo->id = (unsigned int)atoi(toks[0]);
	            			//
	            			//	�����û���
	            			//
	            			if (userInfo->name)
	            				free(userInfo->name);
	            			userInfo->name = toks[1];
	            			//
	            			//	����email��ַ
	            			if (userInfo->email)
	            				free(userInfo->email);
	            			
	            			if (num_toks == 4)
	            				userInfo->email = toks[3];
	            			else
	            				userInfo->email = NULL;
	            				
	            			if (userInfo->resource)
	            				free(userInfo->resource);

	            			userInfo->resource = NULL;
	            			userInfo->resourceNum = 0;
							//
							//	��ȡ�û�������Դ
							//
							getResource(userInfo);            			
	            			//
	            			//	�ͷſ���ժҪ��id�ֶ�ռ�õ��ڴ档
	            			//
	            			free(toks[2]);
	            			free(toks[0]);
							free(toks);
							fclose(pf);
							goto exit;
	            		}
        				//
        				//	�ͷ�mSplit������ڴ�
        				//
        				for(k=0;k<num_toks;k++)
							free(toks[k]);
        				free(toks);
						fclose(pf);
						goto exit;
            		}
            		else
            		{
        				//
        				//	�ͷ�mSplit������ڴ�
        				//
        				for(k=0;k<num_toks;k++)
							free(toks[k]);
        				free(toks);
						fclose(pf);        			
            			ret = ERR_PASSWORD;
            			goto exit;
            		}
            	}
    			//
    			//	�ͷ�mSplit������ڴ�
    			//
    			for(k=0;k<num_toks;k++)
    				free(toks[k]);
    			free(toks);
            }
		}
		fclose(pf);
		ret = INVALID_USER;
	}
	ret = OPEN_USER_FILE_FALSE;
exit:
	strncpy(USER_NAME,user,40);	
	if (strlen(USER_NAME)==0)
		sprintf(USER_NAME,"δ֪�û�");
	//log(LOGIN_LOG_FILE_NAME,NULL,"%s\t%s\t%s",user,progName,getResaultMsg(ret,NULL));
	log(LOGIN_LOG_FILE_NAME,NULL,"%s\t%s\t%s\t%s",clientIP,user,progName,getResaultMsg(ret,NULL));
	return ret;
}
/*******************************************************
/	����֤���ж��û��Ƿ�Ϸ�
/*******************************************************/
int IsValidUserByCert(char *cert, USER_INFO* userInfo)
{
	FILE *pf ;
	char buf[STD_BUF];
	char userName[100];
	int k;
	char *pUser;
	int ret = ERR_PASSWORD;
	X509 * x509;
	BIO *bio = BIO_new(BIO_s_mem());
	memset(userName,0,sizeof(userName));
	if (bio==NULL)
	{
		ret = MALLOC_FALSE;
		goto exit;	
	}
	BIO_write(bio,cert,strlen(cert));
	x509=(X509 *)PEM_read_bio_X509(bio,NULL,NULL,NULL);
	BIO_free(bio);
	if (x509==NULL)
	{
		ret = INVALID_USER;
		goto exit;
	}

	X509_NAME_oneline(X509_get_subject_name(x509),buf,STD_BUF);	
	X509_free(x509);

	pUser = (char*)strstr(buf,"/CN=");
	if (pUser)
	{
		char *p;
		pUser += 4;
		p = (char *)strchr(pUser,'/');
		if (p)
			*p = 0;
		strncpy(userName,pUser,100);
	}
	else
		userName[0] = 0 ;
		
	if (strlen(userName)==0)
	{
	 	ret = INVALID_USER;
	 	goto exit;
	}
	pf = fopen(USER_FILE,"r");
	if (pf)
	{
		while((fgets(buf, STD_BUF, pf)) != NULL)	
		{
		    char *index = buf;
		    //
		    // ȥ���հ׷�
		    //
		    while(*index == ' ' || *index == '\t')
            	index++;
            //
            //	ע���У�����ȥ�������ַ���#���͡�;����ʼ����Ϊע���С�
            //
            if((*index != '#') && (*index != 0x0a) && (*index != ';') && (index != NULL))
            {
            	char **toks;
            	int num_toks;
            	//
            	//	�ֽ��ֶ�
            	//
            	toks = mSplit(index, " \t", 6, &num_toks, 0);
           		if ((num_toks >2 )&&(strcmp(toks[1],userName)==0))
            	{
					int i;
            		ret = OK;
          			if (userInfo)
           			{
            			//
            			//	�����û�id
            			//
            			userInfo->id = (unsigned int)atoi(toks[0]);
            			//
            			//	�����û���
            			//
            			if (userInfo->name)
            				free(userInfo->name);
            			userInfo->name = toks[1];
            			//
            			//	����email��ַ
            			if (userInfo->email)
            				free(userInfo->email);
            			
            			if (num_toks == 4)
            				userInfo->email = toks[3];
            			else
            				userInfo->email = NULL;
	            				
            			if (userInfo->resource)
            				free(userInfo->resource);

            			userInfo->resource = NULL;
            			userInfo->resourceNum = 0;
						//
						//	��ȡ�û�������Դ
						//
						getResource(userInfo);            			
            			//
            			//	�ͷſ���ժҪ��id�ֶ�ռ�õ��ڴ档
            			//
            			free(toks[2]);
            			free(toks[0]);
						free(toks);
						fclose(pf);
						goto exit;
            		}
       				//
       				//	�ͷ�mSplit������ڴ�
       				//
       				for(k=0;k<num_toks;k++)
						free(toks[k]);
       				free(toks);
					fclose(pf);
					goto exit;
           		}
           		else
           		{
       				//
       				//	�ͷ�mSplit������ڴ�
       				//
       				for(k=0;k<num_toks;k++)
						free(toks[k]);
       				free(toks);
           		}
           	}
        }
		fclose(pf);
		ret = INVALID_USER;
		goto exit;
	}
	ret = OPEN_USER_FILE_FALSE;
exit:
	strncpy(USER_NAME,userName,40);	
	if (strlen(USER_NAME)==0)
		sprintf(USER_NAME,"δ֪�û�");
	log(LOGIN_LOG_FILE_NAME,NULL,"%s\t%s\t%s",USER_NAME,progName,getResaultMsg(ret,NULL));
	return ret;
}
/************************************************
/	�жϲ˵������Ӳ˵�
/************************************************/
int haveSubMenu(MENU_INFO *pMenu,unsigned int id)
{
	//
	//	ͨ������ÿ���˵��ĸ�id�Ƿ����ָ���Ĳ˵�id
	//	���ж�.
	//
	while(pMenu)
	{
		if (pMenu->father == id)
			return TRUE;
		pMenu = pMenu->next;
	}
	return FALSE;
}
/*************************************************************
/	��ȡ�û����õĲ˵�
/	�˵��ļ��ṹ��
/		�˵�id	��id	�˵���	�˵�ͼ���ļ���	�ű��ļ���
/*************************************************************/
MENU_INFO* getMenu(USER_INFO *userInfo)
{
	FILE *pf ;
	char buf[STD_BUF];
	MENU_INFO *menu = NULL;
	MENU_INFO *pMenu = NULL;
	MENU_INFO *lastMenu = NULL;
	int error = 0;
	int k;

	//
	//	�ж�����������Ƿ���Ч��
	//
	if (userInfo==NULL)
		return menu;
	//
	//	�򿪲˵������ļ�
	//
	pf = fopen(MENU_CONF,"r");
	if (pf)
	{
		while((fgets(buf, STD_BUF, pf)) != NULL)	
		{
		    char *index = buf;
		    //
		    // ȥ���հ׷�
		    //
		    while(*index == ' ' || *index == '\t')
            	index++;
            //
            //	ע���У�����ȥ�������ַ���#���͡�;����ʼ����Ϊע���С�
            //
            if((*index != '#') && (*index != 0x0a) && (*index != ';') && (index != NULL))
            {
            	char **toks;
            	int num_toks;
            	//
            	//	�ֽ��ֶ�
            	//
            	toks = mSplit(index, "\t ", 6, &num_toks, 0);

            	if (num_toks == 5)
            	{
					unsigned int menu_id;
					unsigned int father;
					int menu_ok = 0 ;		// ��¼�ò˵��Ƿ��������
					int father_ok 	;		// ��¼���˵��Ƿ��������
					unsigned int i;
					
					//
					//	��ȡ�˵�id �� ��id
					//
					menu_id = (unsigned int ) atoi(toks[0]);
					father	= (unsigned int ) atoi(toks[1]);
					father_ok = (father>0)? 0:1;
					//
					//	���Ҹ���Դ�Ƿ�������ʡ�
					//
					if (menu_id < 10000)
					{
						for(i=0 ; i< userInfo->resourceNum;i++)
						{
							if (menu_id == userInfo->resource[i])
								menu_ok = 1 ;
							else if (father == userInfo->resource[i])
								father_ok = 1;
						}
					}
					//
					//	ֻ�б��˵��͸��˵�ͬʱ����ʱ������ʹ�á�
					//	��˵�id�Ŵ��� 999 ��ȫ������ʹ��.
					//
					if ((menu_id>9999)||(father_ok && menu_ok))
					{
						if (pMenu == NULL)
						{
							menu = (MENU_INFO *) malloc(sizeof(MENU_INFO));
							pMenu = menu ;
						}
						else
						{
							//
							//	����˵���
							//
							pMenu->next = (MENU_INFO *) malloc(sizeof(MENU_INFO));
							//
							//	ָ���´����Ĳ˵����ַ
							//
							pMenu = pMenu->next;
						}
						if (pMenu)
						{
							memset(pMenu,0,sizeof(MENU_INFO));
							pMenu->id		= menu_id ;	
							pMenu->father	= father ;
							pMenu->item		= toks[2];			// ����˵���
							pMenu->icon		= toks[3];			// ����ͼ���ļ���
							pMenu->script	= toks[4];			// �ű��ļ���
							free(toks[0]);
							free(toks[1]);
							free(toks);
							continue;
						}
						else
							error = 1;
					}
            	}
    			//
    			//	�ͷ�mSplit������ڴ�
    			//
            	for(k=0 ; k<num_toks ; k++)
            		free(toks[k]);
            	free(toks);
            	//
            	//	�ж��Ƿ����ڴ����ʧ������
            	//
            	if (error)
            	{
            		fclose(pf);
            		return menu;	
            	}
            }
        }
        fclose(pf);
	}
	//
	//	�ж����нڵ�ĸ��ڵ�ȫ���ڶ����С�
	//
	pMenu = menu ;
	while(pMenu)
	{
		if (pMenu->father)		// ֻ�жϷǶ���˵��
		{
			MENU_INFO *pFather;
			//
			//	�ڶ����в��Ҹ��ڵ㡣
			//
			pFather = menu;
			while(pFather)
			{

				if (pFather->id == pMenu->father)
					break;
				//
				//	û���ҵ���������һ���ڵ㡣
				//
				pFather = pFather->next;	
			}
			if (pFather == NULL )
			{
				//
				//	ɾ��û�з��ʸ��ڵ�˵��Ľڵ㡣
				//
				if (pMenu = menu)
				{
					//
					//	�Ӷ�����ժ��Ҫɾ���Ľڵ㡣
					//
					menu = menu->next ;
					//
					//	�ͷ�Ҫɾ���ڵ�ռ�õ���Դ��
					//
					free(pMenu->item);
					free(pMenu->icon);
					free(pMenu->script);
					free(pMenu);
					pMenu = menu;
					continue;
				}
				else
				{
					//
					//	�Ӷ�����ժ��Ҫɾ���Ľڵ㡣
					//
					lastMenu->next = pMenu->next ;
					//
					//	�ͷ�Ҫɾ���ڵ�ռ�õ���Դ��
					//
					free(pMenu->item);
					free(pMenu->icon);
					free(pMenu->script);
					free(pMenu);
					pMenu = lastMenu->next;
					continue;
				}
			}
		}
		lastMenu = pMenu ;
		pMenu = pMenu->next ;
	}
/*	{
		pMenu = menu;
		while(pMenu)
		{
			printf("id = %d  father = %d <p>",pMenu->id,pMenu->father);
			pMenu = pMenu->next;	
		}
		return 0;
	}
*/	
	//
	//	���ʲ˵����������
	//
	pMenu = menu;
	while(pMenu)
	{
		//
		//	�ж���û���Ӳ˵�
		//
		if (haveSubMenu(menu,pMenu->id))
		{
			//
			//	���Ӳ˵�
			//
			if (pMenu->father > 0)	// �Ƕ���˵�
				pMenu->type = MENU_SUB_FOLDER;
			else				// ����˵�
				pMenu->type = MENU_TOP_FOLDER;
		}
		else
		{
			//
			//	���Ӳ˵�
			//
			if (pMenu->father > 0)
				pMenu->type = MENU_SUB_ITEM;
			else
				pMenu->type = MENU_TOP_ITEM;
		}
		pMenu = pMenu->next ;
	}
	return menu;
}
/******************************************************
/	��ȡ���еĲ˵�����Ϣ
/******************************************************/
MENU_INFO* getAllMenu(void)
{
	FILE *pf ;
	char buf[STD_BUF];
	MENU_INFO *menu = NULL;
	MENU_INFO *pMenu = NULL;
	MENU_INFO *lastMenu = NULL;
	int error = 0;
	int k;

	//
	//	�򿪲˵������ļ�
	//
	pf = fopen(MENU_CONF,"r");
	if (pf)
	{
		while((fgets(buf, STD_BUF, pf)) != NULL)	
		{
		    char *index = buf;
		    //
		    // ȥ���հ׷�
		    //
		    while(*index == ' ' || *index == '\t')
            	index++;
            //
            //	ע���У�����ȥ�������ַ���#���͡�;����ʼ����Ϊע���С�
            //
            if((*index != '#') && (*index != 0x0a) && (*index != ';') && (index != NULL))
            {
            	char **toks;
            	int num_toks;
            	//
            	//	�ֽ��ֶ�
            	//
            	toks = mSplit(index, " \t", 6, &num_toks, 0);
            	if (num_toks == 5)
            	{
					if (1)
					{
						if (pMenu == NULL)
						{
							menu = (MENU_INFO *) malloc(sizeof(MENU_INFO));
							pMenu = menu ;
						}
						else
						{
							//
							//	����˵���
							//
							pMenu->next = (MENU_INFO *) malloc(sizeof(MENU_INFO));
							//
							//	ָ���´����Ĳ˵����ַ
							//
							pMenu = pMenu->next;
						}
						if (pMenu)
						{
							memset(pMenu,0,sizeof(MENU_INFO));
							pMenu->id		= atoi(toks[0]) ;	
							pMenu->father	= atoi(toks[1]) ;
							pMenu->item		= toks[2];			// ����˵���
							pMenu->icon		= toks[3];			// ����ͼ���ļ���
							pMenu->script	= toks[4];			// �ű��ļ���
							free(toks[0]);
							free(toks[1]);
							free(toks);
							continue;
						}
						else
							error = 1;
					}
            	}
    			//
    			//	�ͷ�mSplit������ڴ�
    			//
            	for(k=0 ; k<num_toks ; k++)
            		free(toks[k]);
            	free(toks);
            	//
            	//	�ж��Ƿ����ڴ����ʧ������
            	//
            	if (error)
            	{
            		fclose(pf);
            		return menu;	
            	}
            }
        }
        fclose(pf);
	}
	//
	//	���ʲ˵����������
	//
	pMenu = menu;
	while(pMenu)
	{
		//
		//	�ж���û���Ӳ˵�
		//
		if (haveSubMenu(menu,pMenu->id))
		{
			//
			//	���Ӳ˵�
			//
			if (pMenu->father > 0)	// �Ƕ���˵�
				pMenu->type = MENU_SUB_FOLDER;
			else				// ����˵�
				pMenu->type = MENU_TOP_FOLDER;
		}
		else
		{
			//
			//	���Ӳ˵�
			//
			if (pMenu->father > 0)
				pMenu->type = MENU_SUB_ITEM;
			else
				pMenu->type = MENU_TOP_ITEM;
		}
		pMenu = pMenu->next ;
	}
	return menu;
}

/*****************************************************************************
/	���ø��˵����������ʾ
/*****************************************************************************
void setItemEnableByfather(MENU_INFO *menu,unsigned int father, int isEnable)
{
	MENU_INFO *pMenu;
	pMenu = menu ;
	while(pMenu)
	{
		if (pMenu->father == father)
			pMenu->enable = isEnable;
		pMenu = pMenu->next;	
	}
}
/**********************************************************************
/	���ò˵������ʾ
/**********************************************************************
void setItemEnable(MENU_INFO *menu,unsigned int id, int isEnable)
{
	MENU_INFO *pMenu;
	pMenu = menu ;
	while(pMenu)
	{
		if (pMenu->id == id)
			pMenu->enable = isEnable;
		pMenu = pMenu->next;	
	}
}

/***************************************************************************
/	����һ���ڵ�����һ��HTML�˵�ָ�
/	sessin = �Ựid
/***************************************************************************/
static void generateMenuItem(MENU_INFO *menuItem, int sessid,char *userName)
{
	if (menuItem)
	{
		int len ;
		char *p;
		char *userName ;
		char *password ;
		userName = cgiFormGetVal("userName");
		password = cgiFormGetVal("userPassword");

		//
		//	�������ɵĴ��롣
		//
		len = strlen(menuItem->item)+strlen(MENU_CGI)+strlen(PLUS_FILE)+512;
		p = (char*) malloc(len);
		if (p)
		{
			int i=0;
			memset(p,0,len);
			if (menuItem->type == MENU_TOP_FOLDER)
			{
				if (strncmp(menuItem->script,"/cgi-bin/",9)==0)
					sprintf(p,"<DIV class=topFolder id=s%d target=\"main\" href=\"%s?userName=%s&sessid=%d&menuid=%d\">"
						"<IMG class=icon height=16 src=\"/icons/folder.gif\" width=16>%s</DIV>",
						menuItem->id,menuItem->script,userName,sessid,menuItem->id,menuItem->item);
				else if (strstr(menuItem->script,".php"))
					sprintf(p,"<DIV class=topFolder id=s%d target=\"main\" href=\"%s\">"
						"<IMG class=icon height=16 src=\"/icons/folder.gif\" width=16>%s</DIV>",
						menuItem->id,menuItem->script,menuItem->item);
				else
					sprintf(p,"<DIV class=topFolder id=s%d target=\"main\" href=\"/cgi-bin/authMenu.cgi?script=%s&userName=%s&sessid=%d&menuid=%d\">"
						"<IMG class=icon height=16 src=\"/icons/folder.gif\" width=16>%s</DIV>",
						menuItem->id,menuItem->script,userName,sessid,menuItem->id,menuItem->item);
					
				sprintf(p,"%s\n<DIV class=sub id=s%dSub>\n",p,menuItem->id);
			}
			else if (menuItem->type == MENU_SUB_FOLDER)
			{
				if (strncmp(menuItem->script,"/cgi-bin/",9)==0)
					sprintf(p,"<DIV class=subFolder id=s%d target=\"main\" href=\"%s?userName=%s&sessid=%d&menuid=%d\">"
						"<IMG class=icon height=16 src=\"/icons/folder.gif\" width=16>%s</DIV>",
						menuItem->id,menuItem->script,userName,sessid,menuItem->id,menuItem->item);
				else if (strstr(menuItem->script,".php"))
					sprintf(p,"<DIV class=subFolder id=s%d target=\"main\" href=\"%s\">"
						"<IMG class=icon height=16 src=\"/icons/folder.gif\" width=16>%s</DIV>",
						menuItem->id,menuItem->script,menuItem->item);
				else
					sprintf(p,"<DIV class=subFolder id=s%d target=\"main\" href=\"/cgi-bin/authMenu.cgi?script=%s&userName=%s&sessid=%d&menuid=%d\">"
						"<IMG class=icon height=16 src=\"/icons/folder.gif\" width=16>%s</DIV>",
						menuItem->id,menuItem->script,userName,sessid,menuItem->id,menuItem->item);

				sprintf(p,"%s\n<DIV class=sub id=s%dSub >\n",p,menuItem->id);
			} 
			else if (menuItem->type == MENU_TOP_ITEM)
			{
				if (strncmp(menuItem->script,"/cgi-bin/",9)==0)
					sprintf(p,"<DIV class=topItem target=\"main\" href=\"%s?userName=%s&sessid=%d&menuid=%d\">"
						"<IMG class=icon height=16 src=\"/icons/hand.right.gif\" width=16>%s</DIV>\n",
						menuItem->script,userName,sessid,menuItem->id,menuItem->item);
				else if (strstr(menuItem->script,".php"))
					sprintf(p,"<DIV class=topItem target=\"main\" href=\"%s\">"
						"<IMG class=icon height=16 src=\"/icons/hand.right.gif\" width=16>%s</DIV>\n",
						menuItem->script,menuItem->item);
				else
					sprintf(p,"<DIV class=topItem target=\"main\" href=\"/cgi-bin/authMenu.cgi?script=%s&userName=%s&sessid=%d&menuid=%d\">"
						"<IMG class=icon height=16 src=\"/icons/hand.right.gif\" width=16>%s</DIV>\n",
						menuItem->script,userName,sessid,menuItem->id,menuItem->item);
			}
			else  //	MENU_SUB_ITEM
			{
				//
				//	���û�� <BLINK> ���ɵĲ˵��ڵ���˵�ʱ,������չ���Ĳ˵��ر�.
				//
				if (strncmp(menuItem->script,"/cgi-bin/",9)==0)
					sprintf(p,"<DIV class=subItem target=\"main\" href=\"%s?userName=%s&sessid=%d&menuid=%d\">"
						"<IMG class=icon height=16 src=\"/icons/hand.right.gif\" width=16><BLINK>%s</DIV>\n",
						menuItem->script,userName,sessid,menuItem->id,menuItem->item);
				else if (strstr(menuItem->script,".php"))
					sprintf(p,"<DIV class=subItem target=\"main\" href=\"%s\">"
						"<IMG class=icon height=16 src=\"/icons/hand.right.gif\" width=16><BLINK>%s</DIV>\n",
						menuItem->script,menuItem->item);
				else
					sprintf(p,"<DIV class=subItem target=\"main\" href=\"/cgi-bin/authMenu.cgi?script=%s&userName=%s&sessid=%d&menuid=%d\">"
						"<IMG class=icon height=16 src=\"/icons/hand.right.gif\" width=16><BLINK>%s</DIV>\n",
						menuItem->script,userName,sessid,menuItem->id,menuItem->item);
				
			}

			//
			//	���p
			//
			cgiPrintf(p);
			/*
			{
				FILE *fp = fopen("wtt.html","a");
				if (fp)
				{
					fwrite(p,strlen(p),1,fp);
					fclose(fp);
				}
			}*/
			free(p);
		}
		else
		{
			//
			// ������
			//
			sprintf(p,"�ڴ����ʧ��");
			//logErr("generateHTMLmenu","�ڴ����ʧ��");
		}
		if (userName) free(userName);
		if (password) free(password);
	}
}

/**********************************************************************
/	���� HTML �˵����ݡ�����һ���ݻغ�����
/	father = ���ɸ�Ϊ��ֵ���Ӳ˵���
/	sessid  = �Ựid
/**********************************************************************/
void generateMenu(MENU_INFO *menu,unsigned int father, int sessid,char* userName)
{
	MENU_INFO *pMenu;
	if (menu == NULL)
		return ;
	pMenu = menu ;
	while(pMenu)
	{
		if (pMenu->father == father)
		{
			//
			// ���HTML�˵�ָ��
			//
			generateMenuItem(pMenu,sessid,userName);
			//
			//	�жϸò˵�������, �ݹ���á�
			//
			generateMenu(menu,pMenu->id,sessid,userName);
			if ((pMenu->type == MENU_TOP_FOLDER) || (pMenu->type == MENU_SUB_FOLDER))
			{
				char buf[]="</DIV>\n";
				//
				//	����ֲ˵���Ľ���tag
				//
				cgiPrintf(buf);
				/*
				FILE *fp = fopen("wtt.html","a");
				if (fp)
				{
					fwrite(buf,sizeof(buf)-1,1,fp);
					fclose(fp);
				}
				*/
			}
		}
		pMenu = pMenu->next ;	
	}
}

#ifdef _cpluspus
}
#endif
