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
/	加锁
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
				//	发生错误.
				//
				return ;
		}
	}
}
/*********************************************
/	解锁
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
/	记录运行日志,自动在尾部添加换行符
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
  		//	加锁
  		//
		lock();
		pf = fopen(name,"a");
  	}
  	if (pf == NULL)
  		return ;
  	//
  	//	显示日志时间
  	// 
  	fprintf(pf,"%d.%d.%d-%d:%d:%d\t",myTime->tm_year+1900,myTime->tm_mon+1,myTime->tm_mday,
  		myTime->tm_hour,myTime->tm_min,myTime->tm_sec);
  	va_start(argp, fmt);
  	vfprintf(pf, fmt, argp);
  	va_end(argp);
  	//
  	//	记录表单输入的内容.
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
	//	解锁
	//
	unlock();
}
/*****************************************************
/	获取用户可用资源
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
		    // 去掉空白符
		    //
		    while(*index == ' ' || *index == '\t')
            	index++;
            //
            //	注释行，空行去掉。以字符“#”和“;”开始的行为注释行。
            //
            if((*index != '#') && (*index != 0x0a) && (*index != ';') && (index != NULL))
            {
            	char **toks;
            	int num_toks;
            	//
            	//	分解字段
            	//
            	toks = mSplit(index, " \t", 6, &num_toks, 0);
            	if ((num_toks >2 )&&(strcmp(toks[1],user)==0))
            	{
					ret = OK;
            		if (userInfo)
            		{
	            		//
	            		//	保存用户id
	            		//
	            		userInfo->id = (unsigned int)atoi(toks[0]);
	            		//
	            		//	保存用户名
	            		//
	            		if (userInfo->name)
	            			free(userInfo->name);
	            		userInfo->name = toks[1];
	            		//
	            		//	保存email地址
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
						//	获取用户可用资源
						//
						getResource(userInfo);            			
	            		//
	            		//	释放口令摘要和id字段占用的内存。
	            		//
	            		free(toks[2]);
	            		free(toks[0]);
						free(toks);
						fclose(pf);
						return ret;
	            	}
        			//
        			//	释放mSplit分配的内存
        			//
        			for(k=0;k<num_toks;k++)
						free(toks[k]);
        			free(toks);
					return ret;
            	}
        		//
        		//	释放mSplit分配的内存
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
/	判断用户是否能够访问指定的资源
/**************************************************************/
int IsAccessRight(unsigned int userId,unsigned int menuId)
{
	FILE *pf ;
	char buf[STD_BUF];
	int ret = NO_ACCESS_RIGHT;

	//
	//	如果菜单号大于1000 认为任何人均可使用。
	//
	if (menuId > 1000)
		return OK;

	pf = fopen(ACCESS_FILE,"r");	// 打开访问控制文件。
	if (pf)
	{
		while((ret != OK) && (fgets(buf, STD_BUF, pf) != NULL))
		{
		    char * index = buf;
		    //
		    // 去掉空白符
		    //
		    while(*index == ' ' || *index == '\t')
            	index++;
            //
            //	注释行，空行去掉。以字符“#”和“;”开始的行为注释行。
            //
            if((*index != '#') && (*index != 0x0a) && (*index != ';') && (index != NULL))
            {
            	char **toks;
            	unsigned int id;
            	int num_toks;
		       	int k;
				
				id = (unsigned int )atoi(index);	// 获取用户id字段数值
				if (id == userId)
				{
	            	//
	            	//	分解字段
	            	//
	            	toks = mSplit(index, " \t", 3, &num_toks, 0);
	            	if (num_toks == 2)
	            	{
						if ((unsigned int)atoi(toks[1])==menuId)
							ret = OK;
					}
        			//
        			//	释放mSplit分配的内存
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
/	获取用户使用的资源。
/	访问控制文件结构：
/					用户id		资源id
/**************************************************************/
void getResource(USER_INFO* userInfo)
{
	FILE *pf ;
	char buf[STD_BUF];
	unsigned int Maxnum = 20;

	if (userInfo == NULL)
		return ;
	//
	//	给用户资源数组分配内存
	//
	if (userInfo->resource)
		free(userInfo->resource);
	
	userInfo->resource = (unsigned int *)malloc(Maxnum*(sizeof(unsigned int)));
	if (userInfo->resource == NULL)
		return ;
	userInfo->resourceNum = 0 ;
	memset(userInfo->resource,0,Maxnum*(sizeof(unsigned int)));
	pf = fopen(ACCESS_FILE,"r");	// 打开访问控制文件。

	if (pf)
	{
		while((fgets(buf, STD_BUF, pf)) != NULL)
		{
		    char * index = buf;
		    //
		    // 去掉空白符
		    //
		    while(*index == ' ' || *index == '\t')
            	index++;
            //
            //	注释行，空行去掉。以字符“#”和“;”开始的行为注释行。
            //
            if((*index != '#') && (*index != 0x0a) && (*index != ';') && (index != NULL))
            {
            	char **toks;
            	unsigned int id;
            	int num_toks;
		       	int k;
				
				id = (unsigned int )atoi(index);	// 获取用户id字段数值
				if (id == userInfo->id)
				{
	            	//
	            	//	分解字段
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
						//	保存资源id
						//
						userInfo->resource[userInfo->resourceNum++] = (unsigned int ) atoi (toks[1]);
						
	            	}
        			//
        			//	释放mSplit分配的内存
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
/	判断用户是否存在,如果不存在，并且userInfo->id=0，则将该值
/	自动设置一个没有使用的id号。
/**************************************************************/
int haveUser(USER_INFO *userInfo)
{
	char buf[STD_BUF];
	int ret = FALSE ;
	FILE *pf;
	int userId = 1;

	if ((NULL == userInfo)||(userInfo->name == NULL)) return INVALID_USER;

	//
	//	打开用户数据文件
	//
	pf = fopen(USER_FILE,"r");
	if (pf)
	{
		while(fgets(buf, STD_BUF, pf) != NULL)
		{
		    char *index = buf;
		    //
		    // 去掉空白符
		    //
		    while(*index == ' ' || *index == '\t')
				index++;
            //
            //	注释行，空行去掉。以字符“#”和“;”开始的行为注释行。
            //
            if((*index != '#') && (*index != 0x0a) && (*index != ';') && (index != NULL))
            {
            	char **toks;
            	int num_toks,i;
            	//
            	//	分解字段
            	//
            	toks = mSplit(index, " \t", 6, &num_toks, 0);
            	if (num_toks > 2)
				{
					int id ;

					id = atoi(toks[0]);
					//
					//	计算最大的用户id号.
					//
					if (userId < id)
						userId = id;
					//
					//	判断用户是否存在
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
/	认证给定的用户是否是系统合法的用户，返回用户信息。
/	用户信息文件结构：
/		用户id	用户名	口令摘要	email地址
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
		    // 去掉空白符
		    //
		    while(*index == ' ' || *index == '\t')
            	index++;
            //
            //	注释行，空行去掉。以字符“#”和“;”开始的行为注释行。
            //
            if((*index != '#') && (*index != 0x0a) && (*index != ';') && (index != NULL))
            {
            	char **toks;
            	int num_toks;
            	//
            	//	分解字段
            	//
            	toks = mSplit(index, " \t", 6, &num_toks, 0);
            	if ((num_toks >2 )&&(strcmp(toks[1],user)==0))
            	{
					int i;
            		MD5_CTX c;
            		unsigned char md[16];
					char buf[16*2];
            		//
            		//	计算口令的摘要
            		//
            		MD5_Init(&c);
            		MD5_Update(&c,pass,strlen(pass));
            		MD5_Final(md,&c);
            		memset(&c,0,sizeof(c));
            		//
            		//	将摘要转换为十六进制字符
            		//
					for (i=0; i<16; i++)
						sprintf(buf+(i*2),"%02x",md[i]);
					//
					//	判断口令是否正确。
					//
            		if (strcmp(toks[2],(const char*)buf)==0) 
            		{
	            		ret = OK;
            			if (userInfo)
            			{
	            			//
	            			//	保存用户id
	            			//
	            			userInfo->id = (unsigned int)atoi(toks[0]);
	            			//
	            			//	保存用户名
	            			//
	            			if (userInfo->name)
	            				free(userInfo->name);
	            			userInfo->name = toks[1];
	            			//
	            			//	保存email地址
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
							//	获取用户可用资源
							//
							getResource(userInfo);            			
	            			//
	            			//	释放口令摘要和id字段占用的内存。
	            			//
	            			free(toks[2]);
	            			free(toks[0]);
							free(toks);
							fclose(pf);
							goto exit;
	            		}
        				//
        				//	释放mSplit分配的内存
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
        				//	释放mSplit分配的内存
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
    			//	释放mSplit分配的内存
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
		sprintf(USER_NAME,"未知用户");
	//log(LOGIN_LOG_FILE_NAME,NULL,"%s\t%s\t%s",user,progName,getResaultMsg(ret,NULL));
	log(LOGIN_LOG_FILE_NAME,NULL,"%s\t%s\t%s\t%s",clientIP,user,progName,getResaultMsg(ret,NULL));
	return ret;
}
/*******************************************************
/	根据证书判断用户是否合法
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
		    // 去掉空白符
		    //
		    while(*index == ' ' || *index == '\t')
            	index++;
            //
            //	注释行，空行去掉。以字符“#”和“;”开始的行为注释行。
            //
            if((*index != '#') && (*index != 0x0a) && (*index != ';') && (index != NULL))
            {
            	char **toks;
            	int num_toks;
            	//
            	//	分解字段
            	//
            	toks = mSplit(index, " \t", 6, &num_toks, 0);
           		if ((num_toks >2 )&&(strcmp(toks[1],userName)==0))
            	{
					int i;
            		ret = OK;
          			if (userInfo)
           			{
            			//
            			//	保存用户id
            			//
            			userInfo->id = (unsigned int)atoi(toks[0]);
            			//
            			//	保存用户名
            			//
            			if (userInfo->name)
            				free(userInfo->name);
            			userInfo->name = toks[1];
            			//
            			//	保存email地址
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
						//	获取用户可用资源
						//
						getResource(userInfo);            			
            			//
            			//	释放口令摘要和id字段占用的内存。
            			//
            			free(toks[2]);
            			free(toks[0]);
						free(toks);
						fclose(pf);
						goto exit;
            		}
       				//
       				//	释放mSplit分配的内存
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
       				//	释放mSplit分配的内存
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
		sprintf(USER_NAME,"未知用户");
	log(LOGIN_LOG_FILE_NAME,NULL,"%s\t%s\t%s",USER_NAME,progName,getResaultMsg(ret,NULL));
	return ret;
}
/************************************************
/	判断菜单有无子菜单
/************************************************/
int haveSubMenu(MENU_INFO *pMenu,unsigned int id)
{
	//
	//	通过查找每个菜单的父id是否等于指定的菜单id
	//	来判断.
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
/	获取用户可用的菜单
/	菜单文件结构：
/		菜单id	父id	菜单项	菜单图标文件名	脚本文件名
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
	//	判断输入的数据是否有效。
	//
	if (userInfo==NULL)
		return menu;
	//
	//	打开菜单配置文件
	//
	pf = fopen(MENU_CONF,"r");
	if (pf)
	{
		while((fgets(buf, STD_BUF, pf)) != NULL)	
		{
		    char *index = buf;
		    //
		    // 去掉空白符
		    //
		    while(*index == ' ' || *index == '\t')
            	index++;
            //
            //	注释行，空行去掉。以字符“#”和“;”开始的行为注释行。
            //
            if((*index != '#') && (*index != 0x0a) && (*index != ';') && (index != NULL))
            {
            	char **toks;
            	int num_toks;
            	//
            	//	分解字段
            	//
            	toks = mSplit(index, "\t ", 6, &num_toks, 0);

            	if (num_toks == 5)
            	{
					unsigned int menu_id;
					unsigned int father;
					int menu_ok = 0 ;		// 记录该菜单是否允许访问
					int father_ok 	;		// 记录父菜单是否允许访问
					unsigned int i;
					
					//
					//	获取菜单id 和 父id
					//
					menu_id = (unsigned int ) atoi(toks[0]);
					father	= (unsigned int ) atoi(toks[1]);
					father_ok = (father>0)? 0:1;
					//
					//	查找该资源是否允许访问。
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
					//	只有本菜单和父菜单同时访问时，才能使用。
					//	或菜单id号大于 999 的全部可以使用.
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
							//	构造菜单链
							//
							pMenu->next = (MENU_INFO *) malloc(sizeof(MENU_INFO));
							//
							//	指向新创建的菜单项地址
							//
							pMenu = pMenu->next;
						}
						if (pMenu)
						{
							memset(pMenu,0,sizeof(MENU_INFO));
							pMenu->id		= menu_id ;	
							pMenu->father	= father ;
							pMenu->item		= toks[2];			// 保存菜单项
							pMenu->icon		= toks[3];			// 保存图标文件名
							pMenu->script	= toks[4];			// 脚本文件名
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
    			//	释放mSplit分配的内存
    			//
            	for(k=0 ; k<num_toks ; k++)
            		free(toks[k]);
            	free(toks);
            	//
            	//	判断是否发生内存分配失败现象。
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
	//	判断所有节点的父节点全部在队列中。
	//
	pMenu = menu ;
	while(pMenu)
	{
		if (pMenu->father)		// 只判断非顶层菜单项。
		{
			MENU_INFO *pFather;
			//
			//	在队列中查找父节点。
			//
			pFather = menu;
			while(pFather)
			{

				if (pFather->id == pMenu->father)
					break;
				//
				//	没有找到，继续下一个节点。
				//
				pFather = pFather->next;	
			}
			if (pFather == NULL )
			{
				//
				//	删除没有访问父节点菜单的节点。
				//
				if (pMenu = menu)
				{
					//
					//	从队列中摘除要删除的节点。
					//
					menu = menu->next ;
					//
					//	释放要删除节点占用的资源。
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
					//	从队列中摘除要删除的节点。
					//
					lastMenu->next = pMenu->next ;
					//
					//	释放要删除节点占用的资源。
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
	//	设资菜单的项的类型
	//
	pMenu = menu;
	while(pMenu)
	{
		//
		//	判断有没有子菜单
		//
		if (haveSubMenu(menu,pMenu->id))
		{
			//
			//	有子菜单
			//
			if (pMenu->father > 0)	// 非顶层菜单
				pMenu->type = MENU_SUB_FOLDER;
			else				// 顶层菜单
				pMenu->type = MENU_TOP_FOLDER;
		}
		else
		{
			//
			//	无子菜单
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
/	获取所有的菜单项信息
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
	//	打开菜单配置文件
	//
	pf = fopen(MENU_CONF,"r");
	if (pf)
	{
		while((fgets(buf, STD_BUF, pf)) != NULL)	
		{
		    char *index = buf;
		    //
		    // 去掉空白符
		    //
		    while(*index == ' ' || *index == '\t')
            	index++;
            //
            //	注释行，空行去掉。以字符“#”和“;”开始的行为注释行。
            //
            if((*index != '#') && (*index != 0x0a) && (*index != ';') && (index != NULL))
            {
            	char **toks;
            	int num_toks;
            	//
            	//	分解字段
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
							//	构造菜单链
							//
							pMenu->next = (MENU_INFO *) malloc(sizeof(MENU_INFO));
							//
							//	指向新创建的菜单项地址
							//
							pMenu = pMenu->next;
						}
						if (pMenu)
						{
							memset(pMenu,0,sizeof(MENU_INFO));
							pMenu->id		= atoi(toks[0]) ;	
							pMenu->father	= atoi(toks[1]) ;
							pMenu->item		= toks[2];			// 保存菜单项
							pMenu->icon		= toks[3];			// 保存图标文件名
							pMenu->script	= toks[4];			// 脚本文件名
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
    			//	释放mSplit分配的内存
    			//
            	for(k=0 ; k<num_toks ; k++)
            		free(toks[k]);
            	free(toks);
            	//
            	//	判断是否发生内存分配失败现象。
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
	//	设资菜单的项的类型
	//
	pMenu = menu;
	while(pMenu)
	{
		//
		//	判断有没有子菜单
		//
		if (haveSubMenu(menu,pMenu->id))
		{
			//
			//	有子菜单
			//
			if (pMenu->father > 0)	// 非顶层菜单
				pMenu->type = MENU_SUB_FOLDER;
			else				// 顶层菜单
				pMenu->type = MENU_TOP_FOLDER;
		}
		else
		{
			//
			//	无子菜单
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
/	设置父菜单的子项可显示
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
/	设置菜单项可显示
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
/	根据一个节点生成一个HTML菜单指令。
/	sessin = 会话id
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
		//	具体生成的代码。
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
				//	如果没有 <BLINK> 生成的菜单在点击菜单时,将其他展开的菜单关闭.
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
			//	输出p
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
			// 错误处理。
			//
			sprintf(p,"内存分配失败");
			//logErr("generateHTMLmenu","内存分配失败");
		}
		if (userName) free(userName);
		if (password) free(password);
	}
}

/**********************************************************************
/	生成 HTML 菜单内容。这是一个递回函数。
/	father = 生成父为该值的子菜单。
/	sessid  = 会话id
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
			// 输出HTML菜单指令
			//
			generateMenuItem(pMenu,sessid,userName);
			//
			//	判断该菜单的子项, 递归调用。
			//
			generateMenu(menu,pMenu->id,sessid,userName);
			if ((pMenu->type == MENU_TOP_FOLDER) || (pMenu->type == MENU_SUB_FOLDER))
			{
				char buf[]="</DIV>\n";
				//
				//	输出字菜单项的结束tag
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
