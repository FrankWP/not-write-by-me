#include <string.h>
#include <stdio.h>
#include <stdlib.h>
//#include <openssl/x509.h>
#include "webadmin.h"
#include "md5.h"

/*******************************************
/	添加用户,将用户信息写入用户文件中
/*******************************************/
int addUser(USER_INFO *userInfo,char *pass)
{
	int i;
	FILE *pf ;
	MD5_CTX c;
	unsigned char md[16];
	char password[16*2];
	//
	//	判断是否存在相同的用户名
	//
	if (haveUser(userInfo))
		return USER_EXIST;
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
		sprintf(password+(i*2),"%02x",md[i]);
	//
	//	将用户信息写入文件
	//
	pf = fopen(USER_FILE,"a");
	if (pf)
	{
		char buf[20];
		sprintf(buf,"\n%d\t",userInfo->id);
		fwrite(buf,strlen(buf),1,pf);
		fwrite(userInfo->name,strlen(userInfo->name),1,pf);
		fwrite("\t",1,1,pf);
		fwrite(password,sizeof(password),1,pf);
		fwrite("\t",1,1,pf);
		fwrite(userInfo->email,strlen(userInfo->email),1,pf);
		fclose(pf);
		return OK;
	}
	return OPEN_USER_FILE_FALSE;
}
/***********************************************************************
/	删除用户.从用户文件中删除多个用户
/***********************************************************************/
int delUser(int numDel,char **delKey)
{
	FILE *pf ;
	FILE *pTmp;
	//
	//	打开用户文件
	//
	pf = fopen(USER_FILE,"r");
	if (pf)
	{
		char tempFile[STD_BUF];
		char buf[STD_BUF];
		//
		//	生成临时文件名
		//
		sprintf(tempFile,"%s.temp",USER_FILE);
		pTmp = fopen(tempFile,"w");
		while((pTmp)&&(fgets(buf, STD_BUF, pf) != NULL))	
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
					int k;
            		//
            		//	分解字段
            		//
            		toks = mSplit(index, " \t", 5, &num_toks, 0);
            		if ((num_toks == 4)||(num_toks == 3))
            		{
            			int k=0;
						
						//
						//	判断是否是删除的用户
						//
						for(k=0;k<numDel;k++)
						{
							if (strcmp(delKey[k],toks[1])==0)
							{
								if (strlen(delKey[k])>strlen(toks[0]))
									strcpy(delKey[k],toks[0]);
								else
								{
									char *p;
									p=(char*)malloc(strlen(toks[0])+1);
									if (p)
									{
										free(delKey[k]);
										delKey[k]=p;
										strcpy(delKey[k],toks[0]);
									}
								}
								break;
							}
						}
						if (k>=numDel)
						{
			            	//
			            	//	其他用户信息写入临时文件
			            	//
			            	fputs(buf,pTmp);
							fwrite("\n",1,1,pTmp);
            			}
            		}
    				//
    				//	释放mSplit分配的内存
    				//
    				for(k=0;k<num_toks;k++)
    					free(toks[k]);
    				free(toks);
	            }
	            else
	            {
	            	//
	            	//	将注释行写入文件
	            	//
	            	fputs(buf,pTmp);
	            }
		}
		fclose(pf);
		if (pTmp)
		{
			fclose(pTmp);
			unlink(USER_FILE);		// 删除原文件:可能出现同步问题.
			rename(tempFile,USER_FILE);	// 改名为新文件
			//
			//	删除访问控制文件中的被删除的用户使用的资源。
			//
			return delMultiRecord(0,numDel,delKey,ACCESS_FILE,NULL);
		}
		else
			return OPEN_TEMP_FILE_FALSE ;
	}
	else
		return OPEN_USER_FILE_FALSE ;
}

/***********************************************************************
/	更新用户数据.
/***********************************************************************/
int updateUser(USER_INFO *userInfo, char *pass)
{
	int i;
	FILE *pf ;
	FILE *pTmp;
	MD5_CTX c;
	unsigned char md[16];
	char password[16*2];
	//
	//	判断是否存在相同的用户名
	//
	if (haveUser(userInfo) == 0)
		return USER_NO_EXIST;
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
		sprintf(password+(i*2),"%02x",md[i]);
	//
	//	打开用户文件
	//
	pf = fopen(USER_FILE,"r");
	if (pf)
	{
		char tempFile[STD_BUF];
		char buf[STD_BUF];
		//
		//	生成临时文件名
		//
		sprintf(tempFile,"%s.temp",USER_FILE);
		pTmp = fopen(tempFile,"w");
		while((pTmp)&&(fgets(buf, STD_BUF, pf) != NULL))	
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
            			int k;
						char **toks;
            			int num_toks;
            			//
            			//	分解字段
            			//
            			toks = mSplit(index, " \t", 5, &num_toks, 0);
            			if ((num_toks == 4)||(num_toks == 3))
            			{
            				if ((unsigned int)atoi(toks[0])!=userInfo->id)
            				{
			            		//
			            		//	其他用户信息写入临时文件
			            		//
			            		fwrite(buf,strlen(buf),1,pTmp);
            				}
            				else
            				{
								char buf[20];
								//
								//	写入新的数据
								//
								sprintf(buf,"\n%d\t",userInfo->id);
								fwrite(buf,strlen(buf),1,pTmp);
								fwrite(userInfo->name,strlen(userInfo->name),1,pTmp);
								fwrite("\t",1,1,pTmp);
								fwrite(password,sizeof(password),1,pTmp);
								fwrite("\t",1,1,pTmp);
								fwrite(userInfo->email,strlen(userInfo->email),1,pTmp);
            				}
            			}
    					//
    					//	释放mSplit分配的内存
    					//
    					for(k=0;k<num_toks;k++)
    						free(toks[k]);
    					free(toks);
	            	}
	            	else
	            	{
	            		//
	            		//	将注释行写入文件
	            		//
	            		fwrite(buf,strlen(buf),1,pTmp);
	            	}
		}
		fclose(pf);
		if (pTmp)
		{
			fclose(pTmp);
			unlink(USER_FILE);		// 删除原文件:可能出现同步问题.
			rename(tempFile,USER_FILE);	// 改名为新文件
			return OK;
		}
		else
			return OPEN_TEMP_FILE_FALSE ;
	}
	else
		return OPEN_USER_FILE_FALSE ;
}
/*******************************************
/	将用户信息列表以供用户选择
/*******************************************/
void listUser(char *operate)
{
	char buf[STD_BUF];
	FILE *pf;
	int oper;
	int line = 0;
	//
	//	打开用户数据文件
	//
	pf = fopen(USER_FILE,"r");
	if (pf)
	{
		if (strcmp(operate,"删除")==0)
		{
			printf("<FORM name=\"request\" action=\"/cgi-bin/delUser.cgi\" method=POST\">"
				"<BR><P><P><TABLE width=\"60%\" border=\"1\" bordercolorlight=\"#808080\" bordercolordark=\"#FFFFFF\" cellpadding=\"0\" cellspacing=\"0\" id=\"AutoNumber1\" height=\"1\" align=center >");
			//
			//	输出表栏
			//
			printf("<tr><th height=\"24\" bgcolor=\"#E1E1E1\"><span style=\"font-weight: 400\">用户名</span></th><th height=\"24\" bgcolor=\"#E1E1E1\"><span style=\"font-weight: 400\">邮件地址</span></th><th height=\"24\" bgcolor=\"#E1E1E1\"><span style=\"font-weight: 400\">删除</span></th></tr>");
			oper = 1;
		}

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
            	toks = mSplit(index, " \t", 5, &num_toks, 0);
            	if ((num_toks == 4)||(num_toks == 3))
				{
					if (oper == 1)
					{
						//printf("<tr bgColor=#ffffff onmouseout=\"this.style.backgroundColor='#FFFFff'\" onmouseover=\"this.style.backgroundColor='#D7F1FB'\">");
						printf("<tr bgColor=#ffffff onmouseout=\"this.style.backgroundColor='#FFFFff'\" "
							"onmouseover=\"this.style.backgroundColor='#D7F1FB'\">"
							"<th align=\"left\" height=\"24\" ><span style=\"font-weight: 400\">");
						DisplayEncodeHttp(toks[1]);
						printf("</span></th><th  align=\"left\" height=\"24\" ><span style=\"font-weight: 400\">");
						DisplayEncodeHttp(toks[3]);
						printf("</span></th><th height=\"24\" ><span style=\"font-weight: 400\">"
							"<input type=\"checkbox\" name=\"record%d\"></span></th></tr>",line);
							
								//printf("<td height=\"24\" ><span style=\"font-weight: 400\">%s</span></td>",toks[order[i]]);	
					}
					printf("<input type=\"hidden\" name=delKey%d value=\"",line++);
					DisplayEncodeHttp(toks[1]);
					printf("\">\n");
				}
				for (i=0;i<num_toks;i++)
					free(toks[i]);
				free(toks);
			}
		}
		fclose(pf);
		printf("<input type=hidden name=numDel value=%d>",line);
		printf("</table><P><P><center><input type=submit value=\"确认删除\">");
	}
}

