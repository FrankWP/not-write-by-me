#include <string.h>
#include <stdio.h>
#include <stdlib.h>
//#include <openssl/x509.h>
#include "webadmin.h"
#include "md5.h"

/*******************************************
/	����û�,���û���Ϣд���û��ļ���
/*******************************************/
int addUser(USER_INFO *userInfo,char *pass)
{
	int i;
	FILE *pf ;
	MD5_CTX c;
	unsigned char md[16];
	char password[16*2];
	//
	//	�ж��Ƿ������ͬ���û���
	//
	if (haveUser(userInfo))
		return USER_EXIST;
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
		sprintf(password+(i*2),"%02x",md[i]);
	//
	//	���û���Ϣд���ļ�
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
/	ɾ���û�.���û��ļ���ɾ������û�
/***********************************************************************/
int delUser(int numDel,char **delKey)
{
	FILE *pf ;
	FILE *pTmp;
	//
	//	���û��ļ�
	//
	pf = fopen(USER_FILE,"r");
	if (pf)
	{
		char tempFile[STD_BUF];
		char buf[STD_BUF];
		//
		//	������ʱ�ļ���
		//
		sprintf(tempFile,"%s.temp",USER_FILE);
		pTmp = fopen(tempFile,"w");
		while((pTmp)&&(fgets(buf, STD_BUF, pf) != NULL))	
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
					int k;
            		//
            		//	�ֽ��ֶ�
            		//
            		toks = mSplit(index, " \t", 5, &num_toks, 0);
            		if ((num_toks == 4)||(num_toks == 3))
            		{
            			int k=0;
						
						//
						//	�ж��Ƿ���ɾ�����û�
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
			            	//	�����û���Ϣд����ʱ�ļ�
			            	//
			            	fputs(buf,pTmp);
							fwrite("\n",1,1,pTmp);
            			}
            		}
    				//
    				//	�ͷ�mSplit������ڴ�
    				//
    				for(k=0;k<num_toks;k++)
    					free(toks[k]);
    				free(toks);
	            }
	            else
	            {
	            	//
	            	//	��ע����д���ļ�
	            	//
	            	fputs(buf,pTmp);
	            }
		}
		fclose(pf);
		if (pTmp)
		{
			fclose(pTmp);
			unlink(USER_FILE);		// ɾ��ԭ�ļ�:���ܳ���ͬ������.
			rename(tempFile,USER_FILE);	// ����Ϊ���ļ�
			//
			//	ɾ�����ʿ����ļ��еı�ɾ�����û�ʹ�õ���Դ��
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
/	�����û�����.
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
	//	�ж��Ƿ������ͬ���û���
	//
	if (haveUser(userInfo) == 0)
		return USER_NO_EXIST;
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
		sprintf(password+(i*2),"%02x",md[i]);
	//
	//	���û��ļ�
	//
	pf = fopen(USER_FILE,"r");
	if (pf)
	{
		char tempFile[STD_BUF];
		char buf[STD_BUF];
		//
		//	������ʱ�ļ���
		//
		sprintf(tempFile,"%s.temp",USER_FILE);
		pTmp = fopen(tempFile,"w");
		while((pTmp)&&(fgets(buf, STD_BUF, pf) != NULL))	
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
            			int k;
						char **toks;
            			int num_toks;
            			//
            			//	�ֽ��ֶ�
            			//
            			toks = mSplit(index, " \t", 5, &num_toks, 0);
            			if ((num_toks == 4)||(num_toks == 3))
            			{
            				if ((unsigned int)atoi(toks[0])!=userInfo->id)
            				{
			            		//
			            		//	�����û���Ϣд����ʱ�ļ�
			            		//
			            		fwrite(buf,strlen(buf),1,pTmp);
            				}
            				else
            				{
								char buf[20];
								//
								//	д���µ�����
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
    					//	�ͷ�mSplit������ڴ�
    					//
    					for(k=0;k<num_toks;k++)
    						free(toks[k]);
    					free(toks);
	            	}
	            	else
	            	{
	            		//
	            		//	��ע����д���ļ�
	            		//
	            		fwrite(buf,strlen(buf),1,pTmp);
	            	}
		}
		fclose(pf);
		if (pTmp)
		{
			fclose(pTmp);
			unlink(USER_FILE);		// ɾ��ԭ�ļ�:���ܳ���ͬ������.
			rename(tempFile,USER_FILE);	// ����Ϊ���ļ�
			return OK;
		}
		else
			return OPEN_TEMP_FILE_FALSE ;
	}
	else
		return OPEN_USER_FILE_FALSE ;
}
/*******************************************
/	���û���Ϣ�б��Թ��û�ѡ��
/*******************************************/
void listUser(char *operate)
{
	char buf[STD_BUF];
	FILE *pf;
	int oper;
	int line = 0;
	//
	//	���û������ļ�
	//
	pf = fopen(USER_FILE,"r");
	if (pf)
	{
		if (strcmp(operate,"ɾ��")==0)
		{
			printf("<FORM name=\"request\" action=\"/cgi-bin/delUser.cgi\" method=POST\">"
				"<BR><P><P><TABLE width=\"60%\" border=\"1\" bordercolorlight=\"#808080\" bordercolordark=\"#FFFFFF\" cellpadding=\"0\" cellspacing=\"0\" id=\"AutoNumber1\" height=\"1\" align=center >");
			//
			//	�������
			//
			printf("<tr><th height=\"24\" bgcolor=\"#E1E1E1\"><span style=\"font-weight: 400\">�û���</span></th><th height=\"24\" bgcolor=\"#E1E1E1\"><span style=\"font-weight: 400\">�ʼ���ַ</span></th><th height=\"24\" bgcolor=\"#E1E1E1\"><span style=\"font-weight: 400\">ɾ��</span></th></tr>");
			oper = 1;
		}

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
		printf("</table><P><P><center><input type=submit value=\"ȷ��ɾ��\">");
	}
}

