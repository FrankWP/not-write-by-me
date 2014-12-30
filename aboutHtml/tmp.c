char *Field[2];
Field[0]=NULL;
ret = cgiGetString(&Field[0],1,20,"userId");
if (ret)
{
	//
	//	没有给出具体的用户id
	//
	dispOperateInfo(NULL,ret,"用户id变量userId<P>");
	return OK;
}
ret = delRecord(0,Field[0],ACCESS_CONF,NULL);

ret =addRecord(-1,2,Field,ACCESS_CONF,NULL);

int addRecord(int keyIndex,int numRecord,char **Record,char *fileName,char *c)
{
	FILE *pf;
	char buf[STD_BUF];
	char *key = NULL;
	int i;
	
	if (keyIndex >= 0)
	{
		//
		//	获取主键值.
		//
		key = Record[keyIndex];
		if (key == NULL)
			return NO_KEY;
	}
	if ( c == NULL)
		c = "\t ";
	//
	//	如果有主键,判断是否有相同主键记录
	//
	if (key)
	{
		pf = fopen(fileName,"r");
		if (pf==NULL)
			return OPEN_FILE_READ_FALSE;
			
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
	            		int num_toks;
						int k;
	            		//
	            		//	分解字段
	            		//
	            		toks = mSplit(index, c , 5, &num_toks, 0);
	            		//
	            		//	判断是否存在相同的主键值.
	            		//
	            		if ((toks)&&(strcmp(toks[keyIndex],key)==0))
	            		{
		            		for(k=0;k<num_toks;k++)
		            			free(toks[k]);
		            		free(toks);
							fclose(pf);
		            		return KEY_EXIST;
	            		}
	            		if (toks)
						{
							for(k=0;k<num_toks;k++)
	            				free(toks[k]);
	            			if (toks) free(toks);
						}
	            	}
	        }
	        fclose(pf);  
 	}
 	pf = fopen(fileName,"a");
 	if (pf == NULL)
 		return OPEN_FILE_WRITE_FALSE;
 	
	fprintf(pf,"\n");
 	for (i=0;i<numRecord;i++)
 	{
		if (i==0)
		{
			if (Record[i])
				fprintf(pf,"%s",Record[i]);
			else
				fprintf(pf,"未设置");
		}
		else
		{
			if (Record[i])
				fprintf(pf,"%c%s",c[0],Record[i]);
			else
				fprintf(pf,"%c未设置",c[0]);
		}
 	}
 	fclose(pf);
	return OK;
}

int ExistRecord(int keyIndex,char *key,char *fileName,char *c)
{
	char buf[STD_BUF];
	FILE *pf;
		
	pf = fopen(fileName,"r");
	if (pf==NULL)
		return OPEN_FILE_READ_FALSE;
	if (c==NULL)
		c = "\t ";
	while((fgets(buf, STD_BUF, pf) != NULL))	
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
			int ret = 0 ;
			//
            //	分解字段
            //
            toks = mSplit(index, c, keyIndex+2, &num_toks, 0);
            //
            //	判断是否是存在指定的记录.
            //
            if (strcmp(toks[keyIndex],key)==0)
            {
				fclose(pf);
				ret = 1;
			}
			if (toks)
			{
				for (k=0;k<num_toks;k++)
					free(toks[k]);
				free(toks);
			}
			if (ret)
				return 1;
        }
	}
    fclose(pf);
	return 0 ;
}

ret = updateRecord(1,5,pFields,USER_CONF,NULL);

int updateRecord(int keyIndex,int numRecord,char **Record,char *fileName,char *c)
{
	char tempFile[STD_BUF];
	char buf[STD_BUF];
	FILE *pf,*pTmp;
	char *key = NULL;
	int  IsModify = 0;
	unsigned int line = 0;
		
	if (keyIndex >= 0)
	{
		//
		//	获取主键值.
		//
		key = Record[keyIndex];
	}
		
	
	pf = fopen(fileName,"r");
	if (pf==NULL)
		return OPEN_FILE_READ_FALSE;
	if (c == NULL)
		c = "\t ";
	//
	//	生成临时文件
	//
	sprintf(tempFile,"%s.temp",fileName);
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
					
					line++;
					if (NULL == key)
					{
						//
						// 以记录号进行修改
						//
						if (line == -keyIndex)
						{
							for(k=0;k<numRecord;k++)
	            			{
								if (k==0)
								{
									fprintf(pTmp,"%s",Record[k]);
								}
								else
								{
									fprintf(pTmp,"%c%s",c[0],Record[k]);
								}
								IsModify = 1;
	            			}
	            			fprintf(pTmp,"\n");
						}
						else
							fprintf(pTmp,"%s",buf);

						continue;
					}
            		//
            		//	分解字段
            		//
            		toks = mSplit(index, c, numRecord+1, &num_toks, 0);
            		//
            		//	判断是否是要修改的记录.
            		//
            		if (( toks ) && (strcmp(toks[keyIndex],key)==0))
            		{
						for(k=0;k<num_toks;k++)
            			{
							if (k==0)
							{
								if (Record[k])
									fprintf(pTmp,"%s",Record[k]);
								else
									fprintf(pTmp,"%s",toks[k]);
							}
							else
							{
								if (Record[k])
									fprintf(pTmp,"%c%s",c[0],Record[k]);
								else
									fprintf(pTmp,"%c%s",c[0],toks[k]);
							}
							IsModify = 1;
            			}
            			fprintf(pTmp,"\n");
            		}
            		else
            		{
						//
						//	如果不是复制数据
						//
						fprintf(pTmp,"%s\n",buf);
            		}
            		for(k=0;k<num_toks;k++)
            			free(toks[k]);
            		if (toks) free(toks);
            	}
            	else
            	{
            		fprintf(pTmp,buf);
            	}
        }
        fclose(pf);
	if (pTmp)
	{
		fclose(pTmp);
		if (IsModify)
		{
			unlink(fileName);		// 删除原文件:可能出现同步问题.
			rename(tempFile,fileName);	// 改名为新文件
			return OK;
		}
		else
		{
			unlink(tempFile);
			return NO_FIND_RECORD;
		}
	}
	return OPEN_TEMP_FILE_FALSE ;
}

int delMultiRecord(int keyIndex,int numDel,char **delKey,char *fileName,char *c)
{
	char tempFile[STD_BUF];
	char buf[STD_BUF];
	int lines = 0;
	FILE *pf,*pTmp;
		
	pf = fopen(fileName,"r");
	if (pf==NULL)
		return OPEN_FILE_READ_FALSE;
	if (c ==NULL)
		c = "\t ";
	//
	//	生成临时文件
	//
	sprintf(tempFile,"%s.temp",fileName);
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
            		lines++;
            		if (keyIndex < 0)
            		{
            			//
            			//	按行号进行删除
            			//
						for(k=0;k<numDel;k++)
						{
							if(lines == atoi(delKey[k]))
								break;
						}
						if (k>=numDel)
            			{
							//
							//	如果不是复制数据
							//
							fprintf(pTmp,"%s\n",buf);							
            			}
            		}
            		else
            		{
            			//
            			//	分解字段
            			//
            			toks = mSplit(index, c, keyIndex+2, &num_toks, 0);
            			//
            			//	判断是否是要删除的记录.
            			//
            			if (toks && (num_toks>=keyIndex))
						{
							
							//
							//	判断该记录是否是要删除的记录
							//
							for(k=0;k<numDel;k++)
							{
								if(strcmp(toks[keyIndex],delKey[k])==0)
									break;
							}
							if (k>=numDel)
            				{
								//
								//	如果不是复制数据
								//
								fprintf(pTmp,"%s\n",buf);
    	        			}
	            			for(k=0;k<num_toks;k++)
            					free(toks[k]);
            				if (toks) free(toks);
						}
					}
            	}
            	else
            	{
            		fprintf(pTmp,buf);
            	}
        }
        fclose(pf);
	if (pTmp)
	{
		fclose(pTmp);
		unlink(fileName);		// 删除原文件:可能出现同步问题.
		rename(tempFile,fileName);	// 改名为新文件
		return OK;
	}
	return OPEN_TEMP_FILE_FALSE ;
}

	char buf[16*2];
for (i=0; i<16; i++)
		sprintf(buf+(i*2),"%02x",md[i]);

	if (pFields[2]) free(pFields[2]);
	pFields[2]=buf;




