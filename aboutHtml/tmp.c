char *Field[2];
Field[0]=NULL;
ret = cgiGetString(&Field[0],1,20,"userId");
if (ret)
{
	//
	//	û�и���������û�id
	//
	dispOperateInfo(NULL,ret,"�û�id����userId<P>");
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
		//	��ȡ����ֵ.
		//
		key = Record[keyIndex];
		if (key == NULL)
			return NO_KEY;
	}
	if ( c == NULL)
		c = "\t ";
	//
	//	���������,�ж��Ƿ�����ͬ������¼
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
	            		toks = mSplit(index, c , 5, &num_toks, 0);
	            		//
	            		//	�ж��Ƿ������ͬ������ֵ.
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
				fprintf(pf,"δ����");
		}
		else
		{
			if (Record[i])
				fprintf(pf,"%c%s",c[0],Record[i]);
			else
				fprintf(pf,"%cδ����",c[0]);
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
			int ret = 0 ;
			//
            //	�ֽ��ֶ�
            //
            toks = mSplit(index, c, keyIndex+2, &num_toks, 0);
            //
            //	�ж��Ƿ��Ǵ���ָ���ļ�¼.
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
		//	��ȡ����ֵ.
		//
		key = Record[keyIndex];
	}
		
	
	pf = fopen(fileName,"r");
	if (pf==NULL)
		return OPEN_FILE_READ_FALSE;
	if (c == NULL)
		c = "\t ";
	//
	//	������ʱ�ļ�
	//
	sprintf(tempFile,"%s.temp",fileName);
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
					
					line++;
					if (NULL == key)
					{
						//
						// �Լ�¼�Ž����޸�
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
            		//	�ֽ��ֶ�
            		//
            		toks = mSplit(index, c, numRecord+1, &num_toks, 0);
            		//
            		//	�ж��Ƿ���Ҫ�޸ĵļ�¼.
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
						//	������Ǹ�������
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
			unlink(fileName);		// ɾ��ԭ�ļ�:���ܳ���ͬ������.
			rename(tempFile,fileName);	// ����Ϊ���ļ�
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
	//	������ʱ�ļ�
	//
	sprintf(tempFile,"%s.temp",fileName);
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
            		lines++;
            		if (keyIndex < 0)
            		{
            			//
            			//	���кŽ���ɾ��
            			//
						for(k=0;k<numDel;k++)
						{
							if(lines == atoi(delKey[k]))
								break;
						}
						if (k>=numDel)
            			{
							//
							//	������Ǹ�������
							//
							fprintf(pTmp,"%s\n",buf);							
            			}
            		}
            		else
            		{
            			//
            			//	�ֽ��ֶ�
            			//
            			toks = mSplit(index, c, keyIndex+2, &num_toks, 0);
            			//
            			//	�ж��Ƿ���Ҫɾ���ļ�¼.
            			//
            			if (toks && (num_toks>=keyIndex))
						{
							
							//
							//	�жϸü�¼�Ƿ���Ҫɾ���ļ�¼
							//
							for(k=0;k<numDel;k++)
							{
								if(strcmp(toks[keyIndex],delKey[k])==0)
									break;
							}
							if (k>=numDel)
            				{
								//
								//	������Ǹ�������
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
		unlink(fileName);		// ɾ��ԭ�ļ�:���ܳ���ͬ������.
		rename(tempFile,fileName);	// ����Ϊ���ļ�
		return OK;
	}
	return OPEN_TEMP_FILE_FALSE ;
}

	char buf[16*2];
for (i=0; i<16; i++)
		sprintf(buf+(i*2),"%02x",md[i]);

	if (pFields[2]) free(pFields[2]);
	pFields[2]=buf;




