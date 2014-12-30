#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <setjmp.h>
#include <errno.h>
#include <stdlib.h>

int* multi(int*num1,int size1,int* num2,int size2)
{
	int size=size1+size2;
	int* ret=(int*)malloc(size*sizeof(int));
	int i=0;

	memset(ret,0,sizeof(int)*size);

	for(i=0;i<size2;++i)
	{
		int k=i;
		for(int j=0;j<size1;++j)
		{
			ret[k++]+=num2[i]*num1[j];
			printf("ret[%d]:%d num2[%d]:%d num1[%d]:%d\n", k, ret[k], i, num2[i], j, num1[j]);
		}
	}
	for(i=0;i<size;++i)
	{
		printf("result ret[%d]: %d\n", i, ret[i]);
		if(ret[i]>=10)
		{
			ret[i+1]+=ret[i]/10;
			ret[i]%=10;
		}
	}
	return ret;
}

int main()
{
	/*
	int num1[]={1,2,3,4,5,6,7,8,9,1,1,1,1,1};//第一个大整数11111987654321
	int num2[]={1,1,1,2,2,2,3,3,3,4,4,4,5,5};//第二个大整数55444333222111
	int *ret=multi(num1,14,num2,14);
	for(int i=27;i>=0;i--)
	{
		printf("%d",ret[i]);
	}
	*/
	int num1[]={1,2};
	int num2[]={3,5};
	int *ret=multi(num1,2,num2,2);
	for(int i=4;i>=0;i--)
	{
		printf("%d",ret[i]);
	}
	free(ret);
	return 0;
}
