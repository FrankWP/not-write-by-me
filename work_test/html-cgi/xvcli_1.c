#include "syshead.h"
#include "md5.h"
#include "display.h"
#include "read_conf.h"

#include<signal.h>

#define N 100 //�������Ķ�ʱ������
int i=0,t=1; //i����ʱ���ĸ�����t��ʾʱ�䣬�������

struct Timer //Timer�ṹ�壬��������һ����ʱ������Ϣ
{
	time_t total_time; //һ����total_time��
	time_t left_time; //��ʣleft_time��
	time_t warn_time; //������ʱ�䱨��
	int (*func)(); //�ö�ʱ����ʱ��Ҫִ�еĴ���ı�־
}myTimer[N]; //����Timer���͵����飬�����������еĶ�ʱ��

void setTimer(time_t t, time_t wt, int (*func)()) //�½�һ����ʱ��
{
	
	struct Timer a;
	a.total_time = t;
	a.left_time = t;
	a.warn_time = wt;
	a.func=func;
	myTimer[i++]=a;
	
	/*
	myTimer[i].total_time = t;
	myTimer[i].left_time = t;
	myTimer[i].warn_time = wt;
	myTimer[i].func=func;
	i++;
	*/
}

int time_dealer1()
{
	printf("------Timer 1: --Hello Aillo!\n");
	return 0;
}

int time_dealer2()
{
	printf("------Timer 2: --Hello Gcc!\n");
	return 0;
}

void timeout() //�ж϶�ʱ���Ƿ�ʱ���Լ���ʱʱ��Ҫִ�еĶ���
{
	int j;
	for(j=0;j<i;j++)
	{
		if(myTimer[j].left_time!=0)
		{
			myTimer[j].left_time--;
			if (myTimer[j].left_time == myTimer[j].warn_time)
				printf("ֻʣ��%ld�룬���ֵ\n", myTimer[j].warn_time);
		}
		else
		{
			puts("1");
			myTimer[j].func();
			puts("2");
			break;
		}
	}
}

int main() //���Ժ���������������ʱ��
{
	setTimer(5,3, &time_dealer1);
	setTimer(3,2, &time_dealer2);
	signal(SIGALRM, timeout); //�ӵ�SIGALRM�źţ���ִ��timeout����

	while(1)
	{
		sleep(1); //ÿ��һ�뷢��һ��SIGALRM
		kill(getpid(),SIGALRM);
	}
	exit(0);
}
