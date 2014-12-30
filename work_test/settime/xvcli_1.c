#include "syshead.h"
#include "md5.h"
#include "display.h"
#include "read_conf.h"

#include<signal.h>

#define N 100 //设置最大的定时器个数
int i=0,t=1; //i代表定时器的个数；t表示时间，逐秒递增

struct Timer //Timer结构体，用来保存一个定时器的信息
{
	time_t total_time; //一共有total_time秒
	time_t left_time; //还剩left_time秒
	time_t warn_time; //到多少时间报警
	int (*func)(); //该定时器超时，要执行的代码的标志
}myTimer[N]; //定义Timer类型的数组，用来保存所有的定时器

void setTimer(time_t t, time_t wt, int (*func)()) //新建一个计时器
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

void timeout() //判断定时器是否超时，以及超时时所要执行的动作
{
	int j;
	for(j=0;j<i;j++)
	{
		if(myTimer[j].left_time!=0)
		{
			myTimer[j].left_time--;
			if (myTimer[j].left_time == myTimer[j].warn_time)
				printf("只剩下%ld秒，请充值\n", myTimer[j].warn_time);
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

int main() //测试函数，定义三个定时器
{
	setTimer(5,3, &time_dealer1);
	setTimer(3,2, &time_dealer2);
	signal(SIGALRM, timeout); //接到SIGALRM信号，则执行timeout函数

	while(1)
	{
		sleep(1); //每隔一秒发送一个SIGALRM
		kill(getpid(),SIGALRM);
	}
	exit(0);
}
