#include<stdio.h>
#include<curses.h>
int main(){
	initscr();  //初始化curses库和tty
	clear();    //清屏
	int i;
	for(i=0;i<LINES;i++){
		move(i,i+1); //把光标移到(10,20)的位置
		if(i%2==1)
			standout();//启动standout模式，一般使屏幕反色
		char a[128] = {0};
		sprintf(a, "step:%d", i);
		addstr(a);  //在光标添加字符串
		if(i%2==1)
			standend(); //关闭standout模式
		sleep(1);    //sleep和alarm提供的时间精度为秒
		refresh();  //curses保存了两个屏幕：内部屏幕和工作屏幕，必须调用refresh才能用工作屏幕去替换真实屏幕
		move(i,i+1);
		addstr("");    //擦掉字符串
	}
	//getch();    //等待用户按下任意一个键
	    endwin();   //关闭curses并重置tty
}
