#include<stdio.h>
#include<curses.h>
int main(){
	initscr();  //��ʼ��curses���tty
	clear();    //����
	int i;
	for(i=0;i<LINES;i++){
		move(i,i+1); //�ѹ���Ƶ�(10,20)��λ��
		if(i%2==1)
			standout();//����standoutģʽ��һ��ʹ��Ļ��ɫ
		char a[128] = {0};
		sprintf(a, "step:%d", i);
		addstr(a);  //�ڹ������ַ���
		if(i%2==1)
			standend(); //�ر�standoutģʽ
		sleep(1);    //sleep��alarm�ṩ��ʱ�侫��Ϊ��
		refresh();  //curses������������Ļ���ڲ���Ļ�͹�����Ļ���������refresh�����ù�����Ļȥ�滻��ʵ��Ļ
		move(i,i+1);
		addstr("");    //�����ַ���
	}
	//getch();    //�ȴ��û���������һ����
	    endwin();   //�ر�curses������tty
}
