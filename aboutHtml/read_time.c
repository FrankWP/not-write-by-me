/*      显示系统时间	*/

#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "cgi.h"
#include "webadmin.h"

#define SIZE 20
int display_table();

char *cgiDebug;
char *progName = "readtime";
int  logEnable = FALSE;


int cgiMain (void)
{
    char date_week_buffer[SIZE];
    char date_year_buffer[SIZE];
    char date_month_buffer[SIZE];
    char date_day_buffer[SIZE];
    char date_hour_buffer[SIZE];
    char date_minute_buffer[SIZE];
    
    int ret;

    time_t curtime;
    struct tm *loctime;

    /* Get the current time. */
    curtime = time (NULL);

    /* Convert it to local time representation. */
     loctime = localtime (&curtime);

    /* Print it out in a nice format. */
    strftime (date_year_buffer, SIZE, "%Y", loctime);
    strftime (date_month_buffer, SIZE, "%m", loctime);
    strftime (date_day_buffer, SIZE, "%d", loctime);
    strftime (date_hour_buffer, SIZE, "%H", loctime);
    strftime (date_minute_buffer, SIZE, "%M", loctime);

    //认证用户
    ret = authentication(NULL,NULL);
    /*以下输出可见*/
    cgiHeaderContent("text/html");
    
    	if ( ret )
	{
		//认证失败
		dispOperateInfo( NULL, INVALID_USER, NULL );	// 显示错误信息
		return OK;
	}


    cgiPrintf("<html> <head> <meta http-equiv=\"refresh\" content=\"290;URL=/timeout.html\"> <title>系统时间设置</title> </head>");
    cgiPrintf("<body background=\"/icons/bg01.gif\"><br><center><H2>系统时间设置</H2><P></center><FORM name=\"form1\" action=\"/cgi-bin/update_time.cgi\" method=POST><P><P><HR width=70%> <P><P><P><P><P><P><P><P><P>");

    cgiPrintf("  <div align=\"center\"> <center> <table border=\"0\" cellpadding=\"0\" cellspacing=\"0\" style=\"border-collapse: collapse\" bordercolor=\"#111111\" width=\"60%\" id=\"AutoNumber1\" height=\"139\">");
        cgiPrintf("  <tr> <td width=\"17%\" height=\"24\" align=\"center\"> </td>  <td width=\"17%\" height=\"24\" align=\"center\"> </td> <td width=\"17%\" height=\"24\" align=\"right\"> 当前时间</td>");
    cgiPrintf("<tr> <td width=\"17%\" height=\"43\" align=\"center\"> <p align=\"right\">&nbsp;<input type=\"text\" name=\"T_Year\" value=\"%s\" size=\"10\" MAXLENGTH =\"4\"></td> <td width=\"17%\" height=\"43\" align=\"center\"> 年</td>",date_year_buffer);
    cgiPrintf("<td width=\"17%\" height=\"43\" align=\"center\"> <input type=\"text\" name=\"T_Month\" size=\"10\" MAXLENGTH =\"2\" value=\"%s\"></td> <td width=\"17%\" height=\"43\" align=\"center\"> 月</td>",date_month_buffer);
    cgiPrintf("<td width=\"16%\" height=\"43\" align=\"center\"> <input type=\"text\" name=\"T_Day\" size=\"10\" MAXLENGTH =\"2\" value=\"%s\"></td> <td width=\"16%\" height=\"43\" align=\"center\"> 日</td> </tr>",date_day_buffer);
    cgiPrintf("  <tr> <td width=\"17%\" height=\"42\" align=\"center\"> </td> ");
    cgiPrintf("  <td width=\"17%\" height=\"42\" align=\"center\"> <input type=\"text\" name=\"T_Hour\" size=\"10\" MAXLENGTH =\"2\" value=\"%s\">:</td> <td width=\"17%\" height=\"42\" align=\"center\"> <input type=\"text\" name=\"T_Minute\" size=\"10\" MAXLENGTH =\"2\" value=\"%s\"></td> <td width=\"16%\" height=\"42\" align=\"center\"> 24小时制</td> <td width=\"16%\" height=\"42\" align=\"center\"> </td> </tr>",date_hour_buffer,date_minute_buffer);
    cgiPrintf("  </table> </center> </div> <HR width=70%><center> <input TYPE=submit  value=\" 保 存 \" ></FORM></BODY><HEAD><META HTTP-EQUIV=\"PRAGMA\" CONTENT=\"NO-CACHE\"></HEAD></HTML>");
    cgiPrintf ("</table></center><BR><P><p><Br></p></body></HTML>\n");
}
