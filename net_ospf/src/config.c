/***************************************************************************************
 *   Copyright (C), 2006-2014, Legendsec Technology Co., Ltd.
 *
 *    Filename: config.c
 * Description: Load the configure file to memory.
 *     Version: 1.0
 *     Created: Liujfa   11/19/14 03:37:08
 *    Revision: none
 *
 *     History: <author>   <time>    <version >         <desc>
 *              Liujfa   11/19/14                  build this moudle  
 ***************************************************************************************/
#include "common.h"
#include "config.h"

/*************************************************************************************** 
 *   Name: parse_com_line
 *   Desc: Parse common configure to data
 *  Input: 
 *         @line - line to parse
 * Output: 
 *         @cc   - common data
 * Return: int, 0 on success; -1 on error 
 * Others: -
 ***************************************************************************************/
void parse_com_line(const char *line, COM_CFG_T *cc)
{
	if (!line || !cc) {
		LOGW("NULL\n");
		return;
	}

	char val[32] = {0};

	if (strstr(line, "sis_out_ip")) {

		sscanf(line + strlen("sis_out_ip="), "%[0-9.]", val);
		cc->sis_out_ip = ip_aton(val);
	} 
	else if (strstr(line, "sis_in_ip")) {

		sscanf(line + strlen("sis_in_ip="), "%[0-9.]", val);
		cc->sis_in_ip = ip_aton(val);
	} 
	else if (strstr(line, "sis_interface")) {

		sscanf(line + strlen("sis_interface="), "%s", cc->sis_if);
	}
	else {
		LOGW("Matching fail, %s", line);
	}
}

/*************************************************************************************** 
 *   Name: parse_router_line
 *   Desc: Parse router configure to data
 *  Input: 
 *         @line - line to parse
 * Output: 
 *         @rc   - router data
 * Return: int, 0 on success; -1 on error 
 * Others: -
 ***************************************************************************************/
void parse_router_line(const char *line, RT_CFG_T *rc)
{
	if (!line || !rc) {
		LOGW("NULL\n");
		return;
	}

	char val[32] = {0};

	if (strstr(line, "router_src_ip")) {

		sscanf(line + strlen("router_src_ip="), "%[0-9.]", val);
		rc->rt_src_ip = ip_aton(val);
	} 
	else if (strstr(line, "router_dst_ip")) {

		sscanf(line + strlen("router_dst_ip="), "%[0-9.]", val);
		rc->rt_dst_ip = ip_aton(val);
	} 
	else if (strstr(line, "router_netmask")) {

		sscanf(line + strlen("router_netmask="), "%[0-9.]", val);
		rc->rt_netmask = ip_aton(val);
	}
	else if (strstr(line, "router_interface")) {

		sscanf(line + strlen("router_interface="), "%s", rc->rt_if);
	}
	else {
		LOGW("Matching fail, %s", line);
	}

}


/*************************************************************************************** 
 *   Name: cfg_load
 *   Desc: Load the configure file to memory. 
 *  Input: 
 *         @filep  - configure file
 *         @sec    - session
 * Output: 
 *         @cfg_list - data
 * Return: int, 0 on success; -1 on error 
 * Others: Called by initialization.
 ***************************************************************************************/
int cfg_load(const char *filep, const char *sec, void *cfg_list)
{

	if ( !filep || !sec || !cfg_list ) {
		LOGW("NULL\n");
		return FAILURE;
	}
	FILE	*fp;
	int     flag = 0;
	char    line[128], *ps;

	if ((fp = fopen(filep, "r")) == NULL) {
		fprintf(stderr, "error: open the file [%s]\n", filep);
		return -1;
	}

	while (fgets(line, sizeof(line) - 1, fp)) {
		ps = line;

		while (*ps == ' ' || *ps == '\t') {
			ps++;
		}

		if (*ps == '#' || *ps == 0 || *ps == '\r' || *ps == '\n' || *ps == ';') {
			continue;
		}

		if (*ps == '[') {
			if (strstr(ps, sec)) {
				++flag;
			}
			else if (flag) {
				break;
			}
		} else if (flag) {
			if (strstr(sec, CFG_COM_TASK)) {
				parse_com_line(line, (COM_CFG_T *)cfg_list);
			}
			else {
				parse_router_line(line, (RT_CFG_T *)cfg_list);
			}
		}
	}

	fclose(fp);
	return SUCCESS;
}
