#include <stdio.h>
#include <stdlib.h>
#include "common.h"

/*************************************************************************************** 
 *   Name: main
 *   Desc: Check source and destination address if in the same network
 *  Input: 
 *         $1 - source address
 *         $2 - destination address
 *         $3 - netmask
 * Output: -
 * Return: int, 0 on success; -1 on error 
 * Others: -
 ***************************************************************************************/
int main(int argc, char *argv[])
{
	int src_addr = 0;
	int dst_addr = 0;
	int net_addr = 0;

	if ( argc != 4 ) {
		printf("Usage %s source destination netmask\n", argv[0]);
		return FAILURE;
	}

	src_addr = ip_aton(argv[1]);
	dst_addr = ip_aton(argv[2]);
	net_addr = ip_aton(argv[3]);

	if ( (src_addr & net_addr) != (dst_addr & net_addr) ) {
		return FAILURE;
	}

	return SUCCESS;
}
