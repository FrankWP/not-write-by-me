#!/bin/sh
################################################################
# Copyright (C), 2006-2015, Legendsec Technology Co., Ltd.     #
# FileName:  net_ospf_boot.sh                                  #
#   Author:  liujfa                                            #
#     Date:  2015/01/07                                        #
#     Desc:  Get configure and set the ospf router address.    #
#  History:  -                                                 #
################################################################

CFG_TASK="/storage/hawk/net_ospf/conf/task.conf"
CFG_OSPF="/storage/hawk/net_ospf/conf/net_ospf.conf"
CFG_NET="/storage/hawk/etc/netconfig.conf"

TMP_TASK="/tmp/task.conf"
TMP_IF="/tmp/net_ospf_interface.tmp"
TMP_ERR="/tmp/net_ospf_error.conf"

CMD_GETIF="/usr/local/hawk/shell/config gets /storage/hawk/etc/netconfig.conf ip 2"
CMD_IP_CAL="/usr/local/hawk/net_ospf/ip_cal"

#
#   Desc: address configure preparation
#
net_ospf_before()
{
	cp -af ${CFG_TASK} ${TMP_TASK}

	if [ -e "${TMP_ERR}" ]; then
		rm -rf ${TMP_ERR}
	fi

	if [ ! -d "/storage/hawk/net_ospf/conf/" ]; then
		mkdir -p /storage/hawk/net_ospf/conf/
	fi

	# Get interface
	${CMD_GETIF} > ${TMP_IF}
}

#
#   Desc: set address, format the configure for process
# Return: 0 if success, 1 means failure
#
net_ospf_after()
{
	task_line=`sed -n '/^\[ ip \]/{n;p}' ${CFG_TASK}`
	if [ -z "${task_line}" ]; then
		# Task del
		return 1
	fi

	tmp_line=`sed -n '/^\[ ip \]/{n;p}' ${TMP_TASK}`
	diff ${TMP_TASK} ${CFG_TASK} > /dev/null
	if [ $? -eq 1  ] && [ -n "${tmp_line}" ]; then
		# Task modify
		/etc/rc.d/init.d/net_ospf.sh stop
	fi

	router_src_ip=`echo ${task_line} | awk '{print $1}'`
	router_dst_ip=`echo ${task_line} | awk '{print $2}'`
	tmp_line=`sed -n "/[\t]${router_dst_ip}[\t]/p" ${CFG_NET}`
	router_netmask=`echo ${tmp_line} | awk '{print $3}'` 
	router_interface=`echo ${tmp_line} | awk '{print $1}'`

	# Check task input legitimacy
	tmp_line=`sed -n "/[\t]${router_src_ip}[\t]/p" ${CFG_NET}`
	if [ ${router_src_ip} == ${router_dst_ip} ] || [ -n "${tmp_line}" ]; then
		echo "源路由地址${router_src_ip}错误！" > ${TMP_ERR}
		return 1
	fi

	${CMD_IP_CAL} ${router_src_ip} ${router_dst_ip} ${router_netmask}
	if [ "$?" -ne 0 ]; then
		echo "路由地址不在同一网段" > ${TMP_ERR}
		return 1
	fi

	# Set process configure file
	if [ ! -e ${CFG_OSPF} ]; then
		echo "[ common ]" > ${CFG_OSPF}
		echo "sis_in_ip=127.0.16.1"  >> ${CFG_OSPF}
		echo "sis_out_ip=127.0.16.2" >> ${CFG_OSPF}
		echo "sis_interface=sis0"    >> ${CFG_OSPF}
		echo ""                      >> ${CFG_OSPF}
		echo "[ router ]"            >> ${CFG_OSPF}
		echo "router_src_ip="        >> ${CFG_OSPF}
		echo "router_dst_ip="        >> ${CFG_OSPF}
		echo "router_netmask="       >> ${CFG_OSPF}
		echo "router_interface="     >> ${CFG_OSPF}
	fi

	sed -i "s/^router_src_ip=.*/router_src_ip=${router_src_ip}/g" ${CFG_OSPF}
	sed -i "s/^router_dst_ip=.*/router_dst_ip=${router_dst_ip}/g" ${CFG_OSPF}
	sed -i "s/^router_netmask=.*/router_netmask=${router_netmask}/g" ${CFG_OSPF}
	sed -i "s/^router_interface=.*/router_interface=${router_interface}/g" ${CFG_OSPF}

	return 0
}

#
#   Desc: Main entrance
#
if [ "$#" -ne 1 ] || [ -z "$1" ]; then
	echo "Usage: $0 {before | after}"
	exit 1;
fi

case $1 in

	before)
		net_ospf_before
		;;

	after)
		net_ospf_after
		if [ "$?" -ne 0 ]; then
			/etc/rc.d/init.d/net_ospf.sh stop
			if [ -e "${CFG_TASK}" ]; then
				rm -rf ${CFG_TASK}
			fi
		fi
		;;

	*)
		echo "Usage: $0 {before | after}"
		;;
esac
