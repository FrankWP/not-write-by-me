#!/bin/bash

SYN_SOCK_CONF=/tmp/syn_sock.conf

if [ -F $SYN_SCOK_CONF ]; then
	rm  -rf $SYN_SOCK_CONF
	echo 1
fi

CMD_GETIP=/usr/local/hawk/shell/config
PATH_GETIP=/storage/hawk/etc/netconfig.conf
#CMD_GETIP=./config
#PATH_GETIP=./netconfig.conf
IP=`$CMD_GETIP gets $PATH_GETIP manage 2 | grep -v ":"`
PORT=5000

touch $SYN_SOCK_CONF
	echo "[socket]"						>> $SYN_SOCK_CONF
	echo "	syn_sock_conf_ip=$IP"		>> $SYN_SOCK_CONF
	echo "	syn_sock_conf_port=$PORT"	>> $SYN_SOCK_CONF
	echo "[/socket]"					>> $SYN_SOCK_CONF
