#!/bin/bash
# 根据管理IP修改sshd的配置
echo $# $1
if [ $# -eq 1 ];then
	if [  $1 = "ha" ];then
		/usr/local/hawk/shell/setip.sh restart ha
	fi
	if [ $1 = "before" ];then
		/bin/cp /storage/hawk/etc/netconfig.conf /tmp/netconfig.conf
	fi
else
	/usr/local/hawk/shell/config gets /storage/hawk/etc/netconfig.conf manage 2 > /tmp/admin_ip.conf
	if test -e /tmp/admin_ip.conf
	then
		ipaddr=$(head -1 /tmp/admin_ip.conf)
		#
		#is ipv4?
		#
		flg=`echo $ipaddr | grep '\.' `
		if [ "a$flg" = "a" ];then
			echo "IPv4 地址错误" > /tmp/admin_err.conf
			cp -a /tmp/netconfig.conf /storage/hawk/etc/netconfig.conf			
			exit 1
		fi
		ipaddr=$(tail -n 1 /tmp/admin_ip.conf)
		flg=`echo $ipaddr |grep ':' `  
		if [ "a$flg" = "a" ];then
		    	echo "IPv6 地址错误"> /tmp/admin_err.conf
			cp /tmp/netconfig.conf /storage/hawk/etc/netconfig.conf 
			exit 1
		else 
			spitflg=`echo $ipaddr | cut -d : -f 1`
			if [ "a$spitflg" = "afe80" ];then
				echo "非法管理地址" >/tmp/admin_err.conf
				cp /tmp/netconfig.conf /storage/hawk/etc/netconfig.conf 
				exit 1
			fi
		fi
	fi
	

	/usr/local/hawk/shell/config gets /storage/hawk/etc/netconfig.conf manage 3 > /tmp/admin_mask.conf
	if test -e /tmp/admin_mask.conf
	then
		netmask=$(head -1 /tmp/admin_mask.conf)
		flg=`echo $netmask | grep '\.' `
		if [ "a$flg" = "a" ];then
			echo "IPv4 地址掩码错误" > /tmp/admin_err.conf
			cp /tmp/netconfig.conf /storage/hawk/etc/netconfig.conf 
			exit 1
		fi
		netmask=$(tail -n 1 /tmp/admin_mask.conf)
		flg=`echo $netmask | grep '\.' `
		if [  "a$flg" != "a" ];then
			echo "IPv6 地址掩码错误" >/tmp/admin_err.conf
			cp /tmp/netconfig.conf /storage/hawk/etc/netconfig.conf 
			exit 1
		fi
	fi	

	/usr/local/hawk/shell/setip.sh restart manage
	sleep 2

	# 重启ssh
	if test -e /etc/rc.d/init.d/sshd
	then
		/etc/rc.d/init.d/sshd stop	
		sleep 1
		/etc/rc.d/init.d/sshd start
	fi

	# 修改apache配置文件中的地址后， 重启apache
	/etc/rc.d/init.d/mini_httpd restart
fi
