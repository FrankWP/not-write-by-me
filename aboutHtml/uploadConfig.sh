#!/bin/bash

STO=/tmp/uploadDir/storage/hawk
CONF=/${STO}/list/config_export.conf
DIR=/storage/hawk
SCRIPT=/usr/local/hawk/web/cgi-bin/script/changeutil

function switch(){
	if [ ! -e /storage/hawk/tcp/task.conf ];then
		touch /storage/hawk/tcp/task.conf
	fi
	${SCRIPT} $1 /storage/hawk/tcp/task.conf
	if [ ! -e ${STO}/tcp/task.conf ];then
		touch ${STO}/tcp/task.conf
	fi
	if [ `/usr/local/hawk/shell/config gets ${STO}/tcp/task.conf $1|wc -l` != "0" ];then
		echo "[ $1 ]" >> /storage/hawk/tcp/task.conf
		/usr/local/hawk/shell/config gets ${STO}/tcp/task.conf $1 >> /storage/hawk/tcp/task.conf
	fi
	if [ ! -e /storage/hawk/tcp/task_server.conf ];then
		touch /storage/hawk/tcp/task_server.conf
	fi
	${SCRIPT} $2 /storage/hawk/tcp/task_server.conf
	if [ ! -e ${STO}/tcp/task_server.conf ];then
		touch ${STO}/tcp/task_server.conf
	fi
	if [ `/usr/local/hawk/shell/config gets ${STO}/tcp/task_server.conf $2|wc -l` != "0" ];then
		echo "[ $2 ]" >> /storage/hawk/tcp/task_server.conf
		/usr/local/hawk/shell/config gets ${STO}/tcp/task_server.conf $2 >> /storage/hawk/tcp/task_server.conf 
	fi
	rm -f /storage/hawk/$3*
	cp -f /tmp/uploadDir/storage/hawk/firewall/$3* /storage/hawk/firewall/
}


mv $1 /tmp/gapconfig.tar.gz
rm -rf /tmp/uploadDir/* /tmp/upload.error
mkdir -p /tmp/uploadDir/storage/hawk
tar zxf /tmp/gapconfig.tar.gz -C /tmp/uploadDir/storage/hawk > /dev/null
mv /tmp/uploadDir/storage/hawk/conff /tmp/uploadDir/storage/hawk/conf

#squid
if [ `grep yes ${CONF}|grep -c http` != "0" ];then
	rm -f /storage/hawk/firewall/squid*
	cp -f /tmp/uploadDir/storage/hawk/firewall/squid* /storage/hawk/firewall
fi

#ftp
if [ `grep yes ${CONF}|grep -c ftp` != "0" ];then
	rm -f /storage/hawk/firewall/ftp.conf
	cp -f /tmp/uploadDir/storage/hawk/firewall/ftp.conf /storage/hawk/firewall
fi

#file
if [ `grep yes ${CONF}|grep -c file` != "0" ];then
	rm -f /storage/hawk/conf/smbpasswd
	cp -f /tmp/uploadDir/storage/hawk/conf/smbpasswd /storage/hawk/conf/
fi

#socks
if [ `grep yes ${CONF}|grep -c socks` !=0 ];then
	rm -rf /storage/hawk/socks
	cp -aR /tmp/uploadDir/storage/hawk/socks /storage/hawk/
fi
#logcenter
cp -f /tmp/uploadDir/storage/hawk/list/logcenter.conf /storage/hawk/etc/

#sslChannel
if [ `grep yes ${CONF}|grep -c sslChannel` !=0 ];then
	rm -rf /storage/hawk/sslChannel
	cp -aR /tmp/uploadDir/storage/hawk/sslChannel /storage/hawk/
fi
noftp=`grep yes ${CONF}|grep -c onlyftp`
nodb=`grep yes ${CONF}|grep -c onlydb` 
nomail=`grep yes ${CONF}|grep -c onlymail` 
notcp=`grep yes ${CONF}|grep -c tcp`
noudp=`grep yes ${CONF}|grep -c udp`
novideo=`grep yes ${CONF}|grep -c video`

#ftp access
if [ ${noftp} != "0" ];then
	switch ftp ftp ftpwtt
fi

#db access
if [ ${nodb} != "0" ];then
	switch oracle oracle oracle	
	switch sqlserver sqlserver sqlserver	
	switch db2 db2 db2	
	switch sybase sybase sybase	
	switch mysql mysql mysql
	rm -f /storage/hawk/tcp/*_user.conf
	cp -f ${STO}/list/*_user.conf /storage/hawk/tcp/
fi

#mail access
if [ ${nomail} != "0" ];then
	rm -f ${DIR}/tcp/mail*
	cp -f ${STO}/tcp/mail* ${DIR}/tcp/
	
	switch pop3 pop3 pop3
	switch smtp smtp smtp
fi

#tcp
if [ ${notcp} != "0" ];then
	switch tcp TCP tcp
fi
#video
if [ ${novideo} != "0" ];then
	switch video video video
	rm -f /storage/hawk/firewall/udpvideo-*.conf
	cp -f /tmp/uploadDir/storage/hawk/firewall/udpvideo-*.conf /storage/hawk/firewall/
fi

#udp
if [ ${noudp} != "0" ];then
	rm -f /storage/hawk/firewall/udp-*.conf                                  
        cp -f /tmp/uploadDir/storage/hawk/firewall/udp-*.conf /storage/hawk/firewall/	
fi

#admin
if [ `grep yes ${CONF}|grep -c admin` != "0" ];then
	rm -f /usr/local/hawk/web/cgi-bin/conf/user.conf
	rm -f /storage/hawk/firewall/admin.conf
	#rm -f /usr/local/hawk/web/cgi-bin/conf/access.conf
	rm -f /usr/local/hawk/web/cgi-bin/conf/roler.conf  
	rm -f /storage/hawk/etc/system.conf
	cp -f ${STO}/list/user.conf /usr/local/hawk/web/cgi-bin/conf/user.conf
	cp -f ${STO}/list/admin.conf /storage/hawk/firewall/admin.conf
	#cp -f ${STO}/list/access.conf /usr/local/hawk/web/cgi-bin/conf/access.conf
	cp -f ${STO}/list/roler.conf /usr/local/hawk/web/cgi-bin/conf/roler.conf  
	cp -f ${STO}/list/system.conf /storage/hawk/etc/system.conf
	cp -f ${STO}/conf/shadow /storage/hawk/conf/
fi

#license
if [ `grep yes ${CONF}|grep -c license` != "0" ];then
	rm -f /storage/hawk/conf/license
	cp -f ${STO}/conf/license /storage/hawk/conf/license
	rm -f /usr/local/hawk/web/cgi-bin/conf/access.conf 
	rm -f /usr/local/hawk/web/cgi-bin/conf/menu.conf
	cp -f ${STO}/list/access.conf /usr/local/hawk/web/cgi-bin/conf/access.conf 
	cp -f ${STO}/list/menu.conf /usr/local/hawk/web/cgi-bin/conf/menu.conf  
fi

rm -rf ${STO}/tcp
rm -rf ${STO}/list
rm -rf ${STO}/firewall
rm -f ${STO}/etc/system.conf

cd ${STO}
cp -f conf/resolv.conf .
find conf |grep -v '[0-9].*' |xargs rm   
mv resolv.conf conf/
tar zcvf /tmp/t.tar.gz *
tar zxvf /tmp/t.tar.gz -C /storage/hawk/

rm -rf /tmp/uploadDir
rm -f /tmp/gapconfig.tar.gz
rm -f /tmp/t.tar.gz
rm -rf /storage/hawk/conff

