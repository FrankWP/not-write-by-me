#!/bin/bash

CONF=/storage/hawk/ha/sync_config/config_file.conf
TAR=/storage/hawk/ha/sync_config/syn_item.conf
video=`cat ${CONF} | grep yes | awk -F '=' '{print $1}' |grep video`
buf=`cat ${CONF} | grep yes | awk -F '=' '{print $1}' | grep -v only | grep -v license |grep -v admin |grep -v video`
if [ `cat ${CONF} | grep yes | grep -c only` > 0 ] && [ `cat ${CONF} | grep yes | grep -c tcp` == 0 ];then
	buf="${buf} tcp"
fi
cd /storage/hawk
mkdir -p /storage/hawk/list/
rm /storage/hawk/list/* -f

allvideo=`/usr/local/hawk/shell/verify_license 6 1`
if [ "a$allvideo" = "aTRUE" ] && [ `echo "${buf}" | grep udp` !=  0 ];then
	buf="${buf} packet"
else
	buf="${buf} udp packet"
fi
skyvideo=`/usr/local/hawk/shell/verify_license 15 1`
if [ "a$skyvideo" = "aTRUE" ];then
	if [ -e /storage/hawk/end ];then
		buf="${buf} end"
	else
		buf="${buf} front"
	fi
fi
starVideo=`/usr/local/hawk/shell/verify_license 6 4`
if [ "a$starVideo" = "aTRUE" ];then
	buf="${buf} starVideo"
fi
#===============================
#  content mod 
#==============================
if [ -f /tmp/config_file.conf ];then
	echo "[ mod ]" > /tmp/syn_mod.conf
	cat /tmp/config_file.conf >> /tmp/syn_mod.conf
	echo "[ /mod ]" >> /tmp/syn_mod.conf
fi

#file 2
> $TAR
#=====================================================
# list the dir ,which in the $buf  
#=====================================================
for dir in $buf
do
	echo "[ $dir ]" >> $TAR
		conten=`find /storage/hawk/$dir`
		num=0;
		for files in $conten
		do 
			if [ -f $files ];then
				num=`expr $num + 1`
				echo "$dir$num=$files" >> $TAR
			fi
		done
	echo "[ /$dir ] "  >> $TAR
	echo "" >> $TAR
done


#========================================================
# files in the list 
#========================================================
echo "[ others ]" >> $TAR
echo	"others1=/storage/hawk/list/${CONF}" >> $TAR
echo	"others2=/usr/local/hawk/web/cgi-bin/conf/user.conf" >> $TAR
echo	"others3=/storage/hawk/firewall/admin.conf" >> $TAR
echo	"others4=/usr/local/hawk/web/cgi-bin/conf/access.conf" >> $TAR
echo	"others5=/usr/local/hawk/web/cgi-bin/conf/roler.conf" >> $TAR
echo	"others6=/storage/hawk/etc/system.conf" >> $TAR
echo	"others7=/storage/hawk/tcp/*_user.conf" >> $TAR
echo	"others8=/usr/local/hawk/web/cgi-bin/conf/menu.conf" >> $TAR
echo	"others9=/storage/hawk/etc/logcenter.conf" >> $TAR
echo "[ /others ]" >> $TAR
echo "" >> $TAR
#=========================================================
# files in the conff
#=========================================================
cp -aR /storage/hawk/conf/ /storage/hawk/conff/
rm -rf /storage/hawk/conff/license
rm -rf /storage/hawk/conff/menu.conf
rm -rf /storage/hawk/conff/access.conf
conten=`find /storage/hawk/conff/`
num=0
echo "[ conf ]" >> $TAR
 for files in $conten                                                                                     
                do                                                                                                       
                        if [ -f $files ];then                                                                            
				num=`expr $num + 1`
                                echo "conf$num=$files" >> $TAR
                        fi                                                                                               
                done 
echo "[ /conf ]" >> $TAR
echo "" >> $TAR
#==========================================================
# files in the firewall
#==========================================================
conten=`find /storage/hawk/firewall`
echo "[ firewall ]"  >> $TAR
num=0
 for files in $conten                                                                                                    
                do                                                                                                       
                        if [ -f $files ];then                                                                            
				num=`expr $num + 1`
                                echo "firewall$num=$files" >> $TAR
                        fi                                                                                               
                done                                                                                                     
echo "[ /firewall ]" >> $TAR
#=====================
	/usr/local/hawk/ha/sync_config/sync_start_cli.sh
