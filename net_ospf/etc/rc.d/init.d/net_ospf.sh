FILE_PID="/var/run/net_ospf.pid"
CFG_TASK="/storage/hawk/net_ospf/conf/task.conf"
CFG_OSPF="/storage/hawk/net_ospf/conf/net_ospf.conf"
PATH_BIN="/usr/local/hawk/net_ospf"

#
#   Desc: process setup
#
net_ospf_start()
{
	task_line=`sed -n '/^\[ ip \]/{n;p}' ${CFG_TASK}`
	if [ -n "${task_line}" ]; then
		${PATH_BIN}/net_ospf ${CFG_OSPF} > /dev/null 2>&1 &
	fi
}

#
#   Desc: process shutdown, remove pid file
#
net_ospf_stop()
{
	if [ -e "${FILE_PID}" ]; then
		kill -USR2 `cat ${FILE_PID}`
		rm -rf ${FILE_PID}
	fi
}

#
#   Desc: Main entrance
#
. /etc/rc.d/rc.functions

if [ "$#" -ne 1 ] || [ -z "$1" ]; then
	echo "Usage: $0 {start | stop | restart}"
	exit 1;
fi

case $1 in

	start)
		net_ospf_start
		exit 0;
		;;

	stop)
		net_ospf_stop
		exit 0;
		;;
	
	restart)
		net_ospf_stop
		sleep 1
		net_ospf_start
		exit 0;
		;;

	*)
		echo "Usage: $0 {start | stop | restart}"
		exit 1;
		;;
esac
