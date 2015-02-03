#该脚本用于执行文件同步服务端程序
#!/bin/bash

PATH=/bin:/sbin:/usr/bin:/usr/sbin
SYNPROC_PATH=/usr/local/hawk/ha/sync_config
EXEC=syn_file_ser

killall $EXEC
$SYNPROC_PATH/$EXEC >/dev/null 2>&1 &
