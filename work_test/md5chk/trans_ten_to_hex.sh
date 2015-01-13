#!/bin/bash

BEGIN {
	FS=",|)"
}
{
	print $7 >> "./single.txt"
#system("echo ibase=10;obase=16;$7|bc")
#echo $7|{system("echo $1")}
}


#echo 'ibase=10;obase=16;32'|bc
