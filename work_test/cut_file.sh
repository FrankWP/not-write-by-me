#bash

name=$1
lines=`wc -l $name|awk '{print $1}'`
filename="filepart_"

index=0
count=1
app=2

while [ $count -lt $lines ]
do
	end=`expr $count - 1 + $app `
	sed -n "$count, ${end}p" $name > ${filename}${index}
	count=`expr $count + $app`
	index=`expr $index + 1`
done
