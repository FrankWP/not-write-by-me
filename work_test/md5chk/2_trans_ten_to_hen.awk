BEGIN{
	FS=",|)"	
	var="cat 123.txt"
#system(var)
}
{
#printf ("%s%s%s%s%s%s 0x%x %s\n",$1,$2,$3,$4,$5,$6,$7,$8) >> "./123.txt"
	system(var)
}
END{

}
