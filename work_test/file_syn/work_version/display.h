#include "syshead.h"
#define t_disbuf(p, size) _t_disbuf((const unsigned char*)(p), (int)size)
static void print_char(char ch);
static void dis_interpret(const unsigned char *buf, int len);
void _t_disbuf(const unsigned char *buf, int len);

