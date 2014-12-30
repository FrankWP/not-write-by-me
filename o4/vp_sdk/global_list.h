#ifndef __GLOBAL_LIST_H
#define __GLOBAL_LIST_H

typedef struct __global_list_data
{
	char name[128];
	char *data;
	int len;

	//true length of memory
	int __mem_len;

	struct __global_list_data *next;
}gldata;

bool gl_set_data(const char *name, char *data, int len);
gldata *gl_get_data(const char *name);
bool gl_mod_data(const char *name, char *data, int len);
bool gl_rm_data(const char *name);
void gl_clr_data();

#endif

