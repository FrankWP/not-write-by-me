#ifndef __THREAD_PRIVATE_DATA_H
#define __THREAD_PRIVATE_DATA_H

typedef struct __thread_data
{
	char name[128];
	char *data;
	int len;

	//true length of memory
	int __mem_len;

	struct __thread_data *next;
}tdata;

bool tp_set_data(const char *name, const char *data, int len);
tdata *tp_get_data(const char *name);
bool tp_mod_data(const char *name, const char *data, int len);
bool tp_rm_data(const char *name);
void tp_clr_data();

// for test
/*
void tp_show_tdata(tdata *tdata);
void tp_show_current();
void tp_showall();
*/

#endif

