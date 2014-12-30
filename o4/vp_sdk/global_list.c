#include "common.h"
#include "global_list.h"

static gldata *g_gl_data = NULL;
static pthread_mutex_t s_gldata_mutex = PTHREAD_MUTEX_INITIALIZER;

gldata *gl_get_data(const char *name)
{
    gldata *gld = NULL;
    if (name == NULL)
        return NULL;

pthread_mutex_lock(&s_gldata_mutex);
    gld = g_gl_data;
    while (gld != NULL)
    {
        if (strncmp(gld->name, name, sizeof(gld->name)-1) == 0)
            break;
        gld = gld->next;
    }
pthread_mutex_unlock(&s_gldata_mutex);
    return gld;
}

bool gl_set_data(const char *name, char *data, int len)
{
	gldata *gld = NULL;
	char *tmp_data = NULL;

	if ((name == NULL) || (data == NULL) || (len < 0))
    {
        logdbg_fmt("gl_set_data: arg error! nameptr:[%p], dataptr:[%p], len:[%d]\n", name,data,len);
		return false;
    }

	// data using this name, has already exist.
	if (gl_get_data(name) != NULL)
    {
        logdbg_fmt("gl_set_data: name:[%s] already been used!", name);
		return false;
    }

	//if ((gld = (gldata*)malloc(sizeof(gldata))) == NULL)
    if (oss_malloc(&gld, sizeof(gldata)) < 0)
    {
        logdbg_out("gl_set_data: malloc gld struct failed!");
		return false;
    }
    
    if (oss_malloc(&tmp_data, len) < 0)
	{
		oss_free(&gld);
        logdbg_fmt("gl_set_data: malloc data buffer failed! size:[%d]", len);
		return false;
	}

	strncpy(gld->name, name, sizeof(gld->name)-1);
	memcpy(tmp_data, data, len);
	gld->data = tmp_data;
	gld->len = len;
    puts("1 >>>>>>>>>>>>>>>>>>>>>>");
    t_disbuf(gld->data, gld->len);
    puts("2 >>>>>>>>>>>>>>>>>>>>>>");

pthread_mutex_lock(&s_gldata_mutex);
	gld->next = g_gl_data;
    g_gl_data = gld;
pthread_mutex_unlock(&s_gldata_mutex);

	return true;
}

bool gl_mod_data(const char *name, char *data, int len)
{
	gldata *thread_data = NULL;
	char *tmp_data = NULL;

	if ((name == NULL) || (data == NULL) || (len < 0))
		return false;
    /*
	if ((thread_data = gl_get_data(name)) == NULL)
		return false;
        */
    // data use this not exist, create one
	if ((thread_data = gl_get_data(name)) == NULL)
        return gl_set_data(name, data, len);

	if (thread_data->__mem_len < len)
	{
		if ((tmp_data = (char*)malloc(len)) == NULL)
			return false;
		free(thread_data->data);

		thread_data->data = tmp_data;
		thread_data->len = len;
		thread_data->__mem_len = len;
	}

	memcpy(thread_data->data, data, len);
	thread_data->len = len;
	
	return true;
}

bool gl_rm_data(const char *name)
{
	gldata *gl_data = NULL;
	gldata *gl_data_tmp = NULL;
	bool res = false;

	if (name == NULL)
		return false;

pthread_mutex_lock(&s_gldata_mutex);
	gl_data = g_gl_data;
	gl_data_tmp = gl_data;

	while (gl_data != NULL)
	{
		if (strncmp(name, gl_data->name, sizeof(gl_data->name)-1) == 0)
		{
			if (gl_data != g_gl_data) // is not head data
				gl_data_tmp->next = gl_data->next;
			else	// is head of struct list.
				g_gl_data = gl_data->next;
			free(gl_data);
			gl_data = NULL;
			res = true;
			break;
		}

		gl_data_tmp = gl_data;
		gl_data = gl_data->next;
	}
pthread_mutex_unlock(&s_gldata_mutex);

	return res;
}

void gl_clr_data()
{
	gldata *gl_data = NULL;
	gldata *gl_data_tmp = NULL;

pthread_mutex_lock(&s_gldata_mutex);
    gl_data = g_gl_data;
	// do clear
    while (gl_data != NULL)
    {
        gl_data_tmp = gl_data;
        gl_data = gl_data->next;

        free(gl_data_tmp);
    }
    g_gl_data = NULL;
pthread_mutex_unlock(&s_gldata_mutex);
}

