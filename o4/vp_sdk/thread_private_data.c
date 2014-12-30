#include "common.h"
#include "thread_private_data.h"

typedef struct __thread_private_data
{
	pthread_t thread_id;
	tdata *t_data;

	struct __thread_private_data *next;
}tprivate;

static pthread_mutex_t s_tp_mutex = PTHREAD_MUTEX_INITIALIZER;
static tprivate *g_tprivate = NULL;

static tprivate *current_tprivate();
static tdata *tp_getdata_from_priv(tprivate *tpriv, const char *name);

tprivate *current_tprivate()
{
	tprivate *tpriv = NULL;

pthread_mutex_lock(&s_tp_mutex);
	tpriv = g_tprivate;
	while (tpriv != NULL)
	{
		if (tpriv->thread_id == pthread_self())
			break;
		tpriv = tpriv->next;
	}
	// if private data does not exist, create one.
	if ((tpriv == NULL) &&
		((tpriv = (tprivate*)malloc(sizeof(tprivate))) != NULL))
	{
		tpriv->thread_id = pthread_self();
		tpriv->t_data = NULL;
		tpriv->next = g_tprivate;
		g_tprivate = tpriv;
	}
pthread_mutex_unlock(&s_tp_mutex);

	return tpriv;
}

static tdata *tp_getdata_from_priv(tprivate *tpriv, const char *name)
{
	tdata *thread_data = NULL;
	if ((tpriv == NULL) || (name == NULL))
		return NULL;
	thread_data = tpriv->t_data;	
	while (thread_data != NULL)
	{
		if (strncmp(name, thread_data->name, sizeof(thread_data->name)-1) == 0)
			break;
		thread_data = thread_data->next;
	}

	return thread_data;	
}

tdata *tp_get_data(const char *name)
{
	tprivate *tpriv = NULL;

	if ((name == NULL) || 
		(tpriv = current_tprivate()) == NULL)
		return NULL;

	return tp_getdata_from_priv(tpriv, name);
}

bool tp_set_data(const char *name, const char *data, int len)
{
	tprivate *tpriv = NULL;
	tdata *thread_data = NULL;
	char *tmp_data = NULL;

	if ((name == NULL) || (data == NULL) || (len < 0))
    {
        logdbg_fmt("tp_set_data: arg error! nameptr:[%p], dataptr:[%p], len:[%d]\n", name,data,len);
		return false;
    }

	if ((tpriv = current_tprivate()) == NULL)
    {
        logdbg_out("tp_set_data: get current private data flg failed!");
		return false;
    }

	// data using this name, has already exist.
	if (tp_getdata_from_priv(tpriv, name) != NULL)
    {
        logdbg_fmt("tp_set_data: name:[%s] already been used!", name);
		return false;
    }

	if (oss_malloc(&thread_data, sizeof(tdata)) < 0)
		return false;
	//if ((thread_data = (tdata*)malloc(sizeof(tdata))) == NULL)
		//return false;
	//if ((tmp_data = (char*)malloc(len)) == NULL)
	if (oss_malloc(&tmp_data, len) < 0)
	{
		oss_free(&thread_data);
		return false;
	}

	strncpy(thread_data->name, name, sizeof(thread_data->name)-1);
	memcpy(tmp_data, data, len);
	thread_data->data = tmp_data;
	thread_data->len = len;

	thread_data->next = tpriv->t_data;
	tpriv->t_data = thread_data;

	return true;
}

bool tp_mod_data(const char *name, const char *data, int len)
{
	tdata *thread_data = NULL;
	char *tmp_data = NULL;

	if ((name == NULL) || (data == NULL) || (len < 0))
		return false;
	if ((thread_data = tp_get_data(name)) == NULL)
		return false;
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

bool tp_rm_data(const char *name)
{
	tprivate *tpriv = NULL;
	tdata *thread_data = NULL;
	tdata *thread_data_tmp = NULL;
	bool res = false;

	if (name == NULL)
		return false;

	if ((tpriv = current_tprivate()) == NULL)
		return false;

	thread_data = tpriv->t_data;	
	thread_data_tmp = thread_data;

	while (thread_data != NULL)
	{
		if (strncmp(name, thread_data->name, sizeof(thread_data->name)) == 0)
		{
			if (thread_data != tpriv->t_data) // is not head data
				thread_data_tmp->next = thread_data->next;
			else	// is head of struct list.
				tpriv->t_data = thread_data->next;
            printf("rm thread_data: %s\n", thread_data->name);
			free(thread_data);
			thread_data = NULL;
			res = true;
			break;
		}

		thread_data_tmp = thread_data;
		thread_data = thread_data->next;
	}

	return res;
}

void tp_clr_data()
{
	tprivate *tpriv = NULL;
	tprivate *tpriv_tmp = NULL;
	tdata *thread_data = NULL;
	tdata *thread_data_tmp = NULL;

pthread_mutex_lock(&s_tp_mutex);
	tpriv = g_tprivate;
	while (tpriv != NULL)
	{
		if (tpriv->thread_id == pthread_self())
			break;
		tpriv_tmp = tpriv;
		tpriv = tpriv->next;
	}

	if (tpriv != NULL)
	{
		if (tpriv == g_tprivate)
			g_tprivate = tpriv->next;
		else
			tpriv_tmp->next = tpriv->next;
	}
pthread_mutex_unlock(&s_tp_mutex);

	// do clear
	if (tpriv != NULL)
	{
		thread_data = tpriv->t_data;
		while (thread_data != NULL)
		{
			thread_data_tmp = thread_data;
			thread_data = thread_data->next;

			free(thread_data_tmp);
		}
		tpriv->t_data = NULL;
		free(tpriv);
	}
}

void tp_show_tdata(tdata *tdata)
{
	if (tdata == NULL)
	{
		puts("tp_show_tdata: tdata is NULL");
	}
	while (tdata != NULL)
	{
		printf("show data:%s\nlen:%d\n", tdata->data, tdata->len);
		tdata = tdata->next;
	}
}

void tp_show_current()
{
	tprivate *tpriv = NULL;
	if ((tpriv = current_tprivate()) == NULL)
	{
		puts("current private is NULL!");
		return;
	}
	tp_show_tdata(tpriv->t_data);
}

void tp_showall()
{
	tprivate *tpriv = NULL;
pthread_mutex_lock(&s_tp_mutex);
	tpriv = g_tprivate;
	while (tpriv != NULL)
	{
		tp_show_tdata(tpriv->t_data);
		tpriv = tpriv->next; 
	}
pthread_mutex_unlock(&s_tp_mutex);
}

