#include "../vpheader.h"

//typedef int*(*tfunc_reducer)(void *arg, char *data, int sz_data);
static pthread_mutex_t  g_cache_fifo_mutex = PTHREAD_MUTEX_INITIALIZER;

static void show_x(cache_handle *h)
{
    printf("buffer_head: %p\n", h->buffer_head);
    printf("buffer_tail: %p\n", h->buffer_tail);
    printf("sz_buffer: %d\n", h->sz_buffer);
    printf("sz_cache: %d\n", h->sz_cache);
    printf("b_head_is_head: %d\n", h->b_head_is_head);
    printf("cursor_head: %p\n", h->cursor_head);
    printf("cursor_tail: %p\n", h->cursor_tail);
    printf("reducer: %p\n", h->reducer);
    printf("arg_reducer: %d\n", h->arg_reducer);
    puts("");
}

static int mod_cache_fifo_get_data_size(cache_handle *h)
{
    int size_data  = 0;
    if (h == NULL)
    {
        logwar_out("mod_cache_fifo_get_data_size: invalid argument!");
        return -1;
    }

pthread_mutex_lock(&g_cache_fifo_mutex);
    show_x(h);
    sleep(1000*1000*5);

    if (h->b_head_is_head)
        size_data = h->cursor_tail - h->cursor_head;
    else
        size_data = (h->buffer_tail - h->cursor_head) + (h->cursor_tail - h->buffer_head);
pthread_mutex_unlock(&g_cache_fifo_mutex);

    return size_data;
}

static int mod_cache_fifo_get_data_left_size(cache_handle *h)
{
    int size_data = 0;

    if (h == NULL)
    {
        logwar_out("mod_cache_fifo_get_data_left_size: invalid argument!");
        return -1;
    }

    if ((size_data = mod_cache_fifo_get_data_size(h)) < 0)
    {
        logdbg_fmt("mod_cache_fifo_get_data_left_size: invalid data size %d!", size_data);
        return -1;
    }

    return h->sz_buffer - size_data;
}

static int mod_cache_fifo_write_buffer(cache_handle *h, char *data, int sz_data)
{
    int sz_left = 0;
    char *ptr = NULL;

    logwar_out("mod_cache_fifo_write_buffer: 1");
    if ((h == NULL) || (data == NULL) || (sz_data < 0))
    {
        logwar_out("mod_cache_fifo_write_buffer: invalid arguments!");
        return -1;
    }

    logwar_out("mod_cache_fifo_write_buffer: 2");
    if ((sz_left = mod_cache_fifo_get_data_left_size(h)) < sz_data)
    {
        logwar_out("mod_cache_fifo_write_buffer: memory space not enough!");
        return -1;
    }

    logwar_out("mod_cache_fifo_write_buffer: 3");
    if (h->b_head_is_head)
    {
        int n = 0;
        n = h->buffer_tail - h->cursor_tail;
        if (n >= sz_data)
        {
pthread_mutex_lock(&g_cache_fifo_mutex);
            ptr = h->cursor_tail;
            h->cursor_tail += sz_data;
pthread_mutex_unlock(&g_cache_fifo_mutex);
            //memcpy(h->cursor_tail, data, sz_data);
            memcpy(ptr, data, sz_data);
        }
        else
        {
pthread_mutex_lock(&g_cache_fifo_mutex);
            ptr = h->cursor_tail;
            h->cursor_tail = h->buffer_head + (sz_data - n);
            h->b_head_is_head = 0;
pthread_mutex_unlock(&g_cache_fifo_mutex);
            //memcpy(h->cursor_tail, data, n);
            memcpy(ptr, data, n);
            memcpy(h->buffer_head, data + n, sz_data - n);
        }
    }
    else
    {
pthread_mutex_lock(&g_cache_fifo_mutex);
        ptr = h->cursor_tail;
        h->cursor_tail += sz_data;
pthread_mutex_unlock(&g_cache_fifo_mutex);
        //memcpy(h->cursor_tail, data, sz_data);
        memcpy(ptr, data, sz_data);
    }
     
    return sz_data;
}

static int mod_cache_fifo_read_buffer(cache_handle *h, char *data, int sz_data)
{
    char *ptr = NULL;
    int sz_read = 0;
    int sz_data_left = 0;

    if ((h == NULL) || (data == NULL) || (sz_data < 0))
    {
        logwar_out("mod_cache_fifo_read_buffer: invalid arguments!");
        return -1;
    }

    sz_data_left = mod_cache_fifo_get_data_left_size(h);
    sz_read = sz_data > sz_data_left ? sz_data_left : sz_data;

    if (h->b_head_is_head)
    {
pthread_mutex_lock(&g_cache_fifo_mutex);
        ptr = h->cursor_head;
        h->cursor_head += sz_read;
pthread_mutex_unlock(&g_cache_fifo_mutex);
        //memcpy(data, h->cursor_head, sz_read);
        memcpy(data, ptr, sz_read);
    }
    else
    {
        int n = 0;
        n = h->buffer_tail - h->cursor_head;
        if (n >= sz_read)
        {
pthread_mutex_lock(&g_cache_fifo_mutex);
            ptr = h->cursor_head;
            h->cursor_head += sz_read;
pthread_mutex_unlock(&g_cache_fifo_mutex);
            //memcpy(data, h->cursor_head, sz_read);
            memcpy(data, ptr, sz_read);
        }
        else
        {
pthread_mutex_lock(&g_cache_fifo_mutex);
            ptr = h->cursor_head;
            h->cursor_head = h->buffer_head + (sz_data - n);
            h->b_head_is_head = 1;
pthread_mutex_unlock(&g_cache_fifo_mutex);

            //memcpy(data, h->cursor_head, n);
            memcpy(data, ptr, n);
            memcpy(data + n, h->buffer_head, sz_data - n);
        }
    }
   
    return sz_read;
}

//
//////////////////////////////////////////////////////////////////////////////
//

//int mod_cache_fifo_init(cache_handle *h, int size_cache, int size_buf)
//int mod_cache_fifo_init(cache_handle *h, int size_cache, int size_buf, tfunc_reducer reducer, void *arg_reducer)
int mod_cache_fifo_init(cache_handle *h, int size_cache, int size_buf, tfunc_reducer reducer, int svr_sock)
{
    if ((h == NULL) || (size_cache <= 0) || (size_buf <= 0))
    {
        logwar_out("mod_cache_fifo_init: invalid argumengs!");
        return -1;
    }
    if (size_cache > MOD_CACHE_SIZE_MAX)
    {
        logwar_fmt("mod_cache_fifo_init: size_cache %d is too large!", size_cache);
        return -1;
    }
    if (size_buf < size_cache)
    {
        logwar_fmt("mod_cache_fifo_init: size_cache %d is less than size_buf %d!", size_cache, size_buf);
        return -1;
    }

    //logwar_out("fifo init: 1");
    memset(h, 0, sizeof(cache_handle));
    if (oss_malloc(&h->buffer_head, size_buf) < 0)
    {
        logwar_out("mod_cache_fifo_init: malloc buffer failed!");
        return -1;
    }
    //logwar_out("fifo init: 2");
    h->buffer_tail = h->buffer_head + size_buf;

    h->sz_buffer = size_buf;
    h->sz_cache = size_cache;
    h->b_head_is_head = 1;
    h->cursor_head = h->buffer_head;
    h->cursor_tail = h->cursor_head;
    h->reducer = reducer;
    h->arg_reducer = svr_sock;
    //h->arg_reducer = arg_reducer;

    //logwar_out("fifo init: x");
    show_x(h);
    puts("-----------------------------");
    //sleep(1000*1000*10);
    return 1;
}

void mod_cache_fifo_destroy(cache_handle *h)
{
    if (h == NULL)
        return;

    oss_free(&h->buffer_head);
    memset(h, 0, sizeof(cache_handle));
    pthread_mutex_destroy(&g_cache_fifo_mutex);
}

int mod_cache_fifo_produce(cache_handle *h, char *data, int sz_data)
{
    return mod_cache_fifo_write_buffer(h, data, sz_data);
}

void *reduce_run(void *arg)
{
    int data_size = 0;
    cache_handle *h = (cache_handle*)arg;
    char buf[512] = {0};

    
    while ((data_size = mod_cache_fifo_get_data_size(h)) < h->sz_cache)
    {
        logdbg_fmt("1 reduce_run: data-size %d, cache_size:%d ", data_size, h->sz_cache);
        usleep(1000 * 100);
    }
logdbg_fmt("***** reduce_run: data-size %d, cache_size:%d ", data_size, h->sz_cache);

    while (1)
    {
        mod_cache_fifo_read_buffer(h, buf, sizeof(buf));
        h->reducer(h->arg_reducer, buf, sizeof(buf));
    }

    return NULL;
}

//int mod_cache_fifo_reduce_run(cache_handle *h, tfunc_reducer reducer, void *arg_reducer)
int mod_cache_fifo_reduce_run(cache_handle *h)
{
    int        tret = -1;
    pthread_t  tid;
    cache_handle *hd = NULL;
    
    if (h == NULL)
        return -1;

    oss_malloc(&hd, sizeof(cache_handle));
    memcpy(hd, h, sizeof(cache_handle));

    //tret = pthread_create(&tid, NULL, reduce_run, (void *)h);
    tret = pthread_create(&tid, NULL, reduce_run, hd);
    if (tret != 0)
        return -1;

    pthread_detach(tid);

    return 1;
}

