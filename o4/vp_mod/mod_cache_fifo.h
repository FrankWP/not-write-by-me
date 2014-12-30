#ifndef _MOD_CACHE_FIFO_H_
#define _MOD_CACHE_FIFO_H_

#define MOD_CACHE_SIZE_MAX  1024 * 1024 * 10

//typedef int (*tfunc_reducer)(void *arg, char *data, int sz_data);
typedef int (*tfunc_reducer)(int svr_sock, char *data, int sz_data);

typedef struct _cache_handle
{
    char *buffer_head;
    char *buffer_tail;
    int  sz_buffer;
    int  sz_cache;          // begin to reduce when data size reached sz_cache
    int  b_head_is_head;    // whether cursor_head is head of cursor_tail by address
    char *cursor_head;
    char *cursor_tail;
    tfunc_reducer reducer;
    //void *arg_reducer;
    int arg_reducer;
}cache_handle;


//int mod_cache_fifo_init(cache_handle *h, int size_cache, int size_buf);
//int mod_cache_fifo_init(cache_handle *h, int size_cache, int size_buf, tfunc_reducer reducer, void *arg_reducer);
int mod_cache_fifo_init(cache_handle *h, int size_cache, int size_buf, tfunc_reducer reducer, int svr_sock);
void mod_cache_fifo_destroy(cache_handle *h);
int mod_cache_fifo_produce(cache_handle *h, char *data, int sz_data);
int mod_cache_fifo_reduce_run(cache_handle *h);
//int mod_cache_fifo_reduce_run(cache_handle *h, tfunc_reducer reducer, void *arg_reducer);

#endif  // _MOD_CACHE_FIFO_H_

