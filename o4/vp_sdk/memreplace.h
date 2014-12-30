#ifndef _MEMREPLACE_H_
#define _MEMREPLACE_H_

typedef struct __find_pos
{
    char *pos;
    int  len;
    struct __find_pos *next;
    struct __find_pos *prev;
}find_pos;

typedef struct __find_mem
{
    find_pos *fnd_pos;
    find_pos *fnd_pos_tail;
    find_pos *loop_cur;	// for loop getting position use.
    int nfind; // how many position have been find.
}find_mem;


void init_find(find_mem *fmem);
void clr_find(find_mem *fmem);
void add_find(find_mem *fmem, char *pfind);
char *loop_find(find_mem *fmem);
void reset_loop_find(find_mem *fmem, bool head);
char *loop_find_back(find_mem *fmem);

//int memreplace_pos(char *pos_b, char *pos_e, char **content, u32 *len, int times, char *src, int nsrc, char *dst, int ndst)
int array_replace(char *array, int sz_array, int *sz_valid,
        char *pos_b, char *pos_e, int times, char *src, int nsrc, char *dst, int ndst);

#endif  // _MEMREPLACE_H_


