#include <pthread.h>

/*Define list struct and function*/
typedef struct node{
  char key[64];
  void *val;
  struct node *next;
}node_t;

typedef struct {
  node_t *head;
  pthread_mutex_t lock;
}map_t;

/*****************************************
 *Initialize map.
 ****************************************/
void map_init(map_t *pmap);

/********************************************
 *Search for a node in map with key.
 *******************************************/
void * map_search(map_t *pmap, char *key);
           
/*********************************************
 *Add a new val to map
**********************************************/
int map_add(map_t *pmap, char *key, void *val);

/*****************************************************
 *Delete node from map with key.
 *****************************************************/
int map_del(map_t *pmap, char *key);

/******************************************
 *Display map
 *****************************************/
int map_show(map_t *pmap);

/******************************************
 *Delete all nodes from map
 *****************************************/
int map_clear(map_t *pmap);

/*******************************************************
 *Destroy map
 ******************************************************/
int map_destroy(map_t *pmap);

