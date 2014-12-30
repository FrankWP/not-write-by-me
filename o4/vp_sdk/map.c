#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "map.h"

/*****************************************
 *Initialize map.
 ****************************************/
void map_init(map_t *pmap)
{
  pmap->head = NULL;
  pthread_mutex_init(&pmap->lock, NULL);
}

/********************************************
 *Search for a node in map with key.
 *******************************************/
void * map_search(map_t *pmap, char *key)
{
  node_t *node;
  int rtn;

  /*Find node from map*/
  if(0 != (rtn = pthread_mutex_lock(&pmap->lock))){
    printf("[%s:%d]pthread_mutex_lock:%s.\n",
           __FILE__,__LINE__,strerror(rtn));
    return NULL;
  }

  node = pmap->head;
  while(node){
    if(0 == strcmp(key,node->key))
      break;

    node = node->next;
  }

  if(0 != (rtn = pthread_mutex_unlock(&pmap->lock))){
    printf("[%s:%d]pthread_mutex_uplock:%s.\n",
           __FILE__,__LINE__,strerror(rtn));
    return NULL;							
  }

  if(node)
    return node->val;
  else
    return NULL;
}

/*********************************************
 *Add a new val to map
**********************************************/
int map_add(map_t *pmap, char *key, void *val)
{
  node_t *node;
  int rtn;

  if(0 != (rtn = pthread_mutex_lock(&pmap->lock))){
    printf("[%s:%d]pthread_mutex_lock:%s.\n",
           __FILE__,__LINE__,strerror(rtn));
    return -1;
  }

  node = pmap->head;
  while(node){
    if(0 == strcmp(key, node->key))
      break;
    node = node->next;
  }
     
  if(NULL != node){
    if(0 != (rtn = pthread_mutex_unlock(&pmap->lock))){
      printf("[%s:%d]pthread_mutex_uplock:%s.\n",
             __FILE__,__LINE__,strerror(rtn));
      return -1;
    }
    return 1;

  }else{
    node = (node_t *)malloc(sizeof(node_t));
    strcpy(node->key, key);
    node->val = val;
    node->next = pmap->head;
    pmap->head = node;
  }

  if(0 != (rtn = pthread_mutex_unlock(&pmap->lock))){
    printf("[%s:%d]pthread_mutex_uplock:%s.\n",
           __FILE__,__LINE__,strerror(rtn));
    return -1;
  }

  return 0;
}

/*****************************************************
 *Delete node from map with key.
 *****************************************************/
int map_del(map_t *pmap, char *key)
{
  node_t *cur, *pre;
  int    rtn;

  if(0 != (rtn = pthread_mutex_lock(&pmap->lock))){
    printf("[%s:%d]pthread_mutex_lock:%s.\n",
           __FILE__,__LINE__,strerror(rtn));
    return -1;
  }

  pre = cur = pmap->head;
  while(cur){
    if(0 == strcmp(key, cur->key)){
      if(cur ==  pmap->head)
        pmap->head = cur->next;
      else
        pre->next = cur->next;
      
      free(cur->val);
      free(cur);

      break;
    }else{
      pre = cur;
      cur = cur->next;
    }
  }
  if(0 != (rtn = pthread_mutex_unlock(&pmap->lock))){
    printf("[%s:%d]pthread_mutex_uplock:%s.\n",
           __FILE__,__LINE__,strerror(rtn));
    return -1;
  }

  return 0;
}

/******************************************
 *Display map
 *****************************************/
int map_show(map_t *pmap)
{
  node_t *node;
  int rtn;

  if(0 != (rtn = pthread_mutex_lock(&pmap->lock))){
    printf("[%s:%d]pthread_mutex_lock:%s.\n",
           __FILE__,__LINE__,strerror(rtn));
    return -1;
  }

  node = pmap->head;
  while(node){
    printf("key:%s\n",node->key);
    node = node->next;
  }

  if(0 != (rtn = pthread_mutex_unlock(&pmap->lock))){
    printf("[%s:%d]pthread_mutex_uplock:%s.\n",
           __FILE__,__LINE__,strerror(rtn));
    return -1;
  }

  return 0;
}

/******************************************
 *Delete all nodes from map
 *****************************************/
int map_clear(map_t *pmap)
{
  node_t *cur,*pre;
  int rtn;

  if(0 != (rtn = pthread_mutex_lock(&pmap->lock))){
    printf("[%s:%d]pthread_mutex_lock:%s.\n",
	   __FILE__,__LINE__,strerror(rtn));
    return -1;
  }

  cur = pmap->head;
  while(cur){
    pre = cur;
    cur = cur->next;
    free(pre->val);
    free(pre);
  }

  pmap->head = NULL;

  if(0 != (rtn = pthread_mutex_unlock(&pmap->lock))){
    printf("[%s:%d]pthread_mutex_uplock:%s.\n",
           __FILE__,__LINE__,strerror(rtn));
    return -1;
  }

  return 0;
}

/*******************************************************
 *Destroy map
 ******************************************************/
int map_destroy(map_t *pmap)
{
  node_t *cur,*pre;
  int rtn;

  if(0 != (rtn = pthread_mutex_lock(&pmap->lock))){
    printf("[%s:%d]pthread_mutex_lock:%s.\n",
	   __FILE__,__LINE__,strerror(rtn));
    return -1;
  }

  cur = pmap->head;
  while(cur){
    pre = cur;
    cur = cur->next;
    free(pre->val);
    free(pre);
  }

  pmap->head = NULL;

  if(0 != (rtn = pthread_mutex_unlock(&pmap->lock))){
    printf("[%s:%d]pthread_mutex_uplock:%s.\n",
           __FILE__,__LINE__,strerror(rtn));
    return -1;
  }

  free(pmap);

  return 0;
}
