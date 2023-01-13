#ifndef _TAPKIT_TPOOL_H_
#define _TAPKIT_TPOOL_H_

#include "common.h"

typedef void (*thread_func_t)(void* arg);

struct tpool_work {
  thread_func_t func;
  void* arg;
  struct tpool_work* next;
};

struct tpool {
  struct tpool_work* work_first;
  struct tpool_work* work_last;
  pthread_mutex_t work_mutex;
  pthread_cond_t work_cond;
  pthread_cond_t working_cond;
  size_t working_cnt;
  size_t thread_cnt;
  bool stop;
};

struct tpool* tpool_create(size_t num);

void tpool_destroy(struct tpool* tm);

bool tpool_add_work(struct tpool* tm, thread_func_t func, void* arg);

void tpool_wait(struct tpool* tm);

#endif