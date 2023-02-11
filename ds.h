#ifndef _TAPKIT_DS_H_
#define _TAPKIT_DS_H_

#include "common.h"

struct circ_buffer {
  void* const buffer;
  int push_count;
  int pop_count;
  int const size;
  int const element_size;
};

#define _NEW_CIRC_BUFFER(type, buf, sz)           \
  type buf##_data[sz];                            \
  struct circ_buffer buf = {.buffer = buf##_data, \
                            .push_count = 0,      \
                            .pop_count = 0,       \
                            .size = sz,           \
                            .element_size = sizeof(type)};

int _circ_buffer_push(struct circ_buffer* buf, void* elem);
int _circ_buffer_pop(struct circ_buffer* buf, void* elem, int read_only);
int _circ_buffer_free(struct circ_buffer* buf);

#define NEW_CIRC_BUFFER(type, buf, size)                                 \
  _NEW_CIRC_BUFFER(type, buf, size)                                      \
  int buf##_push_refd(type* pt) { return _circ_buffer_push(&buf, pt); }  \
  int buf##_pop_refd(type* pt) { return _circ_buffer_pop(&buf, pt, 0); } \
  int buf##_peek_refd(type* pt) { return _circ_buffer_pop(&buf, pt, 1); }

#define CIRC_BUFFER_FLUSH(buf) \
  do {                         \
    buf.push_count = 0;        \
    buf.pop_count = 0;         \
  } while (0)

#define CIRC_BUFFER_PUSH(buf, elem) buf##_push_refd(elem)

#define CIRC_BUFFER_PEEK(buf, elem) buf##_peek_refd(elem)

#define CIRC_BUFFER_POP(buf, elem) buf##_pop_refd(elem)

#define CIRC_BUFFER_FS(buf) _circ_buffer_free(&buf)

#endif