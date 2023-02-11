#include "ds.h"

int _circ_buffer_pop(struct circ_buffer* buf, void* elem, int read_only) {
  int total;
  char* tail;

  total = buf->push_count - buf->pop_count;
  if (total < 0) total += (2 * buf->size);

  if (total == 0) {
    return -1;
  }

  tail =
      (char*)buf->buffer + ((buf->pop_count % buf->size) * buf->element_size);

  if (elem) {
    memcpy(elem, tail, buf->element_size);
  }

  if (!read_only) {
    buf->pop_count++;
    if (buf->pop_count >= (2 * buf->size)) buf->pop_count = 0;
  }

  return 0;
}

int _circ_buffer_push(struct circ_buffer* buf, void* elem) {
  int total;
  char* head;

  total = buf->push_count - buf->pop_count;
  if (total < 0) {
    total += (2 * buf->size);
  }

  if (total >= buf->size) {
    return -1;
  }

  head =
      (char*)buf->buffer + ((buf->push_count % buf->size) * buf->element_size);
  memcpy(head, elem, buf->element_size);
  buf->push_count++;
  if (buf->push_count >= (2 * buf->size)) {
    buf->push_count = 0;
  }

  return 0;
}

int _circ_buffer_free_space(struct circ_buffer* buf) {
  int total;

  total = buf->push_count - buf->pop_count;
  if (total < 0) {
    total += (2 * buf->size);
  }

  return buf->size - total;
}