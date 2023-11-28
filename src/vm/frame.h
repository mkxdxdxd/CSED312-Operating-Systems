#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "threads/palloc.h"
#include "threads/thread.h"

typedef int tid_t;

/* Initialization. */
void frame_init(void);

/* Allocation, free. */
void *frame_allocate(enum palloc_flags, void *);
void frame_free(void *);

void frame_remove_all(tid_t);
void frame_pin(void *kpage);
void frame_unpin(void *kpage);

struct lock *frame_get_frame_table_lock(void);

#endif /* vm/frame.h */
