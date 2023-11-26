#ifndef VM_SWAP_H //have to check
#define VM_SWAP_H //have to check


#include <stddef.h>

/* Initialization. */
void swap_init(void);

/* Swap. */
void swap_in(size_t, void *);
size_t swap_out(void *);

void swap_free(size_t swap_idx);

#endif