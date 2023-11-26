#include "vm/swap.h"
#include "devices/block.h"
#include <bitmap.h>
#include "threads/synch.h"
#include "threads/vaddr.h"

#define NUM_SECTORS_PER_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)

static struct block *swap_block;
static struct bitmap *swap_table;
static size_t swap_table_size;
static struct lock swap_table_lock;


void swap_init(void)
{
    swap_block = block_get_role(BLOCK_SWAP);
    swap_table_size = block_size(swap_block) / NUM_SECTORS_PER_PAGE;
    swap_table = bitmap_create(swap_table_size);
    lock_init(&swap_table_lock);

}

void swap_in(size_t swap_idx, void *kpage)
{
    size_t i;

    ASSERT(swap_idx < swap_table_size);
    ASSERT(is_kernel_vaddr(kpage));

    lock_acquire(&swap_table_lock);

    for (i = 0; i < NUM_SECTORS_PER_PAGE; i++)
        block_read(swap_block, swap_idx * NUM_SECTORS_PER_PAGE + i,
                   kpage + i * BLOCK_SECTOR_SIZE);

    ASSERT(bitmap_test(swap_table, swap_idx));
    bitmap_set(swap_table, swap_idx, false);

    lock_release(&swap_table_lock);
}

size_t swap_out(void *kpage)
{
    size_t swap_idx;
    size_t i;
    ASSERT(is_kernel_vaddr(kpage));

    lock_acquire(&swap_table_lock);

    swap_idx = bitmap_scan_and_flip(swap_table, 0, 1, false);
    ASSERT(swap_idx < swap_table_size);
    for (i = 0; i < NUM_SECTORS_PER_PAGE; i++)
        block_write(swap_block, swap_idx * NUM_SECTORS_PER_PAGE + i,
                    kpage + i * BLOCK_SECTOR_SIZE);
    lock_release(&swap_table_lock);
    return swap_idx;
}


void swap_free(size_t swap_idx)
{
    ASSERT(swap_idx < swap_table_size);

    lock_acquire(&swap_table_lock);

    ASSERT(bitmap_test(swap_table, swap_idx));
    bitmap_set(swap_table, swap_idx, false);

    lock_release(&swap_table_lock);
}
