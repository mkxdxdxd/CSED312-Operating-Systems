#include "vm/swap.h"
#include "devices/block.h"
#include <bitmap.h>
#include "threads/synch.h"
#include "threads/vaddr.h"

static struct block *swap_block; // we use when swapping
static struct bitmap *swap_table; 
static size_t swap_table_size; //store the swap_table's size
static struct lock swap_table_lock; //when we use swap_table, we have to check lock


void swap_init(void)
{
    /*get the swap_block with block*/
    swap_block = block_get_role(BLOCK_SWAP);
    /*calculate swap_table_size with block_size*/
    swap_table_size = block_size(swap_block) / 8;
    /*make the table with bitmap*/
    swap_table = bitmap_create(swap_table_size);
    /*initialize the swap_table_lock*/
    lock_init(&swap_table_lock);

}

// Bring the page from swap space to memory. Note that swap disk is NOT the same as disk file space
void swap_in(size_t index_swap, void *kpage)
{
    size_t i;

    ASSERT(index_swap < swap_table_size);//if bigger than swap_table_size, assertion
    ASSERT(is_kernel_vaddr(kpage));

    //we have to check swap_table
    lock_acquire(&swap_table_lock);

    /*Copy swap block corresponding to swap_idx to frame connected to kpage*/
    for (i = 0; i < 8; i++)
    {
        block_read(swap_block, index_swap * 8 + i, kpage + i * BLOCK_SECTOR_SIZE); //copy data from swap_block in swap disk to memory buffer
    }
           
    ASSERT(bitmap_test(swap_table, index_swap));
    bitmap_set(swap_table, index_swap, false); //we have to set the swap_table with false

    lock_release(&swap_table_lock);
}

// Copy from memory buffer to swap_block in swap disk. Note that swap disk is NOT the same as disk file space
size_t swap_out(void *kpage)
{
    size_t index_num_swap;
    ASSERT(is_kernel_vaddr(kpage)); //check that kpage is in valid space

    lock_acquire(&swap_table_lock); //to change the swap_table

    index_num_swap = bitmap_scan_and_flip(swap_table, 0, 1, false); //check the swap_table and flip the status and retrun the swap number
    ASSERT(index_num_swap < swap_table_size); //size check and assertion

    size_t i;
    for (i = 0; i < 8; i++)
    {
        block_write(swap_block, index_num_swap * 8 + i, kpage + i * BLOCK_SECTOR_SIZE); //copy data from memory buffer to swap_block in swap disk
    }
               
    lock_release(&swap_table_lock);
    return index_num_swap; //return the number
}


void swap_free(size_t index_swap)
{
    ASSERT(index_swap < swap_table_size); //check that the size and index
    lock_acquire(&swap_table_lock); //to check the swap_table
    ASSERT(bitmap_test(swap_table, index_swap));
    bitmap_set(swap_table, index_swap, false); //setting the swap_table with false in bitmap
    lock_release(&swap_table_lock);
}
