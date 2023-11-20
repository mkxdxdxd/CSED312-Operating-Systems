#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <stdbool.h>
#include <stdint.h>
#include <hash.h>
#include "filesys/file.h"
#include "filesys/off_t.h"

/* States of a page. */
enum page_type
{
    PAGE_FILE, 
    PAGE_ZERO, 
    PAGE_SWAP, 
    PAGE_FRAME 
};

/* struct page: becomes the entry of supplementary page table*/
struct page 
{
    void *upage; // user virtual address
    void *kpage; // kernel virtual address that directly mapps to physical address
    
    struct file *file_to_read;
    off_t offset;
    uint32_t read_bytes, zero_bytes;
    bool write_able;

    enum page_type status; // page type defined just above
    struct hash_elem sptelem; // hash element for supplemental page table
};

//spt init and free
void page_spt_init(struct hash *spt);

//page allocation
void page_install_frame(struct hash *spt, void *upage, void *kpage);

#endif /* vm/page.h */