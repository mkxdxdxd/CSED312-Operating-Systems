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

    size_t index_num_for_swap; //to check the number of swapping page
    bool is_dirty; //if there is experience of dirty

    enum page_type status; // page type defined just above
    struct hash_elem sptelem; // hash element for supplemental page table
};

//spt init and free
void page_spt_init(struct hash *spt);
void page_delete(struct hash *spt, void *upage, bool is_dirty);

//page allocation
void page_install_frame(struct hash *spt, void *upage, void *kpage);
void page_install_file(struct hash *spt, void *upage, struct file *file, off_t offset, uint32_t read_bytes, uint32_t zero_bytes, bool writable);
void page_install_zero(struct hash *spt, void *upage);
void load_page(struct hash *spt, void *upage, bool unpin);

//page search
struct page *page_lookup(struct hash *spt, void *upage);
void page_evict(struct hash *spt, void *upage, bool is_dirty);
void page_spt_destroy(struct hash *spt);



#endif /* vm/page.h */