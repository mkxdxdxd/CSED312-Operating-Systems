#include "vm/page.h"
#include <string.h>
#include <debug.h>
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "vm/frame.h"
#include "vm/swap.h"
#include "filesys/file.h"

// helper in initialising the hash spt
static hash_hash_func page_hash;
static hash_less_func page_less;
static void page_destructor(struct hash_elem *e, void *aux UNUSED);

void page_spt_init(struct hash *spt)
{
    //initialise the hash table
    hash_init(spt, page_hash, page_less, NULL); 
}

void page_install_file(struct hash *spt, void *upage, struct file *file, off_t offset, uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
    /* you install a page in spt allocate spt entry, initialise and insert into the hash table*/
    struct page *p;
    ASSERT(is_user_vaddr(upage));
    ASSERT(file != NULL);
    ASSERT(read_bytes + zero_bytes ==PGSIZE);


    p = (struct page *)malloc(sizeof *p); // allocate supplemental page entry
    p->upage = upage; // initialise upage
    p->kpage = NULL; // change!

    /* initialise status 'PAGE_FILE', inidicating that 
        the page has not been allocated in the memory. */
    p->status = PAGE_FILE;

    p->file_to_read = file;
    p->offset = offset;
    p->read_bytes = read_bytes;
    p->zero_bytes = zero_bytes;
    p->write_able = writable;

    p->swap_idx = -1;
    p->is_dirty = false;


    if (hash_insert(spt, &p->sptelem)) //insert the spt entry into hash spt
        syscall_exit(-1);

    //printf("***** page_install_file() : supplemental page table entry for upage 0x%08x is installed *****\n", upage);
}

void page_install_frame(struct hash *spt, void *upage, void *kpage)
{
    /* you install a page in spt allocate spt entry for stack page, initialise and insert into the hash table*/
    struct page *p;
    ASSERT(is_user_vaddr(upage));
    ASSERT(is_kernel_vaddr(kpage));
    p = (struct page *)malloc(sizeof *p); // allocate supplemental page entry
    p->upage = upage; // initialse upage
    p->kpage = kpage; // initilaise kpage

    /* initialise status 'PAGE_FRAME', inidicating that 
        the page has not been allocated in the memory. */
    p->status = PAGE_FRAME;

    p->file_to_read = NULL;
    p->write_able = true;
    p->swap_idx = -1;
    p->is_dirty = false;

    if (hash_insert(spt, &p->sptelem)) //insert the spt entry into hash spt
        syscall_exit(-1);

    //printf("***** page_install_frame() : supplemental page table entry for upage 0x%08x is installed *****\n", upage);
}

struct page *page_lookup(struct hash *spt, void *upage)
{
    struct page p;
    p.upage = upage;
    struct hash_elem *elem = hash_find(spt, &p.sptelem);

    if (elem != NULL){ //if elem is found in spt hash
        return hash_entry(elem, struct page, sptelem);
    }
    else { //if elem is not found
        return NULL;
    }
}

//helper function in hash table
static unsigned int page_hash(const struct hash_elem *e, void *aux UNUSED)
{
    struct page *p = hash_entry(e, struct page, sptelem);
    return hash_bytes(&p->upage, sizeof p->upage);
}

//helper function in hash table
static bool page_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
    struct page *a_p = hash_entry(a, struct page, sptelem);
    struct page *b_p = hash_entry(b, struct page, sptelem);
    return a_p->upage < b_p->upage;
}


void load_page(struct hash *spt, void *upage, bool unpin)
{
    struct lock *filesys_lock;
    uint32_t *pagedir;

    ASSERT(is_user_vaddr(upage));

    struct page *p= page_lookup(spt,upage);
    if(!p) {
        syscall_exit(-1);
    }

    void *kpage = frame_allocate(PAL_USER, upage);
    if(kpage == NULL)
    {
        syscall_exit(-1);
    }

    if(p->status == PAGE_FILE)
    {
        filesys_lock = syscall_get_filesys_lock();
        lock_acquire(filesys_lock);

        if(file_read_at(p->file_to_read, kpage, p->read_bytes, p->offset) != p->read_bytes)
        {
            frame_free(kpage);
            lock_release(filesys_lock);
            syscall_exit(-1);
        }

        memset(kpage + p->read_bytes, 0, p->zero_bytes);
        lock_release(filesys_lock);
    }
    else if (p->status == PAGE_ZERO){
        memset(kpage, 0, PGSIZE);
    }
    else if (p->status == PAGE_SWAP){
        swap_in(p->swap_idx, kpage);
        p->swap_idx = -1;
    }
    else
        (syscall_exit(-1));

    pagedir = thread_get_pagedir();
    if(!pagedir_set_page(pagedir, upage, kpage, p->write_able))
    {
        frame_free(kpage);
        syscall_exit(-1);
    }

    p->kpage = kpage;
    p->status = PAGE_FRAME;

    if (unpin)
        frame_unpin(kpage);

    return;

}

void page_install_zero(struct hash *spt, void *upage)
{
    // Set spt entry for stack growth, and add it to the table
    ASSERT(is_user_vaddr(upage));
    struct page *p = (struct page *)malloc(sizeof *p);
    p->upage = upage;
    p->kpage = NULL;

    p->status = PAGE_ZERO;

    p->file_to_read = NULL;
    p->write_able = true;
    p->swap_idx = -1;
    p->is_dirty = false;

    if (hash_insert(spt, &p->sptelem))
        syscall_exit(-1);
}

void page_delete(struct hash *spt, void *upage, bool is_dirty)
{
    //delete spt entry from spt & free the frame from phyisical memory
    struct page *p;
    ASSERT(is_user_vaddr(upage));
    //find spt entry from spt using upage
    p = page_lookup(spt, upage);
    if (!p){
        syscall_exit(-1);
    }

    switch(p->status){
    case PAGE_FILE:
    case PAGE_ZERO:
        break;
    case PAGE_SWAP:
        load_page(spt, upage, false);
        is_dirty = true;
        frame_pin(p->kpage);
        if(p->file_to_read && (p->is_dirty || is_dirty)){ 
            //if mmap file has been modified, its data has to be updated to the file in the disk
            file_write_at(p->file_to_read, upage, p->read_bytes, p->offset);
        }
        //free the physical frame
        frame_free(p->kpage);
        break;
    case PAGE_FRAME:
    {   
        //if the page is allocated in the frame, and you want to delete a page
        //syscall_unmap() calls this
        frame_pin(p->kpage);
        if(p->file_to_read && (p->is_dirty || is_dirty)){ 
            //if mmap file has been modified, its data has to be updated to the file in the disk
            file_write_at(p->file_to_read, upage, p->read_bytes, p->offset);
        }
        //free the physical frame
        frame_free(p->kpage);
        break;
    }
    default:
        syscall_exit(-1);
    }
    //remove spt elem from spt
    hash_delete(spt, &p->sptelem);
    //free the spt entry
    free(p);
}

/* Evicts page. Status is set properly. */
void page_evict(struct hash *spt, void *upage, bool is_dirty)
{
    struct page *p;
    ASSERT(is_user_vaddr(upage));

    p = page_lookup(spt, upage);
    if (!p)
        syscall_exit(-1);

    ASSERT(p->status == PAGE_FRAME);
    ASSERT(p->kpage != NULL);

    if (p->is_dirty || is_dirty)
    {
        p->status = PAGE_SWAP;
        p->swap_idx = swap_out(p->kpage);
        p->is_dirty = true;
    }
    else if (p->file_to_read)
        p->status = PAGE_FILE;
    else
        p->status = PAGE_ZERO;

    p->kpage = NULL;
}

void page_spt_destroy(struct hash *spt)
{
    struct lock *frame_table_lock = frame_get_frame_table_lock();

    lock_acquire(frame_table_lock);
    hash_destroy(spt, page_destructor);
    lock_release(frame_table_lock);
}


static void page_destructor(struct hash_elem *e, void *aux UNUSED)
{
    struct page *p;

    p = hash_entry(e, struct page, sptelem);

    if (p->status == PAGE_SWAP)
        swap_free(p->swap_idx);
    else if (p->status == PAGE_FRAME)
        frame_pin(p->kpage);

    free(p);
}


