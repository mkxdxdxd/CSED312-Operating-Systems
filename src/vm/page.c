#include "vm/page.h"
#include <string.h>
#include <debug.h>
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "vm/frame.h"

// helper in initialising the hash spt
static hash_hash_func page_hash;
static hash_less_func page_less;

void page_spt_init(struct hash *spt)
{
    //initialise the hash table
    hash_init(spt, page_hash, page_less, NULL); 
}

void page_install_frame(struct hash *spt, void *upage, void *kpage)
{
    /* after allocating the page frame, you install a page in spt
        allocate spt entry, initialise and insert into the hash table*/
    struct page *p;
    ASSERT(is_user_vaddr(upage));
    ASSERT(is_kernel_vaddr(kpage));
    p = (struct page *)malloc(sizeof *p); // allocate supplemental page entry
    p->upage = upage; // initialse upage
    p->kpage = kpage; // initilaise kpage

    /* initialise status 'PAGE_FRAME', inidicating that 
        the page has been allocated in physical frame. */
    p->status = PAGE_FILE;

    p->file_to_read = file;



    if (hash_insert(spt, &p->sptelem)) //insert the spt entry into hash spt
        syscall_exit(-1);

    //printf("***** page_install_frame() : supplemental page table entry for upage 0x%08x is installed *****\n", upage);
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