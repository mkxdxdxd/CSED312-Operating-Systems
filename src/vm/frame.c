#include "vm/frame.h"
#include <stdbool.h>
#include <stdint.h>
#include <hash.h>
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"

struct frame
{
    //kernel virtual page, stroing address for allocated page in physicall address
    void *kpage;
    //user virtual page, storing virtual address for a page
    void *upage; 

    //id of the thread who has this frame entry
    tid_t tid; 

    //hash element for the frame table
    struct hash_elem list_elem; 
};

static struct hash frame_table;
static struct lock frame_table_lock;

static struct frame *frame_lookup(void *kpage);

//helpers
static hash_hash_func frame_hash;
static hash_less_func frame_less;

void frame_init(void)
{
    //initialize the frame table with hash table
    hash_init(&frame_table, frame_hash, frame_less, NULL);
    //initialize frame_table_lock
    lock_init(&frame_table_lock);
}


static unsigned int frame_hash(const struct hash_elem *e, void *aux UNUSED)
{
    //function for hash_init
    struct frame *f = hash_entry(e, struct frame, list_elem);

    return hash_bytes(&f->kpage, sizeof f->kpage);
}

static bool frame_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
    //function for hash_init to comparing
    struct frame *a_f = hash_entry(a, struct frame, list_elem);
    struct frame *b_f = hash_entry(b, struct frame, list_elem);

    return a_f->kpage < b_f->kpage;
}



void *frame_allocate(enum palloc_flags flags, void *upage)
{
    //allocate the frame with upage
    
    struct frame *f;
    void *kpage; //kernel page to be associated with upage

    ASSERT(flags & PAL_USER);
    ASSERT(is_user_vaddr(upage));

    lock_acquire(&frame_table_lock);

    kpage = palloc_get_page(flags); //allocation in the memory

    if(kpage){
        f = (struct frame *)malloc(sizeof *f); //allocation using the frame pointer

        f->kpage = kpage;
        f->upage = upage; //update the information
        f->tid = thread_tid();

        hash_insert(&frame_table, &f->list_elem); //insert in frame_tabel that use hash function
    }

    //printf("***** frame_allocate() : frame for upage 0x%08x is allocated at kpage 0x%08x *****\n", upage, kpage);
    
    lock_release(&frame_table_lock);

    return kpage;
}


void frame_free(void *kpage)
{
    struct frame *f; //to find the frame

    ASSERT(is_kernel_vaddr(kpage));

    lock_acquire(&frame_table_lock);

    f = frame_lookup(kpage); //find the frame with kpage
    if (!f)
        PANIC("Invalid kpage");

    hash_delete(&frame_table, &f->list_elem); //delete the element in hash_table
    palloc_free_page(f->kpage); //palloc_free the kpage


    pagedir_clear_page(thread_get_from_tid(f->tid)->pagedir, f->upage); //clear page
    free(f);

    lock_release(&frame_table_lock);
}

static struct frame *frame_lookup(void *kpage)
{
    //find the frame that use kpage
    struct frame f; //to use the hash function
    struct hash_elem *e;

    f.kpage = kpage;
    e = hash_find(&frame_table, &f.list_elem);

    if(e==NULL)
    {
        return NULL;
    }

    return hash_entry(e, struct frame, list_elem);
}


