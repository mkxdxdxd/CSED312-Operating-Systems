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
    struct hash_elem ftelem; 
    //list element for frame clock
    struct list_elem fcelem;
    bool is_pinned;
};

static struct hash frame_table;
static struct lock frame_table_lock;

static struct frame *frame_lookup(void *kpage);
static void frame_evict(void);
static struct frame *frame_find_victim(void);
static struct list_elem *frame_clock_next(struct list_elem *e);


//helpers
static hash_hash_func frame_hash;
static hash_less_func frame_less;

//frame clock
static struct list frame_clock;
static struct list_elem *frame_clock_hand;

void frame_init(void)
{
    //initialize the frame table with hash table
    hash_init(&frame_table, frame_hash, frame_less, NULL);
    
    //initialize frame clock & frame clock hand
    list_init(&frame_clock);
    frame_clock_hand = list_head(&frame_clock);
    //initialize frame_table_lock
    lock_init(&frame_table_lock);
}

static unsigned int frame_hash(const struct hash_elem *e, void *aux UNUSED)
{
    //function for hash_init
    struct frame *f = hash_entry(e, struct frame, ftelem);

    return hash_bytes(&f->kpage, sizeof f->kpage);
}

static bool frame_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
    //function for hash_init to comparing
    struct frame *a_f = hash_entry(a, struct frame, ftelem);
    struct frame *b_f = hash_entry(b, struct frame, ftelem);

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

    if (!kpage){ //physical page is full..! need to evict a page!
        frame_evict();
        kpage = palloc_get_page(flags);
        ASSERT(kpage != NULL);
    }

    //kpage has been allocated, initialise the frame table entry
    f = (struct frame *)malloc(sizeof *f); //allocation using the frame pointer

    f->kpage = kpage;
    f->upage = upage; //update the information
    f->tid = thread_tid();
    f->is_pinned = true;

    hash_insert(&frame_table, &f->ftelem); //insert in frame_tabel that use hash function
    list_push_back(&frame_clock, &f->fcelem);


    //printf("***** frame_allocate() : frame for upage 0x%08x is allocated at kpage 0x%08x *****\n", upage, kpage);
    
    lock_release(&frame_table_lock);

    return kpage;
}


void frame_free(void *kpage)
{
    struct frame *f; //to find the frame
    bool is_held = lock_held_by_current_thread(&frame_table_lock);
    ASSERT(is_kernel_vaddr(kpage));

    if (!is_held)
        lock_acquire(&frame_table_lock);

    f = frame_lookup(kpage); //find the frame with kpage
    if (!f)
        PANIC("Invalid kpage");

    hash_delete(&frame_table, &f->ftelem); //delete the element in hash_table
    list_remove(&f->fcelem);
    palloc_free_page(f->kpage); //palloc_free the kpage


    pagedir_clear_page(thread_get_from_tid(f->tid)->pagedir, f->upage); //clear page
    free(f);

    if (!is_held)
        lock_release(&frame_table_lock);
}

static struct frame *frame_lookup(void *kpage)
{
    //find the frame that use kpage
    struct frame f; //to use the hash function
    struct hash_elem *e;

    f.kpage = kpage;
    e = hash_find(&frame_table, &f.ftelem);

    if(e==NULL)
    {
        return NULL;
    }

    return hash_entry(e, struct frame, ftelem);
}

static void frame_evict(void)
{
    struct frame *victim_f = frame_find_victim();
    struct thread *victim_t = thread_get_from_tid(victim_f->tid);
    bool is_dirty = pagedir_is_dirty(victim_t->pagedir, victim_f->upage);

    page_evict(&victim_t->spt, victim_f->upage, is_dirty);
    frame_free(victim_f->kpage);
}

static struct frame *frame_find_victim(void)
{
    size_t size = list_size(&frame_clock);
    size_t i;
    for (i = 0; i < 2 * size; i++) //change
    {
        struct frame *f;
        struct thread *t;

        frame_clock_hand = frame_clock_next(frame_clock_hand);
        f = list_entry(frame_clock_hand, struct frame, fcelem);
        t = thread_get_from_tid(f->tid);

        if (!t)
            PANIC("Invalid tid");

        if (!f->is_pinned){
            if (!pagedir_is_accessed(t->pagedir, f->upage))
                return f;
            else
                pagedir_set_accessed(t->pagedir, f->upage, false);
        }
    }
    PANIC("Cannot find victim");
}

static struct list_elem *frame_clock_next(struct list_elem *e)
{
    return list_next(frame_clock_hand) == list_end(&frame_clock)
                ? list_begin(&frame_clock)
                : list_next(frame_clock_hand);
}


void frame_delete_all(tid_t tid)
{
    struct list_elem *e;
    lock_acquire(&frame_table_lock);

    for (e = list_begin(&frame_clock); e != list_end(&frame_clock);)
    {
        struct frame *f = list_entry(e, struct frame, fcelem);

        if (f->tid == tid)
        {
            hash_delete(&frame_table, &f->ftelem);
            e = list_remove(e);
            free(f);
        }
        else{
            e = list_next(e);
        }
    }

    lock_release(&frame_table_lock);
}

struct lock *frame_get_frame_table_lock(void)
{
    return &frame_table_lock;
}

void frame_pin(void *kpage)
{
    struct frame *f;
    bool is_held = lock_held_by_current_thread(&frame_table_lock);

    if (!is_held)
        lock_acquire(&frame_table_lock);

    f = frame_lookup(kpage);
    if (!f)
        PANIC("Invalid kpage");

    f->is_pinned = true;

    if (!is_held)
        lock_release(&frame_table_lock);
}

void frame_unpin(void *kpage)
{
    struct frame *f;

    lock_acquire(&frame_table_lock);

    f = frame_lookup(kpage);
    if (!f)
        PANIC("Invalid kpage");

    f->is_pinned = false;

    lock_release(&frame_table_lock);
}
