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
    struct list_elem frame_clock_elem;

    bool is_pinned;
};

static struct hash frame_table;
static struct lock frame_table_lock;

static struct frame *frame_lookup(void *kpage);
static void frame_evict(void);
static struct frame *find_victim(void);
static struct list_elem *next_frame_clock(void);

//helpers
static hash_hash_func frame_hash;
static hash_less_func frame_less;

//frame clock algorithm
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
    bool is_held = lock_held_by_current_thread(&frame_table_lock);

    ASSERT(flags & PAL_USER);
    ASSERT(is_user_vaddr(upage));

    if (!is_held)
    lock_acquire(&frame_table_lock);

    kpage = palloc_get_page(flags); //allocation in the memory

    if (!kpage){ //physical page is full..! need to evict a page!
        frame_evict(); //page eviction occur
        kpage = palloc_get_page(flags); //allocate a page in phyisical memory once again
        ASSERT(kpage != NULL);
    }

    //kpage has been allocated, initialise the frame table entry
    f = (struct frame *)malloc(sizeof *f); //allocation using the frame pointer
    f->kpage = kpage;
    f->upage = upage; 
    f->tid = thread_tid();
    f->is_pinned = true; //pin the page when it is first allocated in the physical memory

    hash_insert(&frame_table, &f->ftelem); //insert in frame_table that use hash function
    list_push_back(&frame_clock, &f->frame_clock_elem); //insert in frame_clock that is a list 

    //printf("***** frame_allocate() : frame for upage 0x%08x is allocated at kpage 0x%08x *****\n", upage, kpage);
    if (!is_held)
    lock_release(&frame_table_lock);

    return kpage;
}


void frame_free(void *kpage)
{
    //free the frame from physical memory and free the frame table entry from frame table
    struct frame *f; //to find the frame
    bool is_held = lock_held_by_current_thread(&frame_table_lock);
    ASSERT(is_kernel_vaddr(kpage));

    if (!is_held) //frame_evict may be holding a lock, in this case do not acquire a lock
        lock_acquire(&frame_table_lock);

    f = frame_lookup(kpage); //find the frame with kpage
    if (!f)
        PANIC("Invalid kpage");

    hash_delete(&frame_table, &f->ftelem); //delete the element in hash_table
    list_remove(&f->frame_clock_elem); //delete the element in the list
    palloc_free_page(f->kpage); //palloc_free the kpage

    //remove the entry from page table. page table can be searched with f->tid
    pagedir_clear_page(thread_get_from_tid(f->tid)->pagedir, f->upage); 
    free(f);

    if (!is_held)
        lock_release(&frame_table_lock);
}

static struct frame *frame_lookup(void *kpage)
{
    //find the frame that use kpage from frame table
    struct frame f; //to use the hash function
    struct hash_elem *e;

    f.kpage = kpage;
    e = hash_find(&frame_table, &f.ftelem);

    if(e == NULL)
    {
        return NULL;
    }

    return hash_entry(e, struct frame, ftelem);
}

static void frame_evict(void)
{
    bool is_held = lock_held_by_current_thread(&frame_table_lock);
    if (!is_held) 
        lock_acquire(&frame_table_lock);

    // 1. find victim page that will be evicted
    struct frame *victim_frame = find_victim();
    // 2. get the tid of the victim page as the page entry will be removed from the page table
    struct thread *victim_thread = thread_get_from_tid(victim_frame->tid);
    // 3. check page table if the victim page has been modified
    bool is_dirty = pagedir_is_dirty(victim_thread->pagedir, victim_frame->upage);
    //4. evict the page(execution varies depend on 'is_dirty')
    page_evict(&victim_thread->spt, victim_frame->upage, is_dirty);
    //5. free the frame from the frame table.

    frame_free(victim_frame->kpage);
    if (!is_held)
        lock_release(&frame_table_lock);
}

static struct frame *find_victim(void)
{
    //clock algorithm
    size_t size = list_size(&frame_clock);
    size_t i;
    for (i = 0; i < 2 * size; i++) //iterate over frame clock
    {
        struct frame *frame;
        struct thread *thread;

        frame_clock_hand = next_frame_clock(); //find next element in the list
        frame = list_entry(frame_clock_hand, struct frame, frame_clock_elem); //get information about the frame 
        thread = thread_get_from_tid(frame->tid); //get the tid of the frame taht frame_clock_hand is pointing

        if (!thread)
            PANIC("Invalid tid");

        if (!frame->is_pinned){ //if the frame is pinned, the page should not be evicted from the memory. 

            /* is_accessed is set to 1 by the HW if the page has been accessed.
                if page has been recently accessed, you give a second chance, by setting the bit to 0
                however, if the accessed bit is 0, you select the frame as a victim */
            if (!pagedir_is_accessed(thread->pagedir, frame->upage)) //recently not accessed
                return frame; //victim frame
            else
                pagedir_set_accessed(thread->pagedir, frame->upage, false); //recently accessed 
        }
    }
    PANIC("Cannot find victim");
}

static struct list_elem *next_frame_clock()
{
    //find the next frame in the frame_clock list. 
    if (list_next(frame_clock_hand) == list_end(&frame_clock))
        return list_begin(&frame_clock); //if next is tail, so that the pointer has to move back to the beginning of the list
    else return list_next(frame_clock_hand); //next pointer
}

/* Given tid, remove all frames from frame table, the actual page will be freed in pagedir_destroy() in process_exit()*/
void frame_remove_all(tid_t tid)
{
    /* when tid is given, free all the frames with tid.*/
    struct list_elem *e;
    lock_acquire(&frame_table_lock);
    /* iterate over the frame_clock list. frame is inserted into the frame_clock list when the page is allocated.
        if a frame has tid that is equal to 'tid' given, delete the element from hash table and remove from frame_clock list.
        do not free the actual physical frame. it will be done by pagedir_destroy. */
    for (e = list_begin(&frame_clock); e != list_end(&frame_clock);)
    {
        struct frame *f = list_entry(e, struct frame, frame_clock_elem);
        if (f->tid == tid){
            hash_delete(&frame_table, &f->ftelem); //remove from frame table
            struct list_elem *next_e = list_next(e);
            e = list_remove(e); //remove from frame_clock list
            free(f);
            e = next_e;
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
    /* set the frame status 'pinned', prevent the frame from being evicted! */
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
    /* set the frame status 'unpined', allowing the frame to be evicted! */
    struct frame *f;

    lock_acquire(&frame_table_lock);

    f = frame_lookup(kpage);
    if (!f)
        PANIC("Invalid kpage");

    f->is_pinned = false;

    lock_release(&frame_table_lock);
}