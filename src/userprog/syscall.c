#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "lib/kernel/stdio.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"

#include "threads/malloc.h"
#include "vm/page.h"

static struct lock filesys_lock;

static void syscall_handler(struct intr_frame *);
static void check_address(const void *vaddr);
void check (int *esp, int count);

static void syscall_halt(void);
static pid_t syscall_exec(const char *file);
static int syscall_wait(pid_t pid);
static bool syscall_create(const char *file, unsigned initial_size);
static bool syscall_remove(const char *file);
static int syscall_open(const char *file);
static int syscall_filesize(int fd);
static int syscall_read(int fd, void *buffer, unsigned size);
static int syscall_write(int fd, void *buffer, unsigned size);
static void syscall_seek(int fd, unsigned position);
static unsigned syscall_tell(int fd);
static mapid_t syscall_mmap(int fd, void *addr);

// struct lock *get_file_lock(void)
// {
//     return &filesys_lock;
// }

/* Registers the system call interrupt handler. */
void syscall_init(void)
{
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
    lock_init(&filesys_lock);
}

static void
syscall_handler(struct intr_frame *f UNUSED)
{
    void *esp = f->esp;
    int syscall_num;

    check(esp, 1);
    syscall_num = *(int *)esp;

#ifdef VM
    thread_set_esp(esp); //store and set the user stack pointer
#endif

    switch (syscall_num)
    {
    case SYS_HALT:
    {
        syscall_halt();
        NOT_REACHED();
    }
    case SYS_EXIT:
    {
        check(esp, 2);
        int exit_status = *(int *)(esp + sizeof(uintptr_t));

        syscall_exit(exit_status);
        NOT_REACHED();
    }
    case SYS_EXEC:
    {
        check(esp, 2);
        char *file_name = *(char **)(esp + sizeof(uintptr_t));

        f->eax = (uint32_t)syscall_exec(file_name);
        break;
    }
    case SYS_WAIT:
    {
        check(esp, 2);
        pid_t process_id = *(pid_t *)(esp + sizeof(uintptr_t));

        f->eax = (uint32_t)syscall_wait(process_id);
        break;
    }
    case SYS_CREATE:
    {
        check(esp, 3);
        char *file_name = *(char **)(esp + sizeof(uintptr_t));
        unsigned file_size = *(unsigned *)(esp + 2 * sizeof(uintptr_t));

        f->eax = (uint32_t)syscall_create(file_name, file_size);
        break;
    }
    case SYS_REMOVE:
    {
        check(esp, 2);
        char *file_name = *(char **)(esp + sizeof(uintptr_t));

        f->eax = (uint32_t)syscall_remove(file_name);
        break;
    }
    case SYS_OPEN:
    {
        check(esp, 2);
        char *file_name = *(char **)(esp + sizeof(uintptr_t));

        f->eax = (uint32_t)syscall_open(file_name);
        break;
    }
    case SYS_FILESIZE:
    {
        check(esp, 2);

        int fd_idx = *(int *)(esp + sizeof(uintptr_t));

        f->eax = (uint32_t)syscall_filesize(fd_idx);
        break;
    }
    case SYS_READ:
    {
        check(esp, 4);

        int fd_idx = *(int *)(esp + sizeof(uintptr_t));
        void *buffer_address = *(void **)(esp + 2 * sizeof(uintptr_t));
        unsigned file_size = *(unsigned *)(esp + 3 * sizeof(uintptr_t));

        f->eax = (uint32_t)syscall_read(fd_idx, buffer_address, file_size);
        break;
    }
    case SYS_WRITE:
    {
        check(esp, 4);
        int fd_idx = *(int *)(esp + sizeof(uintptr_t));
        void *buffer_address = *(void **)(esp + 2 * sizeof(uintptr_t));
        unsigned file_size = *(unsigned *)(esp + 3 * sizeof(uintptr_t));

        f->eax = (uint32_t)syscall_write(fd_idx, buffer_address, file_size);
        break;
    }
    case SYS_SEEK:
    {
        check(esp, 3);
        int fd_idx = *(int *)(esp + sizeof(uintptr_t));
        unsigned ptr = *(unsigned *)(esp + 2 * sizeof(uintptr_t));

        syscall_seek(fd_idx, ptr);
        break;
    }
    case SYS_TELL:
    {
        check(esp, 2);
        int fd_idx = *(int *)(esp + sizeof(uintptr_t));

        f->eax = (uint32_t)syscall_tell(fd_idx);
        break;
    }
    case SYS_CLOSE:
    {
        check(esp, 2);
        int fd_idx = *(int *)(esp + sizeof(uintptr_t));

        syscall_close(fd_idx);
        break;
    }
    #ifdef VM
    case SYS_MMAP:
    {
        check(esp, 3);
        int fd= *(int *)(esp + sizeof(uintptr_t));
        void *addr = *(void **)(esp + 2*sizeof(uintptr_t));

        f->eax = (uint32_t)syscall_mmap(fd, addr);
        break;
    }
    case SYS_MUNMAP:
    {   
        check(esp, 2);
        mapid_t mpid = *(int *)(esp + sizeof(uintptr_t));
        
        syscall_munmap(mpid);
        break;
    }

    #endif

    default:
        syscall_exit(-1);
    }
}

static void
check_address(const void *vaddr)
{
    #ifdef VM
    if (!vaddr || !is_user_vaddr(vaddr)) //in Virtual Memory, we don't need to check the pagedir
        syscall_exit(-1);

    return;
    #endif
    
    if (!vaddr || !is_user_vaddr(vaddr) ||
        !pagedir_get_page(thread_current()->pagedir, vaddr))
        syscall_exit(-1);
}

static void syscall_halt(void)
{
    shutdown_power_off();
}

void syscall_exit(int exit_status)
{
    struct process *pcb = thread_current()->pcb;
    pcb->exit_status = exit_status;
    printf("%s: exit(%d)\n", thread_name(), exit_status);

    // exit process, so files have to be closed.
    

    thread_exit(); //inside thread_exit(), process_exit() is called, and handle parent-child relationship.
}

static pid_t
syscall_exec(const char *file_name)
{
    /* During syscall_exec, parent process does not need to wait for a child to exit. 
        Instead, it waits only til a child process loads to the memory.
        Two threads are independent. */
    pid_t pid;
    struct process *child = NULL;
    int i;
     
    check_address(file_name);
    for (i = 0; *(file_name + i); i++)
        check_address(file_name + i + 1);

    pid = process_execute(file_name);
    
    /* find child with 'pid' in child list and check if its pcb has been successfuly loaded
        if it has been successfully loaded, return pid, if not, return PID_ERROR.*/
    struct list *children = &thread_current()->children;
    struct list_elem *e;
    for (e = list_begin(children); e != list_end(children); e = list_next(e)){
        struct process *pcb = list_entry(e, struct process, childelem);
        if (pcb->pid == pid){
            child = pcb;
            break;
        }
    }

    if (!child || !child->is_load)
        return PID_ERROR;

    return pid;
}

static int
syscall_wait(pid_t process_id)
{
    // wait for 'proceess_id' process to exit
    return process_wait(process_id);
}

static bool
syscall_create(const char *file_name, unsigned file_size)
{
    bool success;
    int i;

    check_address(file_name);
    for (i = 0; *(file_name + i); i++)
        check_address(file_name + i + 1);

    //create file with 'file_name' and 'file_size'
    lock_acquire(&filesys_lock);
    success = filesys_create(file_name, (off_t)file_size);
    lock_release(&filesys_lock);

    return success;
}

static bool
syscall_remove(const char *file_name)
{
    bool success;
    int i;

    check_address(file_name);
    for (i = 0; *(file_name + i); i++)
        check_address(file_name + i + 1);

    //remove file with file_name
    lock_acquire(&filesys_lock);
    success = filesys_remove(file_name);
    lock_release(&filesys_lock);

    return success;
}

// file related sycall
static int
syscall_open(const char *file_name)
{

    struct file *file_created;
    int i, j, return_num;

    check_address(file_name);
    for (i = 0; *(file_name + i); i++)
        check_address(file_name + i + 1);

    //open file with 'file_name'
    lock_acquire(&filesys_lock);
    file_created = filesys_open(file_name);
    if (!file_created){ //if open failed, release lock and return -1
        lock_release(&filesys_lock);
        return -1;
    }

    /* if open succeeds, loop around fdt_list and put the pointer in the list*/
    for (j = 2; j < 131; j++){
        if (thread_current()->fdt_list[j] == NULL){
            thread_current()->fdt_list[j] = file_created;
            return_num = j;
            break;
        }
    }
    lock_release(&filesys_lock);
    return return_num;
}
static int
syscall_filesize(int fd_idx)
{
    int filesize;
    if (thread_current()->fdt_list[fd_idx] == NULL){ //fild not found
        syscall_exit(-1);
    }  

    //return filesize, of which has fdt index 'fd_idx'
    lock_acquire(&filesys_lock);
    filesize = file_length(thread_current()->fdt_list[fd_idx]);
    lock_release(&filesys_lock);

    return filesize;
}

static int
syscall_read(int fd_idx, void *buffer_address, unsigned file_size)
{
    int bytes_read, i;

    //check if buffer is large enough to fit the file with file_size
    for (i = 0; i < file_size; i++)
        check_address(buffer_address + i);

    //STDIN, read from the buffer
    if (fd_idx == 0){
        unsigned i;
        for (i = 0; i < file_size; i++)
            *(uint8_t *)(buffer_address + i) = input_getc();
        return file_size;
    }

    //if fd_idx is invalidn or fd_idx is empty, exit the process.
    if (fd_idx < 2 || fd_idx>130 ||thread_current()->fdt_list[fd_idx] == NULL)
    {
        syscall_exit(-1);
    }

    //read inforamtion from the file
    lock_acquire(&filesys_lock);
    bytes_read = (int)file_read(thread_current()->fdt_list[fd_idx], buffer_address, (off_t)file_size);
    lock_release(&filesys_lock);

    return bytes_read;
}
static int
syscall_write(int fd_idx, void *buffer_address, unsigned file_size)
{

    int bytes_written, i;

    //check if buffer is large enough to read the file with file_size.
    for (i = 0; i < file_size; i++)
        check_address(buffer_address + i);

    //STDOUT, write on the buffer.
    if (fd_idx == 1){
        putbuf((const char *)buffer_address, (size_t)file_size);
        return file_size;
    }

    //if fd_idx is invalid or fd_idx is empty, exit the process.
    if (fd_idx < 2 || fd_idx>130 ||thread_current()->fdt_list[fd_idx] == NULL){
        syscall_exit(-1);
    }

    //write on file
    lock_acquire(&filesys_lock);
    bytes_written = (int)file_write(thread_current()->fdt_list[fd_idx], buffer_address, (off_t)file_size);
    lock_release(&filesys_lock);

    return bytes_written;
}
static void
syscall_seek(int fd_idx, unsigned ptr)
{   
    //fd_idx has no file to seek
    if (thread_current()->fdt_list[fd_idx] == NULL){ 
        syscall_exit(-1);
    }
    //move the file pointer to ptr
    lock_acquire(&filesys_lock);
    file_seek(thread_current()->fdt_list[fd_idx], (off_t)ptr);
    lock_release(&filesys_lock);
}

static unsigned
syscall_tell(int fd_idx)
{
    unsigned pos;
    if (thread_current()->fdt_list[fd_idx] == NULL){
        syscall_exit(-1);
    }
    //find the location of the ptr and return
    lock_acquire(&filesys_lock);
    pos = (unsigned)file_tell(thread_current()->fdt_list[fd_idx]);
    lock_release(&filesys_lock);

    return pos;
}

void syscall_close(int fd_idx)
{
    //if fd_idx is invalid or fd_idx is empty, exit the process.
    if (fd_idx < 2 || fd_idx>130 || thread_current()->fdt_list[fd_idx] == NULL){
        syscall_exit(-1);
    }

    lock_acquire(&filesys_lock);
    file_close(thread_current()->fdt_list[fd_idx]);
    thread_current()->fdt_list[fd_idx] = NULL;
    lock_release(&filesys_lock);
}

void check (int *esp, int count)
{
  int i;
  check_address(esp + sizeof(uintptr_t));
  for (i = 1; i <= count; i++)
  {
    check_address(esp + count * sizeof(uintptr_t) - 1);
  }
}

struct lock *syscall_get_filesys_lock(void)
{
    return &filesys_lock;
}

#ifdef VM
static mapid_t syscall_mmap(int fd, void *addr)
{
    if (is_kernel_vaddr(addr))
        syscall_exit(-1);

    if(!addr||pg_ofs(addr)||fd<=1) //check that address and page offset are valid value
    {
        return -1;
    }
    if(!(thread_current()->fdt_list))
    {
        return -1;
    }
    //look up the file descriptor table with fd
    lock_acquire(&filesys_lock);
    struct file* file;
    //if(!file) //if there is no file, we have to return
    //{
       // return -1;
    //}
    //open the file
    
    file = file_reopen(thread_current()->fdt_list[fd]); //reopen the file
    if(! file) //if there is no file, return
    {
        lock_release(&filesys_lock);
        return -1;
    }
    //get the file size
    off_t size = file_length(file);
    if(size == 0)
    {
        lock_release(&filesys_lock);
        return -1;
    }
    lock_release(&filesys_lock);
    /* look up spt and if the given parameter 'addr' already exists in the spt, 
        you should not map a file. */
    for(off_t i = 0; i < size; i += PGSIZE)
    {
        if(page_lookup(&thread_current()->spt, addr+i))
        {
            return -1;
        }
    }
    /*map a file to the memory, using page_install_file, allocate spt entry. 
        NOTE that mmap does not 'load' a file into a physical frame, instead it allocates spt entry
        real loading occurs when the process access to address of the memory mapped file! */
    for (off_t j = 0; j < size; j += PGSIZE)
    {
        void *upage = addr + j;
        uint32_t read_bytes;
        if(size - j >= PGSIZE){ //if size is bigger than page size(4KB)
            read_bytes = PGSIZE;
        }
        else{
            read_bytes = size - j;
        }
        uint32_t zero_bytes = PGSIZE - read_bytes;
        //allocate spt entry!
        page_install_file(&thread_current()->spt, upage, file, j, read_bytes, zero_bytes, true);
    }
    //set the mmap table
    struct mdt_entry* mde = (struct mdt_entry*) malloc(sizeof* mde);
    mde->mapid = thread_current()->next_mapid++;
    mde->file = file;
    mde->size = size;
    mde->upage = addr;
    list_push_back(&thread_current()->mdt, &mde->mdt_elem); //push the mdt_elem in current thread's mdt
    return mde->mapid; //if all set, return the mapid
}

void syscall_munmap(mapid_t mapid)
{
    struct mdt_entry* mde = process_get_mde(mapid);
    if (!mde) return; //if therer is no mde in current process, we have to return

    lock_acquire(&filesys_lock); 
    uint32_t* pagedir = thread_current()->pagedir;

    /*delete all memory mapped spt entry. If file elements are change,
    we have to set dirty bit. When delete the page, we have to check the dirty bit*/

    for (off_t i = 0; i < mde->size; i += PGSIZE) {
        bool is_dirty = pagedir_is_dirty(pagedir, mde->upage + i);
        page_delete(&thread_current()->spt, mde->upage + i, is_dirty);
    }

    file_close(mde->file); //close the reopend file
    list_remove(&mde->mdt_elem); //remove the mde form mdt
    free(mde); //free the mde that allocated before
    lock_release(&filesys_lock);//if finish, lock release
}
#endif