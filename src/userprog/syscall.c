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

static struct lock filesys_lock;

static void syscall_handler(struct intr_frame *);
static void check_vaddr(const void *vaddr);

static void syscall_halt(void);
static pid_t syscall_exec(const char *file);
static int syscall_wait(pid_t pid);
static bool syscall_create(const char *file, unsigned initial_size);
static bool syscall_remove(const char *file);
static int syscall_open(const char *file);
static int syscall_filesize(int fd);
static int syscall_read(int fd, void *buffer, unsigned size);
static int syscall_write(int fd, void *buffer, unsigned size);
static int syscall_seek(int fd, unsigned position);
static unsigned syscall_tell(int fd);

struct lock *syscall_get_filesys_lock(void)
{
    return &filesys_lock;
}

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

    check_vaddr(esp);
    check_vaddr(esp + sizeof(uintptr_t) - 1);
    syscall_num = *(int *)esp;

    switch (syscall_num)
    {
    case SYS_HALT:
    {
        syscall_halt();
        NOT_REACHED();
    }
    case SYS_EXIT:
    {
        int status;

        check_vaddr(esp + sizeof(uintptr_t));
        check_vaddr(esp + 2 * sizeof(uintptr_t) - 1);
        status = *(int *)(esp + sizeof(uintptr_t));

        syscall_exit(status);
        NOT_REACHED();
    }
    case SYS_EXEC:
    {
        char *cmd_line;

        check_vaddr(esp + sizeof(uintptr_t));
        check_vaddr(esp + 2 * sizeof(uintptr_t) - 1);
        cmd_line = *(char **)(esp + sizeof(uintptr_t));

        f->eax = (uint32_t)syscall_exec(cmd_line);
        break;
    }
    case SYS_WAIT:
    {
        pid_t pid;

        check_vaddr(esp + sizeof(uintptr_t));
        check_vaddr(esp + 2 * sizeof(uintptr_t) - 1);
        pid = *(pid_t *)(esp + sizeof(uintptr_t));

        f->eax = (uint32_t)syscall_wait(pid);
        break;
    }
    case SYS_CREATE:
    {
        char *file;
        unsigned initial_size;

        check_vaddr(esp + sizeof(uintptr_t));
        check_vaddr(esp + 3 * sizeof(uintptr_t) - 1);
        file = *(char **)(esp + sizeof(uintptr_t));
        initial_size = *(unsigned *)(esp + 2 * sizeof(uintptr_t));

        f->eax = (uint32_t)syscall_create(file, initial_size);
        break;
    }
    case SYS_REMOVE:
    {
        char *file;

        check_vaddr(esp + sizeof(uintptr_t));
        check_vaddr(esp + 2 * sizeof(uintptr_t) - 1);
        file = *(char **)(esp + sizeof(uintptr_t));

        f->eax = (uint32_t)syscall_remove(file);
        break;
    }
    case SYS_OPEN:
    {
        char *file;

        check_vaddr(esp + sizeof(uintptr_t));
        check_vaddr(esp + 2 * sizeof(uintptr_t) - 1);
        file = *(char **)(esp + sizeof(uintptr_t));

        f->eax = (uint32_t)syscall_open(file);
        break;
    }
    case SYS_FILESIZE:
    {
        int fd;

        check_vaddr(esp + sizeof(uintptr_t));
        check_vaddr(esp + 2 * sizeof(uintptr_t) - 1);
        fd = *(int *)(esp + sizeof(uintptr_t));

        f->eax = (uint32_t)syscall_filesize(fd);
        break;
    }
    case SYS_READ:
    {
        int fd;
        void *buffer;
        unsigned size;

        check_vaddr(esp + sizeof(uintptr_t));
        check_vaddr(esp + 4 * sizeof(uintptr_t) - 1);
        fd = *(int *)(esp + sizeof(uintptr_t));
        buffer = *(void **)(esp + 2 * sizeof(uintptr_t));
        size = *(unsigned *)(esp + 3 * sizeof(uintptr_t));

        f->eax = (uint32_t)syscall_read(fd, buffer, size);
        break;
    }
    case SYS_WRITE:
    {
        int fd;
        void *buffer;
        unsigned size;

        check_vaddr(esp + sizeof(uintptr_t));
        check_vaddr(esp + 4 * sizeof(uintptr_t) - 1);
        fd = *(int *)(esp + sizeof(uintptr_t));
        buffer = *(void **)(esp + 2 * sizeof(uintptr_t));
        size = *(unsigned *)(esp + 3 * sizeof(uintptr_t));

        f->eax = (uint32_t)syscall_write(fd, buffer, size);
        break;
    }
    case SYS_SEEK:
    {
        int fd;
        unsigned position;

        check_vaddr(esp + sizeof(uintptr_t));
        check_vaddr(esp + 3 * sizeof(uintptr_t) - 1);
        fd = *(int *)(esp + sizeof(uintptr_t));
        position = *(unsigned *)(esp + 2 * sizeof(uintptr_t));

        syscall_seek(fd, position);
        break;
    }
    case SYS_TELL:
    {
        int fd;

        check_vaddr(esp + sizeof(uintptr_t));
        check_vaddr(esp + 2 * sizeof(uintptr_t) - 1);
        fd = *(int *)(esp + sizeof(uintptr_t));

        f->eax = (uint32_t)syscall_tell(fd);
        break;
    }
    case SYS_CLOSE:
    {
        int fd;

        check_vaddr(esp + sizeof(uintptr_t));
        check_vaddr(esp + 2 * sizeof(uintptr_t) - 1);
        fd = *(int *)(esp + sizeof(uintptr_t));

        syscall_close(fd);
        break;
    }
    default:
        syscall_exit(-1);
    }
}

static void
check_vaddr(const void *vaddr)
{
    if (!vaddr || !is_user_vaddr(vaddr) ||
        !pagedir_get_page(thread_current()->pagedir, vaddr))
        syscall_exit(-1);
}

static void syscall_halt(void)
{
    shutdown_power_off();
}

void syscall_exit(int status)
{
    struct process *pcb = thread_current()->pcb;
    pcb->exit_status = status;
    printf("%s: exit(%d)\n", thread_name(), status);

    int i;
    for (i = 2; i < 131; i++) {
        if (thread_current()->fdt_list[i] != NULL) {
            syscall_close(i);
        }
    }

    thread_exit(); //Inside thread_exit(), process_exit() is called.
}

static pid_t
syscall_exec(const char *cmd_line)
{
    /* During syscall_exec, parent process does not need to wait for a child to exit. 
        Instead, it waits only til a child process loads to the memory.
        Two threads are independent. */
    pid_t pid;
    struct process *child = NULL;
    int i;

    check_vaddr(cmd_line);
    for (i = 0; *(cmd_line + i); i++)
        check_vaddr(cmd_line + i + 1);

    pid = process_execute(cmd_line);
    
    /* find child with 'pid' in child list and check if its pcb has been successfuly loaded
        if it has been successfully loaded, return pid, if not, return PID_ERROR.*/

    struct list *children = &thread_current()->children;
    struct list_elem *e;

    for (e = list_begin(children); e != list_end(children); e = list_next(e))
    {
        struct process *pcb = list_entry(e, struct process, childelem);

        if (pcb->pid == pid)
        {
            child = pcb;
            break;
        }
    }


    if (!child || !child->is_loaded)
        return PID_ERROR;

    return pid;
}

static int
syscall_wait(pid_t pid)
{
    return process_wait(pid);
}

static bool
syscall_create(const char *file, unsigned initial_size)
{
    bool success;
    int i;

    check_vaddr(file);
    for (i = 0; *(file + i); i++)
        check_vaddr(file + i + 1);

    lock_acquire(&filesys_lock);
    success = filesys_create(file, (off_t)initial_size);
    lock_release(&filesys_lock);

    return success;
}

static bool
syscall_remove(const char *file)
{
    bool success;
    int i;

    check_vaddr(file);
    for (i = 0; *(file + i); i++)
        check_vaddr(file + i + 1);

    lock_acquire(&filesys_lock);
    success = filesys_remove(file);
    lock_release(&filesys_lock);

    return success;
}

// file related sycall
static int
syscall_open(const char *file)
{

    struct file *new_file;
    int i, j, return_num;

    check_vaddr(file);
    for (i = 0; *(file + i); i++)
        check_vaddr(file + i + 1);

    lock_acquire(&filesys_lock);

    new_file = filesys_open(file);
    if (!new_file)
    {
        lock_release(&filesys_lock);

        return -1;
    }

    for (j = 2; j < 131; j++)
    {
        if (thread_current()->fdt_list[j] == NULL)
        {
            thread_current()->fdt_list[j] = new_file;
            return_num = j;
            break;
        }
    }

    lock_release(&filesys_lock);
    return return_num;
}
static int
syscall_filesize(int fd)
{

    int filesize;

    if (thread_current()->fdt_list[fd] == NULL)
    {
        //return -1;
        syscall_exit(-1);
    }

    lock_acquire(&filesys_lock);
    filesize = file_length(thread_current()->fdt_list[fd]);
    lock_release(&filesys_lock);

    return filesize;
}
static int
syscall_read(int fd, void *buffer, unsigned size)
{

    int bytes_read, i;

    for (i = 0; i < size; i++)
        check_vaddr(buffer + i);

    if (fd == 0)
    {
        unsigned i;

        for (i = 0; i < size; i++)
            *(uint8_t *)(buffer + i) = input_getc();

        return size;
    }

    if (fd < 2 || fd>130 ||thread_current()->fdt_list[fd] == NULL)
    {
        //return -1;
        syscall_exit(-1);
    }

    lock_acquire(&filesys_lock);
    bytes_read = (int)file_read(thread_current()->fdt_list[fd], buffer, (off_t)size);
    lock_release(&filesys_lock);

    return bytes_read;
}
static int
syscall_write(int fd, void *buffer, unsigned size)
{

    int bytes_written, i;

    for (i = 0; i < size; i++)
        check_vaddr(buffer + i);

    if (fd == 1)
    {
        putbuf((const char *)buffer, (size_t)size);

        return size;
    }

    if (fd < 2 || fd>130 ||thread_current()->fdt_list[fd] == NULL)
    {
        //return -1;
        syscall_exit(-1);
    }

    lock_acquire(&filesys_lock);
    bytes_written = (int)file_write(thread_current()->fdt_list[fd], buffer, (off_t)size);
    lock_release(&filesys_lock);

    return bytes_written;
}
static int
syscall_seek(int fd, unsigned position)
{

    if (thread_current()->fdt_list[fd] == NULL)
    {
        //return -1;
        syscall_exit(-1);
    }

    lock_acquire(&filesys_lock);
    file_seek(thread_current()->fdt_list[fd], (off_t)position);
    lock_release(&filesys_lock);
}

static unsigned
syscall_tell(int fd)
{

    unsigned pos;

    if (thread_current()->fdt_list[fd] == NULL)
    {
        //return -1;
        syscall_exit(-1);
    }

    lock_acquire(&filesys_lock);
    pos = (unsigned)file_tell(thread_current()->fdt_list[fd]);
    lock_release(&filesys_lock);

    return pos;
}
void syscall_close(int fd)
{
    if (fd < 2 || fd>130 || thread_current()->fdt_list[fd] == NULL)
    {
        //return -1;
        syscall_exit(-1);
    }

    lock_acquire(&filesys_lock);
    file_close(thread_current()->fdt_list[fd]);
    thread_current()->fdt_list[fd] = NULL;
    lock_release(&filesys_lock);
}
