#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/syscall.h"

#ifdef VM
#include "vm/frame.h"
#include "vm/page.h"
#endif

#ifndef VM
#define frame_allocate(f, u) palloc_get_page(f)
#define frame_free(k) palloc_free_page(k)
#endif


static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
static void parse(const char *line, int *argc, char **argv);
static void save_the_argument_in_stack (int argc, char** argv, void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
//2.2 Argument Passing
tid_t
process_execute (const char *file_name) 
{ /* process_execute is called by kernel thread in init.c 
    and syscall_execute in syscall.c */
  char *fn_copy, *fn_copy2, *thread_name, *ptr;
  tid_t tid;
  struct process *pcb;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  // while checking the file name, race condition can occur. So make fn_copy2.
  fn_copy2 = palloc_get_page (0);
  if (fn_copy2 == NULL)
    return TID_ERROR;
  strlcpy(fn_copy2, file_name , PGSIZE);

  //allocate process control block
  pcb = palloc_get_page(0);
  if (!pcb)
      return TID_ERROR;
  pcb->file_name = fn_copy;
  pcb->parent = thread_current();
  sema_init(&pcb->load_sema, 0);
  sema_init(&pcb->exit_sema, 0);
  pcb->is_exit = false;
  pcb->is_load = false;
  pcb->exit_status = -1;

  thread_name = strtok_r(fn_copy2, " ", &ptr);

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (thread_name, PRI_DEFAULT, start_process, pcb);
  if (tid == TID_ERROR)
  {
      palloc_free_page(fn_copy);
      palloc_free_page(pcb);
      palloc_free_page(fn_copy2);
      return tid;
  }

  /* Wait until child process successfully loads.
    Otherwise, child process cannot be inserted into the child list. */
  sema_down(&pcb->load_sema);
  if (pcb->pid != PID_ERROR) // When child process has been successfully loaded, push child into the list.
      list_push_back(&thread_current()->children, &pcb->childelem);

  palloc_free_page(fn_copy2);
  return tid;

}

/* A thread function that loads a user process and starts it
   running. */
//2.2 Argument Passing
static void
start_process (void *temp)
{ // called by process_executed.
  struct process *pcb = temp;
  char *file_name = pcb->file_name;

  struct intr_frame if_;
  bool success;
  int argc = 0;
  char* argv[MAX_ARGS];

  // set a process's pcb to pcb that has been allocated in process_execute(). 
  thread_current()->pcb = pcb;

#ifdef VM
    page_spt_init(thread_get_spt());
#endif

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;

  parse(file_name, &argc, argv);
  success = load (argv[0], &if_.eip, &if_.esp); //argv[0] has file name
  pcb->is_load = success;

  if (success) { 
    pcb->pid = thread_tid();
  }
  else {
    pcb->pid = PID_ERROR;
  }

  sema_up(&pcb->load_sema);

  if (success){ //if load success, push arguments in the stack.
      save_the_argument_in_stack(argc, argv, &if_.esp);
  }

  /* If load failed, quit. */
  palloc_free_page (file_name);

  if (!success){
    syscall_exit(-1);
  }
 
  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */

  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

//2.2 Argument Passing
static void 
parse(const char *line, int *argc, char **argv)
{
  //tokenize line and put it in argv stack
  char *token, *ptr;
  token = strtok_r(line, " ", &ptr);
  while(token != NULL && *argc < MAX_ARGS){
    argv[(*argc)++] = token;
    token = strtok_r(NULL, " ", &ptr);
  }

}

//2.2 Argument Passing
static void 
save_the_argument_in_stack (int argc, char** argv, void **esp){
  uintptr_t addr[MAX_ARGS];
  int i;
  
  //1. put argv into addr
  for (i = argc - 1; i >= 0;i--){
    *esp -= strlen(argv[i])+1;
    strlcpy(*esp, argv[i], strlen(argv[i])+1);
    addr[i] = (uintptr_t)*esp;
  }

  //2. allign the adress
  *esp = (uintptr_t)*esp & ~0x3;

  size_t size = sizeof(uintptr_t);
  *esp -= size;

  //3. points to the saved argument's address
  for (i = argc - 1; i >= 0; i--){
    *esp -= size;
    *(uintptr_t *)*esp = addr[i];
  }
  *esp -= size;

  //4. push argv
  *(uintptr_t *)*esp = (uintptr_t)*esp + size;

  //5. push argc
  *esp -= sizeof(int);
  *(int *)*esp = argc;

  //6. decrease the pointer when arguments are saved
  *esp -= size;
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid) 
{ //called by kernel thread in init.c

  // find the child thread with 'child_tid', which you want to wait for its exit.
  struct process* child = get_child_process(child_tid);

  if (!child)
    return -1;

  sema_down(&child->exit_sema); // parent process waits until child finishes execution
  int exit_status = child->exit_status; // child has exited, remove from the child list 

  // now remove child with 'child_tid' from the parent's child list.
  list_remove(&child->childelem);
  child->parent = NULL; //separate parent and child process. 
  if (child->is_exit) 
      palloc_free_page(child);
      
  return exit_status; //returns child's exit status, parent process can continue execution.
}

/* Free the current process's resources. */
void
process_exit (void)
{ 
  //called by syscall_exit() in syscall.c
  struct thread *cur = thread_current ();
  struct process *pcb = cur->pcb;
  struct list *children = &thread_current()->children;
  struct list_elem *e;
  struct lock *filesys_lock = syscall_get_filesys_lock();
  uint32_t *pd;
  struct list *locks = &thread_current()->locks;
#ifdef VM
    mapid_t max_mapid = thread_current()->next_mapid++, j;
#endif

  pcb->is_exit = true;
  /* remove child process from child list, free child pcb.
    now child and parent process become independent */
  for (e = list_begin(children); e != list_end(children); e = list_next(e)){
    struct process *child =(list_entry(e, struct process, childelem));
    if (!child)
          continue;

    list_remove(&child->childelem);
    child->parent = NULL;

    if (child->is_exit)
        palloc_free_page(child);
  }

  int i;
    for (i = 2; i < 131; i++) {
        if (thread_current()->fdt_list[i] != NULL) {
            syscall_close(i);
        }
    }

     /* Running file (Process file) is stored in struct thread. Close the file that a process has opened */
  lock_acquire(filesys_lock);
  file_close(thread_current()->running_file);
  lock_release(filesys_lock); // Now running thread has been closed, you can write on the file. 

  for (e = list_begin(locks); e != list_end(locks); e = list_next(e)){
        lock_release(list_entry(e, struct lock, list_elem));
  }

  #ifdef VM
      for (j = 0; j < max_mapid; j++)
        syscall_munmap(j);

    page_spt_destroy(thread_get_spt());
  #endif

  /* child has been removed from the list, successfully exited.
    parent, waiting in process_wait(), can continue its execution. */
  sema_up(&pcb->exit_sema); 
  if (pcb && !pcb->parent)
      palloc_free_page(pcb); //free parent's pcb

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
#ifdef VM
        frame_delete_all(thread_tid());
#endif
      pagedir_destroy (pd);
    }


}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  struct lock* file_lock = syscall_get_filesys_lock();

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  // Open file with 'file_name'.
  lock_acquire(file_lock); 
  file = filesys_open (file_name);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;
  
  //running file is set to the file which was just opened. 
  thread_current()->running_file = file;
  file_deny_write(file); // running file should be blocked from writing. 

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  lock_release(file_lock);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

#ifdef VM
  struct hash *spt = thread_get_spt();
  while (read_bytes > 0 || zero_bytes > 0)
  {
    //if read_bytes exceeds page size or 4KB, set it to PGSIZE
    size_t p_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t p_zero_bytes = PGSIZE - p_read_bytes;

    //Lazy loading(demand paging): Do not update frame table. Only initialise the entry of spt. 
    page_install_file(spt, upage, file, ofs, p_read_bytes, p_zero_bytes, writable); 
    
    //bytes left for reading
    read_bytes -= p_read_bytes;
    zero_bytes -= p_zero_bytes;

    upage += PGSIZE; //total size of upage
    ofs += p_read_bytes; //offset increases
  }
  return true;
#endif

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = frame_allocate (PAL_USER, upage);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          frame_free (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          frame_free (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = frame_allocate (PAL_USER | PAL_ZERO, PHYS_BASE - PGSIZE);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success) {
#ifdef VM
        // install a spt entry for spt for stack address space.
        struct hash *spt = thread_get_spt();
        page_install_frame(spt, PHYS_BASE - PGSIZE, kpage);
        frame_unpin(kpage);
#endif
        *esp = PHYS_BASE;
      }
      else
        frame_free (kpage);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

struct process* get_child_process(pid_t pid)
{
  struct list *children = &thread_current()->children;
  struct list_elem *e;
  
  // find the child thread with 'child_tid', which you want to wait for its exit.
  for (e = list_begin(children); e != list_end(children); e = list_next(e))
  {
      struct process *pcb = list_entry(e, struct process, childelem);

      if (pcb->pid == pid)
      {
          return pcb;
      }       
  }

  return NULL;

}

struct mdt_entry *process_get_mde(mapid_t mapid)
{
  struct list *mdt = &thread_current()->mdt;
  struct list_elem *e;
  for (e = list_begin(mdt); e != list_end(mdt); e = list_next(e))
  {
    struct mdt_entry *mde = list_entry(e, struct mdt_entry, mdt_elem);
    if (mde->mapid == mapid)
      return mde;
  }
  return NULL;
}