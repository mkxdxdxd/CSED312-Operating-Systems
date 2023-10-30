#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "lib/kernel/stdio.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"

static struct lock file_lock;

static void syscall_handler (struct intr_frame *);
struct lock* get_file_lock();
void syscall_init (void);
static void check_vaddr(const void *vaddr);
void syscall_exit (int status);
void syscall_halt(void);
pid_t syscall_exec (const char *file);
static int syscall_wait(pid_t pid);
bool syscall_create (const char *file, unsigned initial_size);
bool syscall_remove (const char *file);
static int syscall_open (const char *file);
static int syscall_filesize (int fd);
static int syscall_read(int fd , void *buffer, unsigned size);
static int syscall_write(int fd , void *buffer, unsigned size);
static int syscall_seek(int fd, unsigned position);
static unsigned syscall_tell(int fd);
static void syscall_close(int fd);



struct lock* get_file_lock() {
  return &file_lock;
}


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  uint32_t *args = (uint32_t*)(f->esp);
  int size = sizeof(uintptr_t);

  switch(args[0]){
    case SYS_HALT:
    {
      syscall_halt();
      NOT_REACHED();
      break;
    }
    case SYS_EXIT:
    { int status;

      check_vaddr(args + size);
      check_vaddr(args + 2*size -1);
      status = *(int *)(args+size);

      syscall_exit(status);
      NOT_REACHED();
      break;
    }
    case SYS_EXEC:
      {char *cmd;

      check_vaddr(args+size);
      check_vaddr(args + 2* size -1);

      cmd = *(char **)(args + size);

      f->eax = (uint32_t)syscall_exec(cmd);

      break;}
    case SYS_WAIT:
      {pid_t pid;

      check_vaddr(args + size);
      check_vaddr(args + 2 * size - 1);
      pid = *(pid_t *)(args + size);

      f->eax = (uint32_t)syscall_wait(pid);

      break;}
    case SYS_CREATE:
      {char *file;
      unsigned initial_size;

      check_vaddr(args + size);
      check_vaddr(args + 3 * size - 1);
      file = *(char **)(args + size);
      initial_size = *(unsigned *)(args + 2 * size);
      f->eax = (uint32_t)syscall_create(file, initial_size);

      break;}
    case SYS_REMOVE:
      {char *file;

      check_vaddr(args + size);
      check_vaddr(args + 2 * size - 1);
      file = *(char **)(args + size);

      f->eax = (uint32_t)syscall_remove(file);

      break;}
    case SYS_OPEN:
      {char *file;

      check_vaddr(args + size);
      check_vaddr(args + 2 * size - 1);
      file = *(char **)(args + size);

      f->eax = (uint32_t)syscall_open(file);
      break;}
    case SYS_FILESIZE:
      {int fd;

      check_vaddr(args + size);
      check_vaddr(args + 2 * size - 1);
      fd = *(int *)(args + size);

      f->eax = (uint32_t)syscall_filesize(fd);

      break;}
    case SYS_READ:
      {int fd;
      void *buffer;
      unsigned size_t;

      check_vaddr(args + size);
      check_vaddr(args + 4 * size - 1);
      fd = *(int *)(args + size);
      buffer = *(void **)(args + 2 * size);
      size_t = *(unsigned *)(args + 3 * size);

      f->eax = (uint32_t)syscall_read(fd, buffer, size_t);

      break;}
    case SYS_WRITE:
      {int fd;
      void *buffer;
      unsigned size_t;

      check_vaddr(args + size);
      check_vaddr(args + 4 * size - 1);
      fd = *(int *)(args + size);
      buffer = *(void **)(args + 2 * size);
      size_t = *(unsigned *)(args + 3 * size);
      f->eax = (uint32_t)syscall_write(fd, buffer, size_t);

      break;}
    case SYS_SEEK:
      {int fd;
      unsigned position;

      check_vaddr(args + size);
      check_vaddr(args + 3 * size - 1);
      fd = *(int *)(args + size);
      position = *(unsigned *)(args + 2 * size);
      syscall_seek(fd, position);

      break;}
    case SYS_TELL:
      {int fd;

      check_vaddr(args + size);
      check_vaddr(args + 2 * size - 1);
      fd = *(int *)(args + size);

      f->eax = (uint32_t)syscall_tell(fd);

      break;}
    case SYS_CLOSE:
      {int fd;

      check_vaddr(args + size);
      check_vaddr(args + 2 * size - 1);
      fd = *(int *)(args + size);

      syscall_close(fd);

      break;}
    default:
  }
}


static void
check_vaddr(const void *vaddr)
{
    if (!vaddr || !is_user_vaddr(vaddr) ||
        !pagedir_get_page(thread_get_pagedir(), vaddr))
        syscall_exit(-1);
}

void syscall_halt(void){
  shutdown_power_off();
}

void
syscall_exit (int status){
  struct thread* cur = thread_current();
  printf("%s: exit(%d)\n", cur->name, status);
  cur->exit_status = status;

  //check later 
  /*int i;
  for (i = 2; i < 131; i++) {
    if (cur->fdt[i] != NULL) {
        close(i);
    }
  }*/

  //thread_exit() waits for child process to exit
  /*struct thread* temp_thread = NULL;
  struct list_elem* temp_elem = NULL;
  for (temp_elem = list_begin(&thread_current()->child_thread); temp_elem != list_end(&thread_current()->child_thread); temp_elem = list_next(temp_elem)) {
      temp_thread = list_entry(temp_elem, struct thread, child_thread_elem);
      process_wait(temp_thread->tid);
  }*/
  thread_exit();

}

pid_t
syscall_exec (const char *file){

  tid_t tid = (process_execute(file));
 
  if (tid == TID_ERROR) {
    return TID_ERROR;
  } if (!tid) {
    return TID_ERROR;
  }
   
  struct thread* child = get_child_thread(tid);
  if (!child) {;
      return TID_ERROR;
  } if (child->load_failed==1) {
      return TID_ERROR;
  }
  return tid;

}

static int syscall_wait(pid_t pid)
{
    return process_wait(pid);
}

bool
syscall_create (const char *file, unsigned initial_size){

  bool success;
  int i;

  check_vaddr(file);

  //check later
  for (i = 0; *(file + i); i++)
      check_vaddr(file + i + 1);
      //check

  lock_acquire(&file_lock);
  success = filesys_create(file, (off_t)initial_size);
  lock_release(&file_lock);

  return success;

}

bool
syscall_remove (const char *file){

  bool success;
  int i;

  check_vaddr(file);
  //check later
  for (i = 0; *(file + i); i++)
      check_vaddr(file + i + 1);

  lock_acquire(&file_lock);
  success = filesys_remove(file);
  lock_release(&file_lock);

  return success;

}

//file related
static int
syscall_open (const char *file){

  if (file == NULL) syscall_exit(-1);
  check_vaddr(file);
  lock_acquire(&file_lock);
 
  int i, ret = -1;
  struct file* opening_file = filesys_open(file);
  if (opening_file == NULL) {
    ret = -1;
  } 
  else {
    for (i = 2; i < 131; i++) {
      if (thread_current()->fdt[i] == NULL) {
        if (strcmp(thread_name(), file) == 0)
          file_deny_write(opening_file);
        thread_current()->fdt[i] = opening_file;
        ret = i;
        break;
      }
    }
  }
 
  lock_release(&file_lock);
  return ret;


}
static int
syscall_filesize (int fd){

  if (thread_current()->fdt[fd] == NULL)
    syscall_exit(-1);

  lock_acquire(&file_lock);
  int size = file_length(thread_current()->fdt[fd]);
  lock_release(&file_lock);
  return size;


}
static int
syscall_read(int fd , void *buffer, unsigned size){
  int ret = -1;
  int i = 0;
  for (i = 0; i < size; i++)
    check_vaddr(&buffer[i]);


  lock_acquire(&file_lock);
  if (fd == 0) {
    for (i = 0; i < size; i++) {
      ((char *)buffer)[i] = input_getc();
      if (((char *)buffer)[i] == '\0')
        break;
    }
    ret = i;
  } else {
    if (thread_current()->fdt[fd] == NULL) {
      lock_release(&file_lock);
      syscall_exit(-1);
    }
    ret = (int)file_read(thread_current()->fdt[fd], buffer, (off_t)size);
  }
  lock_release(&file_lock);


  return ret;


}
static int 
syscall_write(int fd , void *buffer, unsigned size){
  int i = 0;
  for (i = 0; i < size; i++)
        check_vaddr(&buffer[i]);
  int ret = -1;
 
  lock_acquire(&file_lock);
  if (fd == 1) {
    putbuf(buffer, size);
    ret = size;
  }
  else {
    if (thread_current()->fdt[fd] == NULL) {
      lock_release(&file_lock);
      syscall_exit(-1);
    }
    //if (file_get_deny_write(thread_current()->fdt[fd]))
      file_deny_write(thread_current()->fdt[fd]);
    ret = (int)file_write(thread_current()->fdt[fd], buffer, (off_t)size);
  }


  lock_release(&file_lock);
  return ret;



}
static int 
syscall_seek(int fd, unsigned position){

  if (thread_current()->fdt[fd] == NULL)
      syscall_exit(-1);
  lock_acquire(&file_lock);
  file_seek(thread_current()->fdt[fd], position);
  lock_release(&file_lock);

}
static unsigned 
syscall_tell(int fd){
  if (thread_current()->fdt[fd] == NULL)
      syscall_exit(-1);

  lock_acquire(&file_lock);
  unsigned pos = (unsigned)file_tell(thread_current()->fdt[ fd ]);
  lock_release(&file_lock);
  return pos;

}
static void 
syscall_close(int fd){

  if (thread_current()->fdt[fd] == NULL)
      syscall_exit(-1);
  lock_acquire(&file_lock);
  file_close(thread_current()->fdt[fd]);
  thread_current()->fdt[fd] = NULL;
  lock_release(&file_lock);

}

