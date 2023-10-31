#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);
struct lock* syscall_get_filesys_lock(void);
void syscall_close(int fd);
void syscall_exit (int status);

#endif /* userprog/syscall.h */
