#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);
struct lock* get_file_lock(void);
void syscall_close(int);
void syscall_exit (int);

#endif /* userprog/syscall.h */