#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

typedef int mapid_t;

void syscall_init (void);
//struct lock* get_file_lock(void);
struct lock *syscall_get_filesys_lock(void);
void syscall_close(int);
void syscall_exit (int);
void syscall_munmap(mapid_t mapid);

#endif /* userprog/syscall.h */