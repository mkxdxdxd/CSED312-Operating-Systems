#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "lib/user/syscall.h"
#include "threads/synch.h"
#include "threads/thread.h"

typedef int pid_t;
#define MAX_ARGS 128
tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
static void parse(const char *line, int *argc, char **argv);
static void save_the_argument_in_stack (int argc, char** argv, void **esp);
struct process *process_get_child(pid_t pid);
void process_remove_child(struct process *child);
struct file_descriptor_entry *process_get_fde(int);


struct process
{
 const char *file_name;
 
 /* Shared between process.c and usyscall.c. */
 pid_t pid; /* Process identifier. */
 struct thread *parent; /* Parent process. */
 struct list_elem childelem; /* List elemnt for children list. */
 bool is_loaded; /* Whether program is loaded. */
 struct semaphore load_sema; /* Semaphore for waiting until load. */
 bool is_exited; /* Whether process is exited or not. */
 struct semaphore exit_sema; /* Semaphore for waiting until exit. */
 int exit_status; /* Exit status. */
};

struct file_descriptor_entry
{
    int fd;                   /* File descriptor. */
    struct file *file;        /* File. */
    struct list_elem fdtelem; /* List element for file descriptor table. */
};


#endif /* userprog/process.h */
