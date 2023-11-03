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
struct process* get_child_process(pid_t pid);

struct process
{
    const char *file_name; //process filename
    pid_t pid; //process id 
    struct thread *parent; //store parent thread
    struct list_elem childelem; // store list of child
    struct semaphore load_sema; // semaphore for loading a process into a memory
    struct semaphore exit_sema; // semaphore for process_wait(), waiting for child process to exit
    bool is_exit;  // the process has been exited
    bool is_load; // the process is loaded in memory
    int exit_status; // exit status
};        

#endif /* userprog/process.h */