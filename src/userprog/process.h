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

#endif /* userprog/process.h */
