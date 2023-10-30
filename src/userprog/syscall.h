#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include <list.h>
#include "threads/interrupt.h"
#include "threads/synch.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/fsutil.h"
#include "filesys/inode.h"
#include "filesys/off_t.h"

void syscall_init (void);

#endif /* userprog/syscall.h */
