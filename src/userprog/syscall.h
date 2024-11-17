#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "../src/lib/user/syscall.h"
#include "../src/threads/vaddr.h"
#include "../src/filesys/filesys.h"
#include "../src/filesys/file.h"
#include <limits.h>
#include "threads/thread.h"

void syscall_init (void);

#endif /* userprog/syscall.h */
