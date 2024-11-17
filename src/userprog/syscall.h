#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "../src/lib/user/syscall.h"
#include "../src/threads/vaddr.h"
#include "../src/filesys/off_t.h"
void syscall_init (void);

extern struct semaphore filesys_mutex;
#endif /* userprog/syscall.h */
