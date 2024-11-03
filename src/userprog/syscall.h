#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "../src/lib/user/syscall.h"
#include "../src/threads/vaddr.h"
#include "threads/synch.h"
#include "threads/thread.h"


void syscall_init (void);


/*hold information about each child process*/
struct child_info {
    pid_t pid;
    int exit_status;
    bool terminated;
    struct semaphore sema;  // Semaphore for wait synchronization
    struct list_elem elem;  // List element for linked list in parent process.
};


#endif /* userprog/syscall.h */
