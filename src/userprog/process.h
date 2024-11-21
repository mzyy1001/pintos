#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H
#define MAX_ARGS 32

#include "threads/thread.h"

tid_t process_execute (const char *);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
struct parent_child *get_child_pach(tid_t);

#endif /* userprog/process.h */
