#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include <float.h>
#include <hash.h>
#include "devices/timer.h"

#define MAX_FILES 31

extern f_point load_avg;

/* States in a thread's life cycle. */
enum thread_status
  {
    THREAD_RUNNING,     /* Running thread. */
    THREAD_READY,       /* Not running but ready to run. */
    THREAD_BLOCKED,     /* Waiting for an event to trigger. */
    THREAD_DYING        /* About to be destroyed. */
  };

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Frequency of updates to recent_cpu. */
#define CALC_FREQ 4

/* Used to multiply values by 100 for mlfqs getter functions. */
#define MLFQS_RETURN_FACTOR 100

/* Bounds on nice value. */
#define NICE_MIN -20
#define NICE_MAX 20

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */

/* Return code for all errors. */
#define ERROR_RETURN (-1)
/* Starting value for file descriptors, avoids 1 & 0 which are reserved. */
#define FD_MIN_VALUE 2
/* Exit code when given bad (invalid or out of range) arguments. */
#define BAD_ARGUMENTS ERROR_RETURN
/* Syscall exit code when a memory allocation fails. */
#define MEMORY_ALLOCATION_ERROR ERROR_RETURN

/* An entry into the file descriptor table. */
struct file_descriptor_element{
  int fd;                        /* File descriptor. */
  struct file *file_pointer;     /* Pointer to the file fd refers to. */
  struct hash_elem hash_elem;    /* Hash element to allow addition to hash tables. */
};

/* Used to mediate parent-child data and ensure synchronisatino between them. */
struct parent_child
{
   tid_t child_tid;                 /* Child's TID, used in get_child_pach to find the child. */
   int child_exit_code;             /* Stores the child's exit code, defaults to -1. */
   bool parent_dead;                /* Stores if the parent is dead, used to avoid memory leaks. */
   bool child_dead;                 /* Stores if the child is dead, used to avoid memory leaks. */
   bool been_waited_on;             /* Stores if wait has been called, used to limit to 1 call. */
   bool child_load_success;         /* Stores if the child loaded successfully. */
   struct semaphore sema;           /* Semaphore to ensure access synchronisation to this. */
   struct semaphore waiting;        /* Signals to parent that child died. */
   struct semaphore child_loaded;   /* to signal to parent child has loaded (successfully or not)*/
   struct list_elem child_elem;     /* List element for this to be in a thread's children list. */
   };

/* A kernel thread or user process.

   Each thread structure is stored in its own 4 kB page.  The
   thread structure itself sits at the very bottom of the page
   (at offset 0).  The rest of the page is reserved for the
   thread's kernel stack, which grows downward from the top of
   the page (at offset 4 kB).  Here's an illustration:

        4 kB +---------------------------------+
             |          kernel stack           |
             |                |                |
             |                |                |
             |                V                |
             |         grows downward          |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             +---------------------------------+
             |              magic              |
             |                :                |
             |                :                |
             |               name              |
             |              status             |
        0 kB +---------------------------------+

   The upshot of this is twofold:

      1. First, `struct thread' must not be allowed to grow too
         big.  If it does, then there will not be enough room for
         the kernel stack.  Our base `struct thread' is only a
         few bytes in size.  It probably should stay well under 1
         kB.

      2. Second, kernel stacks must not be allowed to grow too
         large.  If a stack overflows, it will corrupt the thread
         state.  Thus, kernel functions should not allocate large
         structures or arrays as non-static local variables.  Use
         dynamic allocation with malloc() or palloc_get_page()
         instead.

   The first symptom of either of these problems will probably be
   an assertion failure in thread_current(), which checks that
   the `magic' member of the running thread's `struct thread' is
   set to THREAD_MAGIC.  Stack overflow will normally change this
   value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
   the run queue (thread.c), or it can be an element in a
   semaphore wait list (synch.c).  It can be used these two ways
   only because they are mutually exclusive: only a thread in the
   ready state is on the run queue, whereas only a thread in the
   blocked state is on a semaphore wait list. */
struct thread
{
   /* Owned by thread.c. */
   tid_t tid;                          /* Thread identifier. */
   enum thread_status status;          /* Thread state. */
   char name[16];                      /* Name (for debugging purposes). */
   uint8_t *stack;                     /* Saved stack pointer. */
   int priority;                       /* Priority. */
   int nice;                           /* Niceness */
   f_point recent_cpu;                 /* Recent CPU */
   struct list_elem allelem;           /* List element for all threads list. */

   /* Shared between thread.c and synch.c. */
   struct list_elem elem;              /* List element. */
   struct list_elem bfs_elem;          /* List element for BFS in calc_thread_priority() */
   struct list locks;                  /* List of locks that thread has acquired */

#ifdef USERPROG
   /* Owned by userprog/process.c. */
   struct hash file_descriptor_table;  /* The file descriptor table, maps each fd to its file. */
   int next_free_fd;                   /* The next available fd for use in adding to the table. */
   uint32_t *pagedir;                  /* Page directory. */
   struct list children;               /* List of parent_childs, the children of this thread. */
   struct parent_child *parent;        /* An intermediary between this thread and its parent. */
   struct file *executable_file;       /* The executable this is running, used to deny writes. */
#endif

    /* Owned by thread.c. */
    unsigned magic;                     /* Detects stack overflow. */
  };

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "mlfqs". */
extern bool thread_mlfqs;

void yield_if_needed(int64_t);
void thread_init (void);
void thread_start (void);
size_t threads_ready(void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);

/*update for load_avg and recent_CPU*/
void thread_update_load(void);

/* Performs some operation on thread t, given auxiliary data AUX. */
typedef void thread_action_func (struct thread *t, void *aux);
void thread_foreach (thread_action_func *, void *);

bool priority_less (const struct list_elem *, const struct list_elem *, void *);
int thread_get_priority (void);
int calc_thread_priority (struct thread *);
void thread_set_priority (int);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);
void update_priority(struct thread *, void *);

bool thread_is_idle(struct thread *);
void thread_recent_increment(struct thread*);

#ifdef USERPROG
/* Fd table functions*/
struct file *fd_table_get (int);
void fd_table_close (int);
int fd_table_add (struct file*);

/* Parent-child functions. */
void init_parent_child (struct thread *, struct thread *);
void exit_process_with_status (int);
#endif

#endif /* threads/thread.h */
