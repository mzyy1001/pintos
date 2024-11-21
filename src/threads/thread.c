#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include <float.h>
#include <math.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/switch.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"

#ifdef USERPROG
#include "userprog/process.h"
#include "filesys/file.h"
#include "threads/malloc.h"
/* Starting value for file descriptors, avoids 1 & 0 which are reserved. */
#define FD_START_VALUE 2
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list_mlfq[64];
static struct list ready_list;


/* List of all processes.  Processes are added to this list
   when they are first scheduled and removed when they exit. */
static struct list all_list;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Stack frame for kernel_thread(). */
struct kernel_thread_frame 
  {
    void *eip;                  /* Return address. */
    thread_func *function;      /* Function to call. */
    void *aux;                  /* Auxiliary data for function. */
  };

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */
f_point load_avg; /* # of average of load in CPU, used for BSD*/

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-mlfqs". */
bool thread_mlfqs;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *running_thread (void);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static bool is_thread (struct thread *) UNUSED;
static void *alloc_frame (struct thread *, size_t size);
static void schedule (void);
static tid_t allocate_tid (void);
void thread_schedule_tail (struct thread *prev);
void thread_update_priority(void);
void init_ready_list(void);
void thread_add_to_ready_list(struct thread *t);
bool ready_is_empty(void);
static void thread_update_recent_cpu (struct thread *t, void *aux UNUSED);
int thread_get_ready(void);
f_point calculate_recent(f_point recent_cpu,int nice);
int calculate_priority(f_point recent_cpu,int nice);
void init_parent_child(struct thread *child, struct thread *parent);

/*init ready*/
void init_ready_list(void) 
{
    for (int i = 0; i < 64; i++) {
        list_init(&ready_list_mlfq[i]);
    }
}

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init (void) 
{
  ASSERT (intr_get_level () == INTR_OFF);
  load_avg = INT_TO_FLOAT(0);

  lock_init (&tid_lock); 
  if(thread_mlfqs) 
  {
    init_ready_list();
  }
  else
  {
    list_init (&ready_list);
  }
  list_init (&all_list);

  /* Set up a thread structure for the running thread. */
  initial_thread = running_thread ();
  init_thread (initial_thread, "main", PRI_DEFAULT);
  initial_thread->status = THREAD_RUNNING;
  initial_thread->tid = allocate_tid ();
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) 
{
  /* Create the idle thread. */
  struct semaphore idle_started;
  sema_init (&idle_started, 0);
  thread_create ("idle", PRI_MIN, idle, &idle_started);

  /* Start preemptive thread scheduling. */
  intr_enable ();

  /* Wait for the idle thread to initialize idle_thread. */
  sema_down (&idle_started);
}

/* Returns the number of threads currently in the ready list. 
   Disables interrupts to avoid any race-conditions on the ready list. */
size_t
threads_ready (void)
{
  enum intr_level old_level = intr_disable ();
  size_t ready_thread_count;
  if(thread_mlfqs)
  {
    ready_thread_count = list_size (&ready_list_mlfq[0]);
    for(int i = 1; i < 64; i++) 
    {
      ready_thread_count += list_size (&ready_list_mlfq[i]);
    }
  }
  else
  {
    ready_thread_count = list_size (&ready_list);
  }
  intr_set_level (old_level);
  return ready_thread_count;
}
/*add thread to ready list*/
void thread_add_to_ready_list(struct thread *t) 
{
  if(!thread_mlfqs) 
  {
    list_push_back (&ready_list, &t->elem);
    return;
  }
  ASSERT(t->priority >= 0 && t->priority < 64);
  list_push_back(&ready_list_mlfq[t->priority], &t->elem);
  update_priority(t, NULL);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void) 
{
  struct thread *t = thread_current ();

  /* Update statistics. */
  if (t == idle_thread)
    idle_ticks++;
#ifdef USERPROG
  else if (t->pagedir != NULL)
    user_ticks++;
#endif
  else
    kernel_ticks++;

  /* Update the recent_cpu and load_average. */
  if(thread_mlfqs)
  {
    thread_recent_increment(t);
    if(timer_ticks() % TIMER_FREQ == 0){
      thread_update_load();
      thread_foreach(thread_update_recent_cpu, NULL);
#ifdef debug
      printf("seconds: %lld\n",ticks/TIMER_FREQ);
        print_all_lists();
#endif
    }
    if(timer_ticks() % CALC_FREQ == 0) {
      thread_foreach(update_priority, NULL);
      thread_set_priority(thread_current()-> priority);
    }
  }

  /* Enforce preemption. */
  if (++thread_ticks >= TIME_SLICE)
    intr_yield_on_return ();
}

/* Prints thread statistics. */
void
thread_print_stats (void) 
{
  printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
          idle_ticks, kernel_ticks, user_ticks);
}

/* Returns the hash of the file_descriptor_element. */
// TODO(May want to change the implementation)
static unsigned
fd_elem_hash (const struct hash_elem *a, void *aux UNUSED)
{
  struct file_descriptor_element *fd_elem_a = hash_entry (a, struct file_descriptor_element, hash_elem);
  return hash_int (fd_elem_a->fd);
}

/* Compares 2 file descriptor elements using their fds. */
static bool
fd_elem_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED) {
  struct file_descriptor_element *fd_elem_a = hash_entry(a, struct file_descriptor_element, hash_elem);
  struct file_descriptor_element *fd_elem_b = hash_entry(b, struct file_descriptor_element, hash_elem);
  return (fd_elem_a->fd > fd_elem_b->fd);
}


/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t
 thread_create (const char *name, int priority,
               thread_func *function, void *aux) 
{
  struct thread *t;
  struct kernel_thread_frame *kf;
  struct switch_entry_frame *ef;
  struct switch_threads_frame *sf;
  tid_t tid;
  enum intr_level old_level;

  ASSERT (function != NULL);

  /* Allocate thread. */
  t = palloc_get_page (PAL_ZERO);
  if (t == NULL)
    return TID_ERROR;

  /* Initialize thread. */
  init_thread (t, name, priority);
  tid = t->tid = allocate_tid ();

  /* Prepare thread for first run by initializing its stack.
     Do this atomically so intermediate values for the 'stack' 
     member cannot be observed. */
  old_level = intr_disable ();

  /* Stack frame for kernel_thread(). */
  kf = alloc_frame (t, sizeof *kf);
  kf->eip = NULL;
  kf->function = function;
  kf->aux = aux;

  /* Stack frame for switch_entry(). */
  ef = alloc_frame (t, sizeof *ef);
  ef->eip = (void (*) (void)) kernel_thread;

  /* Stack frame for switch_threads(). */
  sf = alloc_frame (t, sizeof *sf);
  sf->eip = switch_entry;
  sf->ebp = 0;

  /* initialises the parent_child struct, including pointers 
   from parent and child threads */
  init_parent_child(t, thread_current());

  #ifdef USERPROG
  hash_init(&(t->file_descriptor_table), &fd_elem_hash, &fd_elem_less, NULL);
  #endif

  intr_set_level (old_level);

  /* Add to run queue. */
  thread_unblock (t);

  return tid;
}

/* Initialises parent_child struct */
void init_parent_child(struct thread *child, struct thread *parent) {
  struct parent_child *parent_child = malloc (sizeof(struct parent_child));
  parent_child->child_tid = child->tid;
  parent_child->parent_exit = false;
  parent_child->child_exit = false;
  parent_child->child_exit_code = -1; /* initialised to -1. exit syscall will modify it*/
  sema_init(&parent_child->sema, 1);
  parent_child->wait = false;
  sema_init(&parent_child->waiting, 0);

  /* pointers from threads to parent_child */
  list_push_front(&parent->children, &parent_child->child_elem);
  child->parent = parent_child;

  sema_init(&parent_child->child_loaded, 0);
}


/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void) 
{
  ASSERT (!intr_context ());
  ASSERT (intr_get_level () == INTR_OFF);
  if (thread_mlfqs) {
      thread_update_priority();
  }
  thread_current ()->status = THREAD_BLOCKED;
  schedule ();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void
thread_unblock (struct thread *t) 
{
  enum intr_level old_level;
  ASSERT (is_thread (t));
  ASSERT (t->status == THREAD_BLOCKED); 
  old_level = intr_disable ();
  t->status = THREAD_READY;
  thread_add_to_ready_list(t);
  yield_if_needed(calc_thread_priority(t));
  intr_set_level (old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name (void) 
{
  return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) 
{
  struct thread *t = running_thread ();
  
  /* Make sure T is really a thread.
     If either of these assertions fire, then your thread may
     have overflowed its stack.  Each thread has less than 4 kB
     of stack, so a few big automatic arrays or moderate
     recursion can cause stack overflow. */
  ASSERT (is_thread (t));
  ASSERT (t->status == THREAD_RUNNING);

  return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void) 
{
  return thread_current ()->tid;
}

/* Frees the file_descriptor_element of the given hash element. */
static void
fd_hash_elem_free(struct hash_elem *e, void *aux UNUSED) {
  struct file_descriptor_element * elem_to_free = hash_entry(e, struct file_descriptor_element, hash_elem);
  synched_file_close(elem_to_free->file_pointer);
  free(elem_to_free);
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) 
{
  ASSERT (!intr_context ());

#ifdef USERPROG
  process_exit ();
  hash_destroy (&(thread_current()->file_descriptor_table), &fd_hash_elem_free);
#endif

  /* Remove thread from all threads list, set our status to dying,
     and schedule another process.  That process will destroy us
     when it calls thread_schedule_tail(). */
  intr_disable ();
  list_remove (&thread_current()->allelem);
  thread_current ()->status = THREAD_DYING;
  // TODO(POSSIBLE MEMORY LEAK WITH THE LISTS HERE);
  schedule ();
  NOT_REACHED ();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void
thread_yield (void) 
{
  struct thread *cur = thread_current ();
  enum intr_level old_level;

  ASSERT (!intr_context ());

  old_level = intr_disable ();
  if (cur != idle_thread) 
    thread_add_to_ready_list(cur);
  cur->status = THREAD_READY;
  schedule ();
  intr_set_level (old_level);
}

/* Called by a function that has in some way added to the ready list, the new
thread's priority is passed in. Current thread yields if it is no longer 
the highest priority thread. */
void
yield_if_needed(int64_t other_priority) {
  enum intr_level old_level = intr_disable();

  /* Check if any thread in the ready_list_mlfq has a higher priority than the current thread */
  if (
      (other_priority> thread_get_priority())
      && thread_current()!= idle_thread
    ) {
    intr_set_level(old_level);
    if (!intr_context()) {
      thread_yield();
    }
    else {
      intr_yield_on_return();
    }
    return;
  }

  intr_set_level(old_level); 
}

/* Invoke function 'func' on all threads, passing along 'aux'.
   This function must be called with interrupts off. */
void
thread_foreach (thread_action_func *func, void *aux)
{
  struct list_elem *e;

  ASSERT (intr_get_level () == INTR_OFF);

  for (e = list_begin (&all_list); e != list_end (&all_list);
       e = list_next (e))
    {
      struct thread *t = list_entry (e, struct thread, allelem);
      func (t, aux);
    }
}

/* Comparison function for thread priorities, called with interrupts off. */
bool
priority_less(
    const struct list_elem *a, const struct list_elem *b, void *aux UNUSED
)
{
  ASSERT (intr_get_level() == INTR_OFF);
  int64_t prior_a = calc_thread_priority(list_entry(a, struct thread, elem));
  int64_t prior_b = calc_thread_priority(list_entry(b, struct thread, elem));
  return prior_a < prior_b;
}

/* Sets the current thread's priority to new_priority, yields the thread
  allowing scheduler to decide if it should actually continue to be running. */
void
thread_set_priority (int new_priority)
{
  if (thread_mlfqs) {
    return;
  }

  ASSERT (PRI_MIN <= new_priority && new_priority <= PRI_MAX);
  thread_current()->priority = new_priority;

  if (!intr_context()) {
    thread_yield();
  }
  else {
    intr_yield_on_return();
  }
}

/* Returns the current thread's priority. */
int
thread_get_priority (void) 
{
  if (thread_mlfqs) {
    return thread_current()->priority;
  }
  enum intr_level old_level = intr_disable();
  int thread_priority = calc_thread_priority(thread_current());
  intr_set_level(old_level);
  return thread_priority;
}

/* Calculates a thread's actual priority taking into account any donations.
Works by iterates through the locks owned by the thread and finding the
priority of the locks' donors using BFS. Must be called with interrupts off. */
int 
calc_thread_priority(struct thread *input_thread) {
  ASSERT (intr_get_level() == INTR_OFF);
  int cur_max = -1;
  struct list_elem *l_elem;

  struct list bfs_queue; 
  list_init(&bfs_queue);
  list_push_back(&bfs_queue, &input_thread->bfs_elem);

  while (!list_empty(&bfs_queue)) {
    struct list_elem *q_elem = list_pop_front(&bfs_queue);
    struct thread *t = list_entry(q_elem, struct thread, bfs_elem);

    cur_max = (cur_max > t->priority) ? cur_max : t->priority;

    struct list_elem *final_t_lock = list_end (&t->locks);

    for (l_elem = list_begin (&t->locks); l_elem != final_t_lock;
         l_elem = list_next(l_elem))
      {
        struct list *l_donors = &(
          list_entry (l_elem, struct lock, locks_elem)->semaphore.waiters
        );
        struct list_elem *d_elem;
        struct list_elem *final_l_donor = list_end (l_donors);

        for (d_elem = list_begin (l_donors); d_elem != final_l_donor;
             d_elem = list_next(d_elem))
          {
            struct thread *thread_to_push = list_entry(d_elem, struct thread, elem);
            list_push_back(&bfs_queue, &thread_to_push->bfs_elem);
          }
      }
  }

  return cur_max;
}

/* Recalculates thread priority based on the formula: 
priority = PRI_MAX - (recent_cpu / 4) - (2 * nice) 
it is then rounded and adjusted to lie in a valid range */
int
calculate_priority(f_point recent_cpu, int nice)
{
  f_point recent_cpu_div_4 = FLOAT_DIV_INT(recent_cpu, 4);
  f_point nice_times_2 = INT_TO_FLOAT(nice * 2);
  f_point priority = FLOAT_SUB(INT_TO_FLOAT(PRI_MAX), recent_cpu_div_4);

  int i_priority = FLOAT_TO_INT_ROUND(FLOAT_SUB(priority, nice_times_2));

  i_priority = MIN(i_priority,PRI_MAX);
  i_priority = MAX(i_priority,PRI_MIN);
  return i_priority;
}

/* Helper function for update_nice, which updates the priority. */
void
thread_update_priority(void)
{
  f_point recent_cpu = thread_get_recent_cpu();
  int priority = calculate_priority(recent_cpu, thread_get_nice());
  thread_set_priority(priority);
}

/*update priority of a specific thread*/
void
update_priority(struct thread *t, void*aux UNUSED)
{
  if (t != idle_thread) {
    t->priority = calculate_priority(t->recent_cpu,t->nice);
  }
}

/* Sets the current thread's nice value to NICE. */
void
thread_set_nice (int nice)
{
  /*check nice is in Legal range*/
  ASSERT(nice <= NICE_MAX && nice >= NICE_MIN);

  thread_current()->nice = nice;
  thread_update_priority();
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void) 
{
  return thread_current ()->nice;
}

/* Returns 100 times the system load average. */
int
thread_get_load_avg (void) 
{
  return FLOAT_TO_INT_ROUND(FLOAT_MUL_INT(load_avg, MLFQS_RETURN_FACTOR));
}

/* Returns 100 times the current thread's recent_cpu value.
Using: recent_cpu = (2*load_avg)/(2*load_avg + 1) * recent_cpu + nice */
int
thread_get_recent_cpu (void) 
{
  return FLOAT_TO_INT_ROUND(
      FLOAT_MUL_INT(thread_current()->recent_cpu, MLFQS_RETURN_FACTOR)
  );
}

/* Calculates the recent CPU with: {r, n -> n + r * 2l/(2l + 1)} */
f_point
calculate_recent(f_point recent_cpu,int nice)
{
  f_point two_load_avg = FLOAT_MUL(load_avg, INT_TO_FLOAT(2));
  f_point denominator = FLOAT_ADD(two_load_avg, INT_TO_FLOAT(1));
  f_point fraction = FLOAT_DIV(two_load_avg, denominator);
  f_point scaled_recent_cpu = FLOAT_MUL(fraction, recent_cpu);
  f_point final_result = FLOAT_ADD(scaled_recent_cpu, INT_TO_FLOAT(nice));
  return final_result;
}

/* Helper function to update recent_CPU. */
static void
thread_update_recent_cpu (struct thread *t, void *aux UNUSED)
{
  ASSERT (intr_get_level() == INTR_OFF);
  f_point recent_cpu = t->recent_cpu;
  t->recent_cpu = calculate_recent(recent_cpu, t->nice);
}

void
thread_recent_increment(struct thread *cur_thread)
{
  if(cur_thread != idle_thread)
  {
    cur_thread->recent_cpu = FLOAT_ADD(
      cur_thread->recent_cpu,INT_TO_FLOAT(1)
    );
  }
}

/* Update load average. */
void
thread_update_load(void)
{
  int ready_threads = threads_ready();
  if (thread_current() != idle_thread) {
    ready_threads++;
  }
  f_point diminished_old_avg = FLOAT_DIV_INT(FLOAT_MUL_INT(load_avg, 59), 60);
  f_point change_avg = FLOAT_DIV_INT(INT_TO_FLOAT(ready_threads), 60);
  load_avg = FLOAT_ADD(diminished_old_avg, change_avg);
}

/* Get the next available fd and increment the counter. */
static int
thread_get_fd (void){
  struct thread *t = thread_current();
  int next_fd = t->next_free_fd;
  t ->next_free_fd ++;
  return next_fd;
}

/* Takes a file *, and attempt to generate an fd and create a
file_descriptor_element. Returns -1 on a failed addition, the fd otherwise. */
int
fd_table_add (struct file* file) {
  struct file_descriptor_element *new_fd = malloc(sizeof (struct file_descriptor_element));

  /* Unable to allocate memory, operation fails. */
  // TODO(Consider terminating the process in such a case)
  if (new_fd == NULL) {
    synched_file_close(file);
    return -1;
  }
  new_fd->fd = thread_get_fd();
  new_fd->file_pointer = file;
  struct hash *hash_table = &(thread_current()->file_descriptor_table);
  struct hash_elem *added_elem = hash_insert(hash_table, &(new_fd->hash_elem));

  // TODO(May want to change implementation if added_elem is NULL e.g. to kill the program)
  /* Equivilent element already in table. Should never occur as thread_get_fd 
  is strictly monotone increasing and int limit is very large. */
  if (added_elem != NULL) {
    synched_file_close(file);
    free (new_fd);
    return -1;
  }
  return new_fd->fd;
}

/* Takes an fd and returns the matching file * from the threads hashtable.
  Still returns result on a failed match, which propagates through the NULL. */
struct file *
fd_table_get (int fd) {
  struct hash *hash_table = &(thread_current()->file_descriptor_table);
  struct file_descriptor_element temp_elem;
  temp_elem.fd = fd;
  struct hash_elem *result = hash_find(hash_table, &(temp_elem.hash_elem));
  /* Propagate NULL.*/
  if (result == NULL) {
    return NULL;
  }
  return (hash_entry (result, struct file_descriptor_element, hash_elem)->file_pointer);
}

/* Takes a fd and closes it. */
// TODO(Consider changing the implementation to return 1 on success or something like that
// this would allow for a different response to no matching result e.g. killing the proccess)
void
fd_table_close (int fd) {
  struct hash *hash_table = &(thread_current()->file_descriptor_table);
  struct file_descriptor_element temp_elem;
  temp_elem.fd = fd;
  struct hash_elem *result = hash_delete(hash_table, &(temp_elem.hash_elem));
  /* No open entry matching fd found.*/
  if (result == NULL) {
    return;
  }
  fd_hash_elem_free (result, NULL);
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) 
{
  struct semaphore *idle_started = idle_started_;
  idle_thread = thread_current ();
  sema_up (idle_started);
  for (;;) 
    {
      /* Let someone else run. */
      intr_disable ();
      thread_block ();

      /* Re-enable interrupts and wait for the next one.

         The `sti' instruction disables interrupts until the
         completion of the next instruction, so these two
         instructions are executed atomically.  This atomicity is
         important; otherwise, an interrupt could be handled
         between re-enabling interrupts and waiting for the next
         one to occur, wasting as much as one clock tick worth of
         time.

         See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
         7.11.1 "HLT Instruction". */
      asm volatile ("sti; hlt" : : : "memory");
    }
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) 
{
  ASSERT (function != NULL);

  intr_enable ();       /* The scheduler runs with interrupts off. */
  function (aux);       /* Execute the thread function. */
  thread_exit ();       /* If function() returns, kill the thread. */
}

/* Returns the running thread. */
struct thread *
running_thread (void) 
{
  uint32_t *esp;

  /* Copy the CPU's stack pointer into `esp', and then round that
     down to the start of a page.  Because `struct thread' is
     always at the beginning of a page and the stack pointer is
     somewhere in the middle, this locates the curent thread. */
  asm ("mov %%esp, %0" : "=g" (esp));
  return pg_round_down (esp);
}

/* Returns true if T appears to point to a valid thread. */
static bool
is_thread (struct thread *t)
{
  return t != NULL && t->magic == THREAD_MAGIC;
}

/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority)
{
  enum intr_level old_level;

  ASSERT (t != NULL);
  ASSERT (name != NULL);
  memset (t, 0, sizeof *t);

  if (!thread_mlfqs) {
    ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
    t->priority = priority;
  }
  else {
    t->recent_cpu = INT_TO_FLOAT(0);
    t->nice = 0;
  }
  #ifdef USERPROG
    t->next_free_fd = FD_START_VALUE;
  #endif
  
  t->status = THREAD_BLOCKED;
  strlcpy (t->name, name, sizeof t->name);
  t->stack = (uint8_t *) t + PGSIZE;
  /* Initialize the locks list */
  list_init(&t->locks);

  list_init(&t->children);
  
  t->magic = THREAD_MAGIC;
  
  old_level = intr_disable ();
  list_push_back (&all_list, &t->allelem);
  intr_set_level (old_level);
}

/* Allocates a SIZE-byte frame at the top of thread T's stack and
   returns a pointer to the frame's base. */
static void *
alloc_frame (struct thread *t, size_t size) 
{
  /* Stack data is always allocated in word-size units. */
  ASSERT (is_thread (t));
  ASSERT (size % sizeof (uint32_t) == 0);

  t->stack -= size;
  return t->stack;
}

/*list empty help function*/
bool 
ready_is_empty(void) {
  return threads_ready() == 0;
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) 
{
  /* Return idle thread if no thread is ready. */
  if (ready_is_empty()) {
    return idle_thread; 
  } else {
    if(thread_mlfqs) {
      enum intr_level old_level = intr_disable();
      for (int i = 63; i >= 0; i--) {
        if (!list_empty(&ready_list_mlfq[i])) {
          /* Get the first thread from the highest priority list */
          struct list_elem *highest_priority_elem = list_pop_front(&ready_list_mlfq[i]);
          intr_set_level(old_level);
          return list_entry(highest_priority_elem, struct thread, elem);
        }
      }
      /* Remove the highest-priority thread from the ready list and return it. */
      intr_set_level(old_level);
      return idle_thread;
    }
    else 
    {
      enum intr_level old_level = intr_disable();
      struct list_elem *highest_priority_elem = list_begin(&ready_list);
      int64_t max_priority = calc_thread_priority(
        list_entry(highest_priority_elem, struct thread, elem)
      );
      for (struct list_elem *cur_elem = list_begin(&ready_list); 
        cur_elem != list_end(&ready_list); 
        cur_elem = list_next(cur_elem)) {

        struct thread *cur_thread = list_entry(cur_elem, struct thread, elem);
        int64_t cur_priority = calc_thread_priority(cur_thread);
        if (cur_priority > max_priority) {
          highest_priority_elem = cur_elem;
          max_priority = cur_priority;
        }
      }
      list_remove(highest_priority_elem);
      intr_set_level(old_level);
      return list_entry(highest_priority_elem, struct thread, elem);
    }
  }
}

/* Completes a thread switch by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.  This function is normally invoked by
   thread_schedule() as its final action before returning, but
   the first time a thread is scheduled it is called by
   switch_entry() (see switch.S).

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function.

   After this function and its caller returns, the thread switch
   is complete. */
void
thread_schedule_tail (struct thread *prev)
{
  struct thread *cur = running_thread ();
  
  ASSERT (intr_get_level () == INTR_OFF);

  /* Mark us as running. */
  cur->status = THREAD_RUNNING;

  /* Start new time slice. */
  thread_ticks = 0;

#ifdef USERPROG
  /* Activate the new address space. */
  process_activate ();
#endif

  /* If the thread we switched from is dying, destroy its struct
     thread.  This must happen late so that thread_exit() doesn't
     pull out the rug under itself.  (We don't free
     initial_thread because its memory was not obtained via
     palloc().) */
  if (prev != NULL && prev->status == THREAD_DYING && prev != initial_thread) 
    {
      ASSERT (prev != cur);
      palloc_free_page (prev);
    }
}

/* Schedules a new process.  At entry, interrupts must be off and
   the running process's state must have been changed from
   running to some other state.  This function finds another
   thread to run and switches to it.

   It's not safe to call printf() until thread_schedule_tail()
   has completed. */
static void
schedule (void) 
{
  struct thread *cur = running_thread ();
  struct thread *next = next_thread_to_run ();
  struct thread *prev = NULL;

  ASSERT (intr_get_level () == INTR_OFF);
  ASSERT (cur->status != THREAD_RUNNING);
  ASSERT (is_thread (next));

  if (cur != next)
    prev = switch_threads (cur, next);
  thread_schedule_tail (prev);
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) 
{
  static tid_t next_tid = 1;
  tid_t tid;

  lock_acquire (&tid_lock);
  tid = next_tid++;
  lock_release (&tid_lock);

  return tid;
}

/* Offset of `stack' member within `struct thread'.
   Used by switch.S, which can't figure it out on its own. */
uint32_t thread_stack_ofs = offsetof (struct thread, stack);

/*return a thread with a tid*/
struct thread *
get_thread_by_tid(tid_t tid)
{
    struct list_elem *e;
    for (e = list_begin(&all_list); e != list_end(&all_list); e = list_next(e)) {
        struct thread *t = list_entry(e, struct thread, allelem);
        if (t->tid == tid) {
            return t;
        }
    }
    return NULL; // Thread not found
}
