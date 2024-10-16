#include <stdio.h>
#include "tests/threads/tests.h"
#include "threads/init.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "devices/timer.h"

static thread_func bsd_scheduler_thread;
static struct semaphore sema;

void
bsd_test (void) 
{
  int i;

  // ASSERT (thread_mlfqs);

  sema_init(&sema, 0);

  for (i = 0; i < 5; i++) 
    {
      int nice_value = i * 5 - 10; 
      char name[16];
      snprintf(name, sizeof name, "nice %d", nice_value);
      thread_create(name, PRI_DEFAULT, bsd_scheduler_thread, (void *)nice_value);
    }

  for (i = 0; i < 5; i++) 
    {
      timer_sleep(100); // simulate cpu time
      sema_up(&sema);
      msg("Load_avg after releasing thread %d: %d", i + 1, thread_get_load_avg());
    }

  timer_sleep(100);  // finish threads
  msg("Final system load_avg: %d", thread_get_load_avg());
}

static void
bsd_scheduler_thread(void *nice_value_) 
{
  int nice_value = (int)nice_value_;
  
  thread_set_nice(nice_value);
  sema_down(&sema);

  msg("Thread %s with nice %d has recent_cpu: %d and priority: %d",
      thread_name(), nice_value, thread_get_recent_cpu(), thread_get_priority());
}