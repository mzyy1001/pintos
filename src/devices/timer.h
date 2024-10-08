#ifndef DEVICES_TIMER_H
#define DEVICES_TIMER_H

#include <round.h>
#include <stdint.h>
#include <list.h>
#include "threads/synch.h"
/* Number of timer interrupts per second. */
#define TIMER_FREQ 100

/* Macro to make getting sleeping_threads from lists cleaner */
#define GET_SLEPT_THREAD(e) list_entry(e, struct sleeping_thread, list_element)

/* A sleeping thread is a thread that has been put to sleep, such 
a thread must only be ready again when awaken_time is reached. */
struct sleeping_thread {
    int64_t awaken_time;  /* Time (ticks) when the thread should wake up. */
    struct list_elem list_element; /* Inserts this struct in sleeping_list. */
    struct semaphore sem; /* Controls thread blocking when slept/awoken. */
};

void timer_init (void);
void timer_calibrate (void);

int64_t timer_ticks (void);
int64_t timer_elapsed (int64_t);

/* Sleep and yield the CPU to other threads. */
void timer_sleep (int64_t ticks);
void timer_msleep (int64_t milliseconds);
void timer_usleep (int64_t microseconds);
void timer_nsleep (int64_t nanoseconds);

/* Busy waits. */
void timer_mdelay (int64_t milliseconds);
void timer_udelay (int64_t microseconds);
void timer_ndelay (int64_t nanoseconds);

void timer_print_stats (void);

#endif /* devices/timer.h */
