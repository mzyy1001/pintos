#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

/* Used to ensure safe memory access by verifying a pointer pre-dereference.
Should certainly be called with interrupts off, or will be useless. */
static bool
verify (void *vaddr) {
  ASSERT (intr_get_level() == INTR_OFF);
  return is_user_vaddr(vaddr) && pagedir_get_page(vaddr);
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  printf ("system call!\n");
  thread_exit ();
}
