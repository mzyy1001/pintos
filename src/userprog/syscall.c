#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
#include "pagedir.h"
#include "filesys/file.h"
#include <string.h>
#include "devices/input.h"
#include "../src/filesys/filesys.h"
#include "../src/filesys/file.h"
#include <limits.h>
#include "threads/palloc.h"

/* Number of syscalls implemented that the syscall handler can call. */
#define NUMBER_OF_SYSCALLS 13
/* Syscall exit code when an operation with the parent_child struct fails. */
#define PARENT_CHILD_ERROR (-1)
/* Syscall exit code when a (filesys/process)_{name} function doesn't run as intended. */
#define FUNCTION_ERROR (-1)
/* Max string argument length to prevent incorrectly structured strings infinite looping. */
#define MAX_STRING_LENGTH (2 << 20)
/* Syscall return code for return that 0 of whatever was 
expected to be done/given was done/given. */
#define NOTHING 0
/* The fd value that refers to the console (for output). */
#define CONSOLE_FD 1
/* The number of bytes put at one time into buffer. */
#define BUFFER_CHUNK_SIZE 300
/* The fd value that refers to the keyboards (for input). */
#define KEYBOARD_FD 0

/* Process identifier. */
typedef int pid_t;
/* Syscall function. */
typedef void (syscall_t) (struct intr_frame *);

/* Used to ensure safe memory access by verifying a pointer pre-dereference. */
static void
verify (void *vaddr) {
  if (vaddr == NULL || !is_user_vaddr(vaddr) || pagedir_get_page(thread_current()->pagedir, vaddr) == NULL) {
    exit_process_with_status(BAD_ARGUMENTS);
  }
}

/* Extract a single argument and return it, not moving the pointer. */
static int
extract_arg_n (int *stack_pointer, int arg_num) {
  verify(stack_pointer + arg_num);
  return stack_pointer[arg_num];
}

/* Extract the first argument and return it, not moving the pointer. */
#define EXTRACT_ARG_1(stack_pointer) (extract_arg_n(stack_pointer, 1))
/* Extract the second argument and return it, not moving the pointer. */
#define EXTRACT_ARG_2(stack_pointer) (extract_arg_n(stack_pointer, 2))
/* Extract the third argument and return it, not moving the pointer. */
#define EXTRACT_ARG_3(stack_pointer) (extract_arg_n(stack_pointer, 3))

/* This function ensures all parts of a string are verified. */
static void
verify_string (const char *str) {
  const char *ptr = str;
  int byte_count = NOTHING;

  /* Verify the first byte. */
  verify((void *) ptr);

  /* Loop through each byte .*/
  while (*ptr != '\0') {
    ptr++;
    byte_count++;

    /* Prevent infinite looping on incorrectly formatted strings (no '\0'). */
    if (byte_count > MAX_STRING_LENGTH) {
      exit_process_with_status(BAD_ARGUMENTS);
    }

    /* Verify byte if crossing into a new page. */
    if ((uint32_t) ptr % PGSIZE == NOTHING) {
      verify((void *) ptr);
    }
  }

  /* Verify the final byte. */ 
  verify((void *)ptr);
}

static void
verify_buffer (const void *buffer, unsigned size) {
  const uint8_t *ptr = (const uint8_t *) buffer;
  const uint8_t *end = ptr + size;

  verify((void *) ptr);

  /* Move pointer to next page boundary */
  ptr = (const uint8_t *)(((uintptr_t)ptr + PGSIZE) & ~(PGSIZE - 1));

  /* Iterate through each page boundary, verifying them. */
  while (ptr < end) {
      verify((void *) ptr);

      /* Move to the next page boundary. */
      ptr += PGSIZE;  
  }
}

/* Terminates PintOS. This should be seldom used, because you lose some
information about possible deadlock situations, etc. */
static void
halt (struct intr_frame *aux UNUSED) {
  shutdown_power_off();
}

/* Wraps exit_process_with_status so it can be called by syscall handler. */
static void
sys_exit (struct intr_frame *f) {
  exit_process_with_status(EXTRACT_ARG_1((int *) f->esp));
}

/* Runs the executable whose name is given in cmd line, passing any given
arguments, and returns the new process’s program id (pid). */
static void
exec (struct intr_frame *f) {
  const char *cmd_line = (char *) EXTRACT_ARG_1((int *) f->esp);
  
  /* Ensure the cmd_line is correctly verified. */
  verify_string(cmd_line);
  if (strlen(cmd_line) > PGSIZE) {
    f ->eax = (int32_t) BAD_ARGUMENTS;
    return;
  }

  /* Make a copy of the command line. */
  char *cmd_copy = palloc_get_page(PAL_ZERO);
  if (cmd_copy == NULL) {
    f ->eax = (int32_t) MEMORY_ALLOCATION_ERROR;
    return;
  }
  strlcpy(cmd_copy, cmd_line, PGSIZE);

  /* Create the new process. */
  tid_t tid = process_execute(cmd_copy);
  if (tid == TID_ERROR) {
    palloc_free_page(cmd_copy);
    f ->eax = (int32_t) FUNCTION_ERROR;
    return;
  }

  /* Find the corresponding intermediary (parent_child) structure corresponding to 
    a child's tid. */
  struct parent_child *child_pach = get_child_pach(tid);
  if (child_pach == NULL) {
    palloc_free_page(cmd_copy);
    f ->eax = (int32_t) PARENT_CHILD_ERROR;
    return;
  }

  /* Wait for the child to finish loading (successfully or not). */
  sema_down(&child_pach->child_loaded); 

  /* Check if the child process loaded successfully. */
  if (!child_pach->child_load_success) {
    tid = PARENT_CHILD_ERROR;
  }

  /* Clean up the command line copy. */
  palloc_free_page(cmd_copy);
  f ->eax = (int32_t) tid;
}

/* Wraps process_wait allowing it to be called by the syscall handler. */
static void
wait (struct intr_frame *f) {
  pid_t pid = EXTRACT_ARG_1((int *) f->esp);
  f->eax = (int32_t) process_wait(pid);
}


/* Creates a new file called file initially initial size bytes in size. Returns
whether it was successfully created. Creating a new file doesn't open it. */
static void
create (struct intr_frame *f) {
  const char *file_name = (char *) EXTRACT_ARG_1((int *) f->esp);
  unsigned initial_size = (unsigned) EXTRACT_ARG_2 ((int *) f->esp);
  
  /* Verify arguments. */
  verify_string(file_name);
  if (initial_size > INT_MAX) {
    exit_process_with_status(BAD_ARGUMENTS);
  }

  f->eax = (int32_t) synched_filesys_create(file_name, (off_t) initial_size);
}

/* Deletes the file called file. Returns whether it was successfully deleted.
A file may be removed regardless of whether it is open or closed, and removing
an open file does not close it. */
static void
remove (struct intr_frame *f) {
  const char *file_name = (char *) EXTRACT_ARG_1((int *) f->esp);

  /* Verify file_name. */
  verify_string(file_name);
  if (*file_name == '\0') {
    f->eax = (int32_t) NOTHING;
    return;
  }

  f->eax = (int32_t) synched_filesys_remove(file_name);
}

/* Opens the file called file. Returns a nonnegative integer handle called a
“file descriptor” (fd), or -1 if the file could not be opened. When a single
file is opened more than once, whether by a single process or different
processes, each open returns a new file descriptor. Different file descriptors
for a single file are closed independently in separate calls to close and
do not share a file position. */
static void
open (struct intr_frame *f) {
  const char *file_name = (char *) EXTRACT_ARG_1((int *) f->esp);

  
  /* Verify arguments. */
  verify_string(file_name);

  /* Does nothing and returns an error code if empty name. */
  if (*file_name == '\0') {
    f->eax = (int32_t) BAD_ARGUMENTS;
    return;
  }
  
  /* Open the file and add it to the fd table. */
  struct file *file = synched_filesys_open(file_name);

  /* If file open fails return error result. */
  if (file == NULL) {
    f->eax = (int32_t) FUNCTION_ERROR;
    return;
  }

  f->eax = (int32_t) fd_table_add(file);
}

/* Returns the size, in bytes, of the file open as fd. -1 on no match. */
static void
filesize (struct intr_frame *f) {
  int fd = EXTRACT_ARG_1((int *) f->esp);
  struct file *file = fd_table_get(fd);

  /* Table_get fails -> no match. */
  if (file == NULL) {
    f->eax = (int32_t) BAD_ARGUMENTS;
    return;
  }

  f->eax = (int32_t) synched_file_length(file);
}

/* Reads size bytes from the file open as fd into buffer. Returns the number
of bytes actually read (0 at end of file), or -1 if the file could not be read
(excluding end of file). KEYBOARD_FD will read from keyboard. */
static void
read (struct intr_frame *f) {
  int fd = EXTRACT_ARG_1((int *) f->esp);
  void *buffer = (void *) EXTRACT_ARG_2((int *) f->esp);
  unsigned size = (unsigned) EXTRACT_ARG_3 ((int *) f->esp);

  /* Check buffer is valid. */
  verify_buffer(buffer, size);

  /* Read from the keyboard one char at a time if KEYBOARD_FD is indicated. */
  if (fd == KEYBOARD_FD) {
    unsigned bytes_read = NOTHING;
    char *buf = buffer;
    acquire_filesys();
    for (unsigned i = 0; i < size; i++) {
      buf[i] = input_getc();
      bytes_read++;
    }
    release_filesys();
    f->eax = (int32_t) bytes_read;
    return;
  }

  /* Read from the fd's file otherwise. */
  struct file *file = fd_table_get(fd);

  /* Table get fails -> bad fd. */
  if (file == NULL) {
    f->eax = (int32_t) BAD_ARGUMENTS;
    return;
  }

  f->eax = (int32_t) synched_file_read(file, buffer, size);
}

/* Writes size bytes from buffer to the open file fd. Returns the number of
bytes actually written, which may be less than size if some bytes could not
be written. if fd is CONSOLE_FD the write is instead to console.*/
static void
write (struct intr_frame *f) {
  int fd = EXTRACT_ARG_1((int *) f->esp);
  const void *buffer = (void *) EXTRACT_ARG_2((int *) f->esp);
  unsigned size = (unsigned) EXTRACT_ARG_3 ((int *) f->esp);

  /* Check buffer is invalid. */
  verify_buffer(buffer, size);

  /* Check size > 0, skip execution if so. */
  if (size == NOTHING) {
    f->eax = NOTHING;
    return;
  } 

  /* Write to the console in BUFFER_CHUNK_SIZEs if CONSOLE_FD is indicated. */
  int bytes_written = NOTHING;
  if (fd == CONSOLE_FD) {
    unsigned remaining = size;
    const char *buf = buffer;

    /* Write in BUFFER_CHUNK_SIZE byte chunks. */
    acquire_filesys();
    while (remaining > BUFFER_CHUNK_SIZE) {
      putbuf(buf, BUFFER_CHUNK_SIZE);
      buf += BUFFER_CHUNK_SIZE;
      remaining -= BUFFER_CHUNK_SIZE;
      bytes_written += BUFFER_CHUNK_SIZE;
    }

    /* Write the remainder. */
    if (remaining > NOTHING) {
      putbuf(buf, remaining);
      bytes_written += remaining;
    }
    
    release_filesys();
  } else {
    /* Write to the fd's file otherwise. */
    struct file *file = fd_table_get(fd);

    /* Table get fails -> bad fd. */
    if (file == NULL) {
      f->eax = (int32_t) BAD_ARGUMENTS;
      return;
    }

    /* Ensure writing is allowed. */
    if (is_deny_write(file)) {
      f->eax = NOTHING;
      return;
    }

    /* Complete the write. */
    bytes_written = synched_file_write(file, buffer, size);
    if (bytes_written < NOTHING) {
      bytes_written = NOTHING;
    }
  }
  f->eax = (int32_t) bytes_written;
}

/* Changes the next byte to be read or written in open file fd to position,
expressed in bytes from the beginning of the file (0 would be the start).
An error leads to the function failing, but the process is not killed. */
static void
seek (struct intr_frame *f) {
  int fd = EXTRACT_ARG_1((int *) f->esp);
  unsigned position = (unsigned) EXTRACT_ARG_2 ((int *) f->esp);

  /* Out of bounds position would overflow in type conversion. */
  if (position > INT_MAX) {
    return;
  }

  /* Seek in the file matching fd. */
  struct file *file = fd_table_get(fd);

  /* Table get fails -> no operation occurs. */
  if (file == NULL) {
    return;
  }

  synched_file_seek(file, (off_t) position);
}

/* Returns the position of the next byte to be read or written in open file fd,
expressed in bytes from the beginning of the file. Returns a relevent error 
code on an error occuring. */
static void
tell (struct intr_frame *f) {
  int fd = EXTRACT_ARG_1((int *) f->esp);
  struct file *file = fd_table_get(fd);

  /* Table get fails -> bad fd. */
  if (file == NULL) {
    f->eax = (int32_t) BAD_ARGUMENTS;
    return;
  }

  f->eax = (int32_t) synched_file_tell(file);
}

/* Closes file descriptor fd. Exiting or terminating a process implicitly
closes all its open file descriptors, as if calling this function for each. */
static void
close (struct intr_frame *f) {
  int fd = EXTRACT_ARG_1((int *) f->esp);
  /* Delegate to thread.c to handle the fd_table. */
  fd_table_close(fd);
}

/* List of function pointers of the syscalls with each at their value's 
position to allow for indexing in into syscalls in syscall_handler. */
static syscall_t *syscalls[NUMBER_OF_SYSCALLS] = {
  &halt, &sys_exit, &exec, &wait, &create, &remove, &open, &filesize, &read, &write, &seek, &tell, &close
};

/* Verifies an interrupt frams's stack pointer and then delegates
handling to the correct syscall using function pointers. */
static void
syscall_handler (struct intr_frame *f)
{
  /* Verify stack pointer. */
  verify(f->esp);

  /* Unpack stack pointer and verify its value. */
  int stack_pointer_val = *((int *) f->esp);
  if (stack_pointer_val < 0 || stack_pointer_val >= NUMBER_OF_SYSCALLS) {
    exit_process_with_status(BAD_ARGUMENTS);
  }

  /* Delegate handling to the correct syscall handler. */
  syscalls[stack_pointer_val](f);
}

/* Initializes the system call handler by registering the syscall interrupt. */
void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}
