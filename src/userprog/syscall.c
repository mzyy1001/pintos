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
#include "threads/palloc.h"

/* Number of syscalls implemented that the syscall handler can call. */
#define NUMBER_OF_SYSCALLS 13
/* Exit code when given bad (invalid or out of range) arguments. */
#define BAD_ARGUMENTS (-1)
/* Syscall exit code when an operation with the parent_child struct fails. */
#define PARENT_CHILD_ERROR (-1)
/* Syscall exit code when a (filesys/process)_{name} function doesn't run as intended. */
#define FUNCTION_ERROR (-1)
/* Syscall exit code when a memory allocation fails. */
#define MEMORY_ALLOCATION_ERROR (-1)
/* Max string argument length to prevent incorrectly structured strings infinite looping. */
#define MAX_STRING_LENGTH (2 << 20)
/* Syscall return code for return that 0 of whatever was 
expected to be done/given was done/given. */
#define NOTHING 0
/* The fd value that refers to the console (for output). */
#define CONSOLE_FD 1
/* The fd value that refers to the keyboards (for input). */
#define KEYBOARD_FD 0


static void exit (int status);
/* Process identifier. */
typedef int pid_t;
/* Syscall function. */
typedef void (syscall_t) (struct intr_frame *);

/* Used to ensure safe memory access by verifying a pointer pre-dereference. */
static bool
verify (void *vaddr) {
  if (vaddr == NULL || !is_user_vaddr(vaddr) || pagedir_get_page(thread_current()->pagedir, vaddr) == NULL) {
    exit(BAD_ARGUMENTS);
  }
  return true;
}

/* Extract a single argument and return it, not moving the pointer. */
static int
extract_arg_n (int *stack_pointer, int arg_num) {
  if (verify(stack_pointer + arg_num)) {
    return stack_pointer[arg_num];
  }
  else {
    thread_exit ();
  }
}

/* Extract the first argument and return it, not moving the pointer. */
#define EXTRACT_ARG_1(stack_pointer) (extract_arg_n(stack_pointer, 1))
/* Extract the second argument and return it, not moving the pointer. */
#define EXTRACT_ARG_2(stack_pointer) (extract_arg_n(stack_pointer, 2))
/* Extract the third argument and return it, not moving the pointer. */
#define EXTRACT_ARG_3(stack_pointer) (extract_arg_n(stack_pointer, 3))

/* This function ensures all parts of a string are verified. */
static bool
verify_string (const char *str) {
  const char *ptr = str;
  int byte_count = 0;

  /* Verify the first byte. */
  if (!verify((void *) ptr)) {
    return false;
  }

  while (*ptr != '\0') {
    ptr++;
    byte_count++;

    /* Prevent infinite looping using the max string length. */
    if (byte_count > MAX_STRING_LENGTH) {
      return false;
    }

    /* Only need to verify if crossing into a new page. */
    if ((uint32_t) ptr % PGSIZE == 0) {
      if (!verify((void *) ptr)) {
        return false;
      }
    }
  }

  /* Verify the final byte. */ 
  verify((void *)ptr);
  return true;
}

static bool
verify_buffer (const void *buffer, unsigned size) {
  const uint8_t *ptr = (const uint8_t *) buffer;
  const uint8_t *end = ptr + size;

  /* Verify the necessary pointers between ptr and end. */
  while (ptr < end) {
    if (!verify((void *) ptr)) {
      return false;
    }
    ptr ++;
    //TODO(Replace with page sized jumps (or end) later)
  }
  return true;
}

/* Terminates PintOS. This should be seldom used, because you lose some
information about possible deadlock situations, etc. */
static void
halt (struct intr_frame *aux UNUSED) {
  shutdown_power_off();
}

/* Terminates the current user program, sending its exit status to the kernel.
If the process’s parent waits for it, this is what will be returned. */
static void
exit (int status) {
  struct parent_child *parent_pach = thread_current()->parent;

  sema_down(&parent_pach->sema);
  parent_pach->child_exit_code = status;
  sema_up(&parent_pach->sema);

  thread_exit();
}

/* Wraps exit allowing it to be called by the syscall handler. */
static void
sys_exit (struct intr_frame *f) {
  exit(EXTRACT_ARG_1((int *) f->esp));
}

/* Runs the executable whose name is given in cmd line, passing any given
arguments, and returns the new process’s program id (pid). */
static void
exec (struct intr_frame *f) {
  const char *cmd_line = (char *) EXTRACT_ARG_1((int *) f->esp);
  // TODO(Naive cmd_line length check may be improvable)
  if (!verify_string(cmd_line) || strlen(cmd_line) > PGSIZE) {
    f ->eax = (int32_t) BAD_ARGUMENTS;
    return;
  }

  /* Make a copy of the command line. */
  char *cmd_copy = palloc_get_page(0);
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
  /* Replace 2nd & 3rd condition with string validate function */
  if (initial_size > INT_MAX || !verify_string(file_name)) {
    exit(BAD_ARGUMENTS);
  }
  f->eax = (int32_t) synched_filesys_create(file_name, (off_t) initial_size);
}

/* Deletes the file called file. Returns whether it was successfully deleted.
A file may be removed regardless of whether it is open or closed, and removing
an open file does not close it. */
static void
remove (struct intr_frame *f) {
  const char *file_name = (char *) EXTRACT_ARG_1((int *) f->esp);
  /* Replace 2nd & 3rd condition with string validate function */
  if (!verify_string(file_name) || *file_name == '\0') {
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
  /* Replace condition with string validate function */
  if (!verify_string(file_name)) {
    exit(BAD_ARGUMENTS);
  }
  if (*file_name == '\0') {
    f->eax = (int32_t) BAD_ARGUMENTS;
    return;
  }
  struct file *file = synched_filesys_open(file_name);
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
  /* May need to add an fd check here too. */
  struct file *file = fd_table_get(fd);
  // TODO(May want to change this behaviour to kill the program or something)
  /* Table get fails -> bad fd. */
  if (file == NULL) {
    f->eax = (int32_t) BAD_ARGUMENTS;
    return;
  }
  f->eax = (int32_t) synched_file_length(file);
}

/* Reads size bytes from the file open as fd into buffer. Returns the number
of bytes actually read (0 at end of file), or -1 if the file could not be read
(excluding end of file). Fd 0 will read from keyboard. */
static void
read (struct intr_frame *f) {
  int fd = EXTRACT_ARG_1((int *) f->esp);
  void *buffer = (void *) EXTRACT_ARG_2((int *) f->esp);
  unsigned size = (unsigned) EXTRACT_ARG_3 ((int *) f->esp);
  /* Check if buffer is valid. */
  if (!verify_buffer(buffer, size)) {
    exit(BAD_ARGUMENTS);
  }
  /* TODO(May need to have mutex acquiring in fd 0 reading. */
  if (fd == KEYBOARD_FD) {
    unsigned bytes_read = NOTHING;
    char *buf = buffer;
    for (unsigned i = 0; i < size; i++) {
      acquire_filesys();
      buf[i] = input_getc();
      release_filesys();
      bytes_read++;
    }
    f->eax = (int32_t) bytes_read;
    return;
  }
  struct file *file = fd_table_get(fd);
  /* Table get fails -> bad fd. */
  if (file == NULL) {
    f->eax = (int32_t) BAD_ARGUMENTS;
    return;
  }
  f->eax = (int32_t) synched_file_read(file, buffer, size);
  return;
}

/* Writes size bytes from buffer to the open file fd. Returns the number of
bytes actually written, which may be less than size if some bytes could not
be written. */
static void
write (struct intr_frame *f) {
  int fd = EXTRACT_ARG_1((int *) f->esp);
  const void *buffer = (void *) EXTRACT_ARG_2((int *) f->esp);
  unsigned size = (unsigned) EXTRACT_ARG_3 ((int *) f->esp);
  /* Check if buffer is invalid. */
  if (!verify_buffer(buffer, size)) {
    exit(BAD_ARGUMENTS);
  }
  /* Check size exits, may be unnecessary. */
  if (size == NOTHING) {
    f->eax = NOTHING;
    return;

  } 
  /* TODO(May need to have mutex acquiring in fd 1 writing. */
  int bytes_written = 0;
  if (fd == CONSOLE_FD) {
    unsigned remaining = size;
    const char *buf = buffer;

    /* Write in 300 byte chunks. */
    while (remaining > 300) {
      acquire_filesys();
      putbuf(buf, 300);
      release_filesys();
      buf += 300;
      remaining -= 300;
      bytes_written += 300;
    }
    if (remaining > 0) {
      putbuf(buf, remaining);
      bytes_written += remaining;
    }
  } else {
    /* Write to a regular file. */
    struct file *file = fd_table_get(fd);
    /* Table get fails -> bad fd. */
    if (file == NULL) {
      f->eax = (int32_t) BAD_ARGUMENTS;
      return;
    }
    if (is_deny_write(file)) {
      f->eax = NOTHING;
      return;

    }
    bytes_written = synched_file_write(file, buffer, size);
    if (bytes_written < NOTHING) {
      bytes_written = NOTHING;
    }
  }
  f->eax = (int32_t) bytes_written;
}

/* Changes the next byte to be read or written in open file fd to position,
expressed in bytes from the beginning of the file (0 would be the start). */
static void
seek (struct intr_frame *f) {
  int fd = EXTRACT_ARG_1((int *) f->esp);
  unsigned position = (unsigned) EXTRACT_ARG_2 ((int *) f->esp);
  /* Out of bounds position would overflow in type conversion. */
  if (position > INT_MAX) {
    // TODO(Figure out how to correctly handle such an error case)
    return;
  }
  /* Locate and verify the file matching fd. */
  struct file *file = fd_table_get(fd);
  // TODO(May want to change this behaviour e.g. to kill the program)
  /* Table get fails -> bad fd. */
  if (file == NULL) {
    return;
  }
  synched_file_seek(file, (off_t) position);
}

/* Returns the position of the next byte to be read or written in open file fd,
expressed in bytes from the beginning of the file. */
static void
tell (struct intr_frame *f) {
  int fd = EXTRACT_ARG_1((int *) f->esp);
  /* May need to add a fd check here too. */
  // TODO(Very similar to filesize, may be refactorable to avoid duplication)
  struct file *file = fd_table_get(fd);
  // TODO(May want to change this behaviour to say kill the program or something)
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
  /* May need to add a fd check here too. */
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
  if (!verify(f->esp)) {
    exit(BAD_ARGUMENTS);
  }

  int *stack_pointer = f->esp;
  if (*stack_pointer < 0 || *stack_pointer >= NUMBER_OF_SYSCALLS) {
    exit(BAD_ARGUMENTS);
  }

  syscalls[*stack_pointer](f);
}

/* Initializes the system call handler by registering the syscall interrupt. */
void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}
