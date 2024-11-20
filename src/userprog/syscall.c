#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
#include "pagedir.h"
#include "filesys/file.h"

static void syscall_handler (struct intr_frame *);

/* Used to ensure safe memory access by verifying a pointer pre-dereference.
TODO(Should it be called with interrupts off, does it need mutex aquire or will it be fine?) */
static bool
verify (void *vaddr) {
  if (vaddr != NULL && is_user_vaddr(vaddr)) {
    if (pagedir_get_page(thread_current()->pagedir, vaddr) != NULL){
      return true;
    }
  }
  return false;
}

/* Used to ensure safe memory access by verifying a string.*/
static bool
verify_string (char *target_string) {
  if (target_string == NULL || *target_string == '\0') {
    return false;
  }
  return true;
}

/* Terminates PintOS. This should be seldom used, because you lose some
information about possible deadlock situations, etc. */
void
halt (void) {
  shutdown_power_off();
}

/* Terminates the current user program, sending its exit status to the kernel.
If the process’s parent waits for it, this is what will be returned. */
void
exit (int status) {
  struct parent_child *parent_pach = thread_current()->parent;

  sema_down(&parent_pach->sema);
  parent_pach->child_exit_code = status;
  sema_up(&parent_pach->sema);
  
  thread_exit();
}

/* Runs the executable whose name is given in cmd line, passing any given
arguments, and returns the new process’s program id (pid). */
pid_t
exec(const char *cmd_line)
{
    if (cmd_line == NULL) {
        return -1; // Invalid command line
    }

    /* Make a copy of the command line. */
    char *cmd_copy = palloc_get_page(0);
    if (cmd_copy == NULL) {
        return -1;
    }
    strlcpy(cmd_copy, cmd_line, PGSIZE);

    /* Create the new process. */
    tid_t tid = process_execute(cmd_copy);
    if (tid == TID_ERROR) {
        palloc_free_page(cmd_copy);
        return -1;
    }

    /* Find the corresponding intermediary (parent_child) structure corresponding to 
      a child's tid. */
    struct parent_child *child_pach = get_child_pach(tid);
    if (child_pach == NULL) {
        palloc_free_page(cmd_copy);
        return -1;
    }

    /* Wait for the child to finish loading (succesfully or not). */
    sema_down(&child_pach->child_loaded); 

    /* Check if the child process loaded successfully. */
    if (!child_pach->child_load_success) {
        tid = -1;
    }

    /* Clean up the command line copy. */
    palloc_free_page(cmd_copy);
    return tid;
}

int
wait (pid_t pid) {
  return process_wait(pid);
}


/* Creates a new file called file initially initial size bytes in size. Returns
whether it was successfully created. Creating a new file doesn't open it. */
bool
create (const char *file_name, unsigned initial_size){
  /* Replace 2nd & 3rd condition with string validate function */
  if (initial_size > INT_MAX || !verify(file_name)) {
    exit(-1);
  }
  acquire_filesys();
  bool creation_outcome = filesys_create(file_name, (off_t) initial_size);
  release_filesys();
  return creation_outcome;
}

/* Deletes the file called file. Returns whether it was successfully deleted.
A file may be removed regardless of whether it is open or closed, and removing
an open file does not close it. */
bool
remove (const char *file_name) {
  /* Replace 2nd & 3rd condition with string validate function */
  if (!verify(file_name) || *file_name == '\0') {
    return false;
  }
  acquire_filesys();
  bool remove_outcome = filesys_remove(file_name);
  release_filesys();
  return remove_outcome;
}

/* Opens the file called file. Returns a nonnegative integer handle called a
“file descriptor” (fd), or -1 if the file could not be opened. When a single
file is opened more than once, whether by a single process or different
processes, each open returns a new file descriptor. Different file descriptors
for a single file are closed independently in separate calls to close and they
do not share a file position. */
int
open (const char *file_name) {
  /* Replace condition with string validate function */
  if (!verify(file_name)) {
    exit(-1);
  }
  if (*file_name == '\0') {
   return -1;
  }
  acquire_filesys();
  struct file *file = filesys_open(file_name);
  release_filesys();
  if (file == NULL) {
    return -1;
  }
  return fd_table_add(file);
}

/* Returns the size, in bytes, of the file open as fd. -1 on no match. */
int
filesize (int fd) {
  /* May need to add an fd check here too. */
  struct file *file = fd_table_get(fd);
  // TODO(May want to change this behaviour to kill the program or something)
  /* No matching file found. */
  /* may need to add a validate fd function to ensure fd isn't 0 or 1, and that it is less than some MAX_FD. */
  if (file == NULL) {
    return -1;
  }
  acquire_filesys();
  int file_len = file_length(file);
  release_filesys();
  return file_len;
}

/* Reads size bytes from the file open as fd into buffer. Returns the number
of bytes actually read (0 at end of file), or -1 if the file could not be read
(excluding end of file). Fd 0 will read from keyboard.*/
int
read (int fd, void *buffer, unsigned size) {
  /* Check if buffer is valid. */
  if (!verify(buffer)) {
    exit(-1);
  }
  /* TODO(May need to have mutex acquiring in fd 0 reading. */
  if (fd == 0) {
    unsigned bytes_read = 0;
    char *buf = buffer;
    for (unsigned i = 0; i < size; i++) {
      buf[i] = input_getc();
      bytes_read++;
    }
    return bytes_read;
  } else if (fd > 1 && fd < MAX_FILES) {
    struct file *file = fd_table_get(fd);
    if (file == NULL) {
      return -1;  // Invalid file descriptor.
    }
    acquire_filesys();
    off_t file_red = file_read(file, buffer, size);
    release_filesys();
    return file_red;
  }
  return -1;  // Invalid file descriptor.
}

/* Writes size bytes from buffer to the open file fd. Returns the number of
bytes actually written, which may be less than size if some bytes could not
be written.*/
int
write (int fd, const void *buffer, unsigned size) {
  /* Check if buffer is invalid. */
  if (!verify(buffer)) {
        exit(-1);
  }
  /* Check size exits, may be unnecessary. */
  if (size == 0) {
    return 0;
  } 
  /* TODO(May need to have mutex acquiring in fd 1 writing. */
  int bytes_written = 0;
  if (fd == 1) {
    // If size is large, break it into chunks to avoid interleaving.
    unsigned remaining = size;
    const char *buf = buffer;
    while (remaining > 300) {  // Write in chunks of 300 bytes.
        putbuf(buf, 300);
        buf += 300;
        remaining -= 300;
        bytes_written += 300;
    }
    if (remaining > 0) {
        putbuf(buf, remaining);
        bytes_written += remaining;
    }
  } else {
    // Write to a regular file.
    struct file *file = fd_table_get(fd);
    if (file == NULL) {
      return -1;
    }
    if (is_deny_write(file)) {
      return 0;
    }
    acquire_filesys();
    bytes_written = file_write(file, buffer, size);
    release_filesys();
    if (bytes_written < 0) {
      bytes_written = 0;
    }
  }
  return bytes_written;
/* Writing past end-of-file would normally extend the file, but file growth is not implemented
by the basic file system. The expected behaviour is to write as many bytes as possible up to
end-of-file and return the actual number written, or 0 if no bytes could be written at all.
Fd 1 writes to the console. Your code to write to the console should write all of buffer in
one call to putbuf(), at least as long as size is not bigger than a few hundred bytes. (It is
reasonable to break up larger buffers.) Otherwise, lines of text output by different processes
may end up interleaved on the console, confusing both human readers and our grading scripts.*/
}

/* Changes the next byte to be read or written in open file fd to position,
expressed in bytes from the beginning of the file (0 would be the start). */
void
seek (int fd, unsigned position) {
  /* May need to add an fd check here too. */
  /* Out of bounds position would overflow in type conversion. */
  if (position > INT_MAX) {
    // TODO(Figure out how to correctly handle such an error case)
    return;
  }
  /* Locate and verify the file matching fd. */
  struct file *file = fd_table_get(fd);
  // TODO(May want to change this behaviour e.g. to kill the program)
  /* No matching file found. */
  if (file == NULL) {
    return;
  }
  acquire_filesys();
  file_seek(file, (off_t) position);
  release_filesys();
}

/* Returns the position of the next byte to be read or written in open file fd,
expressed in bytes from the beginning of the file. */
unsigned
tell (int fd) {
  /* May need to add an fd check here too. */
  // TODO(Very similar to filesize, may be refactorable to avoid duplication)
  struct file *file = fd_table_get(fd);
  // TODO(May want to change this behaviour to say kill the program or something)
  /* No matching file found. */
  if (file == NULL) {
    return -1;
  }
  acquire_filesys();
  int file_pos = file_tell(file);
  release_filesys();
  return file_pos;
}

/* Closes file descriptor fd. Exiting or terminating a process implicitly
closes all its open file descriptors, as if calling this function for each. */
// TODO(Ensure this is called on all file descriptors when terminating or exiting a process)
void
close (int fd) {
  /* May need to add an fd check here too. */
  acquire_filesys();
  fd_table_close(fd);
  release_filesys();
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* Extract a single argument and return it, moving the pointer. */
static int
extract_arg_n(int *stack_pointer, int arg_num) {
  if (verify(stack_pointer + arg_num)) {
    return *(stack_pointer + arg_num);
  }
  else {
    thread_exit ();
  }
}

/* Extract the first argument and return it, moving the pointer. */
static int
extract_arg_1(void *stack_pointer) {
  return extract_arg_n(stack_pointer, 1);
}

/* Extract the second argument and return it, moving the pointer. */
static int
extract_arg_2(void *stack_pointer) {
  return extract_arg_n(stack_pointer, 2);
}

/* Extract the third argument and return it, moving the pointer. */
static int
extract_arg_3(void *stack_pointer) {
  return extract_arg_n(stack_pointer, 3);
}


static void
syscall_handler (struct intr_frame *f)
{
  // printf ("system call!\n");
  /* Match to the right handler. */
  // TODO(MINIMISE DUPLICATION WITH HELPER FUNCTION)
  // TODO(Consider using function pointers in place of large switch statement or in combination with helper function and numb_args)
  // TODO(Ensure everything is synced as it should be)
  if (verify(f->esp)) {
    int *stack_pointer = f -> esp;
    switch (*stack_pointer) {
      case SYS_HALT:
        halt();
        break;
      case SYS_EXIT:
        exit(extract_arg_1(stack_pointer));
        break;
      case SYS_EXEC:
        f->eax = (int32_t) exec((char *) extract_arg_1(stack_pointer));
        break;
      case SYS_WAIT:
        f->eax = (int32_t) wait(extract_arg_1(stack_pointer));
        break;
      case SYS_CREATE:
        f->eax = (int32_t) create((char *) extract_arg_1(stack_pointer), (unsigned) extract_arg_2(stack_pointer));
        break;
      case SYS_REMOVE:
        f->eax = (int32_t) remove((char *) extract_arg_1(stack_pointer));
        break;
      case SYS_OPEN:
        f->eax = (int32_t) open((char *) extract_arg_1(stack_pointer));
        break;
      case SYS_FILESIZE:
        f->eax = (int32_t) filesize(extract_arg_1(stack_pointer));
        break;
      case SYS_READ:
        f->eax = (int32_t) read(extract_arg_1(stack_pointer), (void *) extract_arg_2(stack_pointer), (unsigned) extract_arg_3(stack_pointer));
        break;
      case SYS_WRITE:
        f->eax = (int32_t) write(extract_arg_1(stack_pointer), (void *) extract_arg_2(stack_pointer), (unsigned) extract_arg_3(stack_pointer));
        break;
      case SYS_SEEK:
        seek(extract_arg_1(stack_pointer), (unsigned) extract_arg_2(stack_pointer));
        break;
      case SYS_TELL:
        f->eax = tell(extract_arg_1(stack_pointer));
        break;
      case SYS_CLOSE:
        close(extract_arg_1(stack_pointer));
        break;
      default:
        //TODO(FIGURE OUT HOW TO MORE CORRECTLY HANDLE INVALID CODE)
        exit (-1);
    }
  }
  /* Invalid pointer terminates user process. */
  else {
    thread_exit ();
  }
}
