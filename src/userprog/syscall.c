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
TODO(Should it be called with interrupts off, or will it be fine?) */
static bool
verify (void *vaddr) {
  if (vaddr != NULL && is_user_vaddr(vaddr)) {
    if (pagedir_get_page(thread_current()->pagedir, vaddr) != NULL){
      return true;
    }
  }
  return false;
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
  struct thread *cur = thread_current();
  printf("%s: exit(%d)\n", cur->name, status);
  process_exit();
  thread_exit();
}

/* Runs the executable whose name is given in cmd line, passing any given
arguments, and returns the new process’s program id (pid). */
pid_t
exec (const char *cmd_line ) {
//TODO()
  return -1;

/* Runs the executable whose name is given in cmd line, passing any given arguments, and
returns the new process’s program id (pid). Must return pid -1, which otherwise should not
be a valid pid, if the program cannot load or run for any reason. Thus, the parent process
cannot return from the exec until it knows whether the child process successfully loaded its
executable. You must use appropriate synchronization to ensure this.
*/
}

int
wait (pid_t pid) {
  return process_wait(pid);
}


/* Creates a new file called file initially initial size bytes in size. Returns
whether it was successfully created. Creating a new file doesn't open it. */
bool
create (const char *file, unsigned initial_size) {
  if (file == NULL || strlen(file) == 0) {
    return false;
  }

  return filesys_create(file, initial_size);
}

/* Deletes the file called file. Returns whether it was successfully deleted.
A file may be removed regardless of whether it is open or closed, and removing
an open file does not close it. */
bool
remove (const char *file) {
  if (file == NULL || strlen(file) == 0) {
    return false;
  }
  return filesys_remove(file);
}

/* Opens the file called file. Returns a nonnegative integer handle called a
“file descriptor” (fd), or -1 if the file could not be opened. When a single
file is opened more than once, whether by a single process or different
processes, each open returns a new file descriptor. Different file descriptors
for a single file are closed independently in separate calls to close and they
do not share a file position. */
int
open(const char *filename)
{
  struct thread *cur = thread_current();
  struct file *file = filesys_open(filename);
  if (file == NULL)
  {
    return -1; // File open failed
  }

  // Find an empty slot in the file_descriptors array
  for (int i = 2; i < MAX_FILES; i++)
  { // Skip 0 and 1 for stdin, stdout
    if (cur->file_descriptors[i] == NULL)
    {
      cur->file_descriptors[i] = file;
      //printf("open: Assigned FD %d for file %s\n", i, filename);
      return i; // Return the file descriptor
    }
  }

  file_close(file);
  return -1;
}

/* Returns the size, in bytes, of the file open as fd. */
int
filesize (int fd) {
  struct thread *cur = thread_current();

  if (fd < 2 || fd >= MAX_FILES || cur->file_descriptors[fd] == NULL) {
    return -1;  // Invalid file descriptor.
  }

  struct file *file = cur->file_descriptors[fd];
  return file_length(file);
}

/* Reads size bytes from the file open as fd into buffer. Returns the number
of bytes actually read (0 at end of file), or -1 if the file could not be read
(excluding end of file). Fd 0 will read from keyboard.*/
int
read (int fd, void *buffer, unsigned size) {
  struct thread *cur = thread_current();
  // Check if buffer is valid.
  if (buffer == NULL) {
    return -1;
  }
  if (fd == 0) { 
    unsigned bytes_read = 0;
    char *buf = buffer;
    for (unsigned i = 0; i < size; i++) {
      buf[i] = input_getc();
      bytes_read++;
    }
    return bytes_read;
  } else if (fd > 1 && fd < MAX_FILES) {
    struct file *file = cur->file_descriptors[fd];
    if (file == NULL) {
      return -1;  // Invalid file descriptor.
    }
    return file_read(file, buffer, size);
  }
  return -1;  // Invalid file descriptor.
}

/* Writes size bytes from buffer to the open file fd. Returns the number of
bytes actually written, which may be less than size if some bytes could not
be written.*/
int
write (int fd, const void *buffer, unsigned size) {
  // Check if buffer is NULL or size is 0.
  if (buffer == NULL || size == 0) {
        return 0;
  }
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
        struct file *file = thread_get_file(fd);  
        if (file == NULL) {
            return -1;  
        }
        bytes_written = file_write(file, buffer, size);
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
  //TODO()
/*A seek past the current end of a file is not an error. A later read obtains 0 bytes, indicating
end of file. Normally, a later write would extend the file, filling any unwritten gap with zeros.
However, in PintOS files have a fixed length, so writes past end of file will return an error.
These semantics are implemented in the file system and do not require any special effort in
system call implementation.*/
}

/* Returns the position of the next byte to be read or written in open file fd,
expressed in bytes from the beginning of the file. */
unsigned
tell (int fd) {
  // TODO()
  return 1;
}

/* Closes file descriptor fd. Exiting or terminating a process implicitly
closes all its open file descriptors, as if calling this function for each. */
void
close (int fd) {
  struct thread *cur = thread_current();

  if (fd < 2 || fd >= MAX_FILES || cur->file_descriptors[fd] == NULL) {
    return; 
  }
  struct file *file = cur->file_descriptors[fd];
  file_close(file);
  cur->file_descriptors[fd] = NULL;
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
        thread_exit ();
    }
  }
  /* Invalid pointer terminates user process. */
  else {
    thread_exit ();
  }
}
