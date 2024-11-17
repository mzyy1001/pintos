#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "pagedir.h"
#include "filesys/off_t"

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
  //TODO()
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
wait (pid_t pid){
  //TODO()
  return -1;
  /*
Waits for a child process pid and retrieves the child’s exit status.
If pid is still alive, waits until it terminates. Then, returns the status that pid passed to exit.
If pid did not call exit(), but was terminated by the kernel (e.g. killed due to an exception),
wait(pid) must return -1. It is perfectly legal for a parent process to wait for child processes
that have already terminated by the time the parent calls wait, but the kernel must still
allow the parent to retrieve its child’s exit status, or learn that the child was terminated by
the kernel.
wait must fail and return -1 immediately if any of the following conditions are true:
• pid does not refer to a direct child of the calling process. pid is a direct child of the
calling process if and only if the calling process received pid as a return value from a
successful call to exec.
Note that children are not inherited: if A spawns child B and B spawns child process C,
then A cannot wait for C, even if B is dead. A call to wait(C) by process A must fail.
Similarly, orphaned processes are not assigned to a new parent if their parent process
exits before they do.
• The process that calls wait has already called wait on pid. That is, a process may wait
for any given child at most once.
Processes may spawn any number of children, wait for them in any order, and may even exit
without having waited for some or all of their children. Your design should consider all the
ways in which waits can occur. All of a process’s resources, including its struct thread,
must be freed whether its parent ever waits for it or not, and regardless of whether the child
exits before or after its parent.
As a special case, you must ensure that PintOS does not terminate until the initial pro-
cess exits. The supplied PintOS code tries to do this by calling process_wait() (in
‘userprog/process.c’) from main() (in ‘threads/init.c’).
We strongly suggest that you implement process_wait() according to the comment at the
top of the function and then implement the wait system call in terms of process_wait().
Be aware that implementing this system call requires considerably more work than any of
the others.
*/
}


/* Creates a new file called file initially initial size bytes in size. Returns
whether it was successfully created. Creating a new file doesn't open it. */
bool
create (const char *file, unsigned initial_size){
  //TODO()
  return false;
}

/* Deletes the file called file. Returns whether it was successfully deleted.
A file may be removed regardless of whether it is open or closed, and removing
an open file does not close it. */
bool
remove (const char *file) {
  // TODO()
  return false;
}

/* Opens the file called file. Returns a nonnegative integer handle called a
“file descriptor” (fd), or -1 if the file could not be opened. When a single
file is opened more than once, whether by a single process or different
processes, each open returns a new file descriptor. Different file descriptors
for a single file are closed independently in separate calls to close and they
do not share a file position. */
int
open (const char *file_name) {
  sema_down(&filesys_mutex);
  struct file *file = filesys_open(file_name);
  if (file == NULL) {
    sema_up(&filesys_mutex);
    return -1;
  }
  int fd = fd_table_add(file);
  sema_up(&filesys_mutex);
  return fd
}

/* Returns the size, in bytes, of the file open as fd. -1 on no match. */
int
filesize (int fd) {
  sema_down(&filesys_mutex);
  struct file *file = fd_table_get(fd);
  // TODO(May want to change this behaviour to say kill the program or something)
  /* No matching file found. */
  if (file == NULL) {
    sema_up(&filesys_mutex);
    return -1;
  }
  int file_len = file_length(file);
  sema_up(&filesys_mutex);
  return (file_length);
}

/* Reads size bytes from the file open as fd into buffer. Returns the number
of bytes actually read (0 at end of file), or -1 if the file could not be read
(excluding end of file). Fd 0 will read from keyboard.*/
int
read (int fd, void *buffer, unsigned size) {
  // TODO()
  return -1;
  /*Fd 0 reads from the keyboard using input_getc(), which can be found in ‘src/devices/input.h’.*/
}

/* Writes size bytes from buffer to the open file fd. Returns the number of
bytes actually written, which may be less than size if some bytes could not
be written.*/
int
write (int fd, const void *buffer, unsigned size) {
  // TODO()
  return -1;
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
  /* Out of bounds position would overflow in type conversion. */
  if (position > INT_MAX) {
    // TODO(Figure out how to correctly handle such an error case)
    return;
  }
  sema_down(&filesys_mutex);
  struct file *file = fd_table_get(fd);
  // TODO(May want to change this behaviour to say kill the program or something)
  /* No matching file found. */
  if (file == NULL) {
    sema_up(&filesys_mutex);
    return -1;
  }
  file_seek(file, (off_t) position);
  sema_up(&filesys_mutex);
}

/* Returns the position of the next byte to be read or written in open file fd,
expressed in bytes from the beginning of the file. */
unsigned
tell (int fd) {
  // TODO()
}

/* Closes file descriptor fd. Exiting or terminating a process implicitly
closes all its open file descriptors, as if calling this function for each. */
void
close (int fd) {
  // TODO()
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
  printf ("system call!\n");
  /* Match to the right handler. */
  // TODO(MINIMISE DUPLICATION WITH HELPER FUNCTION)
  // TODO(Consider using function pointers in place of large switch statement or in combination with helper function and numb_args)
  // TODO(Ensure everything is synced as it should be)
  if (verify(f) && verify(f->esp)) {
    int *stack_pointer = f -> esp;
    switch (*stack_pointer) {
      case SYS_HALT:
        halt();
        break;
      case SYS_EXIT:
        exit(extract_arg_1(stack_pointer));
        break;
      case SYS_EXEC:
        exec((char *) extract_arg_1(stack_pointer));
        break;
      case SYS_WAIT:
        wait(extract_arg_1(stack_pointer));
        break;
      case SYS_CREATE:
        create((char *) extract_arg_1(stack_pointer), (unsigned) extract_arg_2(stack_pointer));
        break;
      case SYS_REMOVE:
        remove((char *) extract_arg_1(stack_pointer));
        break;
      case SYS_OPEN:
        open((char *) extract_arg_1(stack_pointer));
        break;
      case SYS_FILESIZE:
        filesize(extract_arg_1(stack_pointer));
        break;
      case SYS_READ:
        read(extract_arg_1(stack_pointer), (void *) extract_arg_2(stack_pointer), (unsigned) extract_arg_3(stack_pointer));
        break;
      case SYS_WRITE:
        write(extract_arg_1(stack_pointer), (void *) extract_arg_2(stack_pointer), (unsigned) extract_arg_3(stack_pointer));
        break;
      case SYS_SEEK:
        seek(extract_arg_1(stack_pointer), (unsigned) extract_arg_2(stack_pointer));
        break;
      case SYS_TELL:
        tell(extract_arg_1(stack_pointer));
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
