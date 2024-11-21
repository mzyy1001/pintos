#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"

#define NUMBER_OF_PARALLEL_FILESYS_USERS 1

/* Semaphore to ensure safe use of filesystem. */
static struct semaphore filesys_mutex;

/* Acquire the filesys_mutex - if wrapping a single function consider 
using a synched_function_name version if it exists instead. */
void
acquire_filesys() {
  sema_down(&filesys_mutex);
}

/* Releases the filesys_mutex - if wrapping a single function consider 
using a synched_function_name version if it exists instead. */
void
release_filesys() {
  sema_up(&filesys_mutex);
}

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  fs_device = block_get_role (BLOCK_FILESYS);
  sema_init(&filesys_mutex, NUMBER_OF_PARALLEL_FILESYS_USERS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  inode_init ();
  free_map_init ();

  if (format) 
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  free_map_close ();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size) 
{
  block_sector_t inode_sector = 0;
  struct dir *dir = dir_open_root ();
  bool success = (dir != NULL
                  && free_map_allocate (1, &inode_sector)
                  && inode_create (inode_sector, initial_size)
                  && dir_add (dir, name, inode_sector));
  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);
  dir_close (dir);

  return success;
}

/* Wraps filesys_create with a semaphore to ensure mutex of filesys. */
bool 
synched_filesys_create (const char *name, off_t initial_size) {
  sema_down(&filesys_mutex);
  bool result = filesys_create(name, initial_size);
  sema_up(&filesys_mutex);
  return result;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{
  struct dir *dir = dir_open_root ();
  struct inode *inode = NULL;

  if (dir != NULL)
    dir_lookup (dir, name, &inode);
  dir_close (dir);

  return file_open (inode);
}

/* Wraps filesys_open with a semaphore to ensure mutex of filesys. */
struct file *
synched_filesys_open (const char *name) {
  sema_down(&filesys_mutex);
  struct file *result = filesys_open(name);
  sema_up(&filesys_mutex);
  return result;
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
  struct dir *dir = dir_open_root ();
  bool success = dir != NULL && dir_remove (dir, name);
  dir_close (dir); 

  return success;
}

/* Wraps filesys_remove with a semaphore to ensure mutex of filesys. */
bool
synched_filesys_remove (const char *name) {
  sema_down(&filesys_mutex);
  bool result = filesys_remove(name);
  sema_up(&filesys_mutex);
  return result;
}

/* Wraps file_close with a semaphore to ensure mutex of filesys. */
void
synched_file_close (struct file *file) {
  sema_down(&filesys_mutex);
  file_close(file);
  sema_up(&filesys_mutex);
}

/* Wraps file_read with a semaphore to ensure mutex of filesys. */
off_t
synched_file_read (struct file *file, void *buffer, off_t offset) {
  sema_down(&filesys_mutex);
  off_t result = file_read(file, buffer, offset);
  sema_up(&filesys_mutex);
  return result;
}

/* Wraps file_write with a semaphore to ensure mutex of filesys. */
off_t
synched_file_write (struct file *file, const void *buffer, off_t offset) {
  sema_down(&filesys_mutex);
  off_t result = file_write(file, buffer, offset);
  sema_up(&filesys_mutex);
  return result;
}

/* Wraps file_seek with a semaphore to ensure mutex of filesys. */
void
synched_file_seek (struct file *file, off_t offset) {
  sema_down(&filesys_mutex);
  file_seek(file, offset);
  sema_up(&filesys_mutex);
}

/* Wraps file_tell with a semaphore to ensure mutex of filesys. */
off_t
synched_file_tell (struct file *file) {
  sema_down(&filesys_mutex);
  off_t result = file_tell(file);
  sema_up(&filesys_mutex);
  return result;
}

/* Wraps file_length with a semaphore to ensure mutex of filesys. */
off_t
synched_file_length (struct file *file) {
  sema_down(&filesys_mutex);
  off_t result = file_length(file);
  sema_up(&filesys_mutex);
  return result;
}

/* Wraps file_deny_write with a semaphore to ensure mutex of filesys. */
void
synched_file_deny_write (struct file *file) {
  sema_down(&filesys_mutex);
  file_deny_write(file);
  sema_up(&filesys_mutex);
}

/* Wraps file_allow_write with a semaphore to ensure mutex of filesys. */
void
synched_file_allow_write (struct file *file) {
  sema_down(&filesys_mutex);
  file_allow_write(file);
  sema_up(&filesys_mutex);
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}
