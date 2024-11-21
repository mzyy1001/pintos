#ifndef FILESYS_FILESYS_H
#define FILESYS_FILESYS_H

#include <stdbool.h>
#include "filesys/off_t.h"
#include "../threads/synch.h"

/* Sectors of system file inodes. */
#define FREE_MAP_SECTOR 0       /* Free map file inode sector. */
#define ROOT_DIR_SECTOR 1       /* Root directory file inode sector. */

/* Block device that contains the file system. */
extern struct block *fs_device;

void filesys_init (bool format);
void filesys_done (void);
bool filesys_create (const char *name, off_t initial_size);
struct file *filesys_open (const char *name);
bool filesys_remove (const char *name);

void acquire_filesys(void);
void release_filesys(void);

/* Wrappers of other file and filesys functions ensuring mutex. */
bool synched_filesys_create (const char *name, off_t initial_size);
struct file *synched_filesys_open (const char *name);
bool synched_filesys_remove (const char *name);
void synched_file_close (struct file *file);
off_t synched_file_read (struct file *, void *, off_t);
off_t synched_file_write (struct file *, const void *, off_t);
void synched_file_seek (struct file *, off_t);
off_t synched_file_tell (struct file *);
off_t synched_file_length (struct file *);
void synched_file_deny_write (struct file *);
void synched_file_allow_write (struct file *);

#endif /* filesys/filesys.h */
