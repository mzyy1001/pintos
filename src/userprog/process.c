#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"

static thread_func start_process NO_RETURN;
static bool load (void *args_, const char *cmdline, void (**eip) (void), void **esp);
static bool setup_stack (void **esp, void *args_, char *file_name);
struct parent_child *get_child_pach(tid_t c_tid);

/* Checks if the stack pointer (`esp`) is within safe memory bounds to prevent stack overflow. */
static bool
stack_overflowing (uint8_t *esp) {
    return (esp < (uint8_t *)PHYS_BASE - PGSIZE);
}

/* Wraps a check of esp so that if it is not 
in safe bounds the correct actions can be taken. */
#define CHECK_STACK_OVERFLOW(esp) \
  do { \
    if (stack_overflowing(esp)) { \
      success = false; \
      goto done; \
    } \
  } while (0)

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *arguments)
{
  char *args_copy;
  tid_t tid;
  char *save_ptr;

  /* Make a single copy of arguments to avoid race conditions. */
  args_copy = palloc_get_page(PAL_ZERO);
  if (args_copy == NULL) {
    return TID_ERROR;
  }
  strlcpy(args_copy, arguments, PGSIZE);

  /* Parse the file name and store it independently using malloc. */
  char *file_name = strtok_r(args_copy, " ", &save_ptr);
  if (file_name == NULL || *file_name == '\0') {
    palloc_free_page(args_copy);
    return -1;
  }

  /* Save the file_name independently. */
  char *file_name_copy = malloc(strlen(file_name) + 1);
  if (file_name_copy == NULL) {
    palloc_free_page(args_copy);
    return TID_ERROR;
  }

  /* Correctly initialise file_name_copy and args_copy*/
  strlcpy(file_name_copy, file_name, strlen(file_name) + 1);
  strlcpy(args_copy, arguments, PGSIZE);

  /* Create a new thread to execute the program. */
  tid = thread_create(file_name_copy, PRI_DEFAULT, start_process, args_copy);

  /* Free the correct memory on thread creation faliure. */
  if (tid == TID_ERROR) {
    free(file_name_copy);
    palloc_free_page(args_copy);
  }

  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *args_)
{
  char *args = args_;
  struct intr_frame if_;
  bool success;
  struct thread *cur = thread_current();
  char *file_name = cur->name;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (args_,file_name, &if_.eip, &if_.esp);
  palloc_free_page(args);

  /* Signal to parent load success/failure */
  struct parent_child *parent_pach = cur->parent;
  sema_down(&parent_pach->sema);
  parent_pach->child_load_success = success;
  sema_up(&parent_pach->sema);
  sema_up(&parent_pach->child_loaded);    

  /* If load failed, quit. */
  if (!success)
  {
    thread_exit ();
  }

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Returns the intermediary structure (parent_child) of the parent's child with child_tid. 
The actual child thread * can be accessed using: get_child_pach(child_tid)->child.
Returns NULL if nothing matches the given c_tid. */
struct parent_child *get_child_pach (tid_t c_tid) {
  struct list_elem *e;
  struct parent_child *child_pach;
  struct list *children = &(thread_current()->children);
  
  /* Loop through the children returning the correct parent-child patch. */
  for (e = list_begin(children); e != list_end(children); e = list_next(e)) {
    child_pach = list_entry(e, struct parent_child, child_elem);

    /* Child located. */
    if (child_pach->child_tid == c_tid) {
      return child_pach;
    }
  }

  /* No matching child. */
  return NULL;
}

/* Waits for thread TID to die and returns its exit status.
 * If it was terminated by the kernel (i.e. killed due to an exception),
 * returns -1.
 * If TID is invalid or if it was not a child of the calling process, or if
 * process_wait() has already been successfully called for the given TID,
 * returns -1 immediately, without waiting.
 *
 * This function will be implemented in task 2.
 * For now, it does nothing. */
int
process_wait (tid_t child_tid)
{
  /* Get the correct parent-child struct. */
  struct parent_child *child_pach = get_child_pach(child_tid);

  /* Child_tid doesn't correspond to any of this thread's children. */
  if (child_pach == NULL) {
    return -1;
  }

  /* Check if parent already called this on the same thread, if so that is 
  not allowed (as child is already dead) and so it returns an error code. */
  if (child_pach->been_waited_on) {
    return -1;
  }

  /* Synchronised modification of child_pach->sema. */ 
  sema_down(&child_pach->sema);
  child_pach->been_waited_on = true;
  sema_up(&child_pach->sema);

  /* Wait for child to exit. */
  sema_down(&child_pach->waiting);      

  /* We know that the child is dead and has provided the exit code, 
  look at process_exit to understand how that happened. */ 
  return child_pach->child_exit_code;
}


/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* Get the parent-child relationship structure with this thread's parent. */
  struct parent_child *parent_pach = cur->parent;

  /* If this thread is a child of some parent perform the necessary cleanup. */
  if (parent_pach != NULL)
  {
    /* Ensure mutex and print the necessary termination message. */
    sema_down(&parent_pach->sema);
    printf("%s: exit(%d)\n", cur->name, parent_pach->child_exit_code);

    /* If the parent is dead the child must clean up the shared structure. */
    if (parent_pach->parent_dead)
    {
      free(parent_pach);
      parent_pach = NULL;
    }
    else
    {
      /* Otherwise mark this child as dead and must release semaphores. */
      parent_pach->child_dead = true;
      sema_up(&parent_pach->waiting);
      sema_up(&parent_pach->sema);
    }
  }

  /* Traverse the list of children, letting each child know it's parent exited. */
  struct list *children = &cur->children;
  if (children != NULL) { 
    struct list_elem *e = list_begin(children);
    while (e != list_end(children)) {
      /* Get the correct parent_child structure and enfore mutex. */
      struct parent_child *child_pach = list_entry(e, struct parent_child, child_elem);
      sema_down(&child_pach->sema);

      /* If the child is dead clear up the structure. */
      if (child_pach->child_dead) {
        e = list_remove(e);
        free(child_pach);
      } else {
        /* Otherwise mark parent as dead and allow reaccess to the structure. */
        child_pach->parent_dead = true;
        sema_up(&child_pach->sema);
        e = list_next(e); 
      }
    }
  }

  /* Allow writes to the associated executable file if it exist. */
  if (thread_current()->executable_file != NULL) {
    synched_file_allow_write(thread_current()->executable_file);
    file_close(thread_current()->executable_file);
    cur->executable_file = NULL;
  }

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL)
  {
    /* Correct ordering here is crucial.  We must set
       cur->pagedir to NULL before switching page directories,
       so that a timer interrupt can't switch back to the
       process page directory.  We must activate the base page
       directory before destroying the process's page
       directory, or our active page directory will be one
       that's been freed (and cleared). */
    cur->pagedir = NULL;
    pagedir_activate (NULL);
    pagedir_destroy (pd);
  }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
{
  unsigned char e_ident[16];
  Elf32_Half    e_type;
  Elf32_Half    e_machine;
  Elf32_Word    e_version;
  Elf32_Addr    e_entry;
  Elf32_Off     e_phoff;
  Elf32_Off     e_shoff;
  Elf32_Word    e_flags;
  Elf32_Half    e_ehsize;
  Elf32_Half    e_phentsize;
  Elf32_Half    e_phnum;
  Elf32_Half    e_shentsize;
  Elf32_Half    e_shnum;
  Elf32_Half    e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
{
  Elf32_Word p_type;
  Elf32_Off  p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (void *args_, const char *file_name, void (**eip) (void), void **esp)
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL)
    goto done;
  process_activate ();

  /* Open executable file. */
  file = synched_filesys_open (file_name);
  if (file == NULL)
  {
    printf ("load: %s: open failed\n", file_name);
    goto done;
  }
  synched_file_deny_write(file);
  thread_current()->executable_file = file;
  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024)
  {
    printf ("load: %s: error loading executable\n", file_name);
    goto done;
  }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
  {
    struct Elf32_Phdr phdr;

    if (file_ofs < 0 || file_ofs > file_length (file))
      goto done;
    file_seek (file, file_ofs);

    if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
      goto done;
    file_ofs += sizeof phdr;
    switch (phdr.p_type)
    {
      case PT_NULL:
      case PT_NOTE:
      case PT_PHDR:
      case PT_STACK:
      default:
        /* Ignore this segment. */
        break;
      case PT_DYNAMIC:
      case PT_INTERP:
      case PT_SHLIB:
        goto done;
      case PT_LOAD:
        if (validate_segment (&phdr, file))
        {
          bool writable = (phdr.p_flags & PF_W) != 0;
          uint32_t file_page = phdr.p_offset & ~PGMASK;
          uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
          uint32_t page_offset = phdr.p_vaddr & PGMASK;
          uint32_t read_bytes, zero_bytes;
          if (phdr.p_filesz > 0)
          {
            /* Normal segment.
               Read initial part from disk and zero the rest. */
            read_bytes = page_offset + phdr.p_filesz;
            zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                          - read_bytes);
          }
          else
          {
            /* Entirely zero.
               Don't read anything from disk. */
            read_bytes = 0;
            zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
          }
          if (!load_segment (file, file_page, (void *) mem_page,
                             read_bytes, zero_bytes, writable))
            goto done;
        }
        else
          goto done;
        break;
    }
  }

  /* Set up stack. */
  if (!setup_stack(esp, args_, (char *)file_name))
  {
    goto done;
  }
  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;
  success = true;

  done:
  /* We arrive here whether the load is successful or not. */
  if (!success && file != NULL)
  {
    /* Revert deny-write if load fails. */
    synched_file_allow_write(file);
    file_close(file);
    t->executable_file = NULL;
  }
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Cleans up and frees all allocated pages within the specified user address range. 
Start page must be lower than end page or no pages will be cleaned. */
static void
cleanup_allocated_pages (uint8_t *start_upage, uint8_t *end_upage) {
  struct thread *t = thread_current();
  /* Loop through each page and clear & free it. */
  while (start_upage < end_upage) {
    void *kpage = pagedir_get_page(t->pagedir, start_upage);
    if (kpage != NULL) {
      pagedir_clear_page(t->pagedir, start_upage);
      palloc_free_page(kpage);
    }
    start_upage += PGSIZE;
  }
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  uint8_t *start_upage = upage;
  while (read_bytes > 0 || zero_bytes > 0)
  {
    /* Calculate how to fill this page.
       We will read PAGE_READ_BYTES bytes from FILE
       and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* Check if virtual page already allocated */
    struct thread *t = thread_current ();
    uint8_t *kpage = pagedir_get_page (t->pagedir, upage);

    if (kpage == NULL){

      /* Get a new page of memory. */
      kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL){
        cleanup_allocated_pages(start_upage, upage);
        return false;
      }

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable))
      {
        palloc_free_page (kpage);
        cleanup_allocated_pages(start_upage, upage);
        return false;
      }

    } else {

      /* Check if writable flag for the page should be updated */
      if(writable && !pagedir_is_writable(t->pagedir, upage)){
        pagedir_set_writable(t->pagedir, upage, writable);
      }

    }

    /* Load data into the page. */
    if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes){
      cleanup_allocated_pages(start_upage, upage);
      return false;
    }

    memset (kpage + page_read_bytes, 0, page_zero_bytes);

    /* Advance. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
  }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp, void *args_, char *file_name)
{
  char *save_ptr = NULL;
  ASSERT(file_name != NULL);
  uint8_t *kpage = NULL;
  bool success = false;

  /* Allocate memory for argv to store arguments. */
  char *argv[MAX_ARGS];
  
  /* Allocate a clean page for the stack. */
  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL)
  {
    /* Try install it it at the top of memory. */
    success = install_page(((uint8_t *)PHYS_BASE) - PGSIZE, kpage, true);
    if (success)
    {
      *esp = PHYS_BASE;

      /* Push arguments onto the stack in reverse order. */ 
      char *args = args_;
      size_t args_size = 0;
      int argc = 0;
      char *arg = strtok_r(args, " ", &save_ptr);

      /* Tokenise the arguments string and push each onto the stack. */
      while (arg != NULL)
      {
        size_t arg_len = strlen(arg) + 1;
        *esp -= strlen(arg) + 1;
        
        /* Ensure MAX_ARGS is not exceeded. */
        if (argc >= MAX_ARGS) {
          success = false;
          goto done;
        }

        /* Update the total size of arguments (includes alignment). */
        args_size += arg_len + ((uintptr_t)(*esp) % 4);

        /* Check for stack overflow to prevent the stack 
        pointer entering incorrect memory locations. */
        CHECK_STACK_OVERFLOW(*esp);

        /* Add argument to the stack. */
        memcpy(*esp, arg, strlen(arg) + 1);
        argv[argc++] = *esp;
        
        /* Get the next argument for repeat. */
        arg = strtok_r(NULL, " ", &save_ptr);
      }

      /* Word-align the stack. */
      uintptr_t align = (uintptr_t)(*esp) % 4;
      if (align)
      {
        *esp -= align;
        CHECK_STACK_OVERFLOW(*esp);
        memset(*esp, 0, align);
      }


      /* Null-terminate argv. */
      argv[argc] = NULL;
      
      /* Push argument addresses onto the stack. */ 
      for (int i = argc; i >= 0; i--)
      {
        *esp -= sizeof(char *);
        CHECK_STACK_OVERFLOW(*esp);
        memcpy(*esp, &argv[i], sizeof(char *));
      }

      /* Push argv onto the stack. */
      char **argv_ptr = *esp;
      *esp -= sizeof(char **);
      CHECK_STACK_OVERFLOW(*esp);
      memcpy(*esp, &argv_ptr, sizeof(char **));

      /* Push argc onto the stack. */
      *esp -= sizeof(int);
      CHECK_STACK_OVERFLOW(*esp);
      *(int *)*esp = argc;

      /* Push a fake return address onto the stack. */ 
      *esp -= sizeof(void *);
      CHECK_STACK_OVERFLOW(*esp);
      *(void **)*esp = 0;
    }
    else
    {
      /* If installing the page fails clean up the page. */
      printf("setup_stack: Cleaning up stack page at %p\n", kpage);
      palloc_free_page(kpage);
      kpage = NULL;
      goto done;
    }
  }
  /* If the setup was unsuccessfull in any way clean up everything. */
  done:
  if (!success && kpage != NULL)
  {
    palloc_free_page(kpage);
    void *upage = ((uint8_t *)PHYS_BASE) - PGSIZE;
    pagedir_clear_page(thread_current()->pagedir, upage);
    kpage = NULL;
  }

  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
