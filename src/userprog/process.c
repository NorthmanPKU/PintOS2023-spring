#include "userprog/process.h"
#include "userprog/syscall.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#ifdef VM
#include "vm/frame.h"
#include "vm/page.h"
#endif

extern struct lock filesys_lock;
extern struct lock filesys_lock2;
extern struct lock lock_for_scan;
extern struct lock sup_page_lock;

#define MAX_ARGS 128

static thread_func start_process NO_RETURN;
static bool load(const char* cmdline, void (**eip)(void), void** esp);


/** Starts a new thread running a user program loaded from 
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t process_execute(const char* command_line) {
    char* fn_copy, *fn_copy_;
    tid_t tid;

    char *file_name, *save_ptr;
    //save arguments


    /* Make copies of FILE_NAME.
       Otherwise there's a race between the caller and load(). */
    fn_copy = palloc_get_page(0);
    fn_copy_ = palloc_get_page(0);

    if (fn_copy == NULL || fn_copy_ == NULL)
        return TID_ERROR;
    strlcpy(fn_copy, command_line, PGSIZE);
    strlcpy(fn_copy_, command_line, PGSIZE);
    file_name = strtok_r(fn_copy, " ", &save_ptr);

    /* Create a new thread to execute FILE_NAME. */
    tid = thread_create(file_name, PRI_DEFAULT, start_process, fn_copy_);
    sema_down(&thread_current()->sc_exec_sema);
    if (tid == TID_ERROR){
        palloc_free_page(fn_copy);
        palloc_free_page(fn_copy_);
        return tid;
    }
    if(thread_current()->child_exec_success == false){
        return -1;
    }
    thread_current()->child_exec_success = false;
    palloc_free_page(fn_copy);
    palloc_free_page(fn_copy_);

    return tid;
}

/** A thread function that loads a user process and starts it
   running. */
static void start_process(void* command_line_) {

    char *token, *save_ptr;
    char* command_line = command_line_;
    char* cmd_l_cpy = palloc_get_page(0);
    strlcpy(cmd_l_cpy, command_line, PGSIZE);

    char* file_name = strtok_r(command_line, " ", &save_ptr);
    struct intr_frame if_;
    bool success;

    /* Initialize interrupt frame and load executable . */
    memset(&if_, 0, sizeof if_);
    if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
    if_.cs = SEL_UCSEG;
    if_.eflags = FLAG_IF | FLAG_MBS;
    //lock_acquire(&filesys_lock);
    //lock_acquire(&filesys_lock2);
    success = load(file_name, &if_.eip, &if_.esp);
    //lock_release(&filesys_lock);
    //lock_release(&filesys_lock2);

    struct thread* cur = thread_current();

    /* If load failed, quit. */
    //palloc_free_page(file_name);
    if (!success){
        cur->self_as_child->is_alive = false;
        cur->exit_code = -1;
        cur->parent->child_exec_success = 0;//
        sema_up(&cur->parent->sc_exec_sema);
        palloc_free_page(cmd_l_cpy);
        thread_exit();
    }

    //cur->parent->child_exec_success = 1;//
    //sema_up(&cur->parent->sc_exec_sema);

    /*
    lock_acquire(&filesys_lock);
    struct file* file = filesys_open(file_name);
    //if (file != NULL) {
    file_deny_write(file);
    //}
    thread_current()->executable_file = file;
    lock_release(&filesys_lock);
    */

    /* Push arguments onto stack. */
    int argc = 0;
    if_.esp = PHYS_BASE;
    void* argv_loc[MAX_ARGS];
    for (token = strtok_r(cmd_l_cpy, " ", &save_ptr); token != NULL;
         token = strtok_r(NULL, " ", &save_ptr)) {
        if_.esp -= strlen(token) + 1;
        memcpy(if_.esp, token, strlen(token) + 1);
        argv_loc[argc] = if_.esp;
        argc++;
    }
    // word align
    if_.esp = (void*)ROUND_DOWN((uint32_t)if_.esp, 4);
    // push argv[argc]
    size_t pointer_size = sizeof(void *);
    if_.esp -= pointer_size;
    memset(if_.esp, 0, pointer_size);
    // push argv[argc-1] ~ argv[0]
    for (int i = argc - 1; i >= 0; i--) {
        if_.esp -= pointer_size;
        memcpy(if_.esp, &argv_loc[i], pointer_size);
    }
    // push argv
    void* argv = if_.esp;
    if_.esp -= pointer_size;
    memcpy(if_.esp, &argv, pointer_size);

    // push argc
    if_.esp -= pointer_size;
    memcpy(if_.esp, &argc, sizeof(pointer_size));

    // push fake return address
    if_.esp -= pointer_size;
    memset(if_.esp, 0, pointer_size);

    thread_current()->parent->child_exec_success = 1;
    sema_up(&thread_current()->parent->sc_exec_sema);
    palloc_free_page(cmd_l_cpy);


    /* Start the user process by simulating a return from an
       interrupt, implemented by intr_exit (in
       threads/intr-stubs.S).  Because intr_exit takes all of its
       arguments on the stack in the form of a `struct intr_frame',
       we just point the stack pointer (%esp) to our stack frame
       and jump to it. */
    asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
    NOT_REACHED();
}

/** Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int process_wait(tid_t child_tid UNUSED) {
    //not a direct child
    if (child_tid == TID_ERROR)
        return -1;
    //check validation of child_tid
    

    struct thread* cur = thread_current();
    struct list_elem* e;
    for(e = list_begin(&cur->child_list); e != list_end(&cur->child_list); e = list_next(e)){

        struct child_thread* c = list_entry(e, struct child_thread, elem);
        if(c->tid == child_tid){
            if(c->is_waited){
                return -1;
            }
            else if(!c->is_alive) {
                list_remove(e);
                return c->exit_status;
            }
            c->is_waited = true;
            sema_down(&(c->sema));
            int exit_status = c->exit_status;
            list_remove(e);
            return exit_status;
        }
    }
    return -1;
}

/** Free the current process's resources. */
void process_exit(void) {
    struct thread* cur = thread_current();
    uint32_t* pd;
    printf ("%s: exit(%d)\n",thread_name(), thread_current()->exit_code);
    enum intr_level old_level = intr_disable();
    if(lock_held_by_current_thread(&filesys_lock))
        lock_release(&filesys_lock);
    lock_acquire(&filesys_lock);
    file_close(cur->executable_file);
    lock_release(&filesys_lock);
    intr_set_level(old_level);
    #ifdef VM
    
    if(lock_held_by_current_thread(&sup_page_lock))
        lock_release(&sup_page_lock);

    lock_acquire(&sup_page_lock);
    lock_acquire(&lock_for_scan);
    hash_destroy(&cur->sup_page_table, page_destroy);
    lock_release(&lock_for_scan);
    lock_release(&sup_page_lock);

    //munmap
    struct list *mmap_l = &cur->mmap_list;
    struct list_elem *e;
    while(!list_empty(mmap_l)){
        e = list_begin(mmap_l);
        struct mmap_file *mmap_f = list_entry(e, struct mmap_file, elem);
        ASSERT(munmap(mmap_f->mapid) == true);
    }
    #endif

    /* Destroy the current process's page directory and switch back
       to the kernel-only page directory. */
    pd = cur->pagedir;
    if (pd != NULL) {
        /* Correct ordering here is crucial.  We must set
           cur->pagedir to NULL before switching page directories,
           so that a timer interrupt can't switch back to the
           process page directory.  We must activate the base page
           directory before destroying the process's page
           directory, or our active page directory will be one
           that's been freed (and cleared). */
        cur->pagedir = NULL;
        pagedir_activate(NULL); 
        pagedir_destroy(pd);
    }

}

/** Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void process_activate(void) {
    struct thread* t = thread_current();

    /* Activate thread's page tables. */
    pagedir_activate(t->pagedir);

    /* Set thread's kernel stack for use in processing
       interrupts. */
    tss_update();
}

/** We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/** ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/** For use with ELF types in printf(). */
#define PE32Wx PRIx32 /**< Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /**< Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /**< Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /**< Print Elf32_Half in hexadecimal. */

/** Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr {
    unsigned char e_ident[16];
    Elf32_Half e_type;
    Elf32_Half e_machine;
    Elf32_Word e_version;
    Elf32_Addr e_entry;
    Elf32_Off e_phoff;
    Elf32_Off e_shoff;
    Elf32_Word e_flags;
    Elf32_Half e_ehsize;
    Elf32_Half e_phentsize;
    Elf32_Half e_phnum;
    Elf32_Half e_shentsize;
    Elf32_Half e_shnum;
    Elf32_Half e_shstrndx;
};

/** Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr {
    Elf32_Word p_type;
    Elf32_Off p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
};

/** Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0           /**< Ignore. */
#define PT_LOAD 1           /**< Loadable segment. */
#define PT_DYNAMIC 2        /**< Dynamic linking info. */
#define PT_INTERP 3         /**< Name of dynamic loader. */
#define PT_NOTE 4           /**< Auxiliary info. */
#define PT_SHLIB 5          /**< Reserved. */
#define PT_PHDR 6           /**< Program header table. */
#define PT_STACK 0x6474e551 /**< Stack segment. */

/** Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /**< Executable. */
#define PF_W 2 /**< Writable. */
#define PF_R 4 /**< Readable. */

static bool setup_stack(void** esp);
static bool validate_segment(const struct Elf32_Phdr*, struct file*);
static bool load_segment(struct file* file,
                         off_t ofs,
                         uint8_t* upage,
                         uint32_t read_bytes,
                         uint32_t zero_bytes,
                         bool writable);

/** Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load(const char* file_name, void (**eip)(void), void** esp) {
    lock_acquire(&filesys_lock);
    struct thread* t = thread_current();
    struct Elf32_Ehdr ehdr;
    struct file* file = NULL;
    off_t file_ofs;
    bool success = false; 
    int i;

    /* Allocate and activate page directory. */
    t->pagedir = pagedir_create();
    #ifdef VM
        /*lab3a*/
        
        //sup_page_table_init(&(t->sup_page_table));
        hash_init(&(t->sup_page_table), sup_page_hash, sup_page_less, NULL);
    #endif
    if (t->pagedir == NULL)
        goto done;
    process_activate();

    /* Open executable file. */
    //printf("file_name : %s\n", file_name);
    file = filesys_open(file_name);
    if (file == NULL) {
        printf("load: %s: open failed\n", file_name);
        goto done;
    }
    file_deny_write(file);
    t->executable_file = file;

    /* Read and verify executable header. */
    if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr ||
        memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 ||
        ehdr.e_machine != 3 || ehdr.e_version != 1 ||
        ehdr.e_phentsize != sizeof(struct Elf32_Phdr) || ehdr.e_phnum > 1024) {
        printf("load: %s: error loading executable\n", file_name);
        goto done;
    }

    /* Read program headers. */
    file_ofs = ehdr.e_phoff;
    for (i = 0; i < ehdr.e_phnum; i++) {
        struct Elf32_Phdr phdr;

        if (file_ofs < 0 || file_ofs > file_length(file))
            goto done;
        file_seek(file, file_ofs);

        if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
            goto done;
        file_ofs += sizeof phdr;
        switch (phdr.p_type) {
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
                if (validate_segment(&phdr, file)) {
                    bool writable = (phdr.p_flags & PF_W) != 0;
                    uint32_t file_page = phdr.p_offset & ~PGMASK;
                    uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
                    uint32_t page_offset = phdr.p_vaddr & PGMASK;
                    uint32_t read_bytes, zero_bytes;
                    if (phdr.p_filesz > 0) {
                        /* Normal segment.
                           Read initial part from disk and zero the rest. */
                        read_bytes = page_offset + phdr.p_filesz;
                        zero_bytes =
                            (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) -
                             read_bytes);
                    } else {
                        /* Entirely zero.
                           Don't read anything from disk. */
                        read_bytes = 0;
                        zero_bytes =
                            ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
                    }
                    if (!load_segment(file, file_page, (void*)mem_page,
                                      read_bytes, zero_bytes, writable))
                        goto done;
                } else
                    goto done;
                break;
        }
    }

    /* Set up stack. */
    if (!setup_stack(esp))
        goto done;

    /* Start address. */
    *eip = (void (*)(void))ehdr.e_entry;

    success = true;

done:
    /* We arrive here whether the load is successful or not. */
    //file_close(file);
    lock_release(&filesys_lock);
    return success;
}

/** load() helpers. */

static bool install_page(void* upage, void* kpage, bool writable);

/** Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Elf32_Phdr* phdr, struct file* file) {
    /* p_offset and p_vaddr must have the same page offset. */
    if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
        return false;

    /* p_offset must point within FILE. */
    if (phdr->p_offset > (Elf32_Off)file_length(file))
        return false;

    /* p_memsz must be at least as big as p_filesz. */
    if (phdr->p_memsz < phdr->p_filesz)
        return false;

    /* The segment must not be empty. */
    if (phdr->p_memsz == 0)
        return false;

    /* The virtual memory region must both start and end within the
       user address space range. */
    if (!is_user_vaddr((void*)phdr->p_vaddr))
        return false;
    if (!is_user_vaddr((void*)(phdr->p_vaddr + phdr->p_memsz)))
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

/** Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool load_segment(struct file* file,
                         off_t ofs,
                         uint8_t* upage,
                         uint32_t read_bytes,
                         uint32_t zero_bytes,
                         bool writable) {
    ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
    ASSERT(pg_ofs(upage) == 0);
    ASSERT(ofs % PGSIZE == 0);

    #ifndef VM

    file_seek(file, ofs);
    while (read_bytes > 0 || zero_bytes > 0) {
        /* Calculate how to fill this page.
           We will read PAGE_READ_BYTES bytes from FILE
           and zero the final PAGE_ZERO_BYTES bytes. */
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        /* Get a page of memory. */
        uint8_t* kpage = palloc_get_page(PAL_USER);
        if (kpage == NULL)
            return false;

        /* Load this page. */
        if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes) {
            palloc_free_page(kpage);
            return false;
        }
        memset(kpage + page_read_bytes, 0, page_zero_bytes);

        /* Add the page to the process's address space. */
        if (!install_page(upage, kpage, writable)) {
            palloc_free_page(kpage);
            return false;
        }

        /* Advance. */
        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;
        upage += PGSIZE;
    }
    return true;

    #else

    //TODO: Implement lazy loading
    while(read_bytes > 0 || zero_bytes > 0) {
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        struct sup_page_entry* sup_page_entry_ = malloc(sizeof(struct sup_page_entry));
        if(sup_page_entry_ == NULL)
            return false;

        //sup_page_entry_->file = file;
        sup_page_entry_->upage = upage;
        sup_page_entry_->zero_bytes = page_zero_bytes;
        sup_page_entry_->read_bytes = page_read_bytes;
        sup_page_entry_->writable = writable;
        sup_page_entry_->loaded = false;
        sup_page_entry_->thread = thread_current();
        sup_page_entry_->sector = (block_sector_t) -1;
        sup_page_entry_->frame_entry = NULL;
        sup_page_entry_->status = FILE;

        // sup_page_entry_->swap = false;
        // sup_page_entry_->swap_index = 0;
        //if(page_read_bytes > 0){
            sup_page_entry_->file = file_reopen(file);
            sup_page_entry_->ofs = ofs;
            sup_page_entry_->read_bytes = page_read_bytes;
        //}

        bool success = sup_page_insert(&thread_current()->sup_page_table, sup_page_entry_);
        ASSERT(success);

        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;
        upage += PGSIZE;
        ofs += page_read_bytes;
    }
    return true;

    #endif
}

/** Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool setup_stack(void** esp) {
    #ifndef VM
    uint8_t* kpage;
    bool success = false;

    kpage = palloc_get_page(PAL_USER | PAL_ZERO);
    if (kpage != NULL) {
        success = install_page(((uint8_t*)PHYS_BASE) - PGSIZE, kpage, true);
        if (success)
            *esp = PHYS_BASE;
        else
            palloc_free_page(kpage);
    }
    return success;
    #else
    //TODO: Implement lazy loading
    // bool success = false;
    // struct sup_page_entry* sup_page_entry_ = malloc(sizeof(struct sup_page_entry));
    // if(sup_page_entry_ == NULL)
    //     return false;
    struct thread* t = thread_current();
    uint8_t* upage = ((uint8_t*)PHYS_BASE) - PGSIZE;

    /* Do not allocate a page. Just set up the stack pointer. */

    struct sup_page_entry* sup_page_entry_ = sup_page_alloc(upage, true);
    *esp = PHYS_BASE;
    if(sup_page_entry_ != NULL){
        // void* frame = get_frame(sup_page_entry_);

        // if(frame != NULL){
        //     bool success = install_page(upage, frame, true);
        //     sup_page_entry_->kpage = frame;
        //     return success;
        // }
        load_page(sup_page_entry_->upage);
    }
    else
        return false;
    #endif
}

/** Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool install_page(void* upage, void* kpage, bool writable) {
    struct thread* t = thread_current();

    /* Verify that there's not already a page at that virtual
       address, then map our page there. */
    return (pagedir_get_page(t->pagedir, upage) == NULL &&
            pagedir_set_page(t->pagedir, upage, kpage, writable));
}
