#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "filesys/filesys.h"

#define N_SYSCALLS 20


struct lock filesys_lock;
struct lock filesys_lock2;
static void syscall_handler(struct intr_frame*);

static void syscall_halt(struct intr_frame* f) {
    shutdown_power_off();
}

static void syscall_exit(struct intr_frame* f) {
    pointer_checker(f->esp, sizeof(int), 0);
    uint32_t* esp = f->esp;
    pointer_checker(esp + 1, sizeof(int), 0);
    uint32_t exit_code = *(uint32_t*)(esp + 1);

    thread_current()->exit_code = exit_code;
    thread_exit();
}
static void syscall_exec(struct intr_frame* f) {
    uint32_t* esp = f->esp;
    pointer_checker(esp + 1, sizeof(int), 0); 
    pointer_checker(*((unsigned*)f->esp + 1), 0, 2);

    f->eax = process_execute((char*) *(esp + 1));

}
static void syscall_wait(struct intr_frame* f) {
    uint32_t* esp = f->esp;
    pointer_checker(esp + 1, sizeof(int), 0);
    f->eax = process_wait(*(uint32_t*)(esp + 1));
}

static struct thread_file* get_thread_file(int fd) {
    struct thread *cur = thread_current();
    struct list_elem *e;
    for (e = list_begin(&cur->files_list); e != list_end(&cur->files_list); e = list_next(e)) {
        struct thread_file *tf = list_entry(e, struct thread_file, elem);
        if (tf->fd == fd) {
            return tf;
        }
    }
    return NULL;
}

static void syscall_create(struct intr_frame* f) {
  pointer_checker(f->esp + 1, sizeof(int), 0);
  pointer_checker(*((unsigned*)f->esp + 1), 0, 2);

  lock_acquire(&filesys_lock);
  f->eax = filesys_create((char*)*((unsigned*)f->esp + 1), *((unsigned*)f->esp + 2));
  lock_release(&filesys_lock);
}
static void syscall_remove(struct intr_frame* f) {
    pointer_checker(f->esp + 1, sizeof(int), 0);
    pointer_checker(*((unsigned*)f->esp + 1), 0, 2);

    lock_acquire(&filesys_lock);
    f->eax = filesys_remove((char*)*((unsigned*)f->esp + 1));
    lock_release(&filesys_lock);
}
static void syscall_open(struct intr_frame* f) {
    pointer_checker(f->esp + 1, sizeof(int), 0);
    pointer_checker(*((unsigned*)f->esp + 1), 0, 2);

    lock_acquire(&filesys_lock);
    struct file *opening_file = filesys_open((char*)*((unsigned*)f->esp + 1));
    lock_release(&filesys_lock);

    if (opening_file == NULL) {
        f->eax = -1;
        return;
    }
    struct thread *cur = thread_current();
    struct thread_file *tf = malloc(sizeof(struct thread_file));
    tf->fd = cur->next_fd;
    cur->next_fd++;
    tf->file = opening_file;
    list_push_back(&cur->files_list, &tf->elem);
    f->eax = tf->fd;
}
static void syscall_filesize(struct intr_frame* f) {
    pointer_checker(f->esp + 1, sizeof(int), 0);
    struct thread_file *tf = get_thread_file(*(int*)(f->esp + sizeof(void*)));
    if (tf == NULL) {
        f->eax = -1;
        return;
    }
    lock_acquire(&filesys_lock);
    f->eax = file_length(tf->file);
    lock_release(&filesys_lock);
}
static void syscall_read(struct intr_frame* f) {
  pointer_checker(f->esp + 1, sizeof(int), 0);
  pointer_checker(f->esp + 2, sizeof(int), 0);
  pointer_checker(*((unsigned*)f->esp + 2), *((unsigned*)f->esp + 3), 2);
  pointer_checker(f->esp + 3, sizeof(int), 0);
    int fd = *(int*)(f->esp + sizeof(void*));
    char* buf_ = *(char**)(f->esp + 2 * sizeof(void*));
    int size = *(int*)(f->esp + 3 * sizeof(void*));

    char *buf = buf_;
    //printf("fd: %d, buf: %s, size: %d\n", fd, buf, size);
    // if (fd == 0) {
    //     int i;
    //     for (i = 0; i < size; i++) {
    //         buf[i] = input_getc();
    //     }
    //     f->eax = size;
    // } else {

    //     struct thread_file *tf = get_thread_file(fd);
    //     if (tf == NULL) {
    //         f->eax = -1;
    //         return;
    //     } 
    //     lock_acquire(&filesys_lock);
    //     f->eax = file_read(tf->file, buf, size);
    //     lock_release(&filesys_lock);
    // }

    int read_bytes = 0;
    int size_ = size;
    struct thread_file *tf = get_thread_file(fd);
    if(tf == NULL){
        f->eax = -1;
        return;
    }
    while(size_ > 0){
        size_t page_left = PGSIZE - pg_ofs(buf);
        size_t read_amt = size_ < page_left ? size_ : page_left;
        off_t return_value;
        //check buf

        if(fd != STDIN_FILENO){
            bool fail = 0;
            // if(!lock_page(buf, true)){ 
            //     fail = 1;
            //     //thread_exit();
            // }
            //enum intr_level old_level = intr_disable();
            // if(lock_held_by_current_thread(&filesys_lock)){
            //     printf("%d: I already have it so i'm releasing it\n", thread_current()->tid);
            //     lock_release(&filesys_lock);
            // } 
            lock_acquire(&filesys_lock);
            // printf("%d: just acquired lock\n", thread_current()->tid);
            //intr_set_level(old_level);
            // printf("%d: just set intr level\n", thread_current()->tid);
            // if(lock_held_by_current_thread(&filesys_lock)){
            //     printf("%d: lock held by current thread\n", thread_current()->tid);
            // }
            //lock_acquire(&filesys_lock);
            return_value = file_read(tf->file, buf, read_amt);
            // if(lock_held_by_current_thread(&filesys_lock)){
            //     printf("%d: lock held by current thread-2\n", thread_current()->tid);
            // }
            if(!lock_held_by_current_thread(&filesys_lock)){
                lock_acquire(&filesys_lock);
            }
            lock_release(&filesys_lock);
            // printf("%d: just released lock\n", thread_current()->tid);
            // unlock_page(buf);
            // if(fail){
            //     f->eax = -1; //TODO: check if this is correct
            //     return;
            // }
        }  
        else {
            printf("stdin\n");
            size_t i; 
            for(i = 0; i < read_amt; i++){
                char c = input_getc();
                if(!lock_page(buf, true)){
                    thread_exit();
                }
                buf[i] = c;
                unlock_page(buf);
            }
            read_bytes = read_amt;
         }
         if(return_value < 0){
            if(read_bytes == 0){
                read_bytes = -1;
            }
            break;
         }
         read_bytes += return_value;
         if(return_value != (off_t)read_amt){
            break;
         }

        size_ -= return_value;
        buf += return_value;

    }
    f->eax = read_bytes;
}
static void syscall_write(struct intr_frame* f) {
    pointer_checker(f->esp + 1, sizeof(int), 0);
    pointer_checker(f->esp + 2, sizeof(int), 0);
    pointer_checker(*((unsigned*)f->esp + 2), *((unsigned*)f->esp + 3), 2);
    pointer_checker(f->esp + 3, sizeof(int), 0);
    int fd = *(int*)(f->esp + sizeof(void*));
    char* buf_ = *(char**)(f->esp + 2 * sizeof(void*));
    int size = *(int*)(f->esp + 3 * sizeof(void*));

    //printf("fd: %d, buf: %s, size: %d\n", fd, buf, size);

    // if (fd == 1) {
    //     putbuf(buf, size);
    //     f->eax = size;
    // }
    // else {
    //     // struct thread_file *tf = get_thread_file(fd);
    //     // if (tf == NULL) {
    //     //     f->eax = -1;
    //     //     return;
    //     // }
    //     // lock_acquire(&filesys_lock);
    //     // f->eax = file_write(tf->file, buf, size);
    //     // lock_release(&filesys_lock);
        
    // }
    char *buf = buf_;
    int size_ = size;
    struct thread_file *tf;
    int written_bytes = 0;
    if(fd != STDOUT_FILENO){
        tf = get_thread_file(fd);
        if(tf == NULL){
            //PANIC("file not found");
            f->eax = -1;
            return;
        }
    }
    while(size_ > 0){
        size_t page_left = PGSIZE - pg_ofs(buf);
        size_t write_amt = size_ < page_left ? size_ : page_left; //TODO: size_之前写成了size
        off_t return_value;

        if(!lock_page(buf, false)){
            thread_exit();
        }
        lock_acquire(&filesys_lock);
        if(fd == STDOUT_FILENO){
            putbuf(buf, write_amt);
            return_value = write_amt;
        }
        else{
            return_value = file_write(tf->file, buf, write_amt);
        }
        lock_release(&filesys_lock);
        unlock_page(buf);

        if(return_value < 0){
            if(written_bytes == 0){
                written_bytes = -1;
            }
            break;
        }
        written_bytes += return_value;

        if (return_value !=(off_t) write_amt) {
            break;
        }
        size_ -= return_value;
        buf += return_value;
    }

    f->eax = written_bytes;
}
static void syscall_seek(struct intr_frame* f) {
    pointer_checker(f->esp + 1, sizeof(int), 0);
    pointer_checker(f->esp + 2, sizeof(int), 0);
    struct thread_file *tf = get_thread_file(*(int*)(f->esp + sizeof(void*)));
    if (tf == NULL) {
        f->eax = -1;
        return;
    }
    lock_acquire(&filesys_lock);
    file_seek(tf->file, *(unsigned*)(f->esp + 2 * sizeof(void*)));
    lock_release(&filesys_lock);
}
static void syscall_tell(struct intr_frame* f) {
    pointer_checker(f->esp + 1, sizeof(int), 0);
    struct thread_file *tf = get_thread_file(*(int*)(f->esp + sizeof(void*)));
    if (tf == NULL) {
        f->eax = -1;
        return;
    }
    lock_acquire(&filesys_lock);
    f->eax = file_tell(tf->file);
    lock_release(&filesys_lock);
}
static void syscall_close(struct intr_frame* f) {
    pointer_checker(f->esp + 1, sizeof(int), 0);
    struct thread_file *tf = get_thread_file(*(int*)(f->esp + sizeof(void*)));
    if (tf == NULL) {
        f->eax = -1;
        return;
    }
    lock_acquire(&filesys_lock);
    file_close(tf->file);
    list_remove(&tf->elem);
    lock_release(&filesys_lock);
    free(tf);
}


static mapid_t sys_mmap(int fd, void *addr){
    //return 666;
    if(fd == 0 || fd == 1){
        return -1;
    }
    // return 6;
    if (addr == NULL || pg_ofs(addr) != 0) {
        return -1;
    }
    struct thread *cur = thread_current();
    lock_acquire(&filesys_lock);
    struct thread_file *file_d = get_thread_file(fd);
    struct file *file = NULL;
    if(file_d && file_d->file){

        file = file_reopen(file_d->file);
    }
    // if (file_d == NULL) {
    //     lock_release(&filesys_lock);
    //     return -1;
    // }
    //struct file *file = tf->file;
    if (file == NULL) {
        lock_release(&filesys_lock);
        return -1;
    }
    int length = file_length(file);
    if (length == 0) {
        lock_release(&filesys_lock);
        return -1; 
    }
    
    int offset_ = 0;
    //Ensure all the page addresses are not mapped
    for(; offset_ < length; offset_ += PGSIZE){
        if(sup_page_exists(addr + offset_)){
            lock_release(&filesys_lock);
            return -1;
        }
    }

    int offset = 0;
    while (length > 0) {
        int read_bytes = length < PGSIZE ? length : PGSIZE;
        int zero_bytes = PGSIZE - read_bytes;

        struct sup_page_entry *spte = malloc(sizeof(struct sup_page_entry));
        spte = sup_page_alloc(addr + offset, true);
        ASSERT(spte != NULL);
        spte->file = file;
        spte->ofs = offset;
        spte->read_bytes = read_bytes;
        spte->zero_bytes = zero_bytes;
        spte->status = FILE;


        length -= read_bytes;
        offset += read_bytes;
        //addr += PGSIZE;
    }

    struct mmap_file *mf = malloc(sizeof(struct mmap_file));
    if(list_empty(&cur->mmap_list)){
        mf->mapid = 1;
    }
    else{
        struct list_elem *e = list_back(&cur->mmap_list);
        struct mmap_file *last = list_entry(e, struct mmap_file, elem);
        mf->mapid = last->mapid + 1;
    }
    mf->fd = cur->next_fd - 1;
    //cur->next_fd++; //TODO: check if this is correct
    mf->file = file;
    mf->addr = addr;
    mf->length = offset;
    list_push_back(&cur->mmap_list, &mf->elem);
    
    lock_release(&filesys_lock);

    return mf->mapid;
}

bool munmap(mapid_t mapping){
    struct thread *cur = thread_current();
    struct list_elem *e;
    struct mmap_file *mf = NULL;
    if (mapping == NULL){
        return false;
     }
    for(e = list_begin(&cur->mmap_list); e != list_end(&cur->mmap_list); e = list_next(e)){
        struct mmap_file *temp = list_entry(e, struct mmap_file, elem);
        if(temp->mapid == mapping){
            mf = temp;
            break;
        }
    }
    if(mf == NULL){
        return false;
    }
    lock_acquire(&filesys_lock);
    int offset = 0;
    while (offset < mf->length) {
        int read_bytes = mf->length - offset < PGSIZE ? mf->length - offset : PGSIZE;

        struct sup_page_entry *spte = sup_page_lookup(mf->addr + offset);
        ASSERT(spte != NULL);
        if (spte != NULL) {
            if(spte->status == FRAME){
                ASSERT(spte->kpage != NULL);
                frame_set_pinned(spte->kpage, true);
            }
            if(spte->status == FRAME || spte->status == SWAP){
                //bool is_dirty = spte->
                //bool is_dirty = 
                bool is_dirty = pagedir_is_dirty(cur->pagedir, spte->upage);
                if (is_dirty) {
                    
                    file_write_at(spte->file, spte->upage, read_bytes, spte->ofs);
                    
                }
                //frame_free(spte->kpage);
                if(spte->status == FRAME){
                    free_frame_from_kpage(spte->kpage);
                    pagedir_clear_page(cur->pagedir, spte->upage);
                }
                if(spte->status == SWAP)
                    swap_free(spte);
                //pagedir_clear_page(cur->pagedir, spte->upage);

            }
            // else if(spte->status == SWAP){
            //     //bool is_dirty = spte->dirty;
            //     bool is_dirty = pagedir_is_dirty(cur->pagedir, spte->upage);
            //     if (is_dirty) {
            //         // void *tmp_page = palloc_get_page(0); // in the kernel
            //         // swap_in (spte->sector, tmp_page);
            //         file_write_at (spte->file, tmp_page, PGSIZE, offset);
            //         // palloc_free_page(tmp_page);
            //      }
            // }
            // if (pagedir_is_dirty(cur->pagedir, spte->upage)) {
            //     //lock_acquire(&filesys_lock);
            //     file_write_at(spte->file, spte->upage, spte->read_bytes, spte->ofs);
            //     //lock_release(&filesys_lock);
            // }
            else if (spte->status == FILE) {

            }
            else{
                ASSERT(false);
            }
            //sup_page_delete(cur->pagedir, spte);
            lock_acquire(&sup_page_lock);
            lock_acquire(&lock_for_scan);
            sup_page_delete(&cur->sup_page_table, spte);
            page_free(spte);
            lock_release(&lock_for_scan);
            lock_release(&sup_page_lock);
        }
        offset += read_bytes;
    }
    list_remove(&mf->elem);
    file_close(mf->file);
    free(mf);
    lock_release(&filesys_lock);
    return true;
}

static syscall_mmap(struct intr_frame* f){
    pointer_checker(f->esp + 1, sizeof(int), 0);
    pointer_checker(f->esp + 2, sizeof(void*), 0);
    int fd = *(int*)(f->esp + sizeof(void*));
    void *addr = *(void**)(f->esp + 2 * sizeof(void*));
    f->eax = sys_mmap(fd, addr);
}

static syscall_munmap(struct intr_frame* f){
    pointer_checker(f->esp + 1, sizeof(int), 0);
    int mapping = *(int*)(f->esp + sizeof(void*));
    f->eax = munmap(mapping);
}

static void (*syscalls[N_SYSCALLS])(struct intr_frame *);

void syscall_init(void) {
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
    lock_init(&filesys_lock);
    lock_init(&filesys_lock2);
    syscalls[SYS_EXEC] = &syscall_exec;
    syscalls[SYS_EXIT] = &syscall_exit;
    syscalls[SYS_WAIT] = &syscall_wait;
    syscalls[SYS_HALT] = &syscall_halt;
    syscalls[SYS_CREATE] = &syscall_create;
    syscalls[SYS_REMOVE] = &syscall_remove;
    syscalls[SYS_OPEN] = &syscall_open;
    syscalls[SYS_FILESIZE] = &syscall_filesize;
    syscalls[SYS_WRITE] = &syscall_write;
    syscalls[SYS_READ] = &syscall_read;
    syscalls[SYS_SEEK] = &syscall_seek;
    syscalls[SYS_TELL] = &syscall_tell;
    syscalls[SYS_CLOSE] = &syscall_close;
    syscalls[SYS_MMAP] = &syscall_mmap;
    syscalls[SYS_MUNMAP] = &syscall_munmap;

}

static void syscall_handler(struct intr_frame* f UNUSED) {
    // printf ("system call!\n");
    pointer_checker(f->esp, sizeof(int), 0);
    int syscall_n = *(int*)f->esp;
    //printf("system call! %d", syscall_n);
    thread_current()-> current_esp = f->esp;
    if(syscall_n < 0 || syscall_n >= N_SYSCALLS) {
        thread_current()->exit_code = -1;
        thread_exit();
    }
    else {
        syscalls[syscall_n](f);
    }

    //thread_exit();
}
