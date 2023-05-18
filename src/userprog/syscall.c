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
    char* buf = *(char**)(f->esp + 2 * sizeof(void*));
    int size = *(int*)(f->esp + 3 * sizeof(void*));

    //printf("fd: %d, buf: %s, size: %d\n", fd, buf, size);

    if (fd == 0) {
        int i;
        for (i = 0; i < size; i++) {
            buf[i] = input_getc();
        }
        f->eax = size;
    } else {
        struct thread_file *tf = get_thread_file(fd);
        if (tf == NULL) {
            f->eax = -1;
            return;
        }
        lock_acquire(&filesys_lock);
        f->eax = file_read(tf->file, buf, size);
        lock_release(&filesys_lock);
    }
}
static void syscall_write(struct intr_frame* f) {
    pointer_checker(f->esp + 1, sizeof(int), 0);
    pointer_checker(f->esp + 2, sizeof(int), 0);
    pointer_checker(*((unsigned*)f->esp + 2), *((unsigned*)f->esp + 3), 2);
    pointer_checker(f->esp + 3, sizeof(int), 0);
    int fd = *(int*)(f->esp + sizeof(void*));
    char* buf = *(char**)(f->esp + 2 * sizeof(void*));
    int size = *(int*)(f->esp + 3 * sizeof(void*));

    //printf("fd: %d, buf: %s, size: %d\n", fd, buf, size);

    if (fd == 1) {
        putbuf(buf, size);
        f->eax = size;
    }
    else {
        struct thread_file *tf = get_thread_file(fd);
        if (tf == NULL) {
            f->eax = -1;
            return;
        }
        lock_acquire(&filesys_lock);
        f->eax = file_write(tf->file, buf, size);
        lock_release(&filesys_lock);
    }
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
    lock_release(&filesys_lock);
    list_remove(&tf->elem);
    free(tf);
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

}

static void syscall_handler(struct intr_frame* f UNUSED) {
    // printf ("system call!\n");
    pointer_checker(f->esp, sizeof(int), 0);
    int syscall_n = *(int*)f->esp;
    //printf("system call! %d", syscall_n);

    if(syscall_n < 0 || syscall_n >= N_SYSCALLS) {
        thread_current()->exit_code = -1;
        thread_exit();
    }
    else {
        syscalls[syscall_n](f);
    }

    //thread_exit();
}
