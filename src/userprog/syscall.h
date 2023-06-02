#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "threads/interrupt.h" // for intr_frame
#include <list.h>
extern struct lock sup_page_lock;
extern struct lock lock_for_scan;
typedef uint32_t mapid_t;
struct mmap_file {
    mapid_t mapid;
    int fd;
    struct file *file;
    void *addr;
    int length;
    struct list_elem elem;
};

void syscall_init (void);
bool munmap(mapid_t mapping); //lab3b used in process_exit

#endif /**< userprog/syscall.h */
