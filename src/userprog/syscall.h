#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "threads/interrupt.h" // for intr_frame
#include <list.h>
extern struct lock sup_page_lock;
extern struct lock lock_for_scan;
typedef uint32_t mapid_t;
struct mmap_file {
    mapid_t mapid; //id of the mapped file
    int fd; //file descriptor
    struct file *file; //file pointer
    void *addr; //address
    int length; //length of the file
    struct list_elem elem; //list element
};

void syscall_init (void);
bool munmap(mapid_t mapping); //lab3b used in process_exit

#endif /**< userprog/syscall.h */
