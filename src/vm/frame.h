#ifndef VM_FRAME_H
#define VM_FRAME_H
#include "threads/synch.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include <hash.h>
#include <string.h>
#include "lib/kernel/hash.h"
#include "vm/page.h"
extern struct lock filesys_lock;
struct frame_entry{
    struct lock frame_lock; /* Lock for frame */
    void* frame; /* Frame */
    struct sup_page_entry *page; /* Page that is mapped to the frame */
    bool pinned; /* Frame is pinned */
};

void frame_table_init (void);
struct frame_entry* get_frame(struct sup_page_entry *page);
//struct frame_entry* get_frame(void);
void frame_free (struct frame_entry *frame_entry);
void free_frame_from_kpage(void *kpage);
struct frame_entry* evict_frame(void);
void frame_set_pinned(void *kpage, bool new_value);
void lock_frame(struct sup_page_entry *p);
void unlock_frame(struct frame_entry *f);
#endif /* vm/frame.h */