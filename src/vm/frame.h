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

struct frame_entry{
    struct lock frame_lock; /* Lock for frame */
    void* frame; /* Frame */
    struct sup_page_entry *page; /* Page that is mapped to the frame */
    bool pinned; /* Frame is pinned */
};

void frame_table_init (void);
struct frame_entry* get_frame(struct sup_page_entry *page);
void frame_free (struct frame_entry *frame_entry);
//evict frame
//void *evict_frame(struct sup_page_entry *page);
struct frame_entry* evict_frame(struct sup_page_entry *page);
#endif /* vm/frame.h */