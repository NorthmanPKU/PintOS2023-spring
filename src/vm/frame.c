#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "vm/page.h"
#include "vm/frame.h"
#include "filesys/file.h"
#include <hash.h>
#include <string.h>
#include "lib/kernel/hash.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static struct frame_entry* frames;
static size_t frame_cnt = 0;
struct lock lock_for_scan;
static size_t hand;

void frame_table_init (void){
    frames = (struct frame_entry *)malloc(sizeof (*frames) * init_ram_pages);
    if (frames == NULL)
        PANIC ("out of memory allocating page frames");
    void* p;
    while(p = palloc_get_page(PAL_USER)){
        struct frame_entry* f = &frames[frame_cnt];
        f->frame = p;
        f->pinned = false;
        f->page = NULL;
        lock_init(&f->frame_lock);
        frame_cnt++;
    }
    #ifdef DEBUG
    printf("Frame init finsh! frame_cnt: %d\n", frame_cnt);
    #endif
    hand = 0;
    lock_init(&lock_for_scan);
}
#ifdef old_get_frame
struct frame_entry* get_frame(struct sup_page_entry *page){
    lock_acquire(&lock_for_scan);
    for(int i = 0; i < frame_cnt; i++){
        // if(!lock_try_acquire(&frames[i].frame_lock))
        //     continue;
        #ifdef DEBUG
        printf("frame %d\n", i);
        #endif
        //lock_acquire(&frames[i].frame_lock);
        if(lock_try_acquire(&frames[i].frame_lock)){
            if(frames[i].page == NULL){
                frames[i].page = page;
                lock_release(&lock_for_scan);
                
                return &frames[i];
            }
            lock_release(&frames[i].frame_lock);
        }
        //lock_release(&frames[i].frame_lock);
    }
    
    struct frame_entry* f= evict_frame(page);
    /* Evict this frame. */
    // if (!page_out (f->page))
    // {
    //     //lock_release (&f->frame_lock);
    //     lock_release(&lock_for_scan);
    //     return NULL;
    // }

    f->page = page;
    lock_release(&lock_for_scan);
    return f;
}
#endif
struct frame_entry* get_frame(void){
    lock_acquire(&lock_for_scan);
    for(int i = 0; i < frame_cnt; i++){
        // if(!lock_try_acquire(&frames[i].frame_lock))
        //     continue;
        #ifdef DEBUG
        printf("frame %d\n", i);
        #endif
        //lock_acquire(&frames[i].frame_lock);
        struct frame_entry* f = &frames[i];
        if(lock_try_acquire(&f->frame_lock)){
            if(f->page == NULL){
                //frames[i].page = page;
                lock_release(&lock_for_scan);
                
                return f;
            }
            lock_release(&f->frame_lock);
        }
        //lock_release(&frames[i].frame_lock);
    }
    
    struct frame_entry* f= evict_frame();
    /* Evict this frame. */
    // if (!page_out (f->page))
    // {
    //     //lock_release (&f->frame_lock);
    //     lock_release(&lock_for_scan);
    //     return NULL;
    // }

    //f->page = page;
    lock_release(&lock_for_scan);
    return f;
}
// struct frame_entry* evict_frame(struct sup_page_entry *page){
//     //TODO:
//     lock_acquire(&lock_for_scan);
//     size_t step_cnt = frame_cnt*2;
//     //clock algorithm
//     uint32_t* pagedir = thread_current()->pagedir;
//     while(step_cnt--){
//         hand = (hand + 1) % frame_cnt;
//         struct frame_entry* f = &frames[hand];
//         // if pinned, continue
//         if(f->pinned)
//             continue;
//         // if referenced, give a second chance.
//         else if(pagedir_is_accessed(pagedir, f->page->upage)) {
//             pagedir_set_accessed(pagedir, f->page->upage, false);
//             continue;
//         }
//         return f->frame;
//     }
//     return NULL;
// }
struct frame_entry* evict_frame(void){
    struct frame_entry *result = NULL;
    for (int i = 0; i < frame_cnt * 2; i++) {
      hand = (hand + 1) % frame_cnt;
      struct frame_entry* f = &frames[hand];
      if(f->pinned)
        continue;
      if (lock_try_acquire(&f->frame_lock)) {
        if (f->page == NULL) {
          result = f;
          break;
        }
        bool accessed = pagedir_is_accessed(f->page->thread->pagedir, f->page->upage);
        if(accessed) pagedir_set_accessed(f->page->thread->pagedir, f->page->upage, false);

        if (accessed) {
          lock_release(&f->frame_lock);
          continue;
        }
        if (page_out(f->page)) {
          ASSERT (f->page == NULL);
          result = f;
          break;
        }
        lock_release(&f->frame_lock);
      }
    }
    return result;
}

void frame_free (struct frame_entry *frame_entry){
    lock_acquire(&lock_for_scan);
    frame_entry->page = NULL;
    lock_release(&lock_for_scan);
}

void free_frame_from_kpage(void *kpage){
    lock_acquire(&lock_for_scan);
    for(int i = 0; i < frame_cnt; i++){
        if(frames[i].frame == kpage){
            frames[i].page = NULL;
            lock_release(&lock_for_scan);
            return;
        }
    }
    lock_release(&lock_for_scan);
}

void frame_set_pinned(void *kpage, bool new_value){
    lock_acquire(&lock_for_scan);
    for(int i = 0; i < frame_cnt; i++){
        if(frames[i].frame == kpage){
            frames[i].pinned = new_value;
            break;
        }
    }
    lock_release(&lock_for_scan);
}
