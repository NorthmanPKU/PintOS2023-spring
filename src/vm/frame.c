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

//#define DEBUG_EVICT

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
        #ifdef DEBUG_EVICT
        // if(frame_cnt == 267){
        //     printf("frame_cnt: %d\n", frame_cnt);
        //     printf("f->frame: %p, f->pinned: %d, f->page: %p\n", f->frame, f->pinned, f->page);
        // }
        #endif
        frame_cnt++;
    }
    #ifdef DEBUG_EVICT
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
struct frame_entry* get_frame(struct sup_page_entry *page){
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
                f->page = page;
                #ifdef DEBUG_EVICT
                if(i == 267){
                    printf("!!!!!!!!!!!!!!!!!!!!!frame_cnt: %d !!!!!!!!!!!!!!!!!!!!!\n", i);
                    printf("f->frame: %p, f->pinned: %d, f->page: %p\n", f->frame, f->pinned, f->page);
                    printf("f->page->thread->pgdir: %p, f->page->upage: %p\n", f->page->thread->pagedir, f->page->upage);
                }
                #endif
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

    f->page = page;
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
    #ifdef DEBUG_EVICT
    printf("****************Start first cycle!****************\n");
    #endif
    for (int i = 0; i < frame_cnt * 2; i++) {
        #ifdef DEBUG_EVICT
        if(i == frame_cnt) printf("****************Start second cycle!****************\n");
        #endif
      hand = (hand + 1) % frame_cnt;
      struct frame_entry* f = &frames[hand];
      if(f->pinned){
        #ifdef DEBUG_EVICT    
        printf("frame %d is pinned!\n", hand);
        #endif
        continue;
        }
      if (lock_try_acquire(&f->frame_lock)) {
        if (f->page == NULL) {
            #ifdef DEBUG_EVICT
            printf("frame %d is empty!\n", hand);
            #endif
          result = f;
          break;
        }
        #ifdef DEBUG_EVICT
        //printf("f->page->thread->pagedir: %p, f->page->upage: %p\n", f->page->thread->pagedir, f->page->upage);
        //printf("f->page->thread: %p\n", f->page->thread);
        #endif
        bool accessed = pagedir_is_accessed(f->page->thread->pagedir, f->page->upage);
        if(accessed) pagedir_set_accessed(f->page->thread->pagedir, f->page->upage, false);

        if (accessed) {
            #ifdef DEBUG_EVICT
            printf("frame %d has been accessed!\n", hand);
            #endif
          lock_release(&f->frame_lock);
          continue;
        }
        if (page_out(f->page)) {
            #ifdef DEBUG_EVICT
            printf("frame %d has been swapped out!\n", hand);
            #endif
          ASSERT (f->page == NULL);
          result = f;
          break;
        }
        else {
          #ifdef DEBUG_EVICT
            printf("frame %d has not been swapped out!\n", hand);
            #endif  
         }

        lock_release(&f->frame_lock);
      }
      else {
        #ifdef DEBUG_EVICT
        printf("frame %d is locked!\n", hand);
        #endif
       }
    }
    if(result == NULL){
        PANIC("No frame can be evicted!\n");
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

void lock_frame(struct sup_page_entry *p){
    struct frame_entry *f = p->frame_entry;
    if(f!= NULL){
        lock_acquire(&f->frame_lock);
        if(f != p->frame_entry){
            lock_release(&f->frame_lock);
            ASSERT(p->frame_entry == NULL);
        }
    }
}

void unlock_frame(struct frame_entry *f){
    ASSERT(lock_held_by_current_thread(&f->frame_lock));
    lock_release(&f->frame_lock);
}