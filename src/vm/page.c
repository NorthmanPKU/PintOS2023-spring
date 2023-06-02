#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"
#include "filesys/file.h"
#include <hash.h>
#include <string.h>
#include "lib/kernel/hash.h"
#include "devices/block.h"
#include "threads/interrupt.h"
struct lock sup_page_lock;
struct lock page_file_lock;
struct sup_page_entry *sup_page_alloc (void *upage, bool writable){ //including insert into hash table
    struct sup_page_entry *sup_page_entry = malloc(sizeof(struct sup_page_entry));
    sup_page_entry->upage = upage;//
    sup_page_entry->writable = writable;//
    sup_page_entry->file = NULL;//
    sup_page_entry->frame_entry = NULL;//
    sup_page_entry->ofs = 0;//
    sup_page_entry->read_bytes = 0;//
    sup_page_entry->zero_bytes = PGSIZE;
    sup_page_entry->loaded = false;
    sup_page_entry->pinned = false;
    sup_page_entry->thread = thread_current();//
    sup_page_entry->sector = (block_sector_t) -1;//
    if(!sup_page_insert(&thread_current()->sup_page_table, sup_page_entry)){
        free(sup_page_entry);
        ASSERT(false);
        return NULL;
    }
    return sup_page_entry;
}

struct sup_page_entry *sup_zero_page_alloc(void *upage, bool writable){
    struct sup_page_entry *sup_page_entry = malloc(sizeof(struct sup_page_entry));
    sup_page_entry->upage = upage;
    sup_page_entry->kpage = NULL;
    sup_page_entry->writable = writable;
    sup_page_entry->file = NULL;
    sup_page_entry->frame_entry = NULL;
    sup_page_entry->ofs = 0;
    sup_page_entry->read_bytes = 0;
    sup_page_entry->zero_bytes = PGSIZE;
    sup_page_entry->loaded = true;
    sup_page_entry->pinned = false;
    sup_page_entry->thread = thread_current();
    sup_page_entry->sector = (block_sector_t) -1;
    sup_page_entry->status = ZERO;
    if(!sup_page_insert(&thread_current()->sup_page_table, sup_page_entry)){
        free(sup_page_entry);
        ASSERT(false);
        return NULL;
    }

    return sup_page_entry;
}

bool sup_page_less (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED){
    struct sup_page_entry *sup_page_entry_a = hash_entry(a, struct sup_page_entry, hash_elem);
    struct sup_page_entry *sup_page_entry_b = hash_entry(b, struct sup_page_entry, hash_elem);
    return sup_page_entry_a->upage < sup_page_entry_b->upage;
}
unsigned sup_page_hash (const struct hash_elem *p_, void *aux UNUSED){
    const struct sup_page_entry *p = hash_entry(p_, struct sup_page_entry, hash_elem);
    return hash_bytes (&p->upage, sizeof p->upage);
}

struct sup_page_entry *sup_page_lookup (void *upage){
    struct sup_page_entry sup_page_entry;
    struct hash_elem *e;
    sup_page_entry.upage = pg_round_down(upage);
    e = hash_find (&thread_current()->sup_page_table, &sup_page_entry.hash_elem);
    if(e == NULL){
        #ifdef DEBUG
        printf("sup_page_lookup: hash_find failed!!\n");
        #endif
        return NULL;
    }
    else{
        #ifdef DEBUG
        printf("sup_page_lookup: hash_find success!!\n");
        #endif
        return hash_entry (e, struct sup_page_entry, hash_elem);
    }
}

bool sup_page_exists (void *upage){
    return sup_page_lookup(upage) != NULL;
}

void sup_page_table_init (){//struct hash *sup_page_table){
    //hash_init(sup_page_table, sup_page_hash, sup_page_less, NULL);
    lock_init(&sup_page_lock);
    lock_init(&page_file_lock);
}
bool sup_page_insert (struct hash *sup_page_table, struct sup_page_entry *sup_page_entry){
    lock_acquire(&sup_page_lock);
    struct hash_elem *e = hash_insert(sup_page_table, &sup_page_entry->hash_elem);
    lock_release(&sup_page_lock);
    return e == NULL; //return true if insert success
}
bool sup_page_delete (struct hash *sup_page_table, struct sup_page_entry *sup_page_entry){
    lock_acquire(&sup_page_lock);
    struct hash_elem *e = hash_delete(sup_page_table, &sup_page_entry->hash_elem);
    lock_release(&sup_page_lock);
    return e != NULL;  
}
// void sup_page_table_destroy (struct hash *sup_page_table){
//     lock_acquire(&sup_page_lock);
//     hash_destroy(sup_page_table, sup_page_destroy);
//     lock_release(&sup_page_lock);
// }

//install page
bool install_page (void *upage, void *kpage, bool writable){
    struct thread *t = thread_current();
    if(pagedir_get_page(t->pagedir, upage) != NULL){
        ASSERT(false);
        return false;
    }
    return pagedir_set_page(t->pagedir, upage, kpage, writable);
    
}
bool load_page (void *upage){
    //enum intr_level old_level = intr_disable();
    //printf("The thread gonna acquire the lock is %d\n", thread_current()->tid);
    // if(lock_held_by_current_thread(&sup_page_lock)){
    //     lock_release(&sup_page_lock);
    // }
    //printf("The thread gonna acquire the lock is %d\n", thread_current()->tid); 
    //lock_acquire(&sup_page_lock);
    //intr_set_level(old_level);
    //lock_acquire(&page_file_lock);
    struct sup_page_entry *sup_page_entry = sup_page_lookup(upage);
    if(sup_page_entry == NULL){
        //printf("140: the thread %d release the lock\n", thread_current()->tid);
        //lock_release(&sup_page_lock);
        //lock_release(&page_file_lock);

        return false;
    }
    // if(sup_page_entry->loaded){
    //     lock_release(&sup_page_lock);
    //     return true;
    // }
    // if(sup_page_entry->file == NULL){
    //     lock_release(&sup_page_lock);
    //     return false;
    // }
    //lock_acquire(&lock_for_scan);
    lock_frame(sup_page_entry);
    if(sup_page_entry->frame_entry != NULL){
        goto HAVE_FRAME;
    }
    struct frame_entry* frame = get_frame(sup_page_entry);
    sup_page_entry->frame_entry = frame;
    if(frame == NULL){
        //printf("157: the thread %d release the lock\n", thread_current()->tid);
        //lock_release(&sup_page_lock);
        //lock_release(&page_file_lock);
        //unlock_frame(sup_page_entry->frame_entry);
        return false;
    }
    //frame->page = sup_page_entry;
    //lock_release(&sup_page_entry->frame_entry->frame_lock);
    if(sup_page_entry->sector != (block_sector_t) -1){
        swap_in(sup_page_entry);
    }
    else if(sup_page_entry->file != NULL){
        size_t bytes_read = file_read_at(sup_page_entry->file, frame->frame, sup_page_entry->read_bytes, sup_page_entry->ofs);
        memset(frame->frame + sup_page_entry->read_bytes, 0, PGSIZE - sup_page_entry->read_bytes);
        if(bytes_read != sup_page_entry->read_bytes){
            printf("bytes_read: %d, read_bytes: %d\n", bytes_read, sup_page_entry->read_bytes);
        }
    }
    else{
        memset(frame->frame, 0, PGSIZE);
    }
HAVE_FRAME:
    ASSERT(lock_held_by_current_thread (&sup_page_entry->frame_entry->frame_lock));
    // if(file_read_at(sup_page_entry->file, frame, sup_page_entry->read_bytes, sup_page_entry->ofs) != (int)sup_page_entry->read_bytes){
    //     //frame_free(frame);
    //     ASSERT(false);
    //     return false;
    // }
    //memset(frame + sup_page_entry->read_bytes, 0, sup_page_entry->zero_bytes);
    if(!install_page(sup_page_entry->upage, frame->frame, sup_page_entry->writable)){
        //frame_free(frame);
        //printf("185: the thread %d release the lock\n", thread_current()->tid);
        //lock_release(&sup_page_lock);
        unlock_frame(sup_page_entry->frame_entry);
        return false;
    }
    //sup_page_entry->loaded = true;
 
    //lock_release(&page_file_lock);
    sup_page_entry->status = FRAME;
    //printf("193: the thread %d release the lock\n", thread_current()->tid);
    //lock_release(&sup_page_lock);
    unlock_frame(sup_page_entry->frame_entry);
    return true;
}

static bool do_load_page(struct sup_page_entry *p){
    struct frame_entry* frame = get_frame(p);
    if(frame == NULL){
        //printf("157: the thread %d release the lock\n", thread_current()->tid);
        //lock_release(&sup_page_lock);
        //lock_release(&page_file_lock);
        return false;
    }
    p->frame_entry = frame;
    //sup_page_entry->frame_entry = frame;
    //frame->page = sup_page_entry;
    //lock_release(&sup_page_entry->frame_entry->frame_lock);
    if(p->sector != (block_sector_t) -1){
        swap_in(p);
    }
    else if(p->file != NULL){
        size_t bytes_read = file_read_at(p->file, p->frame_entry->frame, p->read_bytes, p->ofs);
        memset(p->frame_entry->frame + bytes_read, 0, PGSIZE - bytes_read);
        if(bytes_read != p->read_bytes){
            printf("bytes_read: %d, read_bytes: %d\n", bytes_read, p->read_bytes);
        } 
    }
    else{
        memset(frame->frame, 0, PGSIZE);
    }

    p->status = FRAME;
    //printf("193: the thread %d release the lock\n", thread_current()->tid);
    //lock_release(&sup_page_lock);

    return true;
}



bool page_out (struct sup_page_entry *p){
  bool dirty;
  bool ok = false;

  ASSERT (p->frame_entry != NULL);
  ASSERT (lock_held_by_current_thread (&p->frame_entry->frame_lock));

  pagedir_clear_page(p->thread->pagedir, (void *) p->upage);

  dirty = pagedir_is_dirty (p->thread->pagedir, (const void *) p->upage);

//   if(!dirty){
//     ok = true;
//   }
//   if(p->file == NULL) ok = swap_out(p);
//   else{
//     if(dirty){
        
//     }

//   }
    ok = swap_out(p);
    p->status = SWAP;
  if(ok){
    p->frame_entry->page = NULL;
    p->frame_entry = NULL;
  }
  return ok;
}

void page_destroy (struct hash_elem *e, void *aux UNUSED){
    struct sup_page_entry *p = hash_entry(e, struct sup_page_entry, hash_elem);
    page_free(p);
}

void page_free (struct sup_page_entry *p){
    pagedir_clear_page(p->thread->pagedir, (void *) p->upage);
    if(p->frame_entry != NULL){
        p->frame_entry->page = NULL;
        p->frame_entry = NULL;
    }
    free(p);
}

bool lock_page(void* addr, bool plan2write){
    struct sup_page_entry *p = sup_page_lookup(addr);
    if(p == NULL || (!p->writable && plan2write)){
        return false;
    }
    lock_frame(p);
    if(p->frame_entry == NULL) {
        return do_load_page(p)&&pagedir_set_page(thread_current()->pagedir, p->upage, p->frame_entry->frame, p->writable);
    }
    else {
        return true;
     }    
}

bool unlock_page(void* addr){
    struct sup_page_entry *p = sup_page_lookup(addr);
    if(p == NULL){
        ASSERT(false);
        return false;
    }
    unlock_frame(p->frame_entry);
    return true; 
}