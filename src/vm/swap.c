#include <bitmap.h>
#include <debug.h>
#include <stdio.h>
#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"
#include "threads/synch.h"
#include "threads/vaddr.h"

#define SECTORS_PER_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)

static struct block *swap_device; //swap device, used to store pages

static struct bitmap *swap_bitmap;  //swap bitmap, used to manage swap space

static struct lock swap_lock; //swap lock, used to protect swap device
static struct lock bitmap_lock; //bitmap lock, used to protect swap bitmap

void swap_init(void){
    swap_device = block_get_role(BLOCK_SWAP);
    if(swap_device == NULL)
        PANIC("No swap device");
    else swap_bitmap = bitmap_create(block_size(swap_device) / SECTORS_PER_PAGE);
    if(swap_bitmap == NULL)
        PANIC("No swap bitmap");
    //bitmap_set_all(swap_bitmap, false); 
    lock_init(&bitmap_lock);
    lock_init(&swap_lock);
}

void swap_in (struct sup_page_entry *p){
    lock_acquire(&swap_lock);
    size_t i;
    for(i = 0; i < SECTORS_PER_PAGE; i++)
        block_read(swap_device, p->sector + i, p->frame_entry->frame + i * BLOCK_SECTOR_SIZE);
    lock_acquire(&bitmap_lock);
    bitmap_reset(swap_bitmap, p->sector / SECTORS_PER_PAGE);
    lock_release(&bitmap_lock);
    p->sector = (block_sector_t) -1;
    lock_release(&swap_lock);
}

bool swap_out (struct sup_page_entry *p){
    lock_acquire(&swap_lock);
    lock_acquire(&bitmap_lock);
    size_t i = bitmap_scan_and_flip(swap_bitmap, 0, 1, false);
    lock_release(&bitmap_lock);
    if(i == BITMAP_ERROR)
        PANIC("No swap space");
    p->sector = i * SECTORS_PER_PAGE;
    size_t j;
    for(j = 0; j < SECTORS_PER_PAGE; j++)
        block_write(swap_device, i * SECTORS_PER_PAGE + j, p->frame_entry->frame + j * BLOCK_SECTOR_SIZE);
    lock_release(&swap_lock);

    p->file = NULL; //TODO: are these three OK?
    p->ofs = 0;
    p->read_bytes = 0;
    return true;
}

bool swap_free (struct sup_page_entry *p){
    lock_acquire(&swap_lock);
    lock_acquire(&bitmap_lock);
    bitmap_reset(swap_bitmap, p->sector / SECTORS_PER_PAGE);
    lock_release(&bitmap_lock);
    lock_release(&swap_lock);
    return true;
}