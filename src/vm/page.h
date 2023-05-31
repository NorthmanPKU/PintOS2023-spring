#ifndef VM_PAGE_H
#define VM_PAGE_H
#include "threads/synch.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include <hash.h>
#include <string.h>
#include "lib/kernel/hash.h"
#include "filesys/off_t.h"
#include "vm/frame.h"
#include "devices/block.h"

#define FRAME 0
#define SWAP 1
#define FILE 2



struct hash supplemental_page_table;

struct sup_page_entry{
    void *upage; /* User virtual address */
    void *kpage; /* Kernel virtual address */
    struct frame_entry *frame_entry; /* Frame entry */
    struct file *file; /* File */
    off_t ofs; /* Offset in file */
    uint32_t read_bytes; /* Number of bytes to read from file */
    uint32_t zero_bytes; /* Number of bytes to set to zero */
    bool writable; /* Page is writable */
    bool loaded; /* Page is loaded to memory */
    bool pinned; /* Page is pinned */
    struct thread *thread; /* Thread that owns the page */
    block_sector_t sector; /* Sector number in swap */
    struct hash_elem hash_elem; /* Hash element */
};

struct sup_page_entry *sup_page_alloc (void *upage, bool writable);
bool sup_page_less (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);
unsigned sup_page_hash (const struct hash_elem *p_, void *aux UNUSED);
struct sup_page_entry *sup_page_lookup (void *upage);
void sup_page_table_init (void);
//void sup_page_table_init (struct hash *sup_page_table);
bool sup_page_insert (struct hash *sup_page_table, struct sup_page_entry *sup_page_entry);
bool sup_page_delete (struct hash *sup_page_table, struct sup_page_entry *sup_page_entry);
//void sup_page_table_destroy (struct hash *sup_page_table);
bool load_page (void *upage);

bool page_accessed_recently (struct sup_page_entry *p);
bool page_out (struct sup_page_entry *p);

void page_destroy (struct hash_elem *e, void *aux UNUSED);
void page_free (struct sup_page_entry *p);

#endif /* vm/page.h */