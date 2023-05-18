#ifndef VM_SWAP_H
#define VM_SWAP_H


void swap_init (void);
void swap_in (struct sup_page_entry *p);
bool swap_out (struct sup_page_entry *p);


#endif /* vm/swap.h */
