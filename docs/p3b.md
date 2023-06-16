# Project 3b: Virtual Memory

## Preliminaries

>Fill in your name and email address.

Jianan Ji 2000012995@stu.pku.edu.cn

>If you have any preliminary comments on your submission, notes for the TAs, please give them here.



>Please cite any offline or online sources you consulted while preparing your submission, other than the Pintos documentation, course text, lecture notes, and course staff.



## Stack Growth

#### ALGORITHMS

>A1: Explain your heuristic for deciding whether a page fault for an
>invalid virtual address should cause the stack to be extended into
>the page that faulted.

Firstly check if the fault occurred within the user stack frame. This is done by comparing the fault address (`fault_addr`) with the stack pointer (`esp`). If the fault address is below the stack pointer, or equals to the stack pointer minus 4 or 32 (which could be due to a push or call instruction), then it is considered to be within the stack frame.

Then check if the fault address is within the valid range for user stack addresses. This is done by comparing the fault address with the top of the user virtual address space (`PHYS_BASE`) and the maximum stack size (`STACK_MAX`). If the fault address is within this range, then it is considered to be a valid stack address.

Finally attempt to extend the stack into the page where the fault occurred. This is done by looking up the supplemental page table for the fault page. If the fault page does not exist in the supplemental page table, a new zeroed page is allocated for it. 

## Memory Mapped Files

#### DATA STRUCTURES

>B1: Copy here the declaration of each new or changed struct or struct member, global or static variable, typedef, or enumeration.  Identify the purpose of each in 25 words or less.

```c++
typedef uint32_t mapid_t;
struct mmap_file {
    mapid_t mapid; //id of the mapped file
    int fd; //file descriptor
    struct file *file; //file pointer
    void *addr; //address
    int length; //length of the file
    struct list_elem elem; //list element
};
```



#### ALGORITHMS

>B2: Describe how memory mapped files integrate into your virtual
>memory subsystem.  Explain how the page fault and eviction
>processes differ between swap pages and other pages.

Each mapping holds a reference to its memory address and the file it maps. Each thread maintains a list of all the files mapped to that thread, which aids in managing which files are directly present in memory. Apart from this, pages containing memory-mapped file information are managed just like any other page.

The process of handling page faults and eviction is slightly different for pages associated with memory-mapped files. Pages not related to files are moved to a swap partition upon eviction, regardless of whether the page has been modified or not. However, when pages of memory-mapped files are evicted, they should only be written back to the file if they have been altered. Otherwise, no writing is required.

>B3: Explain how you determine whether a new file mapping overlaps
>any existing segment.

By iterating over the range of the new file mapping and checking if any of the pages within this range are already mapped in the supplemental page table.

#### RATIONALE

>B4: Mappings created with "mmap" have similar semantics to those of
>data demand-paged from executables, except that "mmap" mappings are
>written back to their original files, not to swap.  This implies
>that much of their implementation can be shared.  Explain why your
>implementation either does or does not share much of the code for
>the two situations.

My implementation does share much of the code for both situations. The reason for this is that the underlying mechanism for handling pages, whether they are from an executable or a memory-mapped file, is essentially the same. Both types of pages are stored in the supplemental page table and are loaded into memory upon a page fault. The only significant difference is how the pages are written back when they are evicted from memory. This difference is handled with a simple conditional check during the eviction process. Sharing the code for these operations can reduce redundancy and make the code easier to manage and understand.