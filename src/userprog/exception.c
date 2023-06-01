#include "userprog/exception.h"
#include <inttypes.h>
#include <stdio.h>
#include "userprog/gdt.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "vm/frame.h"
#include "vm/page.h"

/** Number of page faults processed. */
static long long page_fault_cnt;
#define STACK_MAX (1 << 23)

static void kill (struct intr_frame *);
static void page_fault (struct intr_frame *);

/** Registers handlers for interrupts that can be caused by user
   programs.

   In a real Unix-like OS, most of these interrupts would be
   passed along to the user process in the form of signals, as
   described in [SV-386] 3-24 and 3-25, but we don't implement
   signals.  Instead, we'll make them simply kill the user
   process.

   Page faults are an exception.  Here they are treated the same
   way as other exceptions, but this will need to change to
   implement virtual memory.

   Refer to [IA32-v3a] section 5.15 "Exception and Interrupt
   Reference" for a description of each of these exceptions. */
void
exception_init (void) 
{
  /* These exceptions can be raised explicitly by a user program,
     e.g. via the INT, INT3, INTO, and BOUND instructions.  Thus,
     we set DPL==3, meaning that user programs are allowed to
     invoke them via these instructions. */
  intr_register_int (3, 3, INTR_ON, kill, "#BP Breakpoint Exception");
  intr_register_int (4, 3, INTR_ON, kill, "#OF Overflow Exception");
  intr_register_int (5, 3, INTR_ON, kill,
                     "#BR BOUND Range Exceeded Exception");

  /* These exceptions have DPL==0, preventing user processes from
     invoking them via the INT instruction.  They can still be
     caused indirectly, e.g. #DE can be caused by dividing by
     0.  */
  intr_register_int (0, 0, INTR_ON, kill, "#DE Divide Error");
  intr_register_int (1, 0, INTR_ON, kill, "#DB Debug Exception");
  intr_register_int (6, 0, INTR_ON, kill, "#UD Invalid Opcode Exception");
  intr_register_int (7, 0, INTR_ON, kill,
                     "#NM Device Not Available Exception");
  intr_register_int (11, 0, INTR_ON, kill, "#NP Segment Not Present");
  intr_register_int (12, 0, INTR_ON, kill, "#SS Stack Fault Exception");
  intr_register_int (13, 0, INTR_ON, kill, "#GP General Protection Exception");
  intr_register_int (16, 0, INTR_ON, kill, "#MF x87 FPU Floating-Point Error");
  intr_register_int (19, 0, INTR_ON, kill,
                     "#XF SIMD Floating-Point Exception");

  /* Most exceptions can be handled with interrupts turned on.
     We need to disable interrupts for page faults because the
     fault address is stored in CR2 and needs to be preserved. */
  intr_register_int (14, 0, INTR_OFF, page_fault, "#PF Page-Fault Exception");
}

/** Prints exception statistics. */
void
exception_print_stats (void) 
{
  printf ("Exception: %lld page faults\n", page_fault_cnt);
}

/** Handler for an exception (probably) caused by a user process. */
static void
kill (struct intr_frame *f) 
{
  /* This interrupt is one (probably) caused by a user process.
     For example, the process might have tried to access unmapped
     virtual memory (a page fault).  For now, we simply kill the
     user process.  Later, we'll want to handle page faults in
     the kernel.  Real Unix-like operating systems pass most
     exceptions back to the process via signals, but we don't
     implement them. */
     
  /* The interrupt frame's code segment value tells us where the
     exception originated. */
     
  switch (f->cs)
    {
    case SEL_UCSEG:
      /* User's code segment, so it's a user exception, as we
         expected.  Kill the user process.  */
      printf ("%s: dying due to interrupt %#04x (%s).\n",
              thread_name (), f->vec_no, intr_name (f->vec_no));
      intr_dump_frame (f);
      thread_current()->exit_code = -1;
      thread_exit (); 

    case SEL_KCSEG:
      /* Kernel's code segment, which indicates a kernel bug.
         Kernel code shouldn't throw exceptions.  (Page faults
         may cause kernel exceptions--but they shouldn't arrive
         here.)  Panic the kernel to make the point.  */
      intr_dump_frame (f);
      PANIC ("Kernel bug - unexpected interrupt in kernel"); 

    default:
      /* Some other code segment?  Shouldn't happen.  Panic the
         kernel. */
      printf ("Interrupt %#04x (%s) in unknown segment %04x\n",
             f->vec_no, intr_name (f->vec_no), f->cs);
      thread_exit ();
    }
}

/** Page fault handler.  This is a skeleton that must be filled in
   to implement virtual memory.  Some solutions to project 2 may
   also require modifying this code.

   At entry, the address that faulted is in CR2 (Control Register
   2) and information about the fault, formatted as described in
   the PF_* macros in exception.h, is in F's error_code member.  The
   example code here shows how to parse that information.  You
   can find more information about both of these in the
   description of "Interrupt 14--Page Fault Exception (#PF)" in
   [IA32-v3a] section 5.15 "Exception and Interrupt Reference". */
static void
page_fault (struct intr_frame *f) 
{
   // if (f->error_code & PF_P == 0) //page_fault_triggered_by_a_bad_reference_from_a_system_call
   // {
   //    f->eip = (void (*) (void)) f->eax;
   //    f->eax = -1;
   //    return;
   // }
  bool not_present;  /**< True: not-present page, false: writing r/o page. */
  bool write;        /**< True: access was write, false: access was read. */
  bool user;         /**< True: access by user, false: access by kernel. */
  void *fault_addr;  /**< Fault address. */

  /* Obtain faulting address, the virtual address that was
     accessed to cause the fault.  It may point to code or to
     data.  It is not necessarily the address of the instruction
     that caused the fault (that's f->eip).
     See [IA32-v2a] "MOV--Move to/from Control Registers" and
     [IA32-v3a] 5.15 "Interrupt 14--Page Fault Exception
     (#PF)". */
  asm ("movl %%cr2, %0" : "=r" (fault_addr));

  /* Turn interrupts back on (they were only off so that we could
     be assured of reading CR2 before it changed). */
  intr_enable ();

  /* Count page faults. */
  page_fault_cnt++;

  /* Determine cause. */
  not_present = (f->error_code & PF_P) == 0;
  write = (f->error_code & PF_W) != 0;
  user = (f->error_code & PF_U) != 0;

  #ifdef VM
  #ifdef DEBUG
  printf("The fault addr is %p\n", fault_addr);
   #endif
   //print all three flags
   //printf("not_present = %d, write = %d, user = %d, fault_addr = %p\n", not_present, write, user, fault_addr);
   //stack growth
   void* esp = user ? f->esp : thread_current()->current_esp;
   bool on_stack_frame = (f->esp <= fault_addr || fault_addr == f->esp - 4 || fault_addr == f->esp - 32);
   bool ok_stack_addr = (fault_addr >= PHYS_BASE - STACK_MAX)&& (fault_addr < PHYS_BASE);
   void* fault_page = pg_round_down(fault_addr);
   if(on_stack_frame && ok_stack_addr){
      //printf("stack growth\n");
      if(!sup_page_exists(fault_page)){
         //printf("stack growth\n");
         sup_zero_page_alloc(fault_page, true);
      }
      
   }
   if(!not_present){
      goto DEAL;
   }
 
   //if (not_present && (user||fault_addr < PHYS_BASE)){
      //load page from supplemental page table、
      // if (fault_addr == NULL || !is_user_vaddr(fault_addr)) { 
      //    f->eip = (void (*) (void)) f->eax;
      //    f->eax = -1;
      //    return;
      // }
      bool success = load_page(fault_addr);
      // if (!success) {
      //    f->eip = (void (*) (void)) f->eax;
      //    f->eax = -1;
      //    return;
      // }
      // return; 
      if(success) return;
   //}
   #endif
DEAL:
   if (!user) {
    f->eip = (void (*) (void)) f->eax;
    f->eax = -1;
    return; 
  }     
   //    f->eip = (void (*) (void)) f->eax;
   //  f->eax = -1;
   //  return; 
  /* To implement virtual memory, delete the rest of the function
     body, and replace it with code that brings in the page to
     which fault_addr refers. */
//printf("Here I'm in page_fault(), user = %d.\n", user);

   //TODO: Implement lazy loading

  printf ("Page fault at %p: %s error %s page in %s context.\n",
          fault_addr,
          not_present ? "not present" : "rights violation",
          write ? "writing" : "reading",
          user ? "user" : "kernel");
    
   kill (f);
}


/*Implementation in Lab 2*/
/*Provioded codes*/

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}

/*My Implementation*/

void set_and_exit(){
   thread_current()->exit_code = -1;
   thread_exit();
}

/*2 for str, 1 for write and 0 for read*/
void *pointer_checker(const void *vaddr, size_t size, int type){
   //Check whether the addr is below PHYS_BASE
   if (!is_user_vaddr(vaddr)){
      set_and_exit();
   }

   if(type == 0)
      for (size_t i = 0; i < size; i++){
         if (get_user((uint8_t*)vaddr + i) == -1){
            set_and_exit();
         }
      }
   else if(type == 1)
      for (size_t i = 0; i < size; i++){
         if (put_user((uint8_t*)vaddr + i, 0) == false){
            set_and_exit();
         }
      }
   else if(type == 2){
      uint8_t *p_str = (uint8_t*)vaddr;
      while(1){
         int result = get_user(p_str);
         if (result == -1){
            set_and_exit();
         }
         else if (result == 0){
            return p_str;
         }
         p_str++;
      }

   }

   void *ptr = vaddr;
   return ptr;
}

