#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "fixed_point.h"
#include "threads/synch.h"
#include <hash.h>
#include "vm/page.h"
#include "lib/kernel/hash.h"

/** States in a thread's life cycle. */
enum thread_status {
    THREAD_RUNNING, /**< Running thread. */
    THREAD_READY,   /**< Not running but ready to run. */
    THREAD_BLOCKED, /**< Waiting for an event to trigger. */
    THREAD_DYING    /**< About to be destroyed. */
};

/** Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t)-1) /**< Error value for tid_t. */

/** Thread priorities. */
#define PRI_MIN 0      /**< Lowest priority. */
#define PRI_DEFAULT 31 /**< Default priority. */
#define PRI_MAX 63     /**< Highest priority. */

/*Child thread*/
struct child_thread
{
    tid_t tid;                   /*Child thread id*/
    int exit_status;             /*Child thread exit status*/
    bool is_alive;               /*Child thread is alive or not*/
    bool is_waited;              /*Child thread is waited or not*/
    struct semaphore sema;       /*Child thread semaphore*/
    struct thread *self_t;              /*Child thread parent*/
    struct thread *parent;          /*Child thread parent*/
    struct list_elem elem;      /*Child thread list element*/
};

/*files of a thread*/
struct thread_file{
      int fd;                     /*file descriptor*/
      struct file *file;          /*file pointer*/
      struct list_elem elem;      /*file list element*/
   
};

/** A kernel thread or user process.

   Each thread structure is stored in its own 4 kB page.  The
   thread structure itself sits at the very bottom of the page
   (at offset 0).  The rest of the page is reserved for the
   thread's kernel stack, which grows downward from the top of
   the page (at offset 4 kB).  Here's an illustration:

        4 kB +---------------------------------+
             |          kernel stack           |
             |                |                |
             |                |                |
             |                V                |
             |         grows downward          |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             +---------------------------------+
             |              magic              |
             |                :                |
             |                :                |
             |               name              |
             |              status             |
        0 kB +---------------------------------+

   The upshot of this is twofold:

      1. First, `struct thread' must not be allowed to grow too
         big.  If it does, then there will not be enough room for
         the kernel stack.  Our base `struct thread' is only a
         few bytes in size.  It probably should stay well under 1
         kB.

      2. Second, kernel stacks must not be allowed to grow too
         large.  If a stack overflows, it will corrupt the thread
         state.  Thus, kernel functions should not allocate large
         structures or arrays as non-static local variables.  Use
         dynamic allocation with malloc() or palloc_get_page()
         instead.

   The first symptom of either of these problems will probably be
   an assertion failure in thread_current(), which checks that
   the `magic' member of the running thread's `struct thread' is
   set to THREAD_MAGIC.  Stack overflow will normally change this
   value, triggering the assertion. */
/** The `elem' member has a dual purpose.  It can be an element in
   the run queue (thread.c), or it can be an element in a
   semaphore wait list (synch.c).  It can be used these two ways
   only because they are mutually exclusive: only a thread in the
   ready state is on the run queue, whereas only a thread in the
   blocked state is on a semaphore wait list. */
struct thread {
    /* Owned by thread.c. */
    tid_t tid;                 /**< Thread identifier. */
    enum thread_status status; /**< Thread state. */
    char name[16];             /**< Name (for debugging purposes). */
    uint8_t* stack;            /**< Saved stack pointer. */
    int priority;              /**< Priority. */
    struct list_elem allelem;  /**< List element for all threads list. */

    /* Shared between thread.c and synch.c. */
    struct list_elem elem; /**< List element. */

    /* Added by me in Lab1*/
    uint64_t ticks2wait;       /**< Ticks to wait in thread_sleep(). */
    int original_priority;     /**< Original priority. Initiated to -1.*/
    struct list locks_held;    /**< List of locks held by thread. */
    struct lock* lock_waiting; /**< Lock thread is waiting for. */

      /* Added by me in Lab2*/
      struct list child_list; /**< List of child threads. */
      struct child_thread* self_as_child; /**< Self as child thread. */
      struct thread* parent; /**< Parent thread. */
      struct semaphore sc_exec_sema; /**< Semaphore for exec. */
      bool child_exec_success; /**< Child exec success. */
      struct list files_list; /**< List of files. */
      int next_fd; /**< Next file descriptor. */
      struct file* executable_file; /**< Executable file. */

    int nice;
    fixed_point_t recent_cpu;

#ifdef USERPROG
    /* Owned by userprog/process.c. */
    uint32_t* pagedir; /**< Page directory. */

    uint8_t *current_esp;
#endif
#ifdef VM
    struct hash sup_page_table; /**< Supplemental page table. */
    //lab 3b
    struct list mmap_list; /**< List of mmap files. */
#endif

    int exit_code; /**< Exit code of thread. */

    /* Owned by thread.c. */
    unsigned magic; /**< Detects stack overflow. */
};

/** If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init(void);
void thread_start(void);

void thread_tick(void);
void thread_print_stats(void);

typedef void thread_func(void* aux);
tid_t thread_create(const char* name, int priority, thread_func*, void*);

void thread_block(void);
void thread_unblock(struct thread*);

struct thread* thread_current(void);
tid_t thread_tid(void);
const char* thread_name(void);

void thread_exit(void) NO_RETURN;
void thread_yield(void);

/** Performs some operation on thread t, given auxiliary data AUX. */
typedef void thread_action_func(struct thread* t, void* aux);
void thread_foreach(thread_action_func*, void*);

int thread_get_priority(void);
void thread_set_priority(int);

int thread_get_nice(void);
void thread_set_nice(int);
int thread_get_recent_cpu(void);
int thread_get_load_avg(void);

void thread_sleeptime_check(struct thread* t, void* aux UNUSED);

bool thread_priority_bigger(const struct list_elem* a,
                            const struct list_elem* b,
                            void* aux UNUSED);

// void thread_donate_priority(struct thread* t);
void list_insert_ordered_inthread(struct list_elem* elem,
                                  list_less_func* less,
                                  void* aux);

void thread_donate_priority(
    struct thread* t);  // donator, struct lock* donatee);

void print_ready_list(void);  // for debugging

/*Mission 3*/
void thread_mlfqs_increment_recent_cpu(void);
// void thread_mlfqs_update_recent_cpu();

void thread_update_recent_cpu(struct thread* t, void* aux UNUSED);
// void thread_mlfqs_update_load_avg();
void thread_update_load_avg(void);

int modify_in_range(int priority);
void thread_mlfqs_update_priority(struct thread* t);

#endif /**< threads/thread.h */
