#ifndef THREADS_SYNCH_H
#define THREADS_SYNCH_H

#include <list.h>
#include <stdbool.h>

/** A counting semaphore. */
struct semaphore {
    unsigned value;      /**< Current value. */
    struct list waiters; /**< List of waiting threads. */
};

void sema_init(struct semaphore*, unsigned value);
void sema_down(struct semaphore*);
bool sema_try_down(struct semaphore*);
void sema_up(struct semaphore*);
void sema_self_test(void);

/** Lock. */
struct lock {
    struct list_elem elem; /**< List element. */
    int max_priority;      /**< Max priority of the threads wanting the lock. */
    int have_thread_waiting; /**< Whether there is a thread waiting for the lock. */
    struct thread* holder; /**< Thread holding lock (for debugging). */
    struct semaphore semaphore; /**< Binary semaphore controlling access. */
};

void lock_init(struct lock*);
void lock_acquire(struct lock*);
bool lock_try_acquire(struct lock*);
void lock_release(struct lock*);
bool lock_held_by_current_thread(const struct lock*);

/** Condition variable. */
struct condition {
    struct list waiters; /**< List of waiting threads. */
};

void cond_init(struct condition*);
void cond_wait(struct condition*, struct lock*);
void cond_signal(struct condition*, struct lock*);
void cond_broadcast(struct condition*, struct lock*);

/** My own functions.*/

void donate_priority(
    struct thread* t,
    int priority); /**< Donate priority to the thread recursively. */

bool lock_cmp_priority(
    const struct list_elem* a,
    const struct list_elem* b,
    void* aux); /**< Compare the priority of two locks. */

//void thread_update_priority(struct thread* donatee);

//void thread_hold_lock(struct lock* l);
void thread_hold_the_lock(struct lock *lock);
void thread_remove_lock(struct lock* l);
int max(int a, int b);

bool cond_compare_priority(const struct list_elem* a,
                           const struct list_elem* b, void* aux);


bool thread_cmp_priority(const struct list_elem* a,
                         const struct list_elem* b,
                         void* aux);

/** Optimization barrier.

   The compiler will not reorder operations across an
   optimization barrier.  See "Optimization Barriers" in the
   reference guide for more information.*/
#define barrier() asm volatile("" : : : "memory")

#endif /**< threads/synch.h */
