#ifndef __LINUX_MUTEX_WRAPPER_H
#define __LINUX_MUTEX_WRAPPER_H


#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16)

#include <asm/semaphore.h>

struct mutex {
	struct semaphore sema;
};

#define mutex_init(mutex) init_MUTEX(&mutex->sema)
#define mutex_destroy(mutex) do { } while (0)

#define __MUTEX_INITIALIZER(name) \
			__SEMAPHORE_INITIALIZER(name,1)

#define DEFINE_MUTEX(mutexname) \
	struct mutex mutexname = { __MUTEX_INITIALIZER(mutexname.sema) }

/*
 * See kernel/mutex.c for detailed documentation of these APIs.
 * Also see Documentation/mutex-design.txt.
 */
static inline void mutex_lock(struct mutex *lock)
{
	down(&lock->sema);
}

static inline int mutex_lock_interruptible(struct mutex *lock)
{
	return down_interruptible(&lock->sema);
}

#define mutex_lock_nested(lock, subclass) mutex_lock(lock)
#define mutex_lock_interruptible_nested(lock, subclass) mutex_lock_interruptible(lock)

/*
 * NOTE: mutex_trylock() follows the spin_trylock() convention,
 *       not the down_trylock() convention!
 */
static inline int mutex_trylock(struct mutex *lock)
{
	return !down_trylock(&lock->sema);
}

static inline void mutex_unlock(struct mutex *lock)
{
	up(&lock->sema);
}
#else 

#include_next <linux/mutex.h>

#endif /* linux version < 2.6.16 */

#endif 
