#ifndef __LINUX_MUTEX_H
#define __LINUX_MUTEX_H

#include <asm/semaphore.h>

struct mutex {
	struct semaphore sema;
};

#define mutex_init(mutex) init_MUTEX(&mutex->sema)
#define mutex_destroy(mutex) do { } while (0)

#define DEFINE_MUTEX(mutexname) \
	struct mutex mutexname = { __MUTEX_INITIALIZER(mutexname.sema) }

/**
 * mutex_is_locked - is the mutex locked
 * @lock: the mutex to be queried
 *
 * Returns 1 if the mutex is locked, 0 if unlocked.
 */
static inline int mutex_is_locked(struct mutex *lock)
{
	return sem_getcount(&lock->sema) == 0;
}

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

#endif
