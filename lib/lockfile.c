 /* Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>

#include "lockfile.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "coverage.h"
#include "hash.h"
#include "hmap.h"
#include "ovs-thread.h"
#include "timeval.h"
#include "util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(lockfile);

COVERAGE_DEFINE(lockfile_lock);
COVERAGE_DEFINE(lockfile_error);
COVERAGE_DEFINE(lockfile_unlock);

struct lockfile {
    struct hmap_node hmap_node;
    char *name;
    dev_t device;
    ino_t inode;
    int fd;
    HANDLE lock_handle;
};

/* Lock table.
 *
 * We have to do this stupid dance because POSIX says that closing *any* file
 * descriptor for a file on which a process holds a lock drops *all* locks on
 * that file.  That means that we can't afford to open a lockfile more than
 * once. */
static struct ovs_mutex lock_table_mutex = OVS_MUTEX_INITIALIZER;
static struct hmap lock_table__ = HMAP_INITIALIZER(&lock_table__);
static struct hmap *const lock_table OVS_GUARDED_BY(lock_table_mutex)
    = &lock_table__;

static void lockfile_unhash(struct lockfile *);
static int lockfile_try_lock(const char *name, pid_t *pidp,
                             struct lockfile **lockfilep)
    OVS_REQUIRES(&lock_table_mutex);
static void lockfile_do_unlock(struct lockfile * lockfile)
    OVS_REQUIRES(&lock_table_mutex);

/* Returns the name of the lockfile that would be created for locking a file
 * named 'filename_'.  The caller is responsible for freeing the returned name,
 * with free(), when it is no longer needed. */
char *
lockfile_name(const char *filename_)
{
    char *filename;
    const char *slash;
    char *lockname;

    /* If 'filename_' is a symlink, base the name of the lockfile on the
     * symlink's target rather than the name of the symlink.  That way, if a
     * file is symlinked, but there is no symlink for its lockfile, then there
     * is only a single lockfile for both the source and the target of the
     * symlink, not one for each. */
    filename = follow_symlinks(filename_);
    slash = strrchr(filename, '/');
    lockname = (slash
                ? xasprintf("%.*s/.%s.~lock~",
                            (int) (slash - filename), filename, slash + 1)
                : xasprintf(".%s.~lock~", filename));
    free(filename);

    return lockname;
}

/* Locks the configuration file against modification by other processes and
 * re-reads it from disk.
 *
 * Returns 0 on success, otherwise a positive errno value.  On success,
 * '*lockfilep' is set to point to a new "struct lockfile *" that may be
 * unlocked with lockfile_unlock().  On failure, '*lockfilep' is set to
 * NULL.  Will not block if the lock cannot be immediately acquired. */
int
lockfile_lock(const char *file, struct lockfile **lockfilep)
{
    /* Only exclusive ("write") locks are supported.  This is not a problem
     * because the Open vSwitch code that currently uses lock files does so in
     * stylized ways such that any number of readers may access a file while it
     * is being written. */
    char *lock_name;
    pid_t pid;
    int error;

    COVERAGE_INC(lockfile_lock);

    lock_name = lockfile_name(file);

    ovs_mutex_lock(&lock_table_mutex);
    error = lockfile_try_lock(lock_name, &pid, lockfilep);
    ovs_mutex_unlock(&lock_table_mutex);

    if (error) {
        COVERAGE_INC(lockfile_error);
        if (error == EACCES) {
            error = EAGAIN;
        }
        if (pid == getpid()) {
            VLOG_WARN("%s: cannot lock file because this process has already "
                      "locked it", lock_name);
        } else if (pid) {
            VLOG_WARN("%s: cannot lock file because it is already locked by "
                      "pid %ld", lock_name, (long int) pid);
        } else {
            VLOG_WARN("%s: failed to lock file: %s",
                      lock_name, ovs_strerror(error));
        }
    }

    free(lock_name);
    return error;
}

/* Unlocks 'lockfile', which must have been created by a call to
 * lockfile_lock(), and frees 'lockfile'. */
void
lockfile_unlock(struct lockfile *lockfile)
{
    if (lockfile) {
        ovs_mutex_lock(&lock_table_mutex);
        lockfile_do_unlock(lockfile);
        ovs_mutex_unlock(&lock_table_mutex);

        COVERAGE_INC(lockfile_unlock);
        free(lockfile->name);
        free(lockfile);
    }
}

/* Marks all the currently locked lockfiles as no longer locked.  It makes
 * sense to call this function after fork(), because a child created by fork()
 * does not hold its parents' locks. */
void
lockfile_postfork(void)
{
    struct lockfile *lockfile;

    ovs_mutex_lock(&lock_table_mutex);
    HMAP_FOR_EACH (lockfile, hmap_node, lock_table) {
        if (lockfile->fd >= 0) {
            VLOG_WARN("%s: child does not inherit lock", lockfile->name);
            lockfile_unhash(lockfile);
        }
    }
    ovs_mutex_unlock(&lock_table_mutex);
}

static uint32_t
lockfile_hash(dev_t device, ino_t inode)
{
    return hash_bytes(&device, sizeof device,
                      hash_bytes(&inode, sizeof inode, 0));
}

static struct lockfile *
lockfile_find(dev_t device, ino_t inode) OVS_REQUIRES(&lock_table_mutex)
{
    struct lockfile *lockfile;

    HMAP_FOR_EACH_WITH_HASH (lockfile, hmap_node,
                             lockfile_hash(device, inode), lock_table) {
        if (lockfile->device == device && lockfile->inode == inode) {
            return lockfile;
        }
    }
    return NULL;
}

static void
lockfile_unhash(struct lockfile *lockfile) OVS_REQUIRES(&lock_table_mutex)
{
    if (lockfile->fd >= 0) {
        close(lockfile->fd);
        lockfile->fd = -1;
        hmap_remove(lock_table, &lockfile->hmap_node);
    }
}

static struct lockfile *
lockfile_register(const char *name, dev_t device, ino_t inode, int fd)
    OVS_REQUIRES(&lock_table_mutex)
{
    struct lockfile *lockfile;

    lockfile = lockfile_find(device, inode);
    if (lockfile) {
        VLOG_ERR("%s: lock file disappeared and reappeared!", name);
        lockfile_unhash(lockfile);
    }

    lockfile = xmalloc(sizeof *lockfile);
    lockfile->name = xstrdup(name);
    lockfile->device = device;
    lockfile->inode = inode;
    lockfile->fd = fd;
    hmap_insert(lock_table, &lockfile->hmap_node,
                lockfile_hash(device, inode));
    return lockfile;
}

#ifdef _WIN32
static void
lockfile_do_unlock(struct lockfile *lockfile)
    OVS_REQUIRES(&lock_table_mutex)
{
    if (lockfile->fd >= 0) {
        OVERLAPPED overl;
        overl.hEvent = 0;
        overl.Offset = 0;
        overl.OffsetHigh = 0;
        UnlockFileEx(lockfile->lock_handle, 0, 1, 0, &overl);

        close(lockfile->fd);
        lockfile->fd = -1;
    }
}

static int
lockfile_try_lock(const char *name, pid_t *pidp, struct lockfile **lockfilep)
    OVS_REQUIRES(&lock_table_mutex)
{
    HANDLE lock_handle;
    BOOL retval;
    OVERLAPPED overl;
    struct lockfile *lockfile;
    int fd;

    *pidp = 0;

    fd = open(name, O_RDWR | O_CREAT, 0600);
    if (fd < 0) {
        VLOG_WARN("%s: failed to open lock file: %s",
                   name, ovs_strerror(errno));
        return errno;
    }

    lock_handle = (HANDLE)_get_osfhandle(fd);
    if (lock_handle < 0) {
        VLOG_WARN("%s: failed to get the file handle: %s",
                   name, ovs_strerror(errno));
        return errno;
    }

    /* Lock the file 'name' for the region that includes just the first
     * byte. */
    overl.hEvent = 0;
    overl.Offset = 0;
    overl.OffsetHigh = 0;
    retval = LockFileEx(lock_handle, LOCKFILE_EXCLUSIVE_LOCK
                        | LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overl);
    if (!retval) {
        VLOG_WARN("Failed to lock file : %s", ovs_lasterror_to_string());
        return EEXIST;
    }

    lockfile = xmalloc(sizeof *lockfile);
    lockfile->name = xstrdup(name);
    lockfile->fd = fd;
    lockfile->lock_handle = lock_handle;

    *lockfilep = lockfile;
    return 0;
}
#else /* !_WIN32 */
static void
lockfile_do_unlock(struct lockfile *lockfile)
{
    lockfile_unhash(lockfile);
}

static int
lockfile_try_lock(const char *name, pid_t *pidp, struct lockfile **lockfilep)
    OVS_REQUIRES(&lock_table_mutex)
{
    struct flock l;
    struct stat s;
    int error;
    int fd;

    *lockfilep = NULL;
    *pidp = 0;

    /* Check whether we've already got a lock on that file. */
    if (!stat(name, &s)) {
        if (lockfile_find(s.st_dev, s.st_ino)) {
            *pidp = getpid();
            return EDEADLK;
        }
    } else if (errno != ENOENT) {
        VLOG_WARN("%s: failed to stat lock file: %s",
                  name, ovs_strerror(errno));
        return errno;
    }

    /* Open the lock file. */
    fd = open(name, O_RDWR | O_CREAT, 0600);
    if (fd < 0) {
        VLOG_WARN("%s: failed to open lock file: %s",
                  name, ovs_strerror(errno));
        return errno;
    }

    /* Get the inode and device number for the lock table. */
    if (fstat(fd, &s)) {
        VLOG_ERR("%s: failed to fstat lock file: %s",
                 name, ovs_strerror(errno));
        close(fd);
        return errno;
    }

    /* Try to lock the file. */
    memset(&l, 0, sizeof l);
    l.l_type = F_WRLCK;
    l.l_whence = SEEK_SET;
    l.l_start = 0;
    l.l_len = 0;

    error = fcntl(fd, F_SETLK, &l) == -1 ? errno : 0;

    if (!error) {
        *lockfilep = lockfile_register(name, s.st_dev, s.st_ino, fd);
    } else {
        if (!fcntl(fd, F_GETLK, &l) && l.l_type != F_UNLCK) {
            *pidp = l.l_pid;
        }
        close(fd);
    }
    return error;
}
#endif
