/* Copyright (c) 2009, 2010, 2011, 2012, 2013, 2017 Nicira, Inc.
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

#include "log.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "openvswitch/dynamic-string.h"
#include "openvswitch/json.h"
#include "openvswitch/vlog.h"
#include "lockfile.h"
#include "ovsdb.h"
#include "ovsdb-error.h"
#include "sha1.h"
#include "socket-util.h"
#include "transaction.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(ovsdb_log);

/* State in a log's state machine.
 *
 * OVSDB_LOG_READ is the initial state for a newly opened log.  Log records may
 * be read in this state only.  Reaching end of file does not cause a state
 * transition.  A read error transitions to OVSDB_LOG_READ_ERROR.
 *
 * OVSDB_LOG_READ_ERROR prevents further reads from succeeding; they will
 * report the same error as before.  A log write transitions away to
 * OVSDB_LOG_WRITE or OVSDB_LOG_WRITE_ERROR.
 *
 * OVSDB_LOG_WRITE is the state following a call to ovsdb_log_write(), when all
 * goes well.  Any state other than OVSDB_LOG_BROKEN may transition to this
 * state.  A write error transitions to OVSDB_LOG_WRITE_ERROR.
 *
 * OVSDB_LOG_WRITE_ERROR is the state following a write error.  Further writes
 * retry and might transition back to OVSDB_LOG_WRITE.
 *
 * OVSDB_LOG_BROKEN is the state following a call to ovsdb_log_replace() or
 * ovsdb_log_replace_commit(), if it fails in a spectacular enough way that no
 * further reads or writes can succeed.  This is a terminal state.
 */
enum ovsdb_log_state {
    OVSDB_LOG_READ,             /* Ready to read. */
    OVSDB_LOG_READ_ERROR,       /* Read failed, see 'error' for details. */
    OVSDB_LOG_WRITE,            /* Ready to write. */
    OVSDB_LOG_WRITE_ERROR,      /* Write failed, see 'error' for details. */
    OVSDB_LOG_BROKEN,           /* Disk on fire, see 'error' for details. */
};

struct ovsdb_log {
    enum ovsdb_log_state state;
    struct ovsdb_error *error;

    off_t prev_offset;
    off_t offset;
    char *name;                 /* Absolute name of file. */
    char *display_name;         /* For use in log messages, etc. */
    char *magic;
    struct lockfile *lockfile;
    FILE *stream;
    off_t base;
};

/* Whether the OS supports renaming open files.
 *
 * (Making this a variable makes it easier to test both strategies on Unix-like
 * systems.) */
#ifdef _WIN32
static bool rename_open_files = false;
#else
static bool rename_open_files = true;
#endif

static bool parse_header(char *header, const char **magicp,
                         unsigned long int *length,
                         uint8_t sha1[SHA1_DIGEST_SIZE]);
static bool is_magic_ok(const char *needle, const char *haystack);

/* Attempts to open 'name' with the specified 'open_mode'.  On success, stores
 * the new log into '*filep' and returns NULL; otherwise returns NULL and
 * stores NULL into '*filep'.
 *
 * 'magic' is a short text string put at the beginning of every record and used
 * to distinguish one kind of log file from another.  For a conventional OVSDB
 * log file, use the OVSDB_MAGIC macro.  To accept more than one magic string,
 * separate them with "|", e.g. "MAGIC 1|MAGIC 2".
 *
 * Whether the file will be locked using lockfile_lock() depends on 'locking':
 * use true to lock it, false not to lock it, or -1 to lock it only if
 * 'open_mode' is a mode that allows writing.
 *
 * A log consists of a series of records.  After opening or creating a log with
 * this function, the client may use ovsdb_log_read() to read any existing
 * records, one by one.  The client may also use ovsdb_log_write() to write new
 * records (if some records have not yet been read at this point, then the
 * first write truncates them).
 */
struct ovsdb_error *
ovsdb_log_open(const char *name, const char *magic,
               enum ovsdb_log_open_mode open_mode,
               int locking, struct ovsdb_log **filep)
{
    struct lockfile *lockfile;
    struct ovsdb_error *error;
    struct stat s;
    FILE *stream;
    int flags;
    int fd;

    /* If we can create a new file, we need to know what kind of magic to
     * use, so there must be only one kind. */
    if (open_mode == OVSDB_LOG_CREATE_EXCL || open_mode == OVSDB_LOG_CREATE) {
        ovs_assert(!strchr(magic, '|'));
    }

    *filep = NULL;

    /* Get the absolute name of the file because we might need to access it by
     * name again later after the process has changed directory (e.g. because
     * daemonize() chdirs to "/").
     *
     * We save the user-provided name of the file for use in log messages, to
     * reduce user confusion. */
    char *abs_name = abs_file_name(NULL, name);
    if (!abs_name) {
        error = ovsdb_io_error(0, "could not determine current "
                              "working directory");
        goto error;
    }

    ovs_assert(locking == -1 || locking == false || locking == true);
    if (locking < 0) {
        locking = open_mode != OVSDB_LOG_READ_ONLY;
    }
    if (locking) {
        int retval = lockfile_lock(name, &lockfile);
        if (retval) {
            error = ovsdb_io_error(retval, "%s: failed to lock lockfile",
                                   name);
            goto error;
        }
    } else {
        lockfile = NULL;
    }

    switch (open_mode) {
    case OVSDB_LOG_READ_ONLY:
        flags = O_RDONLY;
        break;

    case OVSDB_LOG_READ_WRITE:
        flags = O_RDWR;
        break;

    case OVSDB_LOG_CREATE_EXCL:
#ifndef _WIN32
        if (stat(name, &s) == -1 && errno == ENOENT
            && lstat(name, &s) == 0 && S_ISLNK(s.st_mode)) {
            /* 'name' is a dangling symlink.  We want to create the file that
             * the symlink points to, but POSIX says that open() with O_EXCL
             * must fail with EEXIST if the named file is a symlink.  So, we
             * have to leave off O_EXCL and accept the race. */
            flags = O_RDWR | O_CREAT;
        } else {
            flags = O_RDWR | O_CREAT | O_EXCL;
        }
#else
        flags = O_RDWR | O_CREAT | O_EXCL;
#endif
        break;

    case OVSDB_LOG_CREATE:
        flags = O_RDWR | O_CREAT;
        break;

    default:
        OVS_NOT_REACHED();
    }
#ifdef _WIN32
    flags = flags | O_BINARY;
#endif
    /* Special case for /dev/stdin to make it work even if the operating system
     * doesn't support it under that name. */
    if (!strcmp(name, "/dev/stdin") && open_mode == OVSDB_LOG_READ_ONLY) {
        fd = dup(STDIN_FILENO);
    } else {
        fd = open(name, flags, 0666);
    }
    if (fd < 0) {
        const char *op = (open_mode == OVSDB_LOG_CREATE_EXCL ? "create"
            : open_mode == OVSDB_LOG_CREATE ? "create or open"
            : "open");
        error = ovsdb_io_error(errno, "%s: %s failed", name, op);
        goto error_unlock;
    }

    stream = fdopen(fd, open_mode == OVSDB_LOG_READ_ONLY ? "rb" : "w+b");
    if (!stream) {
        error = ovsdb_io_error(errno, "%s: fdopen failed", name);
        close(fd);
        goto error_unlock;
    }

    /* Read the magic from the first log record. */
    char header[128];
    const char *actual_magic;
    if (!fgets(header, sizeof header, stream)) {
        if (ferror(stream)) {
            error = ovsdb_io_error(errno, "%s: read error", name);
            goto error_fclose;
        }

        /* We need to be able to report what kind of file this is but we can't
         * if it's empty and we accept more than one. */
        if (strchr(magic, '|')) {
            error = ovsdb_error(NULL, "%s: cannot identify file type", name);
            goto error_fclose;
        }
        actual_magic = magic;

        /* It's an empty file and therefore probably a new file, so fsync()
         * its parent directory to ensure that its directory entry is
         * committed to disk. */
        fsync_parent_dir(name);
    } else {
        unsigned long int length;
        uint8_t sha1[SHA1_DIGEST_SIZE];
        if (!parse_header(header, &actual_magic, &length, sha1)) {
            error = ovsdb_error(NULL, "%s: unexpected file format", name);
            goto error_fclose;
        } else if (!is_magic_ok(actual_magic, magic)) {
            error = ovsdb_error(NULL, "%s: cannot identify file type", name);
            goto error_fclose;
        }
    }

    if (fseek(stream, 0, SEEK_SET)) {
        error = ovsdb_io_error(errno, "%s: seek failed", name);
        goto error_fclose;
    }

    struct ovsdb_log *file = xmalloc(sizeof *file);
    file->state = OVSDB_LOG_READ;
    file->error = NULL;
    file->name = abs_name;
    file->display_name = xstrdup(name);
    file->magic = xstrdup(actual_magic);
    file->lockfile = lockfile;
    file->stream = stream;
    file->prev_offset = 0;
    file->offset = 0;
    file->base = 0;
    *filep = file;
    return NULL;

error_fclose:
    fclose(stream);
error_unlock:
    lockfile_unlock(lockfile);
error:
    free(abs_name);
    return error;
}

/* Returns true if 'needle' is one of the |-delimited words in 'haystack'. */
static bool
is_magic_ok(const char *needle, const char *haystack)
{
    /* 'needle' can't be multiple words. */
    if (strchr(needle, '|')) {
        return false;
    }

    size_t n = strlen(needle);
    for (;;) {
        if (!strncmp(needle, haystack, n) && strchr("|", haystack[n])) {
            return true;
        }
        haystack = strchr(haystack, '|');
        if (!haystack) {
            return false;
        }
        haystack++;
    }
}

void
ovsdb_log_close(struct ovsdb_log *file)
{
    if (file) {
        ovsdb_error_destroy(file->error);
        free(file->name);
        free(file->display_name);
        free(file->magic);
        if (file->stream) {
            fclose(file->stream);
        }
        lockfile_unlock(file->lockfile);
        free(file);
    }
}

const char *
ovsdb_log_get_magic(const struct ovsdb_log *log)
{
    return log->magic;
}

/* Attempts to parse 'header' as a header line for an OVSDB log record (as
 * described in ovsdb(5)).  Stores a pointer to the magic string in '*magicp',
 * the length in *length, and the parsed sha1 value in sha1[].
 *
 * Modifies 'header' and points '*magicp' inside it.
 *
 * Returns true if successful, false on failure. */
static bool
parse_header(char *header, const char **magicp,
             unsigned long int *length, uint8_t sha1[SHA1_DIGEST_SIZE])
{
    /* 'header' must consist of "OVSDB "... */
    const char lead[] = "OVSDB ";
    if (strncmp(lead, header, strlen(lead))) {
        return false;
    }

    /* ...followed by a magic string... */
    char *magic = header + strlen(lead);
    size_t magic_len = strcspn(magic, " ");
    if (magic[magic_len] != ' ') {
        return false;
    }
    magic[magic_len] = '\0';
    *magicp = magic;

    /* ...followed by a length in bytes... */
    char *p;
    *length = strtoul(magic + magic_len + 1, &p, 10);
    if (!*length || *length == ULONG_MAX || *p != ' ') {
        return false;
    }
    p++;

    /* ...followed by a SHA-1 hash... */
    if (!sha1_from_hex(sha1, p)) {
        return false;
    }
    p += SHA1_HEX_DIGEST_LEN;

    /* ...and ended by a new-line. */
    if (*p != '\n') {
        return false;
    }

    return true;
}

static struct ovsdb_error *
parse_body(struct ovsdb_log *file, off_t offset, unsigned long int length,
           uint8_t sha1[SHA1_DIGEST_SIZE], struct json **jsonp)
{
    struct json_parser *parser;
    struct sha1_ctx ctx;

    sha1_init(&ctx);
    parser = json_parser_create(JSPF_TRAILER);

    while (length > 0) {
        char input[BUFSIZ];
        int chunk;

        chunk = MIN(length, sizeof input);
        if (fread(input, 1, chunk, file->stream) != chunk) {
            json_parser_abort(parser);
            return ovsdb_io_error(ferror(file->stream) ? errno : EOF,
                                  "%s: error reading %lu bytes "
                                  "starting at offset %lld",
                                  file->display_name, length,
                                  (long long int) offset);
        }
        sha1_update(&ctx, input, chunk);
        json_parser_feed(parser, input, chunk);
        length -= chunk;
    }

    sha1_final(&ctx, sha1);
    *jsonp = json_parser_finish(parser);
    return NULL;
}

/* Attempts to read a log record from 'file'.
 *
 * If successful, returns NULL and stores in '*jsonp' the JSON object that the
 * record contains.  The caller owns the data and must eventually free it (with
 * json_destroy()).
 *
 * If a read error occurs, returns the error and stores NULL in '*jsonp'.
 *
 * If the read reaches end of file, returns NULL and stores NULL in
 * '*jsonp'. */
struct ovsdb_error *
ovsdb_log_read(struct ovsdb_log *file, struct json **jsonp)
{
    *jsonp = NULL;
    switch (file->state) {
    case OVSDB_LOG_READ:
        break;

    case OVSDB_LOG_READ_ERROR:
    case OVSDB_LOG_WRITE_ERROR:
    case OVSDB_LOG_BROKEN:
        return ovsdb_error_clone(file->error);

    case OVSDB_LOG_WRITE:
        return NULL;
    }

    uint8_t expected_sha1[SHA1_DIGEST_SIZE];
    uint8_t actual_sha1[SHA1_DIGEST_SIZE];
    struct ovsdb_error *error;
    unsigned long data_length;
    struct json *json;
    char header[128];

    json = NULL;

    if (!fgets(header, sizeof header, file->stream)) {
        if (feof(file->stream)) {
            return NULL;
        }
        error = ovsdb_io_error(errno, "%s: read failed", file->display_name);
        goto error;
    }
    off_t data_offset = file->offset + strlen(header);

    const char *magic;
    if (!parse_header(header, &magic, &data_length, expected_sha1)
        || strcmp(magic, file->magic)) {
        error = ovsdb_syntax_error(NULL, NULL, "%s: parse error at offset "
                                   "%lld in header line \"%.*s\"",
                                   file->display_name,
                                   (long long int) file->offset,
                                   (int) strcspn(header, "\n"), header);
        goto error;
    }

    error = parse_body(file, data_offset, data_length, actual_sha1, &json);
    if (error) {
        goto error;
    }

    if (memcmp(expected_sha1, actual_sha1, SHA1_DIGEST_SIZE)) {
        error = ovsdb_syntax_error(NULL, NULL, "%s: %lu bytes starting at "
                                   "offset %lld have SHA-1 hash "SHA1_FMT" "
                                   "but should have hash "SHA1_FMT,
                                   file->display_name, data_length,
                                   (long long int) data_offset,
                                   SHA1_ARGS(actual_sha1),
                                   SHA1_ARGS(expected_sha1));
        goto error;
    }

    if (json->type == JSON_STRING) {
        error = ovsdb_syntax_error(NULL, NULL, "%s: %lu bytes starting at "
                                   "offset %lld are not valid JSON (%s)",
                                   file->display_name, data_length,
                                   (long long int) data_offset,
                                   json->u.string);
        goto error;
    }
    if (json->type != JSON_OBJECT) {
        error = ovsdb_syntax_error(NULL, NULL, "%s: %lu bytes starting at "
                                   "offset %lld are not a JSON object",
                                   file->display_name, data_length,
                                   (long long int) data_offset);
        goto error;
    }

    file->prev_offset = file->offset;
    file->offset = data_offset + data_length;
    *jsonp = json;
    return NULL;

error:
    file->state = OVSDB_LOG_READ_ERROR;
    file->error = ovsdb_error_clone(error);
    json_destroy(json);
    return error;
}

/* Causes the log record read by the previous call to ovsdb_log_read() to be
 * effectively discarded.  The next call to ovsdb_log_write() will overwrite
 * that previously read record.
 *
 * Calling this function more than once has no additional effect.
 *
 * This function is useful when ovsdb_log_read() successfully reads a record
 * but that record does not make sense at a higher level (e.g. it specifies an
 * invalid transaction). */
void
ovsdb_log_unread(struct ovsdb_log *file)
{
    ovs_assert(file->state == OVSDB_LOG_READ);
    file->offset = file->prev_offset;
}

static struct ovsdb_error *
ovsdb_log_truncate(struct ovsdb_log *file)
{
    file->state = OVSDB_LOG_WRITE;

    struct ovsdb_error *error = NULL;
    if (fseeko(file->stream, file->offset, SEEK_SET)) {
        error = ovsdb_io_error(errno, "%s: cannot seek to offset %lld",
                               file->display_name,
                               (long long int) file->offset);
    } else if (ftruncate(fileno(file->stream), file->offset)) {
        error = ovsdb_io_error(errno, "%s: cannot truncate to length %lld",
                               file->display_name,
                               (long long int) file->offset);
    }
    return error;
}

/* Composes a log record for 'json' by filling 'header' with a header line and
 * 'data' with a data line (each ending with a new-line).  To write the record
 * to a file, write 'header' followed by 'data'.
 *
 * 'magic' is the magic to use in the header record, e.g. OVSDB_MAGIC.
 *
 * The caller must initialize 'header' and 'data' to empty strings. */
void
ovsdb_log_compose_record(const struct json *json,
                         const char *magic, struct ds *header, struct ds *data)
{
    ovs_assert(json->type == JSON_OBJECT || json->type == JSON_ARRAY);
    ovs_assert(!header->length);
    ovs_assert(!data->length);

    /* Compose content. */
    json_to_ds(json, 0, data);
    ds_put_char(data, '\n');

    /* Compose header. */
    uint8_t sha1[SHA1_DIGEST_SIZE];
    sha1_bytes(data->string, data->length, sha1);
    ds_put_format(header, "OVSDB %s %"PRIuSIZE" "SHA1_FMT"\n",
                  magic, data->length, SHA1_ARGS(sha1));
}

/* Writes log record 'json' to 'file'.  Returns NULL if successful or an error
 * (which the caller must eventually destroy) on failure.
 *
 * If the log contains some records that have not yet been read, then calling
 * this function truncates them.
 *
 * Log writes are atomic.  A client may use ovsdb_log_commit() to ensure that
 * they are durable.
 */
struct ovsdb_error *
ovsdb_log_write(struct ovsdb_log *file, const struct json *json)
{
    switch (file->state) {
    case OVSDB_LOG_WRITE:
        break;

    case OVSDB_LOG_READ:
    case OVSDB_LOG_READ_ERROR:
    case OVSDB_LOG_WRITE_ERROR:
        ovsdb_error_destroy(file->error);
        file->error = ovsdb_log_truncate(file);
        if (file->error) {
            file->state = OVSDB_LOG_WRITE_ERROR;
            return ovsdb_error_clone(file->error);
        }
        file->state = OVSDB_LOG_WRITE;
        break;

    case OVSDB_LOG_BROKEN:
        return ovsdb_error_clone(file->error);
    }

    if (json->type != JSON_OBJECT && json->type != JSON_ARRAY) {
        return OVSDB_BUG("bad JSON type");
    }

    struct ds header = DS_EMPTY_INITIALIZER;
    struct ds data = DS_EMPTY_INITIALIZER;
    ovsdb_log_compose_record(json, file->magic, &header, &data);
    size_t total_length = header.length + data.length;

    /* Write. */
    bool ok = (fwrite(header.string, header.length, 1, file->stream) == 1
               && fwrite(data.string, data.length, 1, file->stream) == 1
               && fflush(file->stream) == 0);
    ds_destroy(&header);
    ds_destroy(&data);
    if (!ok) {
        int error = errno;

        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);
        VLOG_WARN_RL(&rl, "%s: write failed (%s)",
                     file->name, ovs_strerror(error));

        /* Remove any partially written data, ignoring errors since there is
         * nothing further we can do. */
        ignore(ftruncate(fileno(file->stream), file->offset));

        file->error = ovsdb_io_error(error, "%s: write failed",
                                     file->display_name);
        file->state = OVSDB_LOG_WRITE_ERROR;
        return ovsdb_error_clone(file->error);
    }

    file->offset += total_length;
    return NULL;
}

struct ovsdb_error *
ovsdb_log_commit(struct ovsdb_log *file)
{
    if (file->stream && fsync(fileno(file->stream))) {
        return ovsdb_io_error(errno, "%s: fsync failed", file->display_name);
    }
    return NULL;
}

/* Sets the current position in 'log' as the "base", that is, the initial size
 * of the log that ovsdb_log_grew_lots() uses to determine whether the log has
 * grown enough to make compacting worthwhile. */
void
ovsdb_log_mark_base(struct ovsdb_log *log)
{
    log->base = log->offset;
}

/* Returns true if 'log' has grown enough above the base that it's worthwhile
 * to compact it, false otherwise. */
bool
ovsdb_log_grew_lots(const struct ovsdb_log *log)
{
    return log->offset > 10 * 1024 * 1024 && log->offset / 2 > log->base;
}

/* Attempts to atomically replace the contents of 'log', on disk, by the 'n'
 * entries in 'entries'.  If successful, returns NULL, otherwise returns an
 * error (which the caller must eventually free).
 *
 * If successful, 'log' will be in write mode at the end of the log. */
struct ovsdb_error * OVS_WARN_UNUSED_RESULT
ovsdb_log_replace(struct ovsdb_log *log, struct json **entries, size_t n)
{
    struct ovsdb_error *error;
    struct ovsdb_log *new;

    error = ovsdb_log_replace_start(log, &new);
    if (error) {
        return error;
    }

    for (size_t i = 0; i < n; i++) {
        error = ovsdb_log_write(new, entries[i]);
        if (error) {
            ovsdb_log_replace_abort(new);
            return error;
        }
    }
    ovsdb_log_mark_base(new);

    return ovsdb_log_replace_commit(log, new);
}

struct ovsdb_error * OVS_WARN_UNUSED_RESULT
ovsdb_log_replace_start(struct ovsdb_log *old,
                        struct ovsdb_log **newp)
{
    /* If old->name is a symlink, then we want the new file to be in the same
     * directory as the symlink's referent. */
    char *deref_name = follow_symlinks(old->name);
    char *tmp_name = xasprintf("%s.tmp", deref_name);
    free(deref_name);

    struct ovsdb_error *error;

    ovs_assert(old->lockfile);

    /* Remove temporary file.  (It might not exist.) */
    if (unlink(tmp_name) < 0 && errno != ENOENT) {
        error = ovsdb_io_error(errno, "failed to remove %s", tmp_name);
        free(tmp_name);
        *newp = NULL;
        return error;
    }

    /* Create temporary file. */
    error = ovsdb_log_open(tmp_name, old->magic, OVSDB_LOG_CREATE_EXCL,
                           false, newp);
    free(tmp_name);
    return error;
}

/* Rename 'old' to 'new', replacing 'new' if it exists.  Returns NULL if
 * successful, otherwise an ovsdb_error that the caller must destroy. */
static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
ovsdb_rename(const char *old, const char *new)
{
#ifdef _WIN32
    /* Avoid rename() because it fails if the destination exists. */
    int error = (MoveFileEx(old, new, MOVEFILE_REPLACE_EXISTING
                            | MOVEFILE_WRITE_THROUGH | MOVEFILE_COPY_ALLOWED)
                 ? 0 : EACCES);
#else
    int error = rename(old, new) ? errno : 0;
#endif

    return (error
            ? ovsdb_io_error(error, "failed to rename \"%s\" to \"%s\"",
                             old, new)
            : NULL);
}

struct ovsdb_error * OVS_WARN_UNUSED_RESULT
ovsdb_log_replace_commit(struct ovsdb_log *old, struct ovsdb_log *new)
{
    struct ovsdb_error *error = ovsdb_log_commit(new);
    if (error) {
        ovsdb_log_replace_abort(new);
        return error;
    }

    /* Replace original file by the temporary file.
     *
     * We support two strategies:
     *
     *     - The preferred strategy is to rename the temporary file over the
     *       original one in-place, then close the original one.  This works on
     *       Unix-like systems.  It does not work on Windows, which does not
     *       allow open files to be renamed.  The approach has the advantage
     *       that, at any point, we can drop back to something that already
     *       works.
     *
     *     - Alternatively, we can close both files, rename, then open the new
     *       file (which now has the original name).  This works on all
     *       systems, but if reopening the file fails then 'old' is broken.
     *
     * We make the strategy a variable instead of an #ifdef to make it easier
     * to test both strategies on Unix-like systems, and to make the code
     * easier to read. */
    if (!rename_open_files) {
        fclose(old->stream);
        old->stream = NULL;

        fclose(new->stream);
        new->stream = NULL;
    }

    /* Rename 'old' to 'new'.  We dereference the old name because, if it is a
     * symlink, we want to replace the referent of the symlink instead of the
     * symlink itself. */
    char *deref_name = follow_symlinks(old->name);
    error = ovsdb_rename(new->name, deref_name);
    free(deref_name);

    if (error) {
        ovsdb_log_replace_abort(new);
        return error;
    }
    if (rename_open_files) {
        fsync_parent_dir(old->name);
        fclose(old->stream);
        old->stream = new->stream;
        new->stream = NULL;
    } else {
        old->stream = fopen(old->name, "r+b");
        if (!old->stream) {
            old->error = ovsdb_io_error(errno, "%s: could not reopen log",
                                        old->name);
            old->state = OVSDB_LOG_BROKEN;
            return ovsdb_error_clone(old->error);
        }

        if (fseek(old->stream, new->offset, SEEK_SET)) {
            old->error = ovsdb_io_error(errno, "%s: seek failed", old->name);
            old->state = OVSDB_LOG_BROKEN;
            return ovsdb_error_clone(old->error);
        }
    }

    /* Replace 'old' by 'new' in memory.
     *
     * 'old' transitions to OVSDB_LOG_WRITE (it was probably in that mode
     * anyway). */
    old->state = OVSDB_LOG_WRITE;
    ovsdb_error_destroy(old->error);
    old->error = NULL;
    /* prev_offset only matters for OVSDB_LOG_READ. */
    old->offset = new->offset;
    /* Keep old->name. */
    free(old->magic);
    old->magic = new->magic;
    new->magic = NULL;
    /* Keep old->lockfile. */
    old->base = new->base;

    /* Free 'new'. */
    ovsdb_log_close(new);

    return NULL;
}

void
ovsdb_log_replace_abort(struct ovsdb_log *new)
{
    if (new) {
        /* Unlink the new file, but only after we close it (because Windows
         * does not allow removing an open file). */
        char *name = xstrdup(new->name);
        ovsdb_log_close(new);
        unlink(name);
        free(name);
    }
}

void
ovsdb_log_disable_renaming_open_files(void)
{
    rename_open_files = false;
}
