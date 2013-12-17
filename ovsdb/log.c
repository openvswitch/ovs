/* Copyright (c) 2009, 2010, 2011, 2012, 2013 Nicira, Inc.
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

#include "json.h"
#include "lockfile.h"
#include "ovsdb.h"
#include "ovsdb-error.h"
#include "sha1.h"
#include "socket-util.h"
#include "transaction.h"
#include "util.h"

enum ovsdb_log_mode {
    OVSDB_LOG_READ,
    OVSDB_LOG_WRITE
};

struct ovsdb_log {
    off_t prev_offset;
    off_t offset;
    char *name;
    struct lockfile *lockfile;
    FILE *stream;
    struct ovsdb_error *read_error;
    bool write_error;
    enum ovsdb_log_mode mode;
};

/* Attempts to open 'name' with the specified 'open_mode'.  On success, stores
 * the new log into '*filep' and returns NULL; otherwise returns NULL and
 * stores NULL into '*filep'.
 *
 * Whether the file will be locked using lockfile_lock() depends on 'locking':
 * use true to lock it, false not to lock it, or -1 to lock it only if
 * 'open_mode' is a mode that allows writing.
 */
struct ovsdb_error *
ovsdb_log_open(const char *name, enum ovsdb_log_open_mode open_mode,
               int locking, struct ovsdb_log **filep)
{
    struct lockfile *lockfile;
    struct ovsdb_error *error;
    struct ovsdb_log *file;
    struct stat s;
    FILE *stream;
    int flags;
    int fd;

    *filep = NULL;

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

    if (open_mode == OVSDB_LOG_READ_ONLY) {
        flags = O_RDONLY;
    } else if (open_mode == OVSDB_LOG_READ_WRITE) {
        flags = O_RDWR;
    } else if (open_mode == OVSDB_LOG_CREATE) {
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
    } else {
        OVS_NOT_REACHED();
    }
    fd = open(name, flags, 0666);
    if (fd < 0) {
        const char *op = open_mode == OVSDB_LOG_CREATE ? "create" : "open";
        error = ovsdb_io_error(errno, "%s: %s failed", op, name);
        goto error_unlock;
    }

    if (!fstat(fd, &s) && s.st_size == 0) {
        /* It's (probably) a new file so fsync() its parent directory to ensure
         * that its directory entry is committed to disk. */
        fsync_parent_dir(name);
    }

    stream = fdopen(fd, open_mode == OVSDB_LOG_READ_ONLY ? "rb" : "w+b");
    if (!stream) {
        error = ovsdb_io_error(errno, "%s: fdopen failed", name);
        goto error_close;
    }

    file = xmalloc(sizeof *file);
    file->name = xstrdup(name);
    file->lockfile = lockfile;
    file->stream = stream;
    file->prev_offset = 0;
    file->offset = 0;
    file->read_error = NULL;
    file->write_error = false;
    file->mode = OVSDB_LOG_READ;
    *filep = file;
    return NULL;

error_close:
    close(fd);
error_unlock:
    lockfile_unlock(lockfile);
error:
    return error;
}

void
ovsdb_log_close(struct ovsdb_log *file)
{
    if (file) {
        free(file->name);
        fclose(file->stream);
        lockfile_unlock(file->lockfile);
        ovsdb_error_destroy(file->read_error);
        free(file);
    }
}

static const char magic[] = "OVSDB JSON ";

static bool
parse_header(char *header, unsigned long int *length,
             uint8_t sha1[SHA1_DIGEST_SIZE])
{
    char *p;

    /* 'header' must consist of a magic string... */
    if (strncmp(header, magic, strlen(magic))) {
        return false;
    }

    /* ...followed by a length in bytes... */
    *length = strtoul(header + strlen(magic), &p, 10);
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

struct ovsdb_log_read_cbdata {
    char input[4096];
    struct ovsdb_log *file;
    int error;
    unsigned long length;
};

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
                                  "starting at offset %lld", file->name,
                                  length, (long long int) offset);
        }
        sha1_update(&ctx, input, chunk);
        json_parser_feed(parser, input, chunk);
        length -= chunk;
    }

    sha1_final(&ctx, sha1);
    *jsonp = json_parser_finish(parser);
    return NULL;
}

struct ovsdb_error *
ovsdb_log_read(struct ovsdb_log *file, struct json **jsonp)
{
    uint8_t expected_sha1[SHA1_DIGEST_SIZE];
    uint8_t actual_sha1[SHA1_DIGEST_SIZE];
    struct ovsdb_error *error;
    off_t data_offset;
    unsigned long data_length;
    struct json *json;
    char header[128];

    *jsonp = json = NULL;

    if (file->read_error) {
        return ovsdb_error_clone(file->read_error);
    } else if (file->mode == OVSDB_LOG_WRITE) {
        return OVSDB_BUG("reading file in write mode");
    }

    if (!fgets(header, sizeof header, file->stream)) {
        if (feof(file->stream)) {
            error = NULL;
        } else {
            error = ovsdb_io_error(errno, "%s: read failed", file->name);
        }
        goto error;
    }

    if (!parse_header(header, &data_length, expected_sha1)) {
        error = ovsdb_syntax_error(NULL, NULL, "%s: parse error at offset "
                                   "%lld in header line \"%.*s\"",
                                   file->name, (long long int) file->offset,
                                   (int) strcspn(header, "\n"), header);
        goto error;
    }

    data_offset = file->offset + strlen(header);
    error = parse_body(file, data_offset, data_length, actual_sha1, &json);
    if (error) {
        goto error;
    }

    if (memcmp(expected_sha1, actual_sha1, SHA1_DIGEST_SIZE)) {
        error = ovsdb_syntax_error(NULL, NULL, "%s: %lu bytes starting at "
                                   "offset %lld have SHA-1 hash "SHA1_FMT" "
                                   "but should have hash "SHA1_FMT,
                                   file->name, data_length,
                                   (long long int) data_offset,
                                   SHA1_ARGS(actual_sha1),
                                   SHA1_ARGS(expected_sha1));
        goto error;
    }

    if (json->type == JSON_STRING) {
        error = ovsdb_syntax_error(NULL, NULL, "%s: %lu bytes starting at "
                                   "offset %lld are not valid JSON (%s)",
                                   file->name, data_length,
                                   (long long int) data_offset,
                                   json->u.string);
        goto error;
    }

    file->prev_offset = file->offset;
    file->offset = data_offset + data_length;
    *jsonp = json;
    return NULL;

error:
    file->read_error = ovsdb_error_clone(error);
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
    ovs_assert(file->mode == OVSDB_LOG_READ);
    file->offset = file->prev_offset;
}

struct ovsdb_error *
ovsdb_log_write(struct ovsdb_log *file, struct json *json)
{
    uint8_t sha1[SHA1_DIGEST_SIZE];
    struct ovsdb_error *error;
    char *json_string;
    char header[128];
    size_t length;

    json_string = NULL;

    if (file->mode == OVSDB_LOG_READ || file->write_error) {
        file->mode = OVSDB_LOG_WRITE;
        file->write_error = false;
        if (fseeko(file->stream, file->offset, SEEK_SET)) {
            error = ovsdb_io_error(errno, "%s: cannot seek to offset %lld",
                                   file->name, (long long int) file->offset);
            goto error;
        }
        if (ftruncate(fileno(file->stream), file->offset)) {
            error = ovsdb_io_error(errno, "%s: cannot truncate to length %lld",
                                   file->name, (long long int) file->offset);
            goto error;
        }
    }

    if (json->type != JSON_OBJECT && json->type != JSON_ARRAY) {
        error = OVSDB_BUG("bad JSON type");
        goto error;
    }

    /* Compose content.  Add a new-line (replacing the null terminator) to make
     * the file easier to read, even though it has no semantic value.  */
    json_string = json_to_string(json, 0);
    length = strlen(json_string) + 1;
    json_string[length - 1] = '\n';

    /* Compose header. */
    sha1_bytes(json_string, length, sha1);
    snprintf(header, sizeof header, "%s%"PRIuSIZE" "SHA1_FMT"\n",
             magic, length, SHA1_ARGS(sha1));

    /* Write. */
    if (fwrite(header, strlen(header), 1, file->stream) != 1
        || fwrite(json_string, length, 1, file->stream) != 1
        || fflush(file->stream))
    {
        error = ovsdb_io_error(errno, "%s: write failed", file->name);

        /* Remove any partially written data, ignoring errors since there is
         * nothing further we can do. */
        ignore(ftruncate(fileno(file->stream), file->offset));

        goto error;
    }

    file->offset += strlen(header) + length;
    free(json_string);
    return NULL;

error:
    file->write_error = true;
    free(json_string);
    return error;
}

struct ovsdb_error *
ovsdb_log_commit(struct ovsdb_log *file)
{
    if (fsync(fileno(file->stream))) {
        return ovsdb_io_error(errno, "%s: fsync failed", file->name);
    }
    return NULL;
}

/* Returns the current offset into the file backing 'log', in bytes.  This
 * reflects the number of bytes that have been read or written in the file.  If
 * the whole file has been read, this is the file size. */
off_t
ovsdb_log_get_offset(const struct ovsdb_log *log)
{
    return log->offset;
}
