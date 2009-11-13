/* Copyright (c) 2008, 2009 Nicira Networks
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
#include "cfg.h"
#include <arpa/inet.h>
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "coverage.h"
#include "dynamic-string.h"
#include "ofpbuf.h"
#include "packets.h"
#include "svec.h"
#include "timeval.h"
#include "util.h"

#define THIS_MODULE VLM_cfg
#include "vlog.h"

/* XXX This file really needs a unit test!  For a while, cfg_get_string(0,
 * "bridge.a.controller") would return the value of
 * "bridge.a.controller.in-band", if it existed, and I'm really not certain
 * that the fix didn't break other things. */

/* Configuration file name. */
static char *cfg_name;

/* Put the temporary file in the same directory as cfg_name, so that
 * they are guaranteed to be in the same file system and therefore we can
 * rename() tmp_name over cfg_name. */
static char *tmp_name;

/* Lock information. */
static char *lock_name;
static int lock_fd = -1;

/* Flag to indicate whether local modifications have been made. */
static bool dirty;

static uint8_t cfg_cookie[CFG_COOKIE_LEN];

/* Current configuration.  Maintained in sorted order. */
static struct svec cfg = SVEC_EMPTY_INITIALIZER;

static bool has_double_dot(const char *key, size_t len);
static bool is_valid_key(const char *key, size_t len,
                         const char *file_name, int line_number,
                         const char *id);
static char *parse_section(const char *file_name, int line_number,
                           const char *);
static void parse_setting(const char *file_name, int line_number,
                          const char *section, const char *);
static int compare_key(const char *a, const char *b);
static char **find_key_le(const char *key);
static char **find_key_ge(const char *key);
static char *find_key(const char *);
static bool parse_mac(const char *, uint8_t mac[6]);
static bool parse_dpid(const char *, uint64_t *);
static bool is_key(const char *);
static bool is_int(const char *);
static bool is_bool(const char *);
static const char *extract_value(const char *key);
static const char *get_nth_value(int idx, const char *key);
static bool is_type(const char *s, enum cfg_flags);

#define CC_ALPHA "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define CC_DIGIT "0123456789"
#define CC_ALNUM CC_ALPHA CC_DIGIT
#define CC_SPACE " \t\r\n\v"

#define CC_FILE_NAME CC_ALNUM "._-"
#define CC_KEY CC_ALNUM "._-@$:+"

void
cfg_init(void)
{
    svec_terminate(&cfg);
}

/* Sets 'file_name' as the configuration file read by cfg_read().  Returns 0 on
 * success, otherwise a positive errno value if 'file_name' cannot be opened.
 *
 * This function does not actually read the named file or directory.  Use
 * cfg_read() to (re)read all the configuration files. */
int
cfg_set_file(const char *file_name)
{
    const char *slash;
    int fd;

    if (cfg_name) {
        assert(lock_fd < 0);
        free(cfg_name);
        free(lock_name);
        free(tmp_name);
        cfg_name = lock_name = tmp_name = NULL;
    }

    /* Make sure that we can open this file for reading. */
    fd = open(file_name, O_RDONLY);
    if (fd < 0) {
        return errno;
    }
    close(fd);

    cfg_name = xstrdup(file_name);

    /* Put the temporary file in the same directory as cfg_name, so that they
     * are guaranteed to be in the same file system, to guarantee that
     * rename(tmp_name, cfg_name) will work. */
    tmp_name = xasprintf("%s.~tmp~", file_name);

    /* Put the lock file in the same directory as cfg_name, but prefixed by
     * a dot so as not to garner administrator interest. */
    slash = strrchr(file_name, '/');
    if (slash) {
        lock_name = xasprintf("%.*s/.%s.~lock~",
                              (int) (slash - file_name), file_name, slash + 1);
    } else {
        lock_name = xasprintf(".%s.~lock~", file_name);
    }

    VLOG_INFO("using \"%s\" as configuration file, \"%s\" as lock file",
              file_name, lock_name);
    return 0;
}

static int
update_cookie(void)
{
    struct sha1_ctx context;
    int i;

    sha1_init(&context);
    for (i = 0; i < cfg.n; i++) {
        sha1_update(&context, cfg.names[i], strlen(cfg.names[i]));
        sha1_update(&context, "\n", 1);
    }
    sha1_final(&context, cfg_cookie);

    return 0;
}

/* Reads all of the configuration files or directories that have been added
 * with cfg_add_file(), merges their content.  Any previous configuration is
 * replaced.  Returns 0 if successful, otherwise a positive errno value. */
int
cfg_read(void)
{
    struct svec old_cfg;
    struct ds ds;
    FILE *file;
    char *section;
    int line_number;


    if (!cfg_name) {
        return ENODEV;
    }

    /* Save old configuration data and clear the active configuration. */
    svec_init(&old_cfg);
    svec_swap(&old_cfg, &cfg);

    /* Read new configuration. */
    VLOG_DBG("reading configuration from %s", cfg_name);

    file = fopen(cfg_name, "r");
    if (!file) {
        VLOG_ERR("failed to open \"%s\": %s", cfg_name, strerror(errno));
        svec_terminate(&cfg);
        return errno;
    }

    ds_init(&ds);
    section = NULL;
    line_number = 0;
    while (!ds_get_line(&ds, file)) {
        const char *s = ds_cstr(&ds);
        size_t indent = strspn(s, CC_SPACE);

        line_number++;
        s += indent;
        if (*s == '#' || *s == '\0') {
            /* Ignore comments and lines that contain only white space. */
        } else if (*s == '[') {
            if (!indent) {
                free(section);
                section = parse_section(cfg_name, line_number, s);
            } else {
                VLOG_ERR("%s:%d: ignoring indented section header",
                         cfg_name, line_number);
            }
        } else if (indent && !section) {
            VLOG_ERR("%s:%d: ignoring indented line outside any section",
                     cfg_name, line_number);
        } else {
            if (!indent) {
                free(section);
                section = NULL;
            }
            parse_setting(cfg_name, line_number, section, s);
        }
    }
    ds_destroy(&ds);
    free(section);

    svec_sort(&cfg);
    svec_terminate(&cfg);
    update_cookie();

    fclose(file);

    if (VLOG_IS_DBG_ENABLED()) {
        struct svec removed, added;
        size_t i;

        svec_diff(&old_cfg, &cfg, &removed, NULL, &added);
        if (removed.n || added.n) {
            VLOG_DBG("configuration changes:");
            for (i = 0; i < removed.n; i++) {
                VLOG_DBG("-%s", removed.names[i]);
            }
            for (i = 0; i < added.n; i++) {
                VLOG_DBG("+%s", added.names[i]);
            }
        } else {
            VLOG_DBG("configuration unchanged");
        }
        svec_destroy(&added);
        svec_destroy(&removed);
    }
    svec_destroy(&old_cfg);

    dirty = false;

    return 0;
}

/* Fills 'svec' with the entire configuration file. */
void
cfg_get_all(struct svec *svec)
{
    svec_clear(svec);
    svec_append(svec, &cfg);
}

int
cfg_get_cookie(uint8_t *cookie)
{
    if (dirty) {
        update_cookie();
    }

    memcpy(cookie, cfg_cookie, sizeof(cfg_cookie));
    return 0;
}

void
cfg_unlock(void)
{
    if (lock_fd != -1) {
        COVERAGE_INC(cfg_unlock);
        close(lock_fd);
        lock_fd = -1;
    }
}

static int
open_lockfile(const char *name)
{
    for (;;) {
        /* Try to open an existing lock file. */
        int fd = open(name, O_RDWR);
        if (fd >= 0) {
            return fd;
        } else if (errno != ENOENT) {
            VLOG_WARN("%s: failed to open lock file: %s",
                      name, strerror(errno));
            return -errno;
        }

        /* Try to create a new lock file. */
        VLOG_INFO("%s: lock file does not exist, creating", name);
        fd = open(name, O_RDWR | O_CREAT | O_EXCL, 0600);
        if (fd >= 0) {
            return fd;
        } else if (errno != EEXIST) {
            VLOG_WARN("%s: failed to create lock file: %s",
                      name, strerror(errno));
            return -errno;
        }

        /* Someone else created the lock file.  Try again. */
    }
}

static int
try_lock(int fd, bool block)
{
    struct flock l;
    memset(&l, 0, sizeof l);
    l.l_type = F_WRLCK;
    l.l_whence = SEEK_SET;
    l.l_start = 0;
    l.l_len = 0;
    return fcntl(fd, block ? F_SETLKW : F_SETLK, &l) == -1 ? errno : 0;
}

/* Locks the configuration file against modification by other processes and
 * re-reads it from disk.
 *
 * The 'timeout' specifies the maximum number of milliseconds to wait for the
 * config file to become free.  Use 0 to avoid waiting or INT_MAX to wait
 * forever.
 *
 * Returns 0 on success, otherwise a positive errno value. */
int
cfg_lock(uint8_t *cookie, int timeout)
{
    long long int start;
    long long int elapsed = 0;
    int fd;
    uint8_t curr_cookie[CFG_COOKIE_LEN];

    assert(lock_fd < 0);
    COVERAGE_INC(cfg_lock);

    time_refresh();
    start = time_msec();
    for (;;) {
        int error;

        /* Open lock file. */
        fd = open_lockfile(lock_name);
        if (fd < 0) {
            return -fd;
        }

        /* Try to lock it.  This will block (if 'timeout' > 0). */
        error = try_lock(fd, timeout > 0);
        time_refresh();
        elapsed = time_msec() - start;
        if (!error) {
            /* Success! */
            break;
        }

        /* Lock failed.  Close the lock file and reopen it on the next
         * iteration, just in case someone deletes it underneath us (even
         * though that should not happen). */
        close(fd);
        if (error != EINTR) {
            /* Hard error, give up. */
            COVERAGE_INC(cfg_lock_error);
            VLOG_WARN("%s: failed to lock file "
                      "(after %lld ms, with %d-ms timeout): %s",
                      lock_name, elapsed, timeout, strerror(error));
            return error;
        }

        /* Probably, the periodic timer set up by time_init() woke up us.  Just
         * check whether it's time to give up. */
        if (timeout != INT_MAX && elapsed >= timeout) {
            COVERAGE_INC(cfg_lock_timeout);
            VLOG_WARN("%s: giving up on lock file after %lld ms",
                      lock_name, elapsed);
            return ETIMEDOUT;
        }
        COVERAGE_INC(cfg_lock_retry);
    }
    if (elapsed) {
        VLOG_WARN("%s: waited %lld ms for lock file", lock_name, elapsed);
    }
    lock_fd = fd;

    cfg_read();

    if (cookie) {
        cfg_get_cookie(curr_cookie);

        if (memcmp(curr_cookie, cookie, sizeof *curr_cookie)) {
            /* Configuration has changed, so reject. */
            cfg_unlock();
            return EINVAL;
        }
    }

    return 0;
}

static int
do_write_config(const void *data, size_t len)
{
    FILE *file;
    int error;

    file = fopen(tmp_name, "w");
    if (file == NULL) {
        VLOG_WARN("could not open %s for writing: %s",
                  tmp_name, strerror(errno));
        return errno;
    }

    fwrite(data, 1, len, file);

    /* This is essentially equivalent to:
     *       error = ferror(file) || fflush(file) || fclose(file);
     * but it doesn't short-circuit, so that it always closes 'file'. */
    error = ferror(file);
    error = fflush(file) || error;
    error = fclose(file) || error;
    if (error) {
        VLOG_WARN("problem writing to %s: %s", tmp_name, strerror(errno));
        return errno;
    }

    if (rename(tmp_name, cfg_name) < 0) {
        VLOG_WARN("could not rename %s to %s: %s",
                  tmp_name, cfg_name, strerror(errno));
        return errno;
    }

    dirty = false;

    return 0;
}

/* Write the current configuration into the configuration file.  Returns 0 if
 * successful, otherwise a negative errno value. */
int
cfg_write(void)
{
    char *content;
    int retval;

    svec_sort(&cfg);
    content = (cfg.n
               ? svec_join(&cfg, "\n", "\n")
               : xstrdup("# This file intentionally left blank.\n"));
    retval = do_write_config(content, strlen(content));
    free(content);

    return retval;
}

int
cfg_write_data(uint8_t *data, size_t len)
{
    int retval = do_write_config(data, len);
    if (!retval) {
        cfg_read();
    }
    return retval;
}

/* Returns true if the configuration has changed since the last time it was
 * read or written. */
bool
cfg_is_dirty(void)
{
    return dirty;
}

void
cfg_buf_put(struct ofpbuf *buffer)
{
    int i;

    for (i = 0; i < cfg.n; i++) {
        ofpbuf_put(buffer, cfg.names[i], strlen(cfg.names[i]));
        ofpbuf_put(buffer, "\n", 1);
    }
}

/* Formats the printf()-style format string in the parameter 'format', which
 * must be the function's last parameter, into string variable 'dst'.  The
 * function is responsible for freeing 'dst'. */
#define FORMAT_KEY(FORMAT, DST)                 \
    do {                                        \
      va_list args__;                           \
      va_start(args__, FORMAT);                 \
      (DST) = xvasprintf(FORMAT, args__);       \
      va_end(args__);                           \
    } while (0)

/* Returns true if the configuration includes a key named 'key'. */
bool
cfg_has(const char *key_, ...)
{
    char *key;
    bool retval;

    FORMAT_KEY(key_, key);
    retval = find_key(key) != NULL;
    free(key);
    return retval;
}

bool
cfg_is_valid(enum cfg_flags flags, const char *key_, ...)
{
    char *key, **first, **last, **p;
    size_t n;
    bool retval;

    FORMAT_KEY(key_, key);
    first = find_key_le(key);
    last = find_key_ge(key);
    n = last - first;
    retval = ((!(flags & CFG_REQUIRED) || n)
              && (!(flags & CFG_MULTIPLE) || n <= 1));
    for (p = first; retval && p < last; p++) {
        retval = is_type(strchr(*p, '=') + 1, flags);
    }
    free(key);
    return retval;
}

/* Returns true if the configuration includes at least one key whose name
 * begins with 'section' followed by a dot. */
bool
cfg_has_section(const char *section_, ...)
{
    struct ds section;
    bool retval = false;
    va_list args;
    char **p;

    ds_init(&section);
    va_start(args, section_);
    ds_put_format_valist(&section, section_, args);
    ds_put_char(&section, '.');
    va_end(args);

    for (p = cfg.names; *p; p++) { /* XXX this is inefficient */
        if (!strncmp(section.string, *p, section.length)) {
            retval = true;
            break;
        }
    }

    ds_destroy(&section);
    return retval;
}

/* Returns the number of values for the given 'key'.  The return value is 0 if
 * no values exist for 'key'. */
int
cfg_count(const char *key_, ...)
{
    char *key;
    int retval;

    FORMAT_KEY(key_, key);
    retval = find_key_ge(key) - find_key_le(key);
    free(key);
    return retval;
}

/* Fills 'svec' with all of the immediate subsections of 'section'.  For
 * example, if 'section' is "bridge" and keys bridge.a, bridge.b, bridge.b.c,
 * and bridge.c.x.y.z exist, then 'svec' would be initialized to a, b, and
 * c.  The caller must first initialize 'svec'. */
void
cfg_get_subsections(struct svec *svec, const char *section_, ...)
{
    struct ds section;
    va_list args;
    char **p;

    ds_init(&section);
    va_start(args, section_);
    ds_put_format_valist(&section, section_, args);
    ds_put_char(&section, '.');
    va_end(args);

    svec_clear(svec);
    for (p = cfg.names; *p; p++) { /* XXX this is inefficient */
        if (!strncmp(section.string, *p, section.length)) {
            const char *ss = *p + section.length;
            size_t ss_len = strcspn(ss, ".=");
            svec_add_nocopy(svec, xmemdup0(ss, ss_len));
        }
    }
    svec_unique(svec);
    ds_destroy(&section);
}

void
cfg_add_entry(const char *entry_, ...)
{
    char *entry;

    FORMAT_KEY(entry_, entry);
    svec_add_nocopy(&cfg, entry);
    svec_sort(&cfg);
    svec_terminate(&cfg);
    dirty = true;
}

void
cfg_del_entry(const char *entry_, ...)
{
    char *entry;

    FORMAT_KEY(entry_, entry);
    svec_del(&cfg, entry);
    svec_terminate(&cfg);
    free(entry);
    dirty = true;
}

void
cfg_del_section(const char *section_, ...)
{
    struct ds section;
    va_list args;
    char **p;

    ds_init(&section);
    va_start(args, section_);
    ds_put_format_valist(&section, section_, args);
    ds_put_char(&section, '.');
    va_end(args);

    for (p = cfg.names; *p; p++) {
        if (!strncmp(section.string, *p, section.length)) {
            free(*p);
            *p = NULL;
        }
    }
    svec_compact(&cfg);
    svec_terminate(&cfg);

    ds_destroy(&section);
    dirty = true;
}

void
cfg_del_match(const char *pattern_, ...)
{
    bool matched = false;
    char *pattern;
    char **p;

    FORMAT_KEY(pattern_, pattern);

    for (p = cfg.names; *p; p++) {
        if (!fnmatch(pattern, *p, 0)) {
            free(*p);
            *p = NULL;
            matched = true;
        }
    }
    if (matched) {
        svec_compact(&cfg);
        svec_terminate(&cfg);
        dirty = true;
    }

    free(pattern);
}

/* Fills 'svec' with all of the key-value pairs that match shell glob pattern
 * 'pattern'.  The caller must first initialize 'svec'. */
void
cfg_get_matches(struct svec *svec, const char *pattern_, ...)
{
    char *pattern;
    char **p;

    FORMAT_KEY(pattern_, pattern);

    for (p = cfg.names; *p; p++) {
        if (!fnmatch(pattern, *p, 0)) {
            svec_add(svec, *p);
        }
    }

    free(pattern);
}

/* Fills 'svec' with all of the key-value pairs that have sections that
 * begin with 'section'.  The caller must first initialize 'svec'. */
void
cfg_get_section(struct svec *svec, const char *section_, ...)
{
    struct ds section;
    va_list args;
    char **p;

    ds_init(&section);
    va_start(args, section_);
    ds_put_format_valist(&section, section_, args);
    ds_put_char(&section, '.');
    va_end(args);

    for (p = cfg.names; *p; p++) { /* XXX this is inefficient */
        if (!strncmp(section.string, *p, section.length)) {
            svec_add(svec, *p);
        }
    }
    ds_destroy(&section);
}

/* Returns the value numbered 'idx' of 'key'.  Returns a null pointer if 'idx'
 * is greater than or equal to cfg_count(key).  The caller must not modify or
 * free the returned string or retain its value beyond the next call to
 * cfg_read(). */
const char *
cfg_get_string(int idx, const char *key_, ...)
{
    const char *retval;
    char *key;

    FORMAT_KEY(key_, key);
    retval = get_nth_value(idx, key);
    free(key);
    return retval;
}

/* Returns the value numbered 'idx' of 'key'.  Returns a null pointer if 'idx'
 * is greater than or equal to cfg_count(key) or if the value 'idx' of 'key' is
 * not a valid key.  The caller must not modify or free the returned string or
 * retain its value beyond the next call to cfg_read(). */
const char *
cfg_get_key(int idx, const char *key_, ...)
{
    const char *value, *retval;
    char *key;

    FORMAT_KEY(key_, key);
    value = get_nth_value(idx, key);
    retval = value && is_key(value) ? value : NULL;
    free(key);
    return retval;
}

/* Returns the value numbered 'idx' of 'key', converted to an integer.  Returns
 * 0 if 'idx' is greater than or equal to cfg_count(key) or if the value 'idx'
 * of 'key' is not a valid integer.  */
int
cfg_get_int(int idx, const char *key_, ...)
{
    const char *value;
    int retval;
    char *key;

    FORMAT_KEY(key_, key);
    value = get_nth_value(idx, key);
    retval = value && is_int(value) ? atoi(value) : 0;
    free(key);
    return retval;
}

/* Returns the value numbered 'idx' of 'key', converted to a boolean value.
 * Returns false if 'idx' is greater than or equal to cfg_count(key) or if the
 * value 'idx' of 'key' is not a valid boolean.  */
bool
cfg_get_bool(int idx, const char *key_, ...)
{
    const char *value;
    bool retval;
    char *key;

    FORMAT_KEY(key_, key);
    value = get_nth_value(idx, key);
    retval = value && is_bool(value) ? !strcmp(value, "true") : false;
    free(key);
    return retval;
}

/* Returns the value numbered 'idx' of 'key', converted to an IP address in
 * network byte order.  Returns 0 if 'idx' is greater than or equal to
 * cfg_count(key) or if the value 'idx' of 'key' is not a valid IP address (as
 * determined by inet_aton()).  */
uint32_t
cfg_get_ip(int idx, const char *key_, ...)
{
    struct in_addr addr;
    const char *value;
    char *key;

    FORMAT_KEY(key_, key);
    value = get_nth_value(idx, key);
    if (!value || !inet_aton(value, &addr)) {
        addr.s_addr = htonl(0);
    }
    free(key);
    return addr.s_addr;
}

/* Returns the value numbered 'idx' of 'key', converted to an MAC address in
 * host byte order.  Returns 0 if 'idx' is greater than or equal to
 * cfg_count(key) or if the value 'idx' of 'key' is not a valid MAC address in
 * the format "##:##:##:##:##:##".  */
uint64_t
cfg_get_mac(int idx, const char *key_, ...)
{
    uint8_t mac[ETH_ADDR_LEN];
    const char *value;
    char *key;

    FORMAT_KEY(key_, key);
    value = get_nth_value(idx, key);
    if (!value || !parse_mac(value, mac)) {
        memset(mac, 0, sizeof mac);
    }
    free(key);
    return eth_addr_to_uint64(mac);
}

/* Returns the value numbered 'idx' of 'key', parsed as an datapath ID.
 * Returns 0 if 'idx' is greater than or equal to cfg_count(key) or if the
 * value 'idx' of 'key' is not a valid datapath ID consisting of exactly 16
 * hexadecimal digits.  */
uint64_t
cfg_get_dpid(int idx, const char *key_, ...)
{
    uint64_t dpid;
    const char *value;
    char *key;

    FORMAT_KEY(key_, key);
    value = get_nth_value(idx, key);
    if (!value || !parse_dpid(value, &dpid)) {
        dpid = 0;
    }
    free(key);
    return dpid;
}

/* Returns the value numbered 'idx' of 'key', converted to an integer.  Returns
 * -1 if 'idx' is greater than or equal to cfg_count(key) or if the value 'idx'
 * of 'key' is not a valid integer between 0 and 4095.  */
int
cfg_get_vlan(int idx, const char *key_, ...)
{
    const char *value;
    int retval;
    char *key;

    FORMAT_KEY(key_, key);
    value = get_nth_value(idx, key);
    if (value && is_int(value)) {
        retval = atoi(value);
        if (retval < 0 || retval > 4095) {
            retval = -1;
        }
    } else {
        retval = -1;
    }
    free(key);
    return retval;
}

/* Fills 'svec' with all of the string values of 'key'.  The caller must
 * first initialize 'svec'. */
void
cfg_get_all_strings(struct svec *svec, const char *key_, ...)
{
    char **p, **q;
    char *key;

    FORMAT_KEY(key_, key);
    svec_clear(svec);
    for (p = find_key_le(key), q = find_key_ge(key); p < q; p++) {
        svec_add(svec, extract_value(*p));
    }
    free(key);
}

/* Fills 'svec' with all of the values of 'key' that are valid keys.
 * Values of 'key' that are not valid keys are omitted.   The caller 
 * must first initialize 'svec'. */
void
cfg_get_all_keys(struct svec *svec, const char *key_, ...)
{
    char **p, **q;
    char *key;

    FORMAT_KEY(key_, key);
    svec_clear(svec);
    for (p = find_key_le(key), q = find_key_ge(key); p < q; p++) {
        const char *value = extract_value(*p);
        if (is_key(value)) {
            svec_add(svec, value);
        }
    }
    free(key);
}

static bool
has_double_dot(const char *key, size_t len)
{
    if (len >= 2) {
        size_t i;

        for (i = 0; i < len - 1; i++) {
            if (key[i] == '.' && key[i + 1] == '.') {
                return true;
            }
        }
    }
    return false;
}

static bool
is_valid_key(const char *key, size_t len,
                 const char *file_name, int line_number, const char *id)
{
    if (!len) {
        VLOG_ERR("%s:%d: missing %s name", file_name, line_number, id);
        return false;
    } else if (key[0] == '.') {
        VLOG_ERR("%s:%d: %s name \"%.*s\" begins with invalid character '.'",
                 file_name, line_number, id, (int) len, key);
        return false;
    } else if (key[len - 1] == '.') {
        VLOG_ERR("%s:%d: %s name \"%.*s\" ends with invalid character '.'",
                 file_name, line_number, id, (int) len, key);
        return false;
    } else if (has_double_dot(key, len)) {
        VLOG_ERR("%s:%d: %s name \"%.*s\" contains '..', which is not allowed",
                 file_name, line_number, id, (int) len, key);
        return false;
    } else {
        return true;
    }
}

static char *
parse_section(const char *file_name, int line_number, const char *s)
{
    struct ds section;
    size_t len;

    ds_init(&section);

    /* Skip [ and any white space. */
    s++;
    s += strspn(s, CC_SPACE);

    /* Obtain the section name. */
    len = strspn(s, CC_KEY);
    if (!is_valid_key(s, len, file_name, line_number, "section")) {
        goto error;
    }
    ds_put_buffer(&section, s, len);
    s += len;

    /* Obtain the subsection name, if any. */
    s += strspn(s, CC_SPACE);
    if (*s == '"') {
        s++;
        len = strspn(s, CC_KEY);
        if (!is_valid_key(s, len, file_name, line_number, "subsection")) {
            goto error;
        }
        ds_put_char(&section, '.');
        ds_put_buffer(&section, s, len);
        s += len;
        if (*s != '"') {
            VLOG_ERR("%s:%d: missing '\"' following subsection name",
                     file_name, line_number);
            goto error;
        }
        s++;
        s += strspn(s, CC_SPACE);
    }

    /* Check for ]. */
    if (*s != ']') {
        VLOG_ERR("%s:%d: missing ']' following section name",
                 file_name, line_number);
        goto error;
    }
    s++;
    s += strspn(s, CC_SPACE);
    if (*s != '\0') {
        VLOG_ERR("%s:%d: trailing garbage following ']'",
                 file_name, line_number);
        goto error;
    }

    return ds_cstr(&section);

error:
    ds_destroy(&section);
    return NULL;
}

static void
parse_setting(const char *file_name, int line_number, const char *section,
              const char *s)
{
    struct ds key = DS_EMPTY_INITIALIZER;
    struct ds value = DS_EMPTY_INITIALIZER;
    size_t len;

    if (section) {
        ds_put_format(&key, "%s.", section);
    }

    /* Obtain the key. */
    len = strspn(s, CC_KEY);
    if (!len) {
        VLOG_ERR("%s:%d: missing key name", file_name, line_number);
        goto done;
    }
    if (!is_valid_key(s, len, file_name, line_number, "key")) {
        goto done;
    }
    ds_put_buffer(&key, s, len);
    s += len;

    /* Skip the '='. */
    s += strspn(s, CC_SPACE);
    if (*s != '=') {
        VLOG_ERR("%s:%d: missing '=' following key", file_name, line_number);
        goto done;
    }
    s++;
    s += strspn(s, CC_SPACE);

    /* Obtain the value. */
    ds_put_cstr(&value, s);
    while (value.length > 0 && strchr(CC_SPACE, ds_last(&value))) {
        value.length--;
    }

    /* Add the setting. */
    svec_add_nocopy(&cfg, xasprintf("%s=%s", ds_cstr(&key), ds_cstr(&value)));

done:
    ds_destroy(&key);
    ds_destroy(&value);
}

static int
compare_key(const char *a, const char *b)
{
    for (;;) {
        int ac = *a == '\0' || *a == '=' ? INT_MAX : *a;
        int bc = *b == '\0' || *b == '=' ? INT_MAX : *b;
        if (ac != bc) {
            return ac < bc ? -1 : 1;
        } else if (ac == INT_MAX) {
            return 0;
        }
        a++;
        b++;
    }
}

/* Returns the address of the greatest configuration string with a key less
 * than or equal to 'key'.  Returns the address of the null terminator if all
 * configuration strings are greater than 'key'. */
static char **
find_key_le(const char *key)
{
    int low = 0;
    int len = cfg.n;
    while (len > 0) {
        int half = len >> 1;
        int middle = low + half;
        if (compare_key(cfg.names[middle], key) < 0) {
            low = middle + 1;
            len -= half + 1;
        } else {
            len = half;
        }
    }
    return &cfg.names[low];
}

/* Returns the address of the least configuration string with a key greater
 * than or equal to 'key'.  Returns the address of the null terminator if all
 * configuration strings are less than 'key'. */
static char **
find_key_ge(const char *key)
{
    int low = 0;
    int len = cfg.n;
    while (len > 0) {
        int half = len >> 1;
        int middle = low + half;
        if (compare_key(cfg.names[middle], key) > 0) {
            len = half;
        } else {
            low = middle + 1;
            len -= half + 1;
        }
    }
    return &cfg.names[low];
}

static char *
find_key(const char *key)
{
    char **p = find_key_le(key);
    return p < &cfg.names[cfg.n] && !compare_key(*p, key) ? *p : NULL;
}

static bool
parse_mac(const char *s, uint8_t mac[6])
{
    return (sscanf(s, ETH_ADDR_SCAN_FMT, ETH_ADDR_SCAN_ARGS(mac))
            == ETH_ADDR_SCAN_COUNT);
}

static bool
parse_dpid(const char *s, uint64_t *dpid)
{
    if (strlen(s) == 16 && strspn(s, "0123456789abcdefABCDEF") == 16) {
        *dpid = strtoll(s, NULL, 16);
        return true;
    } else {
        return false;
    }
}

static bool
is_key(const char *s)
{
    /* XXX needs to check the same things as is_valid_key() too. */
    return *s && s[strspn(s, CC_KEY)] == '\0';
}

static bool
is_int(const char *s)
{
    return *s && s[strspn(s, CC_DIGIT)] == '\0';
}

static bool
is_bool(const char *s)
{
    return !strcmp(s, "true") || !strcmp(s, "false");
}

static const char *
extract_value(const char *key)
{
    const char *p = strchr(key, '=');
    return p ? p + 1 : NULL;
}

static const char *
get_nth_value(int idx, const char *key)
{
    char **p = find_key_le(key);
    char **q = find_key_ge(key);
    return idx < q - p ? extract_value(p[idx]) : NULL;
}

static bool
is_type(const char *s, enum cfg_flags flags)
{
    uint8_t mac[ETH_ADDR_LEN];
    struct in_addr addr;
    uint64_t dpid;

    return (flags & CFG_STRING
            || (flags & CFG_KEY && is_key(s))
            || (flags & CFG_INT && is_int(s))
            || (flags & CFG_BOOL && is_bool(s))
            || (flags & CFG_IP && inet_aton(s, &addr))
            || (flags & CFG_MAC && parse_mac(s, mac))
            || (flags & CFG_DPID && parse_dpid(s, &dpid)));
}
