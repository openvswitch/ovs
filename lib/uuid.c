/* Copyright (c) 2008, 2009, 2010, 2011 Nicira, Inc.
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

#include "uuid.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "aes128.h"
#include "entropy.h"
#include "sha1.h"
#include "timeval.h"
#include "util.h"

static struct aes128 key;
static uint64_t counter[2];
BUILD_ASSERT_DECL(sizeof counter == 16);

static void do_init(void);

/*
 * Initialize the UUID module.  Aborts the program with an error message if
 * initialization fails (which should never happen on a properly configured
 * machine.)
 *
 * Currently initialization is only needed by uuid_generate().  uuid_generate()
 * will automatically call uuid_init() itself, so it's only necessary to call
 * this function explicitly if you want to abort the program earlier than the
 * first UUID generation in case of failure.
 */
void
uuid_init(void)
{
    static bool inited;
    if (!inited) {
        do_init();
        inited = true;
    }
}

/* Generates a new random UUID in 'uuid'.
 *
 * We go to some trouble to ensure as best we can that the generated UUID has
 * these properties:
 *
 *      - Uniqueness.  The random number generator is seeded using both the
 *        system clock and the system random number generator, plus a few
 *        other identifiers, which is about as good as we can get in any kind
 *        of simple way.
 *
 *      - Unpredictability.  In some situations it could be bad for an
 *        adversary to be able to guess the next UUID to be generated with some
 *        probability of success.  This property may or may not be important
 *        for our purposes, but it is better if we can get it.
 *
 * To ensure both of these, we start by taking our seed data and passing it
 * through SHA-1.  We use the result as an AES-128 key.  We also generate a
 * random 16-byte value[*] which we then use as the counter for CTR mode.  To
 * generate a UUID in a manner compliant with the above goals, we merely
 * increment the counter and encrypt it.
 *
 * [*] It is not actually important that the initial value of the counter be
 *     random.  AES-128 in counter mode is secure either way.
 */
void
uuid_generate(struct uuid *uuid)
{
    uuid_init();

    /* Increment the counter. */
    if (++counter[1] == 0) {
        counter[0]++;
    }

    /* AES output is exactly 16 bytes, so we encrypt directly into 'uuid'. */
    aes128_encrypt(&key, counter, uuid);

    /* Set bits to indicate a random UUID.  See RFC 4122 section 4.4. */
    uuid->parts[2] &= ~0xc0000000;
    uuid->parts[2] |=  0x80000000;
    uuid->parts[1] &= ~0x0000f000;
    uuid->parts[1] |=  0x00004000;
}

/* Sets 'uuid' to all-zero-bits. */
void
uuid_zero(struct uuid *uuid)
{
    uuid->parts[0] = uuid->parts[1] = uuid->parts[2] = uuid->parts[3] = 0;
}

/* Returns true if 'uuid' is all zero, otherwise false. */
bool
uuid_is_zero(const struct uuid *uuid)
{
    return (!uuid->parts[0] && !uuid->parts[1]
            && !uuid->parts[2] && !uuid->parts[3]);
}

/* Compares 'a' and 'b'.  Returns a negative value if 'a < b', zero if 'a ==
 * b', or positive if 'a > b'.  The ordering is lexicographical order of the
 * conventional way of writing out UUIDs as strings. */
int
uuid_compare_3way(const struct uuid *a, const struct uuid *b)
{
    if (a->parts[0] != b->parts[0]) {
        return a->parts[0] > b->parts[0] ? 1 : -1;
    } else if (a->parts[1] != b->parts[1]) {
        return a->parts[1] > b->parts[1] ? 1 : -1;
    } else if (a->parts[2] != b->parts[2]) {
        return a->parts[2] > b->parts[2] ? 1 : -1;
    } else if (a->parts[3] != b->parts[3]) {
        return a->parts[3] > b->parts[3] ? 1 : -1;
    } else {
        return 0;
    }
}

/* Attempts to convert string 's' into a UUID in 'uuid'.  Returns true if
 * successful, which will be the case only if 's' has the exact format
 * specified by RFC 4122.  Returns false on failure.  On failure, 'uuid' will
 * be set to all-zero-bits. */
bool
uuid_from_string(struct uuid *uuid, const char *s)
{
    if (!uuid_from_string_prefix(uuid, s)) {
        return false;
    } else if (s[UUID_LEN] != '\0') {
        uuid_zero(uuid);
        return false;
    } else {
        return true;
    }
}

/* Same as uuid_from_string() but s[UUID_LEN] is not required to be a null byte
 * to succeed; that is, 's' need only begin with UUID syntax, not consist
 * entirely of it. */
bool
uuid_from_string_prefix(struct uuid *uuid, const char *s)
{
    /* 0         1         2         3      */
    /* 012345678901234567890123456789012345 */
    /* ------------------------------------ */
    /* 00000000-1111-1111-2222-222233333333 */

    bool ok;

    uuid->parts[0] = hexits_value(s, 8, &ok);
    if (!ok || s[8] != '-') {
        goto error;
    }

    uuid->parts[1] = hexits_value(s + 9, 4, &ok) << 16;
    if (!ok || s[13] != '-') {
        goto error;
    }

    uuid->parts[1] += hexits_value(s + 14, 4, &ok);
    if (!ok || s[18] != '-') {
        goto error;
    }

    uuid->parts[2] = hexits_value(s + 19, 4, &ok) << 16;
    if (!ok || s[23] != '-') {
        goto error;
    }

    uuid->parts[2] += hexits_value(s + 24, 4, &ok);
    if (!ok) {
        goto error;
    }

    uuid->parts[3] = hexits_value(s + 28, 8, &ok);
    if (!ok) {
        goto error;
    }
    return true;

error:
    uuid_zero(uuid);
    return false;
}

static void
do_init(void)
{
    uint8_t sha1[SHA1_DIGEST_SIZE];
    struct sha1_ctx sha1_ctx;
    uint8_t random_seed[16];
    struct timeval now;
    pid_t pid, ppid;
    uid_t uid;
    gid_t gid;

    /* Get seed data. */
    get_entropy_or_die(random_seed, sizeof random_seed);
    xgettimeofday(&now);
    pid = getpid();
    ppid = getppid();
    uid = getuid();
    gid = getgid();

    /* Convert seed into key. */
    sha1_init(&sha1_ctx);
    sha1_update(&sha1_ctx, random_seed, sizeof random_seed);
    sha1_update(&sha1_ctx, &pid, sizeof pid);
    sha1_update(&sha1_ctx, &ppid, sizeof ppid);
    sha1_update(&sha1_ctx, &uid, sizeof uid);
    sha1_update(&sha1_ctx, &gid, sizeof gid);
    sha1_final(&sha1_ctx, sha1);

    /* Generate key. */
    BUILD_ASSERT(sizeof sha1 >= 16);
    aes128_schedule(&key, sha1);

    /* Generate initial counter. */
    get_entropy_or_die(counter, sizeof counter);
}
