/*
 * Copyright (c) 2021, Red Hat, Inc.
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

#ifndef OVS_REPLAY_H
#define OVS_REPLAY_H 1

/*
 * Library to work with 'replay' files.
 *
 * ovs_replay_file_open() should be used to open a new replay file.
 * 'replay' file contains records.  If current state is OVS_REPLAY_WRITE,
 * files are opened in a write mode and new records could be written by
 * ovs_replay_write().  If current mode is OVS_REPLAY_READ, files are
 * opened in a read mode and records could be read with ovs_replay_read().
 *
 * Each record has several fields:
 *   <seqno> <len> [<data>]
 *
 * Here <seqno> is a global sequence number of the record, it is unique
 * across all the replay files.  By comparing normalized version of this
 * number (ovs_replay_normalized_seqno()) with the current global sequence
 * number (ovs_replay_seqno()) users may detect if this record should be
 * replayed now.
 *
 * Non-normalized versions of seqno are used to distinguish 'read' and 'write'
 * records.  'read' records are records that corresponds to incoming events.
 * Only 'read' records contains <data>.  'write' records contains outgoing
 * events, i.e. stream_write() and contains only the size of outgoing message.
 *
 * For 'read' records, <len> is a size of a <data> stored in this record in
 * bytes.  For 'write' records, it is a size of outgoing message, but there
 * is no <data>.  If it contains negative value, it means that this record
 * holds some recorded error and no data available.
 */

#include <stdbool.h>
#include <stdio.h>

typedef FILE *replay_file_t;

/* Replay state. */
enum ovs_replay_state {
    OVS_REPLAY_NONE,
    OVS_REPLAY_WRITE,
    OVS_REPLAY_READ,
};

void ovs_replay_set_state(enum ovs_replay_state);
enum ovs_replay_state ovs_replay_get_state(void);

static inline bool
ovs_replay_is_active(void)
{
    return ovs_replay_get_state() != OVS_REPLAY_NONE;
}

/* Returns 'true' if provided sequence number belongs to  'read' record. */
static inline bool
ovs_replay_seqno_is_read(int seqno)
{
    return seqno >= 0;
}

/* Normalizes sequence number, so it can be used to compare with result of
 * ovs_replay_seqno(). */
static inline int
ovs_replay_normalized_seqno(int seqno)
{
    return seqno >= 0 ? seqno : -seqno;
}

/* Locks the replay module.
 * Locking required to use ovs_replay_file_open() and ovs_replay_read(). */
void ovs_replay_lock(void);

/* Unlocks the replay module. */
void ovs_replay_unlock(void);

/* Returns current global replay sequence number. */
int ovs_replay_seqno(void);

/* In write mode creates a new replay file to write stream replay.
 * In read mode opens an existing replay file.
 *
 * Requires replay being locked with ovs_replay_lock().
 *
 * On success returns 0,  'f' points to the opened file.  If current mode is
 * OVS_REPLAY_READ, sets 'seqno' to the sequence number of the first record in
 * the file.
 *
 * On failure returns positive errno. */
int ovs_replay_file_open(const char *name, replay_file_t *f, int *seqno);

/* Closes replay file. */
void ovs_replay_file_close(replay_file_t f);

/* Writes a new record of 'n' bytes from 'buffer' to a replay file.
 * 'is_read' should be true if the record belongs to 'read' operation
 * Depending on 'is_read', creates 'read' or 'write' record.  'write' records
 * contains only the size of a bufer ('n').
 * If 'n' is negative, writes 'n' as an error status.
 *
 * On success returns 0.  Otherwise, positive errno. */
int ovs_replay_write(replay_file_t f, const void *buffer, int n, bool is_read);

/* Reads one record from a replay file to 'buffer'.  'buffer_size' should be
 * equal to the size of a memory available.
 *
 * On success, actual size of the read record will be set to 'len', 'seqno'
 * will be set to the sequence number of the next record in the file.  If it
 * was the last record, sets 'seqno' to INT_MAX.
 * Negative 'len' means that record contained an error status.
 *
 * Depending on 'is_read', tries to read 'read' or 'write' record.  For the
 * 'write' record, only 'len' and 'seqno' updated, no data read to 'buffer'.
 *
 * On success returns 0.  Otherwise, positive errno. */
int ovs_replay_read(replay_file_t f, void *buffer, int buffer_size,
                    int *len, int *seqno, bool is_read);

/* Helpers for cmdline options. */
#define OVS_REPLAY_OPTION_ENUMS  \
        OPT_OVS_REPLAY_REC,      \
        OPT_OVS_REPLAY

#define OVS_REPLAY_LONG_OPTIONS                                    \
        {"record", optional_argument, NULL, OPT_OVS_REPLAY_REC},   \
        {"replay", optional_argument, NULL, OPT_OVS_REPLAY}

#define OVS_REPLAY_OPTION_HANDLERS                                 \
        case OPT_OVS_REPLAY_REC:                                   \
            ovs_replay_set_state(OVS_REPLAY_WRITE);                \
            ovs_replay_set_dirname(optarg);                        \
            break;                                                 \
                                                                   \
        case OPT_OVS_REPLAY:                                       \
            ovs_replay_set_state(OVS_REPLAY_READ);                 \
            ovs_replay_set_dirname(optarg);                        \
            break;

#define OVS_REPLAY_CASES \
        case OPT_OVS_REPLAY_REC: case OPT_OVS_REPLAY:

/* Prints usage information. */
void ovs_replay_usage(void);

/* Sets path to the directory where replay files should be stored. */
void ovs_replay_set_dirname(const char *new_dirname);

#endif /* OVS_REPLAY_H */
