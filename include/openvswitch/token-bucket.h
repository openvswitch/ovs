/*
 * Copyright (c) 2012 Nicira, Inc.
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

#ifndef OPENVSWITCH_TOKEN_BUCKET_H
#define OPENVSWITCH_TOKEN_BUCKET_H 1

#include <limits.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct token_bucket {
    /* Configuration settings. */
    unsigned int rate;          /* Tokens added per millisecond. */
    unsigned int burst;         /* Max cumulative tokens credit. */

    /* Current status. */
    unsigned int tokens;        /* Current number of tokens. */
    long long int last_fill;    /* Last time tokens added. */
};

#define TOKEN_BUCKET_INIT(RATE, BURST) { RATE, BURST, 0, LLONG_MIN }

void token_bucket_init(struct token_bucket *,
                       unsigned int rate, unsigned int burst);
void token_bucket_set(struct token_bucket *,
                       unsigned int rate, unsigned int burst);
bool token_bucket_withdraw(struct token_bucket *, unsigned int n);
void token_bucket_wait_at(struct token_bucket *, unsigned int n,
                          const char *where);
#define token_bucket_wait(bucket, n)                    \
    token_bucket_wait_at(bucket, n, OVS_SOURCE_LOCATOR)

#ifdef __cplusplus
}
#endif

#endif /* token-bucket.h */
