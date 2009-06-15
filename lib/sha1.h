/*
 * This file is from the Apache Portable Runtime Library.
 * The full upstream copyright and license statement is included below.
 * Modifications copyright (c) 2009 Nicira Networks.
 */

/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/* NIST Secure Hash Algorithm
 * 	heavily modified by Uwe Hollerbach uh@alumni.caltech edu
 * 	from Peter C. Gutmann's implementation as found in
 * 	Applied Cryptography by Bruce Schneier
 * 	This code is hereby placed in the public domain
 */

#ifndef SHA1_H
#define SHA1_H

#include <stddef.h>
#include <stdint.h>

/* Size of the SHA1 digest. */
#define SHA1_DIGEST_SIZE 20

/* SHA1 context structure. */
struct sha1_ctx {
    uint32_t digest[5];          /* Message digest. */
    uint32_t count_lo, count_hi; /* 64-bit bit counts. */
    uint32_t data[16];           /* SHA data buffer */
    int local;                   /* Unprocessed amount in data. */
};

void sha1_init(struct sha1_ctx *);
void sha1_update(struct sha1_ctx *, const void *, size_t);
void sha1_final(struct sha1_ctx *, uint8_t digest[SHA1_DIGEST_SIZE]);
void sha1_bytes(const void *, size_t, uint8_t digest[SHA1_DIGEST_SIZE]);

#endif  /* sha1.h */
