/*
 * Copyright (c) 2008, 2009, 2010, 2012 Nicira, Inc.
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

#ifndef JHASH_H
#define JHASH_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "util.h"

#ifdef __cplusplus
extern "C" {
#endif

/* This is the public domain lookup3 hash by Bob Jenkins from
 * http://burtleburtle.net/bob/c/lookup3.c, modified for style.
 *
 * Use the functions in hash.h instead if you can.  These are here just for
 * places where we've exposed a hash function "on the wire" and don't want it
 * to change. */

uint32_t jhash_words(const uint32_t *, size_t n_word, uint32_t basis);
uint32_t jhash_bytes(const void *, size_t n_bytes, uint32_t basis);

#ifdef __cplusplus
}
#endif

#endif /* jhash.h */
