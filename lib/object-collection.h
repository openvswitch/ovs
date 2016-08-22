/*
 * Copyright (c) 2016 Nicira, Inc.
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

#ifndef OBJECT_COLLECTION_H
#define OBJECT_COLLECTION_H 1

#include <limits.h>
#include <stdlib.h>

/* A set of object pointers. */
struct object_collection {
    void **objs;                /* Objects. */
    size_t n;                   /* Number of objects collected. */
    size_t capacity;            /* Number of objects that fit in 'objs'. */
    void *stub[5];              /* Preallocated array to avoid malloc(). */
};

void object_collection_init(struct object_collection *);
void object_collection_add(struct object_collection *, void *);
void object_collection_remove(struct object_collection *, void *);
void object_collection_move(struct object_collection *to,
                            struct object_collection *from);
void *object_collection_detach(struct object_collection *);
void object_collection_destroy(struct object_collection *);

/* Macro for declaring type-safe pointer collections.  'TYPE' is the pointer
 * type which are collected, 'NAME' is the name for the type to be used in the
 * function names. */

#define DECL_OBJECT_COLLECTION(TYPE, NAME)                              \
struct NAME##_collection {                                              \
    struct object_collection collection;                                \
};                                                                      \
                                                                        \
static inline void NAME##_collection_init(struct NAME##_collection *coll) \
{                                                                       \
    object_collection_init(&coll->collection);                          \
}                                                                       \
                                                                        \
static inline void NAME##_collection_add(struct NAME##_collection *coll, \
                                         TYPE obj)                      \
{                                                                       \
    object_collection_add(&coll->collection, obj);                      \
}                                                                       \
                                                                        \
static inline void NAME##_collection_remove(struct NAME##_collection *coll, \
                                            TYPE obj)                   \
{                                                                       \
    object_collection_remove(&coll->collection, obj);                   \
}                                                                       \
                                                                        \
static inline void NAME##_collection_move(struct NAME##_collection *to, \
                                          struct NAME##_collection *from) \
{                                                                       \
    object_collection_move(&to->collection, &from->collection);         \
}                                                                       \
                                                                        \
static inline void NAME##_collection_destroy(struct NAME##_collection *coll) \
{                                                                       \
    object_collection_destroy(&coll->collection);                       \
}                                                                       \
                                                                        \
static inline TYPE* NAME##_collection_##NAME##s(const struct NAME##_collection *coll) \
{                                                                       \
    return (TYPE*)coll->collection.objs;                                \
}                                                                       \
                                                                        \
static inline size_t NAME##_collection_n(const struct NAME##_collection *coll) \
{                                                                       \
    return coll->collection.n;                                          \
}                                                                       \
                                                                        \
static inline TYPE* NAME##_collection_detach(struct NAME##_collection *coll) \
{                                                                       \
    return (TYPE*)object_collection_detach(&coll->collection);          \
}

#endif /* object-collection.h */
