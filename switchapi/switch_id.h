/*
Copyright 2013-present Barefoot Networks, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef __SWITCH_ID_H__
#define __SWITCH_ID_H__

#include "switch_base_types.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** ID allocator */
typedef struct switch_id_allocator_t_ {
  switch_uint32_t n_words; /**< number fo 32 bit words in allocator */
  switch_uint32_t *data;   /**< bitmap of allocator */
  bool zero_based;         /**< allocate index from zero if set */
  bool expandable; /**< if set, expand bitmap when needed. zero_based must be
                      FALSE */
} switch_id_allocator_t;

/**
 Create a new allocator, which is expandable
 @param initial_size init size in words (32-bit) for allocator
 @param zero_based allocate index from 0 if set to true
*/
switch_status_t switch_api_id_allocator_new(switch_device_t device,
                                            switch_uint32_t initial_size,
                                            bool zero_based,
                                            switch_id_allocator_t **allocator);

/**
 Delete the allocator
 @param allocator allocator allocated with create
*/
switch_status_t switch_api_id_allocator_destroy(
    switch_device_t device, switch_id_allocator_t *allocator);

/**
 Allocate one id from the allocator
 If bitmap is full and expandable is false, return zero.
 @param allocator allocator created with create
*/
switch_status_t switch_api_id_allocator_allocate(
    switch_device_t device, switch_id_allocator_t *allocator, switch_id_t *id);

/**
 Allocate count consecutive ids from the allocator
 If bitmap is full and expandable is false, return zero.
 @param allocator allocator created with create
 @param count number of consecutive ids to allocate
*/
switch_status_t switch_api_id_allocator_allocate_contiguous(
    switch_device_t device,
    switch_id_allocator_t *allocator,
    switch_uint8_t count,
    switch_id_t *id);

/**
 Free up id in allocator
 @param allocator allocator created with create
 @param id id to free in allocator
*/
switch_status_t switch_api_id_allocator_release(
    switch_device_t device, switch_id_allocator_t *allocator, switch_id_t id);

/**
 Set a bit in allocator
 @param allocator - bitmap allocator reference
 @param id - bit to be set in allocator
*/
switch_status_t switch_api_id_allocator_set(switch_device_t device,
                                            switch_id_allocator_t *allocator,
                                            switch_id_t id);
/**
 Check if a bit is set in allocator
 @param allocator - bitmap allocator reference
 @param id - bit to be checked in allocator
*/
bool switch_api_id_allocator_is_set(switch_device_t device,
                                    switch_id_allocator_t *allocator,
                                    switch_id_t id);

#ifdef __cplusplus
}
#endif

#endif /* __SWITCH_ID_H__ */
