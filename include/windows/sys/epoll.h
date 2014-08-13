/*
 * Copyright 2014 Cloudbase Solutions Srl
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __SYS_EPOLL_H
#define __SYS_EPOLL_H 1

#define EPOLLIN 0x00001

typedef union data {
    uint32_t u32;
} data_t;

struct epoll_event {
    uint32_t events;
    data_t data;
};

#endif /* sys/epoll.h */
