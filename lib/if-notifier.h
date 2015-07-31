/*
 * Copyright (c) 2015 Red Hat, Inc.
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

#ifndef IF_NOTIFIER_H
#define IF_NOTIFIER_H 1

struct if_notifier;

typedef void if_notify_func(void *aux);

struct if_notifier *if_notifier_create(if_notify_func *, void *aux);
void if_notifier_destroy(struct if_notifier *);

void if_notifier_run(void);
void if_notifier_wait(void);

#endif  /* if-notifier.h */
