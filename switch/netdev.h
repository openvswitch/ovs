/* Copyright (C) 2008 Board of Trustees, Leland Stanford Jr. University.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#ifndef NETDEV_H
#define NETDEV_H 1

#include <stdbool.h>
#include <stdint.h>

struct buffer;

struct netdev;
int netdev_open(const char *name, struct netdev **);
void netdev_close(struct netdev *);
int netdev_recv(struct netdev *, struct buffer *, bool block);
int netdev_send(struct netdev *, struct buffer *, bool block);
const uint8_t *netdev_get_etheraddr(const struct netdev *);
int netdev_get_fd(const struct netdev *);
const char *netdev_get_name(const struct netdev *);
int netdev_get_speed(const struct netdev *);
uint32_t netdev_get_features(const struct netdev *);

#endif /* netdev.h */
