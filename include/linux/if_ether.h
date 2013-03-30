/*
 * Copyright (c) 2013 Nicira, Inc.
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

#ifndef LINUX_IF_ETHER_H
#define LINUX_IF_ETHER_H 1

/* On Linux, this header file just includes <linux/if_ether.h>.
 *
 * On other platforms, this header file implements just enough of
 * <linux/if_ether.h> to allow <linux/openvswitch.h> to work. */

#if defined(HAVE_LINUX_IF_ETHER_H) || defined(__KERNEL__)
#include_next <linux/if_ether.h>
#else  /* no <linux/if_ether.h> */
#define ETH_ALEN        6               /* Octets in one ethernet addr   */
#endif

#endif /* <linux/if_ether.h> */
