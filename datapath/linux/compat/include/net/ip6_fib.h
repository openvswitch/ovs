/*
 *      Linux INET6 implementation
 *
 *      Authors:
 *      Pedro Roque             <roque@di.fc.ul.pt>
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#ifndef _IP6_FIB_WRAPPER_H
#define _IP6_FIB_WRAPPER_H

#include_next <net/ip6_fib.h>

#ifndef HAVE_RT6_GET_COOKIE

#ifndef RTF_PCPU
#define RTF_PCPU        0x40000000
#endif

#ifndef RTF_LOCAL
#define RTF_LOCAL       0x80000000
#endif

#define rt6_get_cookie rpl_rt6_get_cookie
static inline u32 rt6_get_cookie(const struct rt6_info *rt)
{
       if (rt->rt6i_flags & RTF_PCPU ||
#ifdef HAVE_DST_NOCACHE
           (unlikely(rt->dst.flags & DST_NOCACHE) && rt->dst.from))
#else
           (unlikely(!list_empty(&rt->rt6i_uncached)) && rt->dst.from))
#endif
               rt = (struct rt6_info *)(rt->dst.from);

       return rt->rt6i_node ? rt->rt6i_node->fn_sernum : 0;
}
#endif

#endif
