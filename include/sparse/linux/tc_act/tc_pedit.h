#ifndef FIX_LINUX_TC_PEDIT_H
#define FIX_LINUX_TC_PEDIT_H

#ifndef __CHECKER__
#error "Use this header only with sparse.  It is not a correct implementation."
#endif

#include_next <linux/tc_act/tc_pedit.h>

/* Fixes endianness of 'mask' and 'val' members. */
#define tc_pedit_key rpl_tc_pedit_key
struct rpl_tc_pedit_key {
    ovs_be32        mask;  /* AND */
    ovs_be32        val;   /* XOR */
    __u32           off;   /* offset */
    __u32           at;
    __u32           offmask;
    __u32           shift;
};

#define tc_pedit_sel rpl_tc_pedit_sel
struct rpl_tc_pedit_sel {
    tc_gen;
    unsigned char           nkeys;
    unsigned char           flags;
    struct tc_pedit_key     keys[0];
};

#endif
