#ifndef _UAPI__LINUX_GENERIC_NETLINK_WRAPPER_H
#define _UAPI__LINUX_GENERIC_NETLINK_WRAPPER_H

#include_next <linux/genetlink.h>

#ifndef GENL_UNS_ADMIN_PERM
#define GENL_UNS_ADMIN_PERM GENL_ADMIN_PERM
#endif

#ifdef GENL_ID_GENERATE
#if GENL_ID_GENERATE != 0
#error "GENL_ID_GENERATE is assumed to be zero"
#endif
#endif

#endif
