#ifndef __LINUX_SOCKIOS_WRAPPER_H
#define __LINUX_SOCKIOS_WRAPPER_H 1

#include_next <linux/sockios.h>

/* bridge calls */
#define SIOCBRADDBR     0x89a0		/* create new bridge device     */
#define SIOCBRDELBR     0x89a1		/* remove bridge device         */
#define SIOCBRADDIF	0x89a2		/* add interface to bridge      */
#define SIOCBRDELIF	0x89a3		/* remove interface from bridge */

#endif
