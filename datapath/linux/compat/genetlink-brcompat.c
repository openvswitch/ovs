/* We fix grp->id to 32 so that it doesn't collide with any of the multicast
 * groups selected by openvswitch, which uses groups 16 through 31.
 * Collision isn't fatal--multicast listeners should check that the family is
 * the one that they want and discard others--but it wastes time and memory to
 * receive unwanted messages. */

#define GENL_FIRST_MCGROUP 32
#define GENL_LAST_MCGROUP  32

#include "genetlink.inc"
