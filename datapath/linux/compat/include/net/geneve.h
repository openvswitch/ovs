#ifndef __NET_GENEVE_WRAPPER_H
#define __NET_GENEVE_WRAPPER_H  1

/* Not yet upstream. */
#define GENEVE_CRIT_OPT_TYPE (1 << 7)
struct geneve_opt {
	__be16	opt_class;
	u8	type;
#ifdef __LITTLE_ENDIAN_BITFIELD
	u8	length:5;
	u8	r3:1;
	u8	r2:1;
	u8	r1:1;
#else
	u8	r1:1;
	u8	r2:1;
	u8	r3:1;
	u8	length:5;
#endif
        u8	opt_data[];
};

#endif
