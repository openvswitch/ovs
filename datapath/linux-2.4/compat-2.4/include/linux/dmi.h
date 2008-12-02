#ifndef __LINUX_DMI_WRAPPER_H
#define __LINUX_DMI_WRAPPER_H 1

enum dmi_field {
	DMI_NONE,
	DMI_BIOS_VENDOR,
	DMI_BIOS_VERSION,
	DMI_BIOS_DATE,
	DMI_SYS_VENDOR,
	DMI_PRODUCT_NAME,
	DMI_PRODUCT_VERSION,
	DMI_PRODUCT_SERIAL,
	DMI_PRODUCT_UUID,
	DMI_BOARD_VENDOR,
	DMI_BOARD_NAME,
	DMI_BOARD_VERSION,
	DMI_BOARD_SERIAL,
	DMI_BOARD_ASSET_TAG,
	DMI_CHASSIS_VENDOR,
	DMI_CHASSIS_TYPE,
	DMI_CHASSIS_VERSION,
	DMI_CHASSIS_SERIAL,
	DMI_CHASSIS_ASSET_TAG,
	DMI_STRING_MAX
};

/* 2.4 kernels didn't provide a general ability to query DMI.  We'll just
 * always return NULL, since this functionality isn't critical. */
static inline 
const char *dmi_get_system_info(int field) {
	return NULL;
}

#endif 
