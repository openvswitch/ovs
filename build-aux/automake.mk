EXTRA_DIST += \
	build-aux/calculate-schema-cksum \
	build-aux/cccl \
	build-aux/check-structs \
	build-aux/cksum-schema-check \
	build-aux/dist-docs \
	build-aux/dpdkstrip.py \
	build-aux/extract-odp-netlink-h \
	build-aux/extract-odp-netlink-macros-h \
	build-aux/extract-odp-netlink-windows-dp-h \
	build-aux/extract-ofp-actions \
	build-aux/extract-ofp-errors \
	build-aux/extract-ofp-fields \
	build-aux/extract-ofp-msgs \
	build-aux/gen_ofp_field_decoders \
	build-aux/generate-dhparams-c \
	build-aux/initial-tab-allowed-files \
	build-aux/sodepends.py \
	build-aux/soexpand.py \
	build-aux/text2c \
	build-aux/xml2nroff

FLAKE8_PYFILES += \
	build-aux/dpdkstrip.py \
	build-aux/extract-ofp-actions \
	build-aux/extract-ofp-errors \
	build-aux/extract-ofp-fields \
	build-aux/extract-ofp-msgs \
	build-aux/gen_ofp_field_decoders \
	build-aux/sodepends.py \
	build-aux/soexpand.py \
	build-aux/xml2nroff
