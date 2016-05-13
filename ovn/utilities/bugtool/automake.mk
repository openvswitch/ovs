if HAVE_PYTHON
bugtool_plugins += \
	ovn/utilities/bugtool/plugins/network-status/ovn.xml

bugtool_scripts += \
	ovn/utilities/bugtool/ovn-bugtool-nbctl-show \
	ovn/utilities/bugtool/ovn-bugtool-sbctl-show \
	ovn/utilities/bugtool/ovn-bugtool-sbctl-lflow-list
endif
