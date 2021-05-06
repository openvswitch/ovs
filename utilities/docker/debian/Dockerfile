FROM ubuntu:16.04
MAINTAINER "Aliasgar Ginwala" <aginwala@ebay.com>

ARG OVS_BRANCH
ARG KERNEL_VERSION
ARG GITHUB_SRC
ARG DISTRO

copy $DISTRO/build-kernel-modules.sh /build-kernel-modules.sh
RUN /build-kernel-modules.sh $KERNEL_VERSION $OVS_BRANCH $GITHUB_SRC

COPY create_ovs_db.sh /etc/openvswitch/create_ovs_db.sh
RUN /etc/openvswitch/create_ovs_db.sh

COPY ovs-override.conf /etc/depmod.d/openvswitch.conf

COPY start-ovs /bin/start-ovs
VOLUME ["/var/log/openvswitch", "/var/lib/openvswitch",\
 "/var/run/openvswitch", "/etc/openvswitch"]
ENTRYPOINT ["start-ovs"]
