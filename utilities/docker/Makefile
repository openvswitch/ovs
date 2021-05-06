#export OVS_BRANCH=branch-2.11
#export OVS_VERSION=2.11
#export KERNEL_VERSION=4.15.0-54-generic
#export DISTRO=debian
#export GITHUB_SRC=https://github.com/openvswitch/ovs.git
#export DOCKER_REPO=openvswitch/ovs

# Example:
#   make build
#   make push

REPO = ${DOCKER_REPO}
tag = ${OVS_VERSION}_${DISTRO}_${KERNEL_VERSION}

build: ;docker build -t ${REPO}:${tag} --build-arg DISTRO=${DISTRO} \
--build-arg OVS_BRANCH=${OVS_BRANCH} \
--build-arg KERNEL_VERSION=${KERNEL_VERSION} \
--build-arg GITHUB_SRC=${GITHUB_SRC} -f ${DISTRO}/Dockerfile .

.PHONY: build

push: ;docker push ${REPO}:${tag}
