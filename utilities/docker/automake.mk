DIR := utilities/docker

OVS_BRANCH ?= branch-2.11
OVS_VERSION ?= 2.11
KERNEL_VERSION ?= 4.15.0-54-generic
DISTRO ?= debian
GITHUB_SRC ?= https://github.com/openvswitch/ovs.git
DOCKER_REPO ?= openvswitch/ovs
DOCKER_TAG ?= ${OVS_VERSION}_${DISTRO}_${KERNEL_VERSION}
DOCKER_SERVER ?= localhost:5000

.PHONY: docker-registry
docker-registry:
	docker rm --force registry 2>/dev/null || true
	docker run -d -p 5000:5000 --restart=always --name registry registry:2
	@echo
	@echo "# For using local repo set:"
	@echo "export DOCKER_REPO=localhost:5000/openvswitch/ovs"
	@echo
	@echo "# For returning to public repo set:"
	@echo "export DOCKER_REPO=openvswitch/ovs"

$(DIR)/vswitch.ovsschema: vswitchd/vswitch.ovsschema
	cp $< $@

$(DIR)/ovsdb-tool: ovsdb/ovsdb-tool
	cp $< $@

.PHONY: docker-build
docker-build: $(DIR)/vswitch.ovsschema $(DIR)/ovsdb-tool
	cd $(DIR) && docker build -t ${DOCKER_REPO}:${DOCKER_TAG} \
		--build-arg DISTRO=${DISTRO} \
		--build-arg OVS_BRANCH=${OVS_BRANCH} \
		--build-arg KERNEL_VERSION=${KERNEL_VERSION} \
		--build-arg GITHUB_SRC=${GITHUB_SRC} \
		-f ${DISTRO}/Dockerfile .

.PHONY: docker-push
docker-push:
	cd $(DIR) && docker push ${DOCKER_REPO}:${DOCKER_TAG}

.PHONY: docker-ovsdb-server
docker-ovsdb-server:
	docker rm --force ovsdb-server 2>/dev/null || true
	docker run -itd --net=host --name=ovsdb-server \
		${DOCKER_REPO}:${DOCKER_TAG} ovsdb-server

.PHONY: docker-ovs-vswitchd
docker-ovs-vswitchd:
	docker rm --force ovs-vswitchd 2>/dev/null || true
	docker run -itd --net=host --name=ovs-vswitchd \
		--volumes-from=ovsdb-server -v /lib:/lib --privileged \
		${DOCKER_REPO}:${DOCKER_TAG} ovs-vswitchd
