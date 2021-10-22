# Copyright (c) 2021 Intel Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#! /bin/bash

if [ -z "$1" ]
then
    echo "- Missing mandatory argument:"
    echo " - Usage: source apply_stratum_artifacts.sh <SDE_INSTALL> "
    exit 1
fi

SDE_INSTALL=$1

echo "#### \
THIS SCRIPT DOES ONE-TIME STRATUM ARTIFACTS AFTER THE P4-OVS CHECKOUT\
####"

WORKSPACE_DIR=${PWD}

echo "Apply the STRATUM patch"
cd $WORKSPACE_DIR/stratum
git apply $WORKSPACE_DIR/external/PATCH-01-STRATUM
cd $WORKSPACE_DIR

mkdir -p /etc/stratum
echo "Manually create the pipeline_cfg.pb.txt file"
touch /etc/stratum/pipeline_cfg.pb.txt

mkdir -p /usr/share/stratum/
echo "Manually copy the target_skip_p4_no_bsp.conf file"
cp $WORKSPACE_DIR/stratum/stratum/hal/bin/barefoot/tofino_skip_p4_no_bsp.conf \
/usr/share/stratum/target_skip_p4_no_bsp.conf

echo "Manually copy the dpdk_vhost_config.pb.txt file"
cp $WORKSPACE_DIR/external/dpdk_vhost_config.pb.txt \
/usr/share/stratum/dpdk_vhost_config.pb.txt

mkdir -p /usr/share/target_sys
echo "Manually copy the zlog-cfg file"
#Make sure to set the $SDE_INSTALL Environment variable before this step
cp $SDE_INSTALL/share/target_sys/zlog-cfg /usr/share/target_sys/zlog-cfg
