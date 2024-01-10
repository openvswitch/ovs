#!/usr/bin/env python3
# Copyright (c) 2024 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


from pathlib import Path
import os
import sys

# The tester might want to select a PCI device, if so, trust it.
if 'DPDK_PCI_ADDR' in os.environ:
    print(os.environ['DPDK_PCI_ADDR'])
    sys.exit(0)

for device in sorted(Path('/sys/bus/pci/devices').iterdir()):
    class_path = device / 'class'
    # Only consider Network class devices
    if class_path.read_text().strip() != '0x020000':
        continue
    kmod_path = device / 'driver' / 'module'
    kmod_name = kmod_path.resolve().name
    # Only care about devices bound to vfio_pci or igb_uio.
    if kmod_name not in ['vfio_pci', 'igb_uio']:
        continue
    print(device.resolve().name)
    sys.exit(0)

sys.exit(1)
