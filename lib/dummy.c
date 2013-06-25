/*
 * Copyright (c) 2010, 2011, 2012, 2013 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>

#include "dummy.h"

/* Enables support for "dummy" network devices and dpifs, which are useful for
 * testing.  A client program might call this function if it is designed
 * specifically for testing or the user enables it on the command line.
 *
 * If 'override' is false, then "dummy" dpif and netdev classes will be
 * created.  If 'override' is true, then in addition all existing dpif and
 * netdev classes will be deleted and replaced by dummy classes.
 *
 * There is no strong reason why dummy devices shouldn't always be enabled. */
void
dummy_enable(bool override)
{
    netdev_dummy_register(override);
    dpif_dummy_register(override);
    timeval_dummy_register();
    vlandev_dummy_enable();
}

