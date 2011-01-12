/*
 * Copyright (c) 2008, 2009, 2010 Nicira Networks.
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

#ifndef OFP_ERRORS_H
#define OFP_ERRORS_H 1

#include <stdint.h>

/* These functions are building blocks for the ofputil_format_error() and
 * ofputil_error_to_string() functions declared in ofp-util.h.  Those functions
 * have friendlier interfaces and should usually be preferred. */
const char *ofp_error_type_to_string(uint16_t value);
const char *ofp_error_code_to_string(uint16_t type, uint16_t code);

#endif /* ofp-errors.h */
