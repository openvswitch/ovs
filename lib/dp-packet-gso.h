/*
 * Copyright (c) 2023 Red Hat, Inc.
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

#ifndef DP_PACKET_GSO_H
#define DP_PACKET_GSO_H 1

void dp_packet_gso(struct dp_packet *, struct dp_packet_batch **);
int dp_packet_gso_nr_segs(struct dp_packet *);

#endif /* dp-packet-gso.h */
