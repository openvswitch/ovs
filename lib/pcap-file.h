/*
 * Copyright (c) 2009 Nicira, Inc.
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

#ifndef PCAP_FILE_H
#define PCAP_FILE_H 1

#include <stdio.h>

struct flow;
struct dp_packet;
struct pcap_file;

/* PCAP file reading and writing. */
struct pcap_file *ovs_pcap_open(const char *file_name, const char *mode);
struct pcap_file *ovs_pcap_stdout(void);
int ovs_pcap_read_header(struct pcap_file *);
void ovs_pcap_write_header(struct pcap_file *);
int ovs_pcap_read(struct pcap_file *, struct dp_packet **,
                  long long int *when);
void ovs_pcap_write(struct pcap_file *, struct dp_packet *);
void ovs_pcap_close(struct pcap_file *);

/* Extracting TCP stream data from an Ethernet packet capture. */

struct tcp_reader *tcp_reader_open(void);
void tcp_reader_close(struct tcp_reader *);
struct dp_packet *tcp_reader_run(struct tcp_reader *, const struct flow *,
                              const struct dp_packet *);

#endif /* pcap-file.h */
