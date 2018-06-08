#ifndef __CAPTURE_H__
#define __CAPTURE_H__

#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <pcap.h>

#include "cb.h"

static FILE * fd = NULL;
static pcap_t * handle = NULL;
static struct cb * circular_buffer = NULL;
static uint64_t nb_packets = 0;

struct pcap_timeval {
    bpf_int32 tv_sec;           /* seconds */
    bpf_int32 tv_usec;          /* microseconds */
};

struct pcap_sf_pkthdr {
    struct pcap_timeval ts;     /* time stamp */
    bpf_u_int32 caplen;         /* length of portion present */
    bpf_u_int32 len;            /* length this packet (off wire) */
};

void write_packet_info(const u_char *, struct pcap_pkthdr);
void packet_handler(u_char *, const struct pcap_pkthdr *, const u_char *);

void packet_count_reset();
int64_t get_packet_count();

int start_capture(const char *, const char *, const char *, const char *);
void stop_capture(void);

void write_pcap_header(void);
void write_pcap_packet(const u_char *, struct pcap_pkthdr *);

#endif /* __CAPTURE_H__ */
