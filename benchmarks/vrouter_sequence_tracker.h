/* Shared bounded sequence validation for Linux packet and DPDK receivers. */
#ifndef VROUTER_SEQUENCE_TRACKER_H
#define VROUTER_SEQUENCE_TRACKER_H
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct batch {
    uint32_t id, expected, highest;
    uint64_t unique, duplicate, reordered;
    unsigned char *seen;
    double first, last;
};
static struct batch batches[32];
static unsigned used;
static uint64_t invalid;
static uint32_t read32(const unsigned char *p) {
    uint32_t v; memcpy(&v,p,4); return ntohl(v);
}
static void packet(const unsigned char *p, unsigned length, double timestamp) {
    unsigned ip = 14;
    if (length >= 18 && p[12] == 0x81 && p[13] == 0x00)
        ip += 4;
    if (length < ip + 20 || (p[ip] >> 4) != 4 ||
        p[ip + 9] != 17)
        { invalid++; return; }
    unsigned ihl = (p[ip] & 15u) * 4u;
    unsigned udp = ip + ihl;
    unsigned payload = udp + 8;
    if (ihl < 20 || length < payload + 18 || memcmp(p+payload,"VRS2",4))
        { invalid++; return; }
    uint32_t id=read32(p+payload+4), seq=read32(p+payload+8), expected=read32(p+payload+12);
    if (!expected || expected>60000000 || seq>=expected) { invalid++; return; }
    unsigned i;
    for (i=0; i<used && batches[i].id!=id; i++) {}
    if (i==used) {
        if (used==32) { invalid++; return; }
        struct batch *b=&batches[used++];
        b->id=id; b->expected=expected;
        b->seen=calloc((expected+7u)/8u,1);
        if (!b->seen) { perror("calloc"); exit(1); }
    }
    struct batch *b=&batches[i];
    if (b->expected!=expected) { invalid++; return; }
    unsigned char mask=(unsigned char)(1u<<(seq&7u));
    if (b->seen[seq>>3]&mask) { b->duplicate++; return; }
    b->seen[seq>>3]|=mask;
    if (!b->unique) b->first=timestamp;
    b->last=timestamp;
    if (b->unique && seq<b->highest) b->reordered++;
    if (seq>b->highest) b->highest=seq;
    b->unique++;
}
static void write_batches(FILE *f) {
    for (unsigned i=0; i<used; i++) {
        struct batch *b=&batches[i];
        fprintf(f,"%s{\"run\":%u,\"expected\":%u,\"unique\":%llu,\"missing\":%llu,\"duplicates\":%llu,\"reordered\":%llu,\"span_s\":%.9f}",
            i?",":"",b->id,b->expected,(unsigned long long)b->unique,
            (unsigned long long)(b->expected-b->unique),(unsigned long long)b->duplicate,
            (unsigned long long)b->reordered,b->last-b->first);
    }
}
#endif
