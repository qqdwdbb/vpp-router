/* libpcap/BPF sequence capture before the Mac UDP socket path. */
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define MAX_BATCHES 32
struct batch {
    uint32_t id, expected, highest;
    uint64_t unique, duplicate, reordered;
    unsigned char *seen;
    double first, last;
};
static struct batch batches[MAX_BATCHES];
static unsigned used;
static volatile sig_atomic_t stop;
static void handle(int sig) { (void)sig; stop = 1; }
static uint32_t u32(const unsigned char *p) {
    uint32_t n; memcpy(&n, p, 4); return ntohl(n);
}
static void packet(unsigned char *user, const struct pcap_pkthdr *h, const unsigned char *p) {
    (void)user;
    unsigned ip = 14;
    if (h->caplen < 60) return;
    if (p[12] == 0x81 && p[13] == 0x00) ip += 4;
    unsigned udp = ip + (p[ip] & 15u) * 4u;
    unsigned payload = udp + 8;
    if (h->caplen < payload + 18 || memcmp(p + payload, "VRS2", 4)) return;
    uint32_t id = u32(p + payload + 4), seq = u32(p + payload + 8);
    uint32_t expected = u32(p + payload + 12);
    if (!expected || expected > 60000000 || seq >= expected) return;
    unsigned i;
    for (i = 0; i < used && batches[i].id != id; ++i) {}
    if (i == used) {
        if (used == MAX_BATCHES) return;
        struct batch *b = &batches[used++];
        b->id = id; b->expected = expected;
        b->seen = calloc((expected + 7u) / 8u, 1);
        if (!b->seen) exit(1);
    }
    struct batch *b = &batches[i];
    if (expected != b->expected) return;
    unsigned char mask = (unsigned char)(1u << (seq & 7u));
    if (b->seen[seq >> 3] & mask) { b->duplicate++; return; }
    b->seen[seq >> 3] |= mask;
    double t = h->ts.tv_sec + h->ts.tv_usec / 1e6;
    if (!b->unique) b->first = t;
    b->last = t;
    if (b->unique && seq < b->highest) b->reordered++;
    if (seq > b->highest) b->highest = seq;
    b->unique++;
}
static void report(pcap_t *pc, const char *path) {
    struct pcap_stat stats;
    memset(&stats, 0, sizeof(stats));
    pcap_stats(pc, &stats);
    char tmp[1024];
    snprintf(tmp, sizeof(tmp), "%s.new", path);
    FILE *f = fopen(tmp, "w");
    if (!f) { perror("report"); exit(1); }
    fprintf(f, "{\"pcap_received\":%u,\"pcap_dropped\":%u,\"pcap_ifdrop\":%u,\"batches\":[",
            stats.ps_recv, stats.ps_drop, stats.ps_ifdrop);
    for (unsigned i = 0; i < used; ++i) {
        struct batch *b = &batches[i];
        fprintf(f, "%s{\"run\":%u,\"expected\":%u,\"unique\":%llu,\"missing\":%llu,"
                "\"duplicates\":%llu,\"reordered\":%llu,\"span_s\":%.9f}",
                i ? "," : "", b->id, b->expected, (unsigned long long)b->unique,
                (unsigned long long)(b->expected - b->unique),
                (unsigned long long)b->duplicate, (unsigned long long)b->reordered,
                b->last - b->first);
    }
    fputs("]}\n", f); fclose(f); chmod(tmp, 0644);
    if (rename(tmp, path)) { perror("rename"); exit(1); }
}
int main(int argc, char **argv) {
    if (argc != 4) return 2;
    char err[PCAP_ERRBUF_SIZE];
    pcap_t *pc = pcap_create(argv[1], err);
    if (!pc) { fprintf(stderr, "%s\n", err); return 1; }
    pcap_set_snaplen(pc, 96);
    pcap_set_promisc(pc, 0);
    pcap_set_buffer_size(pc, 32 * 1024 * 1024);
    pcap_set_timeout(pc, 100);
    if (pcap_activate(pc) < 0 || pcap_datalink(pc) != DLT_EN10MB) {
        fprintf(stderr, "%s\n", pcap_geterr(pc)); return 1;
    }
    struct bpf_program filter;
    if (pcap_compile(pc, &filter,
        "udp and src host 203.0.113.10 and dst host 10.61.20.100 and src port 50000 and dst port 45996",
        1, PCAP_NETMASK_UNKNOWN) || pcap_setfilter(pc, &filter)) {
        fprintf(stderr, "%s\n", pcap_geterr(pc)); return 1;
    }
    pcap_freecode(&filter);
    if (pcap_setnonblock(pc, 1, err)) { fprintf(stderr, "%s\n", err); return 1; }
    signal(SIGTERM, handle); signal(SIGINT, handle);
    time_t end = time(NULL) + atoi(argv[3]), last = 0;
    char stop_path[1024];
    snprintf(stop_path, sizeof(stop_path), "%s.stop", argv[2]);
    report(pc, argv[2]);
    puts("READY BPF en5"); fflush(stdout);
    while (!stop && time(NULL) < end && access(stop_path, F_OK) != 0) {
        int n = pcap_dispatch(pc, 8192, packet, NULL);
        if (n < 0) { fprintf(stderr, "%s\n", pcap_geterr(pc)); break; }
        if (!n) usleep(1000);
        time_t t = time(NULL);
        if (t != last) { report(pc, argv[2]); last = t; }
    }
    report(pc, argv[2]);
    pcap_close(pc);
    for (unsigned i = 0; i < used; ++i) free(batches[i].seen);
    return 0;
}
