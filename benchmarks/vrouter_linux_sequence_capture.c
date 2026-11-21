/* Linux namespace sequence receiver: AF_PACKET/TPACKET_V3, bounded ring and run. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "vrouter_sequence_tracker.h"
static uint64_t received, dropped, freezes;
static volatile sig_atomic_t stop;
static void handle(int sig) { (void)sig; stop=1; }
static double monotonic(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t);
    return t.tv_sec+t.tv_nsec/1e9;
}
static void report(int fd, const char *path) {
    struct tpacket_stats_v3 stats={0}; socklen_t n=sizeof(stats);
    if (getsockopt(fd,SOL_PACKET,PACKET_STATISTICS,&stats,&n)) { perror("statistics"); exit(1); }
    /* PACKET_STATISTICS resets on read; publish cumulative counters. */
    received+=stats.tp_packets; dropped+=stats.tp_drops; freezes+=stats.tp_freeze_q_cnt;
    char tmp[1024];
    if (snprintf(tmp,sizeof(tmp),"%s.new",path)>=(int)sizeof(tmp)) exit(2);
    FILE *f=fopen(tmp,"w"); if (!f) { perror("report"); exit(1); }
    fprintf(f,"{\"method\":\"AF_PACKET_TPACKET_V3\",\"capture_received\":%llu,\"capture_dropped\":%llu,\"capture_freezes\":%llu,\"invalid\":%llu,\"batches\":[",
        (unsigned long long)received,(unsigned long long)dropped,
        (unsigned long long)freezes,(unsigned long long)invalid);
    write_batches(f);
    fputs("]}\n",f); fclose(f); chmod(tmp,0644);
    if (rename(tmp,path)) { perror("rename"); exit(1); }
}
int main(int argc,char **argv) {
    if (argc!=5) return 2;
    int seconds=atoi(argv[3]); struct in_addr destination;
    if (seconds<1 || seconds>1800 || inet_pton(AF_INET,argv[4],&destination)!=1) return 2;
    unsigned index=if_nametoindex(argv[1]); if (!index) { perror("interface"); return 1; }
    int guard=socket(AF_INET,SOCK_DGRAM,0);
    struct sockaddr_in udp={.sin_family=AF_INET,.sin_port=htons(45996),.sin_addr=destination};
    if (guard<0 || bind(guard,(struct sockaddr *)&udp,sizeof(udp))) { perror("UDP guard"); return 1; }
    /* ETH_P_ALL taps delivery before netdev ingress drops the test stream. */
    int fd=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL)), version=TPACKET_V3;
    if (fd<0 || setsockopt(fd,SOL_PACKET,PACKET_VERSION,&version,sizeof(version))) { perror("packet socket"); return 1; }
    /* Fixed IPv4/UDP layout of the existing 64-byte TRex test stream. */
    struct sock_filter code[]={
        BPF_STMT(BPF_LD|BPF_H|BPF_ABS,12), BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,ETH_P_IP,0,13),
        BPF_STMT(BPF_LD|BPF_B|BPF_ABS,14), BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,0x45,0,11),
        BPF_STMT(BPF_LD|BPF_B|BPF_ABS,23), BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,17,0,9),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,26), BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,0xcb00710a,0,7),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,30), BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,ntohl(destination.s_addr),0,5),
        BPF_STMT(BPF_LD|BPF_H|BPF_ABS,34), BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,50000,0,3),
        BPF_STMT(BPF_LD|BPF_H|BPF_ABS,36), BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,45996,0,1),
        BPF_STMT(BPF_RET|BPF_K,96), BPF_STMT(BPF_RET|BPF_K,0)};
    struct sock_fprog filter={.len=sizeof(code)/sizeof(code[0]),.filter=code};
    if (setsockopt(fd,SOL_SOCKET,SO_ATTACH_FILTER,&filter,sizeof(filter))) { perror("filter"); return 1; }
    struct tpacket_req3 req={.tp_block_size=1u<<20,.tp_block_nr=64,.tp_frame_size=2048,
        .tp_frame_nr=64*(1u<<20)/2048,.tp_retire_blk_tov=10};
    if (setsockopt(fd,SOL_PACKET,PACKET_RX_RING,&req,sizeof(req))) { perror("ring"); return 1; }
    size_t size=(size_t)req.tp_block_size*req.tp_block_nr;
    unsigned char *ring=mmap(NULL,size,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
    if (ring==MAP_FAILED) { perror("mmap"); return 1; }
    struct sockaddr_ll address={.sll_family=AF_PACKET,.sll_protocol=htons(ETH_P_ALL),.sll_ifindex=(int)index};
    if (bind(fd,(struct sockaddr *)&address,sizeof(address))) { perror("packet bind"); return 1; }
    signal(SIGTERM,handle); signal(SIGINT,handle);
    char stop_path[1024];
    if (snprintf(stop_path,sizeof(stop_path),"%s.stop",argv[2])>=(int)sizeof(stop_path)) return 2;
    double end=monotonic()+seconds, last=0; unsigned block=0;
    report(fd,argv[2]); puts("READY TPACKET_V3"); fflush(stdout);
    while (!stop && monotonic()<end && access(stop_path,F_OK)!=0) {
        struct tpacket_block_desc *bd=(void *)(ring+(size_t)block*req.tp_block_size);
        if (!(__atomic_load_n(&bd->hdr.bh1.block_status,__ATOMIC_ACQUIRE)&TP_STATUS_USER)) {
            struct pollfd wait={.fd=fd,.events=POLLIN};
            if (poll(&wait,1,100)<0 && errno!=EINTR) { perror("poll"); return 1; }
        } else {
            unsigned offset=bd->hdr.bh1.offset_to_first_pkt;
            for (unsigned i=0;i<bd->hdr.bh1.num_pkts;i++) {
                if (offset>req.tp_block_size-sizeof(struct tpacket3_hdr)) return 1;
                struct tpacket3_hdr *h=(void *)((unsigned char *)bd+offset);
                if (h->tp_mac>req.tp_block_size-offset || h->tp_snaplen>req.tp_block_size-offset-h->tp_mac) return 1;
                packet((unsigned char *)h+h->tp_mac,h->tp_snaplen,h->tp_sec+h->tp_nsec/1e9);
                if (i+1<bd->hdr.bh1.num_pkts && (!h->tp_next_offset || h->tp_next_offset>req.tp_block_size-offset)) return 1;
                offset+=h->tp_next_offset;
            }
            __atomic_store_n(&bd->hdr.bh1.block_status,TP_STATUS_KERNEL,__ATOMIC_RELEASE);
            block=(block+1)%req.tp_block_nr;
        }
        double now=monotonic();
        if (now-last>=1) { report(fd,argv[2]); last=now; }
    }
    report(fd,argv[2]); munmap(ring,size); close(fd); close(guard);
    for (unsigned i=0;i<used;i++) free(batches[i].seen);
    return 0;
}
