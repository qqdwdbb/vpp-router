/* UDP sequence verifier for the Mac 2.5G receiver; one bounded test batch. */
#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static double now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}
int main(int argc, char **argv) {
    if (argc != 6) return 2;
    uint32_t run = (uint32_t)strtoul(argv[3], NULL, 10);
    uint32_t expected = (uint32_t)strtoul(argv[4], NULL, 10);
    double deadline = now() + strtod(argv[5], NULL);
    if (!expected || expected > 60000000) return 2;
    unsigned char *seen = calloc((expected + 7u) / 8u, 1);
    int fd = socket(AF_INET, SOCK_DGRAM, 0), size = 4 * 1024 * 1024;
    if (!seen || fd < 0) return 1;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size))) {
        perror("SO_RCVBUF"); return 1;
    }
    socklen_t slen = sizeof(size);
    getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, &slen);
    struct timeval timeout = {.tv_sec = 0, .tv_usec = 100000};
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout))) return 1;
    struct sockaddr_in addr = {.sin_family = AF_INET,
        .sin_port = htons((uint16_t)strtoul(argv[2], NULL, 10))};
    if (inet_pton(AF_INET, argv[1], &addr.sin_addr) != 1 ||
        bind(fd, (struct sockaddr *)&addr, sizeof(addr))) {
        perror("bind"); return 1;
    }
    struct in_addr source;
    inet_pton(AF_INET, "203.0.113.10", &source);
    uint64_t unique = 0, duplicate = 0, reordered = 0, foreign = 0, bytes = 0;
    uint32_t highest = 0;
    double first = 0, last = 0;
    unsigned char payload[2048];
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("{\"ready\":true,\"rcvbuf\":%d}\n", size);
    while (now() < deadline && unique < expected) {
        struct sockaddr_in peer;
        socklen_t plen = sizeof(peer);
        ssize_t n = recvfrom(fd, payload, sizeof(payload), 0,
                             (struct sockaddr *)&peer, &plen);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) continue;
            perror("recvfrom"); return 1;
        }
        uint32_t batch = 0, seq = 0;
        if (n >= 12) {
            memcpy(&batch, payload + 4, 4); batch = ntohl(batch);
            memcpy(&seq, payload + 8, 4); seq = ntohl(seq);
        }
        if (n != 18 || memcmp(payload, "VRS2", 4) || batch != run ||
            peer.sin_addr.s_addr != source.s_addr || ntohs(peer.sin_port) != 50000 ||
            seq >= expected) { foreign++; continue; }
        unsigned char mask = (unsigned char)(1u << (seq & 7u));
        if (seen[seq >> 3] & mask) { duplicate++; continue; }
        seen[seq >> 3] |= mask;
        double t = now();
        if (!first) first = t;
        last = t;
        if (unique && seq < highest) reordered++;
        if (seq > highest) highest = seq;
        unique++; bytes += (uint64_t)n;
    }
    printf("{\"run\":%u,\"expected\":%u,\"unique\":%llu,\"missing\":%llu,"
           "\"duplicates\":%llu,\"reordered\":%llu,\"foreign\":%llu,"
           "\"payload_bytes\":%llu,\"receive_span_s\":%.9f,\"rcvbuf\":%d}\n",
           run, expected, (unsigned long long)unique,
           (unsigned long long)(expected - unique), (unsigned long long)duplicate,
           (unsigned long long)reordered, (unsigned long long)foreign,
           (unsigned long long)bytes, last - first, size);
    close(fd); free(seen);
    return 0;
}
