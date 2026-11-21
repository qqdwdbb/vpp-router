/* Darwin UDP drain for the physical NAT benchmark. SIGUSR1 prints counters. */
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t report, stop;
static void handle(int sig) {
    if (sig == SIGUSR1) report = 1;
    else stop = 1;
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    int fd = socket(AF_INET, SOCK_DGRAM, 0), size = 4 * 1024 * 1024;
    if (fd < 0) { perror("socket"); return 1; }
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)))
        perror("SO_RCVBUF");
    struct timeval timeout = { .tv_sec = 0, .tv_usec = 100000 };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout))) return 1;
    struct sockaddr_in addr = { .sin_family = AF_INET,
        .sin_port = htons((unsigned short)atoi(argv[2])) };
    if (inet_pton(AF_INET, argv[1], &addr.sin_addr) != 1 ||
        bind(fd, (struct sockaddr *)&addr, sizeof(addr))) {
        perror("bind"); return 1;
    }
    struct sigaction action = { .sa_handler = handle };
    sigemptyset(&action.sa_mask);
    sigaction(SIGUSR1, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    uint64_t packets = 0, bytes = 0;
    char buffer[65536];
    setvbuf(stdout, NULL, _IOLBF, 0);
    puts("READY");
    while (!stop) {
        ssize_t n = recv(fd, buffer, sizeof(buffer), 0);
        if (n >= 0) { packets++; bytes += (uint64_t)n; }
        else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            perror("recv"); return 1;
        }
        if (report) {
            printf("{\"packets\":%llu,\"bytes\":%llu}\n",
                   (unsigned long long)packets, (unsigned long long)bytes);
            report = 0;
        }
    }
    printf("{\"packets\":%llu,\"bytes\":%llu,\"final\":true}\n",
           (unsigned long long)packets, (unsigned long long)bytes);
    close(fd);
    return 0;
}
