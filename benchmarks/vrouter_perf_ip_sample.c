/* Bounded user-IP sampling of one VPP worker with perf_event_open.
 * No process stop, ptrace, or network configuration changes. */
#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <linux/perf_event.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static double now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static void ring_copy(void *dst, const char *data, size_t size,
                      uint64_t tail, size_t length) {
    size_t offset = tail % size;
    size_t first = size - offset;
    if (first > length) first = length;
    memcpy(dst, data + offset, first);
    if (first < length) memcpy((char *)dst + first, data, length - first);
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    int tid = atoi(argv[1]);
    double seconds = atof(argv[2]);
    if (tid <= 0 || seconds <= 0 || seconds > 40) return 2;
    struct perf_event_attr attr = {0};
    attr.size = sizeof(attr);
    attr.type = PERF_TYPE_SOFTWARE;
    attr.config = PERF_COUNT_SW_CPU_CLOCK;
    attr.sample_freq = 499;
    attr.freq = 1;
    attr.disabled = 1;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;
    attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TIME;
    attr.wakeup_events = 1;
    int fd = syscall(__NR_perf_event_open, &attr, tid, -1, -1, 0);
    if (fd < 0) { perror("perf_event_open"); return 1; }
    size_t page = (size_t)sysconf(_SC_PAGESIZE), size = page * 64;
    void *base = mmap(NULL, page + size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (base == MAP_FAILED) { perror("mmap"); close(fd); return 1; }
    struct perf_event_mmap_page *meta = base;
    const char *data = (char *)base + page;
    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    if (ioctl(fd, PERF_EVENT_IOC_ENABLE, 0)) { perror("enable"); return 1; }
    uint64_t tail = 0, lost = 0;
    double start = now();
    printf("{\"tid\":%d,\"frequency\":499,\"samples\":[", tid);
    int comma = 0;
    do {
        uint64_t head = __atomic_load_n(&meta->data_head, __ATOMIC_ACQUIRE);
        while (tail < head) {
            struct perf_event_header hdr;
            ring_copy(&hdr, data, size, tail, sizeof(hdr));
            if (hdr.size < sizeof(hdr) || hdr.size > size || tail + hdr.size > head) return 1;
            if (hdr.type == PERF_RECORD_SAMPLE && hdr.size >= sizeof(hdr) + 16) {
                uint64_t sample[2];
                ring_copy(sample, data, size, tail + sizeof(hdr), sizeof(sample));
                printf("%s[\"0x%" PRIx64 "\",%" PRIu64 "]", comma ? "," : "", sample[0], sample[1]);
                comma = 1;
            } else if (hdr.type == PERF_RECORD_LOST && hdr.size >= sizeof(hdr) + 16) {
                uint64_t record[2];
                ring_copy(record, data, size, tail + sizeof(hdr), sizeof(record));
                lost += record[1];
            }
            tail += hdr.size;
        }
        __atomic_store_n(&meta->data_tail, tail, __ATOMIC_RELEASE);
        usleep(10000);
    } while (now() - start < seconds);
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    printf("],\"lost\":%" PRIu64 ",\"duration_s\":%.6f}\n", lost, now() - start);
    munmap(base, page + size);
    close(fd);
    return 0;
}
