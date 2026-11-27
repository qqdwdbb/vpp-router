"""Run the patch's actual RX trigger and asynchronous controller on Linux."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


HARNESS = r'''
#include "dvfs_control.c"
#include <assert.h>

static void attribute(const char *dir, const char *name, unsigned value) {
    char path[1024];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *f = fopen(path, "w"); assert(f);
    fprintf(f, "%u\n", value); assert(fclose(f) == 0);
}
static unsigned floor_value(const char *dir) {
    char path[1024]; unsigned value = 0;
    snprintf(path, sizeof(path), "%s/scaling_min_freq", dir);
    FILE *f = fopen(path, "r"); assert(f);
    assert(fscanf(f, "%u", &value) == 1); fclose(f); return value;
}
static void wait_floor(const char *dir, unsigned target) {
    uint64_t deadline = dpdk_dvfs_now() + 500000000ULL;
    while (floor_value(dir) != target && dpdk_dvfs_now() < deadline) usleep(1000);
    assert(floor_value(dir) == target);
}
static void wait_releases(unsigned expected) {
    uint64_t deadline = dpdk_dvfs_now() + 500000000ULL;
    dpdk_dvfs_stats_t s;
    do { dpdk_dvfs_snapshot(&s); if (s.releases >= expected) return; usleep(1000); }
    while (dpdk_dvfs_now() < deadline);
    assert(0 && "controller did not finish lease");
}
static void triggers(void) {
    dpdk_dvfs_slot_t local[2] = {0}; local[0].enabled = 1;
    dpdk_dvfs_slots = local;
    dpdk_dvfs_event_fd = eventfd(0, EFD_NONBLOCK); assert(dpdk_dvfs_event_fd >= 0);
    dpdk_dvfs_rx_burst(1, 64); assert(local[1].last == 0);
    dpdk_dvfs_rx_burst(0, 7); assert(local[0].last == 0);
    dpdk_dvfs_rx_burst(0, 8); assert(local[0].last == 0);
    local[0].previous_small = dpdk_dvfs_now() - 2000000ULL;
    dpdk_dvfs_rx_burst(0, 8); assert(local[0].last == 0);
    dpdk_dvfs_rx_burst(0, 0); // even an empty PMD return breaks consecutive bursts
    dpdk_dvfs_rx_burst(0, 8); assert(local[0].last == 0);
    local[0].previous_small = dpdk_dvfs_now();
    dpdk_dvfs_rx_burst(0, 8); assert(local[0].last != 0);
    uint64_t events = 0; assert(read(dpdk_dvfs_event_fd, &events, 8) == 8 && events == 1);
    uint64_t first = local[0].first;
    dpdk_dvfs_rx_burst(0, 64); assert(local[0].first == first);
    assert(read(dpdk_dvfs_event_fd, &events, 8) == -1 && errno == EAGAIN);
    local[0].last = dpdk_dvfs_now() - DPDK_DVFS_HOLD_NS - 1;
    dpdk_dvfs_rx_burst(0, 16);
    assert(read(dpdk_dvfs_event_fd, &events, 8) == 8 && events == 1);
    close(dpdk_dvfs_event_fd); dpdk_dvfs_event_fd = -1; dpdk_dvfs_slots = 0;
}
static void lifecycle(const char *dir) {
    attribute(dir, "cpuinfo_min_freq", 408000);
    attribute(dir, "scaling_max_freq", 1800000);
    attribute(dir, "scaling_min_freq", 1200000);
    unsigned char enabled[2] = {1, 1};
    assert(dpdk_dvfs_start(dir, 408000, 1800001, enabled, 2) == EINVAL);
    assert(dpdk_dvfs_start(dir, 408000, 1800000, enabled, 2) == 0);
    assert(dpdk_dvfs_start(dir, 408000, 1800000, enabled, 2) == EBUSY);
    assert(floor_value(dir) == 408000); // explicit idle floor, no boost just from arming
    dpdk_dvfs_rx_burst(0, 16); wait_floor(dir, 1800000);
    usleep(60000); dpdk_dvfs_rx_burst(1, 16); // second worker extends same policy
    usleep(60000); assert(floor_value(dir) == 1800000);
    wait_releases(1); wait_floor(dir, 408000);
    dpdk_dvfs_stats_t s; dpdk_dvfs_snapshot(&s);
    assert(s.boosts == 1 && s.releases == 1 && s.failures == 0 && !s.active);
    dpdk_dvfs_sample_t *p = &s.samples[0];
    assert(p->trigger <= p->wake && p->wake <= p->write_begin);
    assert(p->write_begin <= p->write_end && p->write_end <= p->released);
    assert(p->released - p->latest >= DPDK_DVFS_HOLD_NS);
    assert(p->released - p->latest < 300000000ULL);
    dpdk_dvfs_rx_burst(0, 64); wait_floor(dir, 1800000);
    assert(dpdk_dvfs_stop() == 0 && floor_value(dir) == 1200000);
    assert(dpdk_dvfs_slots == 0 && dpdk_dvfs_stop() == 0);
    dpdk_dvfs_snapshot(&s); assert(!s.active);
    // A write failure must be visible, bounded to one request per episode.
    assert(dpdk_dvfs_start(dir, 408000, 1800000, enabled, 2) == 0);
    close(min_fd); min_fd = open_attribute(dir, "scaling_min_freq", O_RDONLY);
    dpdk_dvfs_rx_burst(0, 16); wait_releases(1);
    dpdk_dvfs_snapshot(&s); assert(s.boosts == 1 && s.failures == 1 && !s.active);
    assert(s.samples[0].error != 0);
    close(min_fd); min_fd = open_attribute(dir, "scaling_min_freq", O_RDWR);
    assert(dpdk_dvfs_stop() == 0);

}
int main(int argc, char **argv) {
    assert(argc == 3);
    if (!strcmp(argv[1], "triggers")) triggers();
    else lifecycle(argv[2]);
    return 0;
}
'''


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux CPUFreq/eventfd controller')
class AsyncDVFSTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = Path(cls.temp.name)
        patch = Path(__file__).resolve().parents[2] / 'patches/vpp/0049-dpdk-rx-burst-async-dvfs.patch'
        selected = None
        files = {}
        for line in patch.read_text().splitlines(keepends=True):
            if line.startswith('+++ '):
                name = line.strip().rsplit('/', 1)[-1]
                selected = name if name in ('dvfs.h', 'dvfs_control.c') else None
                if selected:
                    files[selected] = []
            elif selected and line.startswith('+'):
                files[selected].append(line[1:])
        for name, lines in files.items():
            (cls.root / name).write_text(''.join(lines))
        (cls.root / 'test.c').write_text(HARNESS)
        cls.binary = cls.root / 'test'
        subprocess.run(['cc', '-O2', '-Wall', '-Wextra', '-Werror', '-pthread',
                        '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                        str(cls.root / 'test.c'), '-o', str(cls.binary)], check=True)

    def run_harness(self, mode):
        subprocess.run([str(self.binary), mode, str(self.root)], check=True, timeout=10)

    def test_burst_thresholds_and_wake_coalescing(self):
        self.run_harness('triggers')

    def test_shared_hold_restore_and_errors(self):
        self.run_harness('lifecycle')


if __name__ == '__main__':
    unittest.main()
