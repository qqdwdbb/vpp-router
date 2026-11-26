"""VPP worker CPUs are kept for VPP: CPU lists, the systemd default, and the post-start fixes."""
from pathlib import Path
import subprocess

import pytest


SOURCE = (Path(__file__).parents[2] / "deploy/install/vpp-router-install.sh").read_text()


def function(name):
    start = SOURCE.index(name + "() {")
    return SOURCE[start:SOURCE.index("\n}", start) + 2] + "\n"


def run(script, **env):
    return subprocess.run(["bash", "-c", script], check=True, capture_output=True, text=True,
                          env={"PATH": "/usr/bin:/bin", **env}).stdout


LISTS = function("cpu_range") + function("worker_cpus") + function("system_cpus")


def test_reconfigure_counts_worker_cpus_excluded_from_installer_affinity():
    script = r'''
uname() { case "$1" in -s) echo Linux ;; -m) echo aarch64 ;; -r) echo test ;; esac; }
id() { echo 0; }
command() { return 0; }
nproc() { if [ "${1:-}" = --all ]; then echo 8; else echo 7; fi; }
info() { :; }; note() { :; }
die() { echo "$*" >&2; exit 1; }
JOBS=1 MODE=config-only WORKERS=1
''' + function("detect_platform") + LISTS + r'''
detect_platform
echo "$CPUS $(system_cpus)"
'''
    assert run(script).strip() == "8 0-1,3-7"


@pytest.mark.parametrize("cpus,workers,worker,system", [
    (8, 1, "2", "0-1,3-7"),
    (8, 3, "2-4", "0-1,5-7"),
    (4, 2, "2-3", "0-1"),
    (3, 1, "2", "0-1"),
    (8, 0, "", ""),
    (1, 0, "", ""),
])
def test_cpu_lists(cpus, workers, worker, system):
    out = run(LISTS + 'echo "w=$(worker_cpus) s=$(system_cpus)"', CPUS=str(cpus), WORKERS=str(workers))
    assert out.strip() == f"w={worker} s={system}"


def test_systemd_default_affinity_leaves_out_the_worker_cpus():
    out = run(LISTS + function("gen_systemd_cpu") + "gen_systemd_cpu", CPUS="8", WORKERS="1")
    lines = out.splitlines()
    assert lines[1:] == ["[Manager]", "CPUAffinity=0-1,3-7"]
    assert "（2）" in lines[0]


def test_reconfigure_updates_and_removes_default_affinity(tmp_path):
    script = r'''
set -eu
CONF="$TEST_ROOT/conf" STATE="$TEST_ROOT/state"
STARTUP="$CONF/router.conf" SYSTEMD_CPU="$TEST_ROOT/systemd/90-vpp-router-cpu.conf"
CPUS=8 WORKERS=1 DNSMASQ=0
info() { :; }; note() { :; }; warn() { :; }
save_ports() { :; }; startup_nat_mode() { :; }; check_nat_mode_change() { :; }
pinned_wan_mac() { :; }; rewrite_nat_mode_files() { :; }; write_dnsmasq() { :; }
gen_startup() { echo '# vpp-router-install.sh'; }
gen_router_vpp() { echo '# vpp-router-install.sh'; }
gen_env() { echo '# vpp-router-install.sh'; }
''' + LISTS + function("gen_systemd_cpu") + function("write_config") + r'''
write_config
test "$CPU_CONF_CHANGED" = 1
grep -q '^CPUAffinity=0-1,3-7$' "$SYSTEMD_CPU"
CPU_CONF_CHANGED=0
write_config
test "$CPU_CONF_CHANGED" = 0
WORKERS=0
write_config
test "$CPU_CONF_CHANGED" = 1
test ! -e "$SYSTEMD_CPU"
'''
    run(script, TEST_ROOT=str(tmp_path))


def test_vpp_unit_keeps_all_cpus_only_when_workers_are_kept():
    units = function("write_units")
    assert 'affinity="CPUAffinity=$(cpu_range 0 $((CPUS - 1)))"' in units
    assert "\n$affinity\n" in units
    assert "systemctl daemon-reexec" in units


def make_task(proc, pid, tid, cmdline, allowed, comm="x"):
    if cmdline is not None:
        (proc / str(pid)).mkdir(exist_ok=True)
        (proc / str(pid) / "cmdline").write_bytes(cmdline)
    task = proc / str(pid) / "task" / str(tid)
    task.mkdir(parents=True)
    (task / "status").write_text(f"Name:\t{comm}\nCpus_allowed_list:\t{allowed}\n")
    (task / "comm").write_text(comm + "\n")


def test_isolate_moves_only_user_tasks_allowed_everywhere(tmp_path):
    proc = tmp_path / "proc"
    proc.mkdir()
    make_task(proc, 100, 100, b"vpp\0-c\0", "0-7")          # VPP itself
    make_task(proc, 100, 101, None, "1")
    make_task(proc, 200, 200, b"sing-box\0", "0-7")         # moved
    make_task(proc, 200, 201, None, "0-7")                  # its second thread too
    make_task(proc, 300, 300, b"heproxy\0", "3")            # custom affinity, kept
    make_task(proc, 400, 400, b"", "0-7")                   # kernel thread, kept
    online = tmp_path / "online"
    online.write_text("0-7\n")
    calls = tmp_path / "calls"
    script = (
        'log() { printf "%s\\n" "$*"; }\n'
        f'taskset_stub() {{ echo "$*" >> {calls}; }}\n'
        + function("isolate_workers") + "isolate_workers")
    out = run(script, PROC=str(proc), CPU_ONLINE=str(online), MAINPID="100", SYSTEM_CPUS="0-1,3-7",
              TASKSET="taskset_stub", CPU_AFFINITY_STATE=str(tmp_path / "managed"))
    assert sorted(calls.read_text().split("\n")[:-1]) == ["-p -c 0-1,3-7 200", "-p -c 0-1,3-7 201"]
    assert "2 个线程" in out


def test_intr_thread_gets_fifo_and_nothing_else(tmp_path):
    proc = tmp_path / "proc"
    proc.mkdir()
    for tid, comm in ((100, "vpp_main"), (101, "dpdk-intr"), (102, "vpp_wk_0")):
        make_task(proc, 100, tid, b"vpp\0" if tid == 100 else None, "1", comm)
    calls = tmp_path / "calls"
    script = (
        'log() { printf "%s\\n" "$*"; }\n'
        f'chrt_stub() {{ echo "$*" >> {calls}; }}\n'
        + function("intr_fifo") + "intr_fifo")
    out = run(script, PROC=str(proc), MAINPID="100", CHRT="chrt_stub")
    assert calls.read_text() == "-f -p 10 101\n"
    assert "SCHED_FIFO 10" in out


@pytest.mark.parametrize("fail", ["0", "1"])
def test_switch_and_rollback_migrate_previous_managed_affinity(tmp_path, fail):
    proc = tmp_path / "proc"
    proc.mkdir()
    make_task(proc, 100, 100, b"vpp\0", "2")
    make_task(proc, 200, 200, b"service\0", "0-1,3-7")
    make_task(proc, 201, 201, b"other\0", "0-1,3-7")
    make_task(proc, 300, 300, b"custom\0", "3")
    online = tmp_path / "online"
    online.write_text("0-7\n")
    state = tmp_path / "managed"
    state.write_text("0-1,3-7\n")
    script = r'''
set -eu
log() { :; }
taskset_stub() {
    local tid=$4
    if [ "$FAIL" = 1 ] && [ "$tid" = 200 ]; then return 1; fi
    printf 'Cpus_allowed_list:\t%s\n' "$3" >"$PROC/$tid/task/$tid/status"
}
''' + function("isolate_workers") + r'''
SYSTEM_CPUS=0-3,5-7
if isolate_workers; then test "$FAIL" = 0; else test "$FAIL" = 1; fi
FAIL=0 SYSTEM_CPUS=0-1,3-7
isolate_workers
grep -q '0-1,3-7$' "$PROC/200/task/200/status"
grep -q '0-1,3-7$' "$PROC/201/task/201/status"
SYSTEM_CPUS=
isolate_workers
grep -q '0-7$' "$PROC/200/task/200/status"
grep -q '0-7$' "$PROC/201/task/201/status"
grep -q '3$' "$PROC/300/task/300/status"
grep -q '2$' "$PROC/100/task/100/status"
'''
    run(script, PROC=str(proc), MAINPID="100", CPU_ONLINE=str(online),
        CPU_AFFINITY_STATE=str(state), TASKSET="taskset_stub", FAIL=fail)


def test_post_runs_both_after_vpp_answers():
    post = function("post")
    assert post.index("set_interrupt") < post.index("isolate_workers") < post.index("intr_fifo")
    assert 'if [ "${SYSTEM_CPUS+x}" = x ]; then isolate_workers || return 1; fi' in post
    # the panel can switch NICs to interrupt receive at run time, so not only when RX_MODE says so
    assert "\tintr_fifo || true\n" in post
