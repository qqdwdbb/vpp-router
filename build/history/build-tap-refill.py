#!/usr/bin/env python3
"""Build an isolated TAP refill candidate using the installed build commands."""
import argparse
from pathlib import Path
import shlex
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--baseline', action='store_true')
    parser.add_argument('--fault-injection', action='store_true')
    parser.add_argument('--patch', type=Path, default=Path(__file__).resolve().parents[2]/'plugins/tap-rx-refill-retry.patch')
    args = parser.parse_args()
    build = Path('/opt/vpp-nic1-test/vpp-build')
    original = Path('/opt/vpp-nic1-test/src/vpp-stable-2606/src')
    output = args.output.resolve()
    source = output/'src'
    output.mkdir(parents=True, exist_ok=True)
    shutil.copytree(original/'plugins/tap', source/'plugins/tap')
    node = source/'plugins/tap/rx_node.c'
    if not args.baseline:
        subprocess.run(['patch', '-p1', '--batch', '-i', str(args.patch.resolve())],
                       cwd=output, check=True)
        shutil.copy2(args.patch, output/'tap-rx-refill-retry.patch')
    if args.fault_injection:
        text = node.read_text()
        anchor = '  n_slots = vlib_buffer_alloc_to_ring_from_pool ('
        assert text.count(anchor) == 1
        text = text.replace(anchor, '  n_slots = tap_test_fail_refill ? 0 : vlib_buffer_alloc_to_ring_from_pool (')
        text = text.replace('static_always_inline void\ntap_refill_vring',
                            'static u32 tap_test_fail_refill;\n\nstatic_always_inline void\ntap_refill_vring', 1)
        text += '''
/* Test build only: never included in the production candidate. */
static clib_error_t *
tap_refill_fault_cli (vlib_main_t *vm, unformat_input_t *input,
                      vlib_cli_command_t *cmd)
{
  u32 value;
  if (!unformat (input, "%u", &value) || value > 1)
    return clib_error_return (0, "expected 0 or 1");
  vlib_worker_thread_barrier_sync (vm);
  tap_test_fail_refill = value;
  vlib_worker_thread_barrier_release (vm);
  return 0;
}
VLIB_CLI_COMMAND (tap_refill_fault_command, static) = {
  .path = "test tap-refill-fail",
  .short_help = "test tap-refill-fail <0|1> (isolated tests only)",
  .function = tap_refill_fault_cli,
};
'''
        node.write_text(text)
    target = 'lib/aarch64-linux-gnu/vpp_plugins/tap_plugin.so'
    line = subprocess.check_output(['ninja', '-t', 'commands', target], cwd=build, text=True).splitlines()[-1]
    link = shlex.split(line.removeprefix(': && ').removesuffix(' && :'))
    assert not any(token in ('&&', ';', '|') for token in link)
    objects = [token for token in link if token.endswith('.o')]
    replacements = {}
    for obj in objects:
        line = subprocess.check_output(['ninja', '-t', 'commands', obj], cwd=build, text=True).splitlines()[-1]
        command = shlex.split(line)
        relative = Path(command[command.index('-c')+1]).relative_to(original)
        destination = output/obj
        destination.parent.mkdir(parents=True, exist_ok=True)
        command.insert(1, '-I'+str(source/'plugins'))
        for flag in ('-o', '-MF', '-MT', '-MQ'):
            if flag in command:
                command[command.index(flag)+1] = str(destination)+('.d' if flag == '-MF' else '')
        command[command.index('-c')+1] = str(source/relative)
        subprocess.run(command, cwd=build, check=True)
        replacements[obj] = str(destination)
    link = [replacements.get(token, token) for token in link]
    link[link.index('-o')+1] = str(output/'tap_plugin.so')
    subprocess.run(link, cwd=build, check=True)
    print(output/'tap_plugin.so')


if __name__ == '__main__':
    main()
