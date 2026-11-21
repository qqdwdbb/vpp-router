#!/usr/bin/env python3
"""Build worker reconfiguration guards and HA/management single-worker fixes.

Uses the previously deployed single-worker candidate as its exact base.
Does not install plugins or restart VPP.
"""
import argparse
from pathlib import Path
import shlex
import subprocess


def replace_once(text, old, new):
    assert text.count(old) == 1, old
    return text.replace(old, new)


def main():
    base = Path('/opt/vpp-vrouter-migration')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-dir', type=Path, default=base / 'nat44-ei-single-worker')
    parser.add_argument('--output-dir', type=Path, default=base / 'nat44-ei-thread-control')
    args = parser.parse_args()
    output = args.output_dir
    output.mkdir(parents=True, exist_ok=True)
    upstream = Path('/opt/vpp-nic1-test/src/vpp-stable-2606/src/plugins/nat/nat44-ei')
    main_source = (args.source_dir / 'nat44_ei.c').read_text()
    main_source = replace_once(main_source,
        '  if (clib_bitmap_last_set (bitmap) >= nm->num_workers)\n',
        '  if (clib_bitmap_is_zero (bitmap) ||\n'
        '      clib_bitmap_last_set (bitmap) >= nm->num_workers)\n')
    main_source = replace_once(main_source, '  vec_free (nm->workers);\n  clib_bitmap_foreach (i, bitmap)', '''  /* Reapplying the same set must not disturb live sessions or port ranges. */
  u32 selected = 0;
  int same = 1;
  clib_bitmap_foreach (i, bitmap)
    {
      if (selected >= vec_len (nm->workers) || nm->workers[selected] != i)
        same = 0;
      selected++;
    }
  if (same && selected == vec_len (nm->workers))
    return 0;

  /* Even an empty session pool can have packets queued for old workers. */
  if (nm->enabled)
    return VNET_API_ERROR_INSTANCE_IN_USE;

  /* CLI/API hold the worker barrier. It cannot migrate existing owners. */
  nat44_ei_main_per_thread_data_t *tnm;
  vec_foreach (tnm, nm->per_thread_data)
    if (pool_elts (tnm->sessions))
      return VNET_API_ERROR_INSTANCE_IN_USE;
  if (pool_elts (nm->static_mappings))
    return VNET_API_ERROR_INSTANCE_IN_USE;

  vec_free (nm->workers);
  clib_bitmap_foreach (i, bitmap)''')

    cli = (base / 'nat44-ei-expiry/nat44_ei_cli.c').read_text()
    cli = replace_once(cli, 'if (nm->num_workers > 1)', 'if (nm->num_workers > 0)')
    cli = replace_once(cli, 'Supported only if 2 or more workes available.',
                       'Supported only if at least one worker is available.')
    cli = replace_once(cli, '    case VNET_API_ERROR_INVALID_WORKER:\n', '''    case VNET_API_ERROR_INSTANCE_IN_USE:
      error = clib_error_return (0, "Worker set is in use: disable NAT before changing workers.");
      goto done;
    case VNET_API_ERROR_INVALID_WORKER:
''')
    api = (upstream / 'nat44_ei_api.c').read_text()
    api = replace_once(api, 'if (nm->num_workers < 2)', 'if (nm->num_workers < 1)')
    ha = (upstream / 'nat44_ei_ha.c').read_text()
    ha = replace_once(ha, 'if (ha->num_workers > 1)', 'if (ha->num_workers > 0)')
    ha = replace_once(ha, '  ASSERT (thread_index == nat_value_get_thread_index (&value));',
                     '  if (thread_index != nat_value_get_thread_index (&value))\n    return;')
    anchor = '  s = pool_elt_at_index (tnm->sessions, nat_value_get_session_index (&value));\n  s->total_pkts = total_pkts;'
    ha = replace_once(ha, anchor,
        '  if (thread_index != nat_value_get_thread_index (&value))\n    return;\n' + anchor)
    ha = replace_once(ha, '_(BAD_VERSION, "bad-version")',
                     '_(BAD_VERSION, "bad-version") ' + chr(92) + '\n_(BAD_THREAD, "bad-thread-index")')
    ha = replace_once(ha, '      ti[0] = clib_net_to_host_u32 (h0->thread_index);', '''      u32 target = clib_net_to_host_u32 (h0->thread_index);
      /* Invalid targets go to the current thread for checked rejection. */
      ti[0] = target < vlib_get_n_threads () ? target : thread_index;''')
    ha = replace_once(ha, 'if (h0->version != NAT_HA_VERSION)', '''if (clib_net_to_host_u32 (h0->thread_index) != thread_index)
        {
          b0->error = node->errors[NAT_HA_ERROR_BAD_THREAD];
          goto done0;
        }

      if (h0->version != NAT_HA_VERSION)''')
    sources = {'nat44_ei': main_source, 'nat44_ei_cli': cli,
               'nat44_ei_api': api, 'nat44_ei_ha': ha}
    build = Path('/opt/vpp-nic1-test/vpp-build')
    template = shlex.split((base / 'baseline/nat44-ei-compile-command.txt').read_text())
    prefix = 'CMakeFiles/plugins/nat/CMakeFiles/nat44_ei_plugin.dir/nat44-ei/'
    replacements = {prefix + 'nat44_ei_in2out.c.o': str(base / 'nat-resource-fix-20261019/nat44_ei_in2out.c.o')}
    for name, content in sources.items():
        source, obj = output / (name + '.c'), output / (name + '.c.o')
        source.write_text(content)
        command = template.copy()
        for flag in ('-o', '-MF', '-MT', '-MQ'):
            if flag in command:
                command[command.index(flag) + 1] = str(obj) + ('.d' if flag == '-MF' else '')
        command[command.index('-c') + 1] = str(source)
        subprocess.run(command, cwd=build, check=True)
        replacements[prefix + name + '.c.o'] = str(obj)
    line = (base / 'baseline/nat44-ei-link-command.txt').read_text().strip()
    command = shlex.split(line.removeprefix(': && ').removesuffix(' && :'))
    assert all(key in command for key in replacements)
    command = [replacements.get(token, token) for token in command]
    command[command.index('-o') + 1] = str(output / 'nat44_ei_plugin.so')
    subprocess.run(command, cwd=build, check=True)
    print(output / 'nat44_ei_plugin.so')


if __name__ == '__main__':
    main()
