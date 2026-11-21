#!/usr/bin/env python3
"""Build EI expiry and user deletion fixes from the deployed resource fix.

Does not install the plugin or restart VPP.
"""
import argparse
from pathlib import Path
import shlex
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    base = Path('/opt/vpp-vrouter-migration')
    parser.add_argument('--source-dir', type=Path, default=base / 'nat-resource-fix-20261019')
    parser.add_argument('--cli-source', type=Path, default=base / 'source/nat44-ei-handoff/src/plugins/nat/nat44-ei/nat44_ei_cli.c')
    parser.add_argument('--output-dir', type=Path, default=base / 'nat44-ei-expiry')
    args = parser.parse_args()
    output = args.output_dir
    output.mkdir(parents=True, exist_ok=True)
    main_source = (args.source_dir / 'nat44_ei.c').read_text()
    assert 'host-fallback-v1 pool-receive-v1' in main_source
    start = main_source.index('int\nnat44_ei_user_del (')
    end = main_source.index('\nvoid\nnat44_ei_static_mapping_del_sessions', start)
    # CLI/API already stop workers. Use the actual owning thread index.
    main_source = main_source[:start] + '''int
nat44_ei_user_del (ip4_address_t *addr, u32 fib_index)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  nat44_ei_main_per_thread_data_t *tnm;
  nat44_ei_user_key_t key = { .addr = *addr, .fib_index = fib_index };
  clib_bihash_kv_8_8_t kv = { .key = key.as_u64 }, value;
  int rv = 1;
  if (!nm->enabled)
    return rv;
  vec_foreach (tnm, nm->per_thread_data)
    {
      if (!clib_bihash_search_8_8 (&tnm->user_hash, &kv, &value))
        {
          nat44_ei_user_del_sessions (
            pool_elt_at_index (tnm->users, value.value),
            tnm - nm->per_thread_data);
          rv = 0;
        }
    }
  return rv;
}
''' + main_source[end:]
    # The last session deletion frees the user's list head. Snapshot indices
    # first, so the iterator never dereferences that freed head afterwards.
    start = main_source.index('static_always_inline void\nnat44_ei_user_del_sessions (')
    end = main_source.index('\nint\nnat44_ei_user_del (', start)
    main_source = main_source[:start] + '''static_always_inline void
nat44_ei_user_del_sessions (nat44_ei_user_t *u, u32 thread_index)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  nat44_ei_main_per_thread_data_t *tnm = &nm->per_thread_data[thread_index];
  u32 *indices = 0, *index;
  u32 head = u->sessions_per_user_list_head_index;
  u32 next = tnm->list_pool[head].next;
  while (next != head)
    {
      vec_add1 (indices, tnm->list_pool[next].value);
      next = tnm->list_pool[next].next;
    }
  vec_foreach (index, indices)
    {
      nat44_ei_session_t *s = pool_elt_at_index (tnm->sessions, *index);
      nat44_ei_free_session_data_v2 (nm, s, thread_index, 0);
      nat44_ei_delete_session (nm, s, thread_index);
    }
  vec_free (indices);
}
''' + main_source[end:]
    main_source += '\n' + Path(__file__).with_name('nat44-ei-cleaner.c').read_text()
    cli_source = args.cli_source.read_text()
    old = 'rv = nat44_ei_user_del (&addr, fib_index);\n\n  if (!rv)'
    assert cli_source.count(old) == 1
    cli_source = cli_source.replace(old, old.replace('if (!rv)', 'if (rv)'))
    build = Path('/opt/vpp-nic1-test/vpp-build')
    template = shlex.split((base / 'baseline/nat44-ei-compile-command.txt').read_text())
    # Preserve the deployed slowpath's port allocation rollback fix.
    rollback_object = args.source_dir / 'nat44_ei_in2out.c.o'
    assert rollback_object.is_file()
    replacements = {
        'CMakeFiles/plugins/nat/CMakeFiles/nat44_ei_plugin.dir/nat44-ei/nat44_ei_in2out.c.o': str(rollback_object),
    }
    for name, content in (('nat44_ei', main_source), ('nat44_ei_cli', cli_source)):
        source = output / (name + '.c')
        source.write_text(content)
        obj = output / (name + '.c.o')
        command = template.copy()
        for flag in ('-o', '-MF', '-MT', '-MQ'):
            if flag in command:
                command[command.index(flag) + 1] = str(obj) + ('.d' if flag == '-MF' else '')
        command[command.index('-c') + 1] = str(source)
        subprocess.run(command, cwd=build, check=True)
        original = 'CMakeFiles/plugins/nat/CMakeFiles/nat44_ei_plugin.dir/nat44-ei/' + name + '.c.o'
        replacements[original] = str(obj)
    line = (base / 'baseline/nat44-ei-link-command.txt').read_text().strip()
    command = shlex.split(line.removeprefix(': && ').removesuffix(' && :'))
    assert not any(token in ('&&', ';', '|') for token in command)
    assert all(key in command for key in replacements)
    command = [replacements.get(token, token) for token in command]
    command[command.index('-o') + 1] = str(output / 'nat44_ei_plugin.so')
    subprocess.run(command, cwd=build, check=True)
    print(output / 'nat44_ei_plugin.so')


if __name__ == '__main__':
    main()
