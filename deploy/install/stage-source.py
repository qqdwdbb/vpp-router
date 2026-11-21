#!/usr/bin/env python3
"""Stage the repository into the source layout the installer and cutover expect.

The repository keeps deploy/ and tools/ at the top level. Installed systems use
scripts/ (from tools/) and scripts/vrouter/ (from deploy/); systemd units and the
recovery tool refer to those paths. cutover/prepare.py must run from the staged
tree, not directly from the repository.

--profile applies a device profile: {"replace": {"neutral name": "device value"}}
to file contents and names. See deploy/profiles/example.profile.json.
"""
import argparse
import json
from pathlib import Path
import re
import shutil

ROOT = Path(__file__).resolve().parents[2]
IGNORE = shutil.ignore_patterns(
    '.*', '__pycache__', '*.pyc', 'dist', 'out', 'artifacts', 'work',
    '*.profile.json', '*.pem', '*.key', '*.crt', '*.p12', 'ipsec.secrets',
    '*.o', '*.so', '*.so.*', '*.ko', '*.log', '*.pcap', '*.pcapng',
    '*.zst', '*.tar', '*.tar.gz', '*.tgz', 'core', 'core.*', '*.core',
    '*~', '*.swp', '*.tmp', '*.bak', '*.orig', '*.rej',
)
LAYOUT = (('tools', 'scripts'), ('deploy', 'scripts/vrouter'), ('plugins', 'plugins'),
          ('patches', 'patches'), ('platforms', 'platforms'))
UNCHANGED_SUFFIXES = ('.patch', '.sum')


def ignore_local_files(directory, names):
    return IGNORE(directory, names) | {name for name in names if (Path(directory) / name).is_symlink()}


def compile_profile(profile):
    replace = profile.get('replace', {})
    if not replace:
        return None, replace
    keys = sorted(replace, key=len, reverse=True)
    return re.compile('|'.join(re.escape(key) for key in keys)), replace


def apply_profile(output, profile):
    pattern, replace = compile_profile(profile)
    if pattern is None:
        return
    swap = lambda text: pattern.sub(lambda match: replace[match[0]], text)
    for path in sorted((p for p in output.rglob('*') if p.is_file()), key=lambda p: len(p.parts), reverse=True):
        if not path.name.endswith(UNCHANGED_SUFFIXES):
            try:
                text = path.read_text(encoding='utf-8')
            except UnicodeDecodeError:
                text = None
            if text is not None and swap(text) != text:
                mode = path.stat().st_mode
                path.write_text(swap(text), encoding='utf-8')
                path.chmod(mode)
    for path in sorted(output.rglob('*'), key=lambda p: len(p.parts), reverse=True):
        renamed = swap(path.name)
        if renamed != path.name:
            path.rename(path.with_name(renamed))


def stage(output, root=ROOT, profile=None, with_benchmarks=False):
    if output.exists() and any(output.iterdir()):
        raise SystemExit(f'Refusing to stage into non-empty {output}')
    for source, target in LAYOUT:
        shutil.copytree(root / source, output / target, ignore=ignore_local_files, dirs_exist_ok=True)
    if with_benchmarks:
        shutil.copytree(root / 'benchmarks', output / 'benchmarks', ignore=ignore_local_files)
    if profile:
        apply_profile(output, profile)
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--profile', type=Path)
    parser.add_argument('--with-benchmarks', action='store_true', help='Also render the benchmark scripts')
    args = parser.parse_args()
    profile = json.loads(args.profile.read_text()) if args.profile else None
    print(stage(args.output, profile=profile, with_benchmarks=args.with_benchmarks))


if __name__ == '__main__':
    main()
