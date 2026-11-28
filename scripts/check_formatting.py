"""Formatting check for the files a change touches (CI's "formatting" job).

    python scripts/check_formatting.py --base origin/master          # check
    python scripts/check_formatting.py --base origin/master --fix    # format them in place

Only files added or changed since --base (git diff <base>...HEAD) are looked at, so older code is
left alone until someone edits it. Per kind of file:

    C / C++ (.c .cpp .h .hpp)    clang-format with the repo's .clang-format files
    Python (.py)                 ruff format (pyproject.toml)
    JavaScript / HTML (.js .mjs .html)    prettier (.prettierrc.json)
    JSON (.json)                 valid, laid out as JSON.stringify(value, null, 2) writes it (2-space
                                 indent, one member / element per line, numbers kept as written,
                                 a final newline) -- the layout the pod editor writes its files in

Vendored code (the third-party libraries in dinput_hook/, modules/) and generated files are skipped.
The tools: pip install clang-format==19.1.7 ruff==0.8.4, and Node.js for prettier (run with npx).
"""

import argparse
import json
import os
import shutil
import subprocess
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
PRETTIER = 'prettier@3.3.3'

SKIP = (
    'dinput_hook/imgui-',
    'dinput_hook/glfw-master/',
    'dinput_hook/detours-master/',
    'dinput_hook/fastgltf-',
    'dinput_hook/glad/',
    'dinput_hook/nv_dds/',
    'dinput_hook/harfbuzz-',
    'dinput_hook/openal-soft/',
    'dinput_hook/stb_image.h',
    'modules/',
    'src/generated/',
    'archive/',
    'ghidra_analysis/',
)
KINDS = {
    'cpp': ('.c', '.cpp', '.h', '.hpp'),
    'python': ('.py',),
    'js': ('.js', '.mjs', '.html'),
    'json': ('.json',),
}


def changed_files(base):
    out = subprocess.run(
        ['git', 'diff', '--name-only', '--diff-filter=ACMR', f'{base}...HEAD'],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    files = [f for f in out.splitlines() if f and not f.startswith(SKIP)]
    return {k: [f for f in files if f.lower().endswith(ext)] for k, ext in KINDS.items()}


def run(cmd, files):
    """Runs cmd on the files (in batches); the files it reports as not formatted."""
    bad = []
    for i in range(0, len(files), 100):
        r = subprocess.run(cmd + files[i : i + 100], cwd=REPO, capture_output=True, text=True)
        if r.returncode != 0:
            sys.stdout.write(r.stdout + r.stderr)
            bad += files[i : i + 100]
    return bad


def tool(name, fallback=None):
    path = shutil.which(name)
    if path is None and fallback is None:
        sys.exit(f'{name} not found (see the notes at the top of {os.path.basename(__file__)})')
    return path or fallback


# ---- JSON: JSON.stringify(value, null, 2) layout, numbers kept as written
class Number(str):
    """A number exactly as the file writes it."""


def stringify(v, indent=''):
    inner = indent + '  '
    if isinstance(v, dict):
        if not v:
            return '{}'
        items = [f'{inner}{json.dumps(k, ensure_ascii=False)}: {stringify(x, inner)}' for k, x in v.items()]
        return '{\n' + ',\n'.join(items) + '\n' + indent + '}'
    if isinstance(v, list):
        if not v:
            return '[]'
        return '[\n' + ',\n'.join(inner + stringify(x, inner) for x in v) + '\n' + indent + ']'
    if isinstance(v, Number):
        return str(v)
    return json.dumps(v, ensure_ascii=False)


def check_json(files, fix):
    bad = []
    for f in files:
        path = os.path.join(REPO, f)
        text = open(path, encoding='utf-8').read()
        try:
            value = json.loads(text, parse_float=Number, parse_int=Number)
        except ValueError as err:
            print(f'{f}: not valid JSON ({err})')
            bad.append(f)
            continue
        want = stringify(value) + '\n'
        if text != want:
            if fix:
                open(path, 'w', encoding='utf-8', newline='\n').write(want)
            else:
                print(f'{f}: not formatted (2-space indent, one member / element per line, final newline)')
                bad.append(f)
    return bad


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--base', required=True, help='the branch / commit the change is compared with')
    ap.add_argument('--fix', action='store_true', help='format the files in place instead of checking')
    args = ap.parse_args()
    files = changed_files(args.base)
    bad = []
    if files['cpp']:
        cf = tool('clang-format')
        bad += run([cf, '-i'] if args.fix else [cf, '--dry-run', '--Werror'], files['cpp'])
    if files['python']:
        ruff = tool('ruff')
        bad += run([ruff, 'format'] if args.fix else [ruff, 'format', '--check'], files['python'])
    if files['js']:
        npx = tool('npx', tool('npx.cmd', ''))
        bad += run([npx, '--yes', PRETTIER, '--write' if args.fix else '--check'], files['js'])
    bad += check_json(files['json'], args.fix)
    n = sum(len(v) for v in files.values())
    if args.fix:
        print(f'formatted {n} changed file(s)')
        return 0
    if bad:
        print(
            f'\n{len(bad)} of {n} changed file(s) not formatted: python scripts/check_formatting.py --base {args.base} --fix'
        )
        return 1
    print(f'{n} changed file(s) formatted')
    return 0


if __name__ == '__main__':
    sys.exit(main())
