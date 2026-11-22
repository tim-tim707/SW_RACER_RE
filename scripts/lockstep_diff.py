"""Diff two lockstep state dumps (lockstep_dump_*.bin) word by word.

usage: python scripts/lockstep_diff.py <a.bin> <b.bin> [--max N]

Words either side flagged as pointers are skipped unless only one side is a pointer.
Offsets are within swrRace (src/types.h, sizeof 0x1f28) / swrObjJdge (0x1e8).
"""
import struct
import sys

RACE_SIZE = 0x1F28
JDGE_SIZE = 0x1E8


def read_dump(path):
    data = open(path, 'rb').read()
    n = struct.unpack_from('<I', data, 0)[0]
    p = 4
    racers = []
    for _ in range(n):
        racers.append((data[p:p + RACE_SIZE], data[p + RACE_SIZE:p + RACE_SIZE + RACE_SIZE // 4]))
        p += RACE_SIZE + RACE_SIZE // 4
    jdge = (data[p:p + JDGE_SIZE], data[p + JDGE_SIZE:p + JDGE_SIZE + JDGE_SIZE // 4])
    return racers, jdge


def diff(label, a, b, limit, counts):
    (ra, ma), (rb, mb) = a, b
    out = []
    for i in range(len(ra) // 4):
        pa, pb = ma[i], mb[i]
        if pa and pb:
            continue
        wa = struct.unpack_from('<I', ra, i * 4)[0]
        wb = struct.unpack_from('<I', rb, i * 4)[0]
        if wa == wb and pa == pb:
            continue
        fa = struct.unpack_from('<f', ra, i * 4)[0]
        fb = struct.unpack_from('<f', rb, i * 4)[0]
        counts[i * 4] = counts.get(i * 4, 0) + 1
        out.append(f'  {label} +0x{i * 4:04x}: {wa:08x} ({fa:.6g}) vs {wb:08x} ({fb:.6g})'
                   + ('  [ptr one side]' if pa != pb else ''))
    for line in out[:limit]:
        print(line)
    if len(out) > limit:
        print(f'  {label}: ... {len(out) - limit} more')
    return len(out)


def main():
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    limit = 40
    if '--max' in sys.argv:
        limit = int(sys.argv[sys.argv.index('--max') + 1])
    ra, ja = read_dump(args[0])
    rb, jb = read_dump(args[1])
    if len(ra) != len(rb):
        print(f'racer count {len(ra)} vs {len(rb)}')
    counts = {}
    total = 0
    for i in range(min(len(ra), len(rb))):
        total += diff(f'racer{i}', ra[i], rb[i], limit, counts)
    total += diff('jdge', ja, jb, limit, {})
    print(f'{total} differing words')
    common = sorted((o for o, c in counts.items() if c == min(len(ra), len(rb))))
    if common:
        print('offsets differing in every racer: ' + ' '.join(f'0x{o:04x}' for o in common))


if __name__ == '__main__':
    main()
