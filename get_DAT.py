#!/bin/python3

import os
import sys

# Run like so:
'''
grep -oh "\w*DAT_\w*" SWEP1RCR_dump.c > dats.txt \
    && sort dats.txt | uniq > DAT_2.txt \
    && rm dats.txt \
    && python3 get_DAT.py \
    && rm DAT_2.txt
'''

def sorting(a: str):
    while (a[0] != 'D'):
        a = a[1:]
    return a

def main():
    lines = None
    with open("DAT_2.txt") as file:
        lines = [line.rstrip() for line in file]
    lines = sorted(lines, key=sorting)
    print('\n'.join(lines))
    with open("DAT_.txt", "w") as file:
        file.write('\n'.join(lines))

if __name__ == "__main__":
    main()
    sys.exit(0)
