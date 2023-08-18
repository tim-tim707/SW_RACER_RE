#!/usr/bin/env python3

import sys

strings = {}

for path in sys.argv[1:]:
  with open(path, 'rb') as in_file:
    data = in_file.read()

    identifiers = [
      b"/LANGID",
      b"/CREDITS_H_",
      b"/MONDOTEXT_H_",
      b"/SCREENTEXT_"
    ]

    for identifier in identifiers:
      cursor = 0
      while True:
        start = data.find(identifier, cursor)
        if start == -1:
          break
        sep = data.find(b"/", start + 1)
        assert(sep > start)
        end = data.find(b"\0", sep + 1)
        assert(end > sep)

        key = data[start + 1:sep]
        value = data[sep + 1:end]

        tmp = value.decode('windows-1252')
        tmp = tmp.translate(str.maketrans({"\n": r"\n",
                                           "\t": r"\t",
                                           "\r": r"\r",
                                           "\"": r"\"",
                                           "\\": r"\\"}))
        value = tmp.encode('windows-1252')

        if key in strings:
          print("Warning: duplicate key " + str(key), file=sys.stderr)
        strings[key] = value

        cursor = end + 1

for key in strings:
  value = strings[key].decode('windows-1252')
  key = key.decode('ascii')
  print(key + "\t" + value + "\r\n", end='', flush=True)
