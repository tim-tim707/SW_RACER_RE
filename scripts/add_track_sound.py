#!/usr/bin/env python3
"""Ship a wav with a track: store it content-addressed and name it in the manifest.

Usage:
    python scripts/add_track_sound.py <out_dir> <slug> <file.wav> --name theme
                                      [--music] [--intro] [--ambient START END [--random]]

    <out_dir>  the converter's output root (tracks/<slug>/track.json + content/<hh>/<sha256>),
               or the game's assets/ folder
    --name     what the manifest calls it; "environment" refers to sounds by this name
    --music    also set environment.music to it
    --intro    also set environment.intro_music to it
    --ambient  also append an ambient cue over that lap-progress range (0..1)

The game appends the wav to its sound bank the first time the track is applied, so the file must
be a plain PCM RIFF wav the game can parse (the stock files are 22 kHz 16-bit; music is streamed
when larger than ~516 KB, which the game decides from the size alone). Sounds are not part of
content_hash: they do not change how the track races.
"""
import argparse
import hashlib
import json
import os
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("out_dir")
    parser.add_argument("slug")
    parser.add_argument("wav")
    parser.add_argument("--name", required=True)
    parser.add_argument("--music", action="store_true")
    parser.add_argument("--intro", action="store_true")
    parser.add_argument("--ambient", nargs=2, type=float, metavar=("START", "END"))
    parser.add_argument("--random", action="store_true", help="ambient cue retriggers at random")
    args = parser.parse_args()

    manifest_path = os.path.join(args.out_dir, "tracks", args.slug, "track.json")
    if not os.path.isfile(manifest_path):
        sys.exit(f"no manifest at {manifest_path}")
    with open(args.wav, "rb") as f:
        payload = f.read()
    if payload[:4] != b"RIFF" or payload[8:12] != b"WAVE":
        sys.exit(f"{args.wav} is not a RIFF/WAVE file")

    digest = hashlib.sha256(payload).hexdigest()
    blob = os.path.join(args.out_dir, "content", digest[:2], digest)
    if not os.path.exists(blob):
        os.makedirs(os.path.dirname(blob), exist_ok=True)
        with open(blob, "wb") as f:
            f.write(payload)

    with open(manifest_path, encoding="utf-8") as f:
        manifest = json.load(f)
    sounds = [s for s in manifest.get("sounds", []) if s.get("name") != args.name]
    sounds.append({"name": args.name, "sha256": digest, "size": len(payload), "format": "wav"})
    manifest["sounds"] = sounds

    env = manifest.setdefault("environment", {})
    if args.music:
        env["music"] = args.name
    if args.intro:
        env["intro_music"] = args.name
    if args.ambient:
        cues = env.setdefault("ambient", [])
        cues.append({"sound": args.name, "start": args.ambient[0], "end": args.ambient[1],
                     "mode": "random" if args.random else "loop"})

    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")
    print(f"{args.slug}: sound '{args.name}' = {digest[:16]}... ({len(payload)} bytes)"
          + (" as music" if args.music else "") + (" as intro" if args.intro else "")
          + (f" ambient {args.ambient}" if args.ambient else ""))


if __name__ == "__main__":
    main()
