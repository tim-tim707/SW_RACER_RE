#!/usr/bin/env python3
"""Serve a converter output directory as a track catalog, for developing the in-game browser.

Usage:
    python scripts/serve_catalog.py <root> [--port 8099]

    <root>  a directory holding tracks/<slug>/track.json and content/<hh>/<sha256>
            (what convert_track_pack.py writes)

This is the whole download protocol:

    GET /index.json          the catalog: one entry per track, with its manifest
    GET /blobs/<sha256>      one asset, immutable

Because assets are content-addressed there is nothing dynamic about it: a real
deployment can be static hosting (a bucket or CDN) rather than an API, and the
client only needs a base URL. Publishing a track is the part that needs a real
backend -- auth, validation, moderation -- and is not this.

The catalog repeats each manifest inline so the browser can list and size a
track without fetching anything else:

    {
      "schema": 1,
      "tracks": [
        {
          "slug": "...", "name": "...", "author": "...", "version": "...",
          "content_hash": "...",
          "download_bytes": 5405876,      // sum of the assets, for the UI
          "manifest": { ... track.json verbatim ... }
        }
      ]
    }
"""
import argparse
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def build_index(root):
    tracks_dir = os.path.join(root, "tracks")
    if not os.path.isdir(tracks_dir):
        sys.exit(f"no tracks directory under {root}")

    entries = []
    for name in sorted(os.listdir(tracks_dir)):
        path = os.path.join(tracks_dir, name, "track.json")
        if not os.path.isfile(path):
            continue

        with open(path, encoding="utf-8") as f:
            manifest = json.load(f)

        assets = [manifest[key] for key in ("model", "spline", "preview_model")
                  if isinstance(manifest.get(key), dict)]
        assets += [t for t in manifest.get("textures", []) if isinstance(t, dict)]
        entries.append({
            "slug": manifest.get("slug", name),
            "name": manifest.get("name", name),
            "author": (manifest.get("author") or {}).get("name", ""),
            "version": manifest.get("version", ""),
            "content_hash": manifest.get("content_hash", ""),
            "download_bytes": sum(a.get("size", 0) for a in assets),
            "manifest": manifest,
        })
    return {"schema": 1, "tracks": entries}


class Handler(BaseHTTPRequestHandler):
    root = "."

    def do_GET(self):
        if self.path in ("/index.json", "/index"):
            body = json.dumps(build_index(self.root), indent=2).encode()
            self.send(200, "application/json", body)
            return

        if self.path.startswith("/blobs/"):
            digest = self.path[len("/blobs/"):]
            if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest.lower()):
                self.send(400, "text/plain", b"not a sha256\n")
                return

            path = os.path.join(self.root, "content", digest[:2], digest)
            if not os.path.isfile(path):
                self.send(404, "text/plain", b"no such blob\n")
                return

            with open(path, "rb") as f:
                self.send(200, "application/octet-stream", f.read())
            return

        self.send(404, "text/plain", b"try /index.json or /blobs/<sha256>\n")

    def send(self, status, content_type, body):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        # Blobs are immutable, so they may be cached forever; the catalog may not.
        self.send_header("Cache-Control",
                         "public, max-age=31536000, immutable" if self.path.startswith("/blobs/")
                         else "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        sys.stderr.write("  %s\n" % (fmt % args))


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("root")
    parser.add_argument("--port", type=int, default=8099)
    args = parser.parse_args()

    Handler.root = args.root
    index = build_index(args.root)
    total = sum(t["download_bytes"] for t in index["tracks"])
    print(f"serving {len(index['tracks'])} track(s), {total} bytes of assets, from {args.root}")
    print(f"  http://127.0.0.1:{args.port}/index.json")
    ThreadingHTTPServer(("127.0.0.1", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
