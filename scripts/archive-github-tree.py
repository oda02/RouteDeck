#!/usr/bin/env python3
"""Create a deterministic ZIP from a pinned GitHub tree without checking it out."""
import hashlib, json, sys, urllib.request, zipfile

spec_path, output_path = sys.argv[1:3]
spec = json.load(open(spec_path, encoding="utf-8"))
headers = {"User-Agent": "RouteDeck-source-packager", "Accept": "application/vnd.github+json"}
total = 0
with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
    for entry in spec["files"]:
        req = urllib.request.Request(entry["url"], headers=headers)
        with urllib.request.urlopen(req, timeout=60) as response:
            data = response.read(64 * 1024 * 1024 + 1)
        if hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest() != entry["sha"]:
            raise RuntimeError("Git blob identity mismatch: " + entry["path"])
        if len(data) != entry["size"] or len(data) > 64 * 1024 * 1024:
            raise RuntimeError("Git blob size mismatch or limit exceeded: " + entry["path"])
        total += len(data)
        if total > spec.get("maxBytes", 1024 * 1024 * 1024):
            raise RuntimeError("source archive uncompressed-size limit exceeded")
        info = zipfile.ZipInfo(spec["root"] + "/" + entry["path"], (1980, 1, 1, 0, 0, 0))
        info.external_attr = 0o100644 << 16
        archive.writestr(info, data)
