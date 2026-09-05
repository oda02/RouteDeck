#!/usr/bin/env python3
"""Verify every regular ZIP member against an exact recursive Git tree manifest."""
import hashlib, json, sys, zipfile
spec=json.load(open(sys.argv[1],encoding="utf-8")); expected={e["path"]:(e["sha"],e["size"]) for e in spec["files"]}
seen=set(); prefix=spec["root"]+"/"
with zipfile.ZipFile(sys.argv[2]) as z:
  bad=z.testzip()
  if bad: raise RuntimeError("ZIP CRC failure: "+bad)
  for info in z.infolist():
    if info.is_dir(): continue
    if not info.filename.startswith(prefix): raise RuntimeError("unexpected ZIP root: "+info.filename)
    path=info.filename[len(prefix):]
    if path not in expected or path in seen: raise RuntimeError("unexpected/duplicate ZIP member: "+path)
    data=z.read(info); identity=hashlib.sha1(b"blob %d\0"%len(data)+data).hexdigest()
    wanted_sha,wanted_size=expected[path]
    if identity != wanted_sha:
      # GitHub codeload honors committed export/eol attributes. Accept only the
      # reversible CRLF export of the exact blob, never arbitrary changed bytes.
      normalized=data.replace(b"\r\n",b"\n")
      identity=hashlib.sha1(b"blob %d\0"%len(normalized)+normalized).hexdigest()
      if identity != wanted_sha: raise RuntimeError("Git identity mismatch: "+path)
    seen.add(path)
if seen != set(expected): raise RuntimeError("ZIP is missing Git tree files")
