#!/usr/bin/env python3
"""Read Go PE build info without executing it and fetch its exact module sources."""
from __future__ import annotations
import argparse, base64, hashlib, json, re, urllib.parse, urllib.request, zipfile
from pathlib import Path

MAGIC = b"\xff Go buildinf:"
MAX_BINARY = 256 * 1024 * 1024
MAX_MODULES = 2048
MAX_DOWNLOAD = 128 * 1024 * 1024

def varint(data: bytes, pos: int) -> tuple[int, int]:
    value = 0
    for shift in range(0, 70, 7):
        if pos >= len(data): raise ValueError("truncated build-info varint")
        byte = data[pos]; pos += 1; value |= (byte & 127) << shift
        if byte < 128: return value, pos
    raise ValueError("oversized build-info varint")

def inline_blob(data: bytes, pos: int) -> tuple[bytes, int]:
    size, pos = varint(data, pos)
    if size > 16 * 1024 * 1024 or pos + size > len(data): raise ValueError("invalid build-info string length")
    return data[pos:pos+size], pos + size

def parse_binary(path: Path) -> dict:
    if path.stat().st_size > MAX_BINARY: raise ValueError("binary exceeds parser limit")
    data = path.read_bytes(); positions=[]; start=0
    while True:
        at=data.find(MAGIC,start)
        if at < 0: break
        positions.append(at); start=at+1
    if len(positions) != 1: raise ValueError("expected exactly one Go build-info header")
    at=positions[0]
    if at+32 > len(data) or data[at+14] not in (4,8) or not (data[at+15]&2):
        raise ValueError("unsupported non-inline Go build info")
    version_bytes,pos=inline_blob(data,at+32); module_bytes,pos=inline_blob(data,pos)
    version=version_bytes.decode("utf-8","strict")
    # Go wraps module data in distinct 16-byte sentinels so string scanners do
    # not mistake it for an ordinary module-info blob.
    if len(module_bytes)>=32 and module_bytes[0]==0x30 and module_bytes[-16]==0xf9: module_bytes=module_bytes[16:-16]
    module_text=module_bytes.decode("utf-8","strict")
    modules=[]; settings=[]; main=None
    for line in module_text.splitlines():
        fields=line.split("\t")
        if fields[0] in ("path","build"):
            if len(fields)!=2: raise ValueError("malformed Go setting")
            settings.append({"key":fields[0],"value":fields[1]})
        elif fields[0] in ("mod","dep"):
            if len(fields) not in (3,4): raise ValueError("malformed Go module line")
            item={"path":fields[1],"version":fields[2],"sum":fields[3] if len(fields)==4 else None,"main":fields[0]=="mod"}
            modules.append(item)
            if item["main"]:
                if main is not None: raise ValueError("multiple main modules")
                main=item
        elif fields[0]=="=>":
            if not modules or len(fields) not in (3,4): raise ValueError("orphan Go replacement")
            modules[-1]["replace"]={"path":fields[1],"version":fields[2],"sum":fields[3] if len(fields)==4 else None}
        elif line: raise ValueError("unknown Go build-info line")
    if len(modules)>MAX_MODULES: raise ValueError("too many linked Go modules")
    return {"goVersion":version,"main":main,"modules":modules,"settings":settings,
            "binary":{"size":len(data),"sha256":hashlib.sha256(data).hexdigest()}}

def escape(value: str) -> str:
    if not value or any(ord(c)<33 or ord(c)>126 for c in value): raise ValueError("invalid module coordinate")
    return "".join("!"+c.lower() if "A"<=c<="Z" else c for c in value)

def hash_zip(path: Path, module: str, version: str) -> str:
    prefix=f"{module}@{version}/"; records=[]
    with zipfile.ZipFile(path) as z:
        if len(z.infolist())>100000: raise ValueError("module ZIP entry limit exceeded")
        seen=set()
        for info in z.infolist():
            name=info.filename
            if info.is_dir(): continue
            if not name.startswith(prefix) or ".." in name.split("/") or name in seen: raise ValueError("unsafe module ZIP layout")
            seen.add(name)
            if info.file_size>MAX_DOWNLOAD: raise ValueError("module file exceeds limit")
            with z.open(info) as src: digest=hashlib.sha256(src.read(MAX_DOWNLOAD+1)).hexdigest()
            records.append((name,digest))
    digest=hashlib.sha256("".join(f"{digest}  {name}\n" for name,digest in sorted(records)).encode()).digest()
    return "h1:"+base64.b64encode(digest).decode()

def download(url: str, target: Path) -> None:
    request=urllib.request.Request(url,headers={"User-Agent":"RouteDeck-source-packager"})
    with urllib.request.urlopen(request,timeout=60) as response:
        if response.geturl().split(":",1)[0]!="https" or urllib.parse.urlparse(response.geturl()).hostname not in ("proxy.golang.org","storage.googleapis.com"):
            raise ValueError("module download redirected outside official Go proxy hosts")
        with target.open("xb") as out:
            total=0
            while chunk:=response.read(65536):
                total+=len(chunk)
                if total>MAX_DOWNLOAD: raise ValueError("module download exceeds limit")
                out.write(chunk)

def collect(binary: Path, output: Path) -> dict:
    info=parse_binary(binary); output.mkdir(parents=True,exist_ok=False); files=[]
    for original in info["modules"]:
        # The main module is covered by the separately pinned engine source
        # archive. Its build-info line normally has no proxy checksum.
        if original["main"]: continue
        item=original.get("replace") or original
        module,version,sum_value=item["path"],item["version"],item.get("sum")
        if not version or not sum_value or not re.fullmatch(r"h1:[A-Za-z0-9+/]{43}=",sum_value):
            raise ValueError(f"linked module lacks verifiable proxy identity: {module}")
        escaped_path,escaped_version=escape(module),escape(version)
        stem=hashlib.sha256(f"{module}@{version}".encode()).hexdigest()[:20]
        zip_path=output/f"module-{stem}.zip"; mod_path=output/f"module-{stem}.mod"
        base=f"https://proxy.golang.org/{escaped_path}/@v/{escaped_version}"
        download(base+".zip",zip_path); download(base+".mod",mod_path)
        if hash_zip(zip_path,escaped_path,escaped_version)!=sum_value: raise ValueError(f"Go directory hash mismatch: {module}@{version}")
        files.append({"module":module,"version":version,"sum":sum_value,"zip":zip_path.name,"mod":mod_path.name,
                      "zipSha256":hashlib.sha256(zip_path.read_bytes()).hexdigest(),"modSha256":hashlib.sha256(mod_path.read_bytes()).hexdigest()})
    manifest={"schemaVersion":1,"buildInfo":info,"modules":files,"toolchainSourceExcluded":True,
              "toolchainNote":"Go toolchain/compiler source is not bundled; see https://go.dev/dl/ and https://go.dev/LICENSE."}
    (output/"go-runtime-sources.json").write_text(json.dumps(manifest,indent=2)+"\n",encoding="utf-8",newline="\n")
    return manifest

def bundle(cache: Path, manifest: dict, engine: str, destination: Path) -> None:
    if not re.fullmatch(r"[a-z0-9-]{1,32}",engine): raise ValueError("invalid engine bundle name")
    destination.mkdir(parents=True,exist_ok=True)
    archive=destination/f"{engine}-go-modules-source.zip"
    provenance=destination/f"{engine}-go-modules-provenance.json"
    notices=destination/f"{engine}-go-modules-NOTICES.txt"
    for path in (archive,provenance,notices):
        if path.exists(): raise ValueError("bundle output already exists")
    notice_parts=[f"{engine} linked Go module license and notice texts\n"]
    allowed={"go-runtime-sources.json"}
    for record in manifest["modules"]:
        for key in ("zip","mod"):
            name=record[key]
            if not re.fullmatch(r"module-[a-f0-9]{20}\.(zip|mod)",name) or name in allowed: raise ValueError("unsafe or duplicate module artifact name")
            allowed.add(name)
    actual={p.name for p in cache.iterdir() if p.is_file() and not p.is_symlink()}
    if actual != allowed or any(p.is_dir() or p.is_symlink() for p in cache.iterdir()): raise ValueError("module cache contains unexpected entries")
    provenance.write_text(json.dumps(manifest,indent=2)+"\n",encoding="utf-8",newline="\n")
    missing_notices=[]
    with zipfile.ZipFile(archive,"x",compression=zipfile.ZIP_STORED) as out:
        for name in sorted(allowed):
            source=cache/name
            info=zipfile.ZipInfo(source.name,(1980,1,1,0,0,0)); info.external_attr=0o100644<<16
            out.writestr(info,source.read_bytes())
        for record in manifest["modules"]:
            found=0
            with zipfile.ZipFile(cache/record["zip"]) as module_zip:
                for entry in sorted(module_zip.infolist(),key=lambda e:e.filename):
                    base=entry.filename.rsplit("/",1)[-1]
                    if entry.is_dir() or not re.match(r"^(LICENSE|LICENCE|NOTICE|COPYING|COPYRIGHT|AUTHORS|PATENTS)(?:[._-].*)?$",base,re.I): continue
                    if entry.file_size>2*1024*1024: raise ValueError("module notice exceeds limit")
                    raw=module_zip.read(entry)
                    try: text=raw.decode("utf-8","strict")
                    except UnicodeDecodeError: text=raw.decode("latin-1")
                    notice_parts.append(f"\n===== {record['module']}@{record['version']} :: {entry.filename} =====\n{text.rstrip()}\n")
                    found+=1
            if not found: missing_notices.append(f"{record['module']}@{record['version']}")
    if missing_notices:
        archive.unlink(missing_ok=True); provenance.unlink(missing_ok=True)
        raise ValueError("linked modules lack license/notice candidates: "+", ".join(missing_notices))
    notices.write_text("".join(notice_parts),encoding="utf-8",newline="\n")

def main():
    p=argparse.ArgumentParser(); p.add_argument("binary",type=Path); p.add_argument("--output",type=Path); p.add_argument("--parse-only",action="store_true"); p.add_argument("--bundle-root",type=Path); p.add_argument("--engine")
    a=p.parse_args(); result=parse_binary(a.binary) if a.parse_only else collect(a.binary,a.output)
    if not a.parse_only and a.bundle_root:
        if not a.engine: p.error("--engine is required with --bundle-root")
        bundle(a.output,result,a.engine,a.bundle_root)
    if a.parse_only: print(json.dumps(result,sort_keys=True))
    else: print(f"Collected {len(result['modules'])} checksum-verified linked Go modules in {a.output}")
if __name__=="__main__": main()
