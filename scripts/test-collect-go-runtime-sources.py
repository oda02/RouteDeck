import hashlib, importlib.util, tempfile, zipfile
from pathlib import Path
here=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("collector",here/"collect-go-runtime-sources.py"); c=importlib.util.module_from_spec(spec); spec.loader.exec_module(c)
def vi(n):
    out=bytearray()
    while n>=128: out.append((n&127)|128); n>>=7
    out.append(n); return bytes(out)
text="path\texample/main\nmod\texample/main\tv1.0.0\th1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\ndep\texample/Dep\tv1.2.3\th1:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\n=>\texample/repl\tv1.2.4\th1:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=\nbuild\tCGO_ENABLED=0\n"
blob=b"MZ"+b"\0"*62+c.MAGIC+bytes([8,2])+b"\0"*16+vi(len(b"go1.25.1"))+b"go1.25.1"+vi(len(text.encode()))+text.encode()
with tempfile.TemporaryDirectory() as td:
    p=Path(td)/"runtime.exe"; p.write_bytes(blob); got=c.parse_binary(p)
    assert got["goVersion"]=="go1.25.1" and got["modules"][1]["replace"]["path"]=="example/repl"
    assert c.escape("example/Dep")=="example/!dep"
    z=Path(td)/"m.zip"
    with zipfile.ZipFile(z,"w") as out: out.writestr("example/mod@v1.0.0/LICENSE","notice"); out.writestr("example/mod@v1.0.0/a.go","package a\n")
    expected=[]
    for name,data in [("example/mod@v1.0.0/LICENSE",b"notice"),("example/mod@v1.0.0/a.go",b"package a\n")]: expected.append((name,hashlib.sha256(data).hexdigest()))
    import base64
    want="h1:"+base64.b64encode(hashlib.sha256("".join(f"{digest}  {name}\n" for name,digest in sorted(expected)).encode()).digest()).decode()
    assert c.hash_zip(z,"example/mod","v1.0.0")==want
    cache=Path(td)/"cache"; cache.mkdir(); (cache/"module-aaaaaaaaaaaaaaaaaaaa.zip").write_bytes(z.read_bytes()); (cache/"module-aaaaaaaaaaaaaaaaaaaa.mod").write_text("module example/mod\n")
    (cache/"go-runtime-sources.json").write_text("{}\n")
    manifest={"modules":[{"module":"example/mod","version":"v1.0.0","zip":"module-aaaaaaaaaaaaaaaaaaaa.zip","mod":"module-aaaaaaaaaaaaaaaaaaaa.mod"}]}
    bundles=Path(td)/"bundles"; c.bundle(cache,manifest,"fixture",bundles)
    assert sorted(p.name for p in bundles.iterdir())==["fixture-go-modules-NOTICES.txt","fixture-go-modules-provenance.json","fixture-go-modules-source.zip"]
    assert "notice" in (bundles/"fixture-go-modules-NOTICES.txt").read_text()
    (cache/"extra.env").write_text("private")
    try: c.bundle(cache,manifest,"fixture2",bundles); raise AssertionError("extra cache file accepted")
    except ValueError as e: assert "unexpected entries" in str(e)
    bad=Path(td)/"bad.exe"; bad.write_bytes(blob+c.MAGIC)
    try: c.parse_binary(bad); raise AssertionError("duplicate header accepted")
    except ValueError as e: assert "exactly one" in str(e)
print("PASS: Go PE build-info and directory-hash fixtures")
