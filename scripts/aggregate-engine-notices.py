#!/usr/bin/env python3
import posixpath, re, sys, zipfile
pattern=re.compile(r"(?:^|/)(?:LICENSE|NOTICE|COPYING|README\.chromium)(?:\.[^/]*)?$",re.I)
pointer=re.compile(r"^(?:License File|Required Text):\s*(.+?)\s*$",re.I|re.M)
total=0
with open(sys.argv[1],"w",encoding="utf-8",newline="\n") as out:
  out.write("RouteDeck engine third-party notices\n\n")
  for archive_path in sys.argv[2:]:
    if not zipfile.is_zipfile(archive_path):
      data=open(archive_path,"rb").read()
      text=data.decode("utf-8").replace("\r\n","\n").rstrip()
      out.write("="*72+"\n"+archive_path.split("/")[-1]+"\n"+"="*72+"\n"+text+"\n\n")
      continue
    with zipfile.ZipFile(archive_path) as archive:
      members={i.filename:i for i in archive.infolist() if not i.is_dir()}
      selected={name for name in members if pattern.search(name)}
      for name in sorted(n for n in selected if n.lower().endswith("readme.chromium")):
        body=archive.read(members[name]).decode("utf-8")
        for raw in pointer.findall(body):
          value=raw.strip().strip('"')
          if value.upper() in ("NOT_SHIPPED","NOT SHIPPED","NONE","N/A"): continue
          for part in (p.strip() for p in value.split(',')):
            if not part: continue
            if part.startswith("//") and "/src/" in name:
              candidate=name.split("/src/",1)[0]+"/src/"+part[2:]
            else:
              candidate=posixpath.normpath(posixpath.join(posixpath.dirname(name),part))
            if candidate not in members: raise RuntimeError("missing README.chromium referenced text: "+name+" -> "+part)
            selected.add(candidate)
      for name in sorted(selected):
        info=members[name]
        data=archive.read(info)
        if b"\0" in data or len(data)>2*1024*1024: raise RuntimeError("invalid notice text: "+info.filename)
        text=data.decode("utf-8").replace("\r\n","\n").rstrip()
        total += len(data)
        if total>64*1024*1024: raise RuntimeError("aggregate notice limit exceeded")
        out.write("="*72+"\n"+archive_path.split("/")[-1]+" :: "+info.filename+"\n"+"="*72+"\n"+text+"\n\n")
      if not selected: raise RuntimeError("source archive has no required notice text: "+archive_path)
  out.write("This conservative aggregation records upstream texts and provenance; it is not a blanket legal opinion.\n")
