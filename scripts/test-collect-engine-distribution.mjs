import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const root=resolve(import.meta.dirname,".."), temp=mkdtempSync(join(tmpdir(),"RouteDeck-engine-distribution-test-"));
const gitBlob=data=>createHash("sha1").update(Buffer.from(`blob ${data.length}\0`)).update(data).digest("hex");
try {
  const zip=join(temp,"fixture.zip"), tree=join(temp,"tree.json"), notices=join(temp,"notices.txt");
  const files={"LICENSE":Buffer.from("top license\n"),"third_party/demo/README.chromium":Buffer.from("Name: demo\nLicense File: odd-name.txt\nRequired Text: COPYRIGHT\n"),"third_party/demo/odd-name.txt":Buffer.from("license body\n"),"third_party/demo/COPYRIGHT":Buffer.from("copyright body\n")};
  const python="import sys,zipfile,json\np=sys.argv[1]; files=json.load(open(sys.argv[2])); z=zipfile.ZipFile(p,'w'); [z.writestr('fixture-abc/'+k,v) for k,v in files.items()]; z.close()";
  const values=Object.fromEntries(Object.entries(files).map(([k,v])=>[k,v.toString()])); writeFileSync(join(temp,"files.json"),JSON.stringify(values));
  execFileSync("python",["-c",python,zip,join(temp,"files.json")]);
  writeFileSync(tree,JSON.stringify({root:"fixture-abc",files:Object.entries(files).map(([path,data])=>({path,size:data.length,sha:gitBlob(data)}))}));
  execFileSync("python",[join(root,"scripts/verify-github-archive.py"),tree,zip]);
  execFileSync("python",[join(root,"scripts/aggregate-engine-notices.py"),notices,zip]);
  const rendered=readFileSync(notices,"utf8"); if(!rendered.includes("license body")||!rendered.includes("copyright body"))throw new Error("README.chromium pointers were not aggregated");
  const missing={...values,"third_party/demo/README.chromium":"License File: absent.txt\n"}; writeFileSync(join(temp,"files.json"),JSON.stringify(missing)); execFileSync("python",["-c",python,zip,join(temp,"files.json")]);
  let rejected=false;try{execFileSync("python",[join(root,"scripts/aggregate-engine-notices.py"),notices,zip],{stdio:"pipe"})}catch{rejected=true}if(!rejected)throw new Error("missing Required Text was accepted");
  const lock=JSON.parse(readFileSync(join(root,"engine/source-distribution.lock.json"),"utf8"));
  for(const key of ["singBox","cronetGo","naiveProxyChromium","xray"]){const item=lock.sources[key];if(!/^[a-f0-9]{40}$/.test(item.commit)||!/^[a-f0-9]{64}$/.test(item.sha256))throw new Error(`unpinned source: ${key}`)}
  console.log("engine distribution collector helper tests passed");
} finally { rmSync(temp,{recursive:true,force:true}); }
