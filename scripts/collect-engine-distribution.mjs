import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const cache = resolve(process.env.ROUTEDECK_ENGINE_SOURCE_CACHE || join(ROOT, ".cache/artifacts/engine-sources"));
const output = process.argv[2] && resolve(process.argv[2]);
if (!output || process.argv.length !== 3) throw new Error("usage: node scripts/collect-engine-distribution.mjs <outputDir>");
const sourceLock = JSON.parse(readFileSync(join(ROOT, "engine/source-distribution.lock.json"), "utf8"));
const goSourceLock = JSON.parse(readFileSync(join(ROOT,"engine/go-runtime-sources.lock.json"),"utf8"));
const goSourceRoot = resolve(process.env.ROUTEDECK_GO_RUNTIME_SOURCES || join(ROOT,"artifacts/go-runtime-sources"));
const singLockPath = join(ROOT, "engine/sing-box.lock.json"), xrayLockPath = join(ROOT, "engine/xray-core.lock.json");
const sing = JSON.parse(readFileSync(singLockPath)), xray = JSON.parse(readFileSync(xrayLockPath));
if (sing.releaseCommit !== sourceLock.sources.singBox.commit || xray.releaseCommit !== sourceLock.sources.xray.commit) throw new Error("source pins do not match runtime pins");
if (sing.provenance?.cronetGo?.commit !== sourceLock.sources.cronetGo.commit || sing.provenance?.naiveProxy?.commit !== sourceLock.sources.naiveProxyChromium.commit) throw new Error("nested engine source pins do not match runtime provenance");
const sha = p => createHash("sha256").update(readFileSync(p)).digest("hex");
const safeName = n => /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(n) && !n.endsWith(".partial");
const validZip = p => existsSync(p) && statSync(p).size > 22 && readFileSync(p).subarray(0,4).equals(Buffer.from([0x50,0x4b,0x03,0x04]));
for (const item of Object.values(sourceLock.sources)) {
  if (!safeName(item.archiveName) || !/^[0-9a-f]{40}$/.test(item.commit) || !/^(SagerNet\/(sing-box|cronet-go|naiveproxy)|XTLS\/Xray-core)$/.test(item.repository) || !/^[0-9a-f]{64}$/.test(item.sha256)) throw new Error("invalid pinned source contract");
}

async function fetchSource(url) {
  const allowed = new Set(["api.github.com", "github.com", "codeload.github.com", "objects.githubusercontent.com", "www.gnu.org"]);
  for (let redirects=0; redirects<=5; redirects++) {
    const parsed = new URL(url);
    if (parsed.protocol!=="https:" || parsed.username || parsed.password || (parsed.port && parsed.port!=="443") || !allowed.has(parsed.hostname)) throw new Error("untrusted source URL");
    const headers={ "User-Agent": "RouteDeck-source-packager", Accept: "application/vnd.github+json" };
    if (parsed.hostname==="api.github.com" && process.env.GH_TOKEN) headers.Authorization=`Bearer ${process.env.GH_TOKEN}`;
    const response = await fetch(parsed, { redirect: "manual", signal: AbortSignal.timeout(180_000), headers });
    if (![301,302,303,307,308].includes(response.status)) return response;
    const location=response.headers.get("location"); await response.body?.cancel();
    if (!location) throw new Error("source redirect has no location");
    url=new URL(location,parsed).href;
  }
  throw new Error("source redirect limit exceeded");
}
async function json(url) {
  const response = await fetchSource(url);
  if (!response.ok) throw new Error(`GitHub request failed (${response.status}): ${url}`);
  const chunks=[]; let size=0;
  for await (const chunk of response.body) { size+=chunk.length; if(size>32*1024*1024) throw new Error("GitHub tree body limit exceeded"); chunks.push(chunk); }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}
async function download(url, path, expected = null) {
  const response = await fetchSource(url);
  if (!response.ok || !response.body) throw new Error(`download failed (${response.status}): ${url}`);
  const final=new URL(response.url); if(final.protocol!=="https:"||!["github.com","codeload.github.com","objects.githubusercontent.com","www.gnu.org"].includes(final.hostname)) throw new Error(`download redirected to untrusted origin: ${final.hostname}`);
  const chunks=[]; let size=0;
  for await (const chunk of response.body) { size += chunk.length; if (size > 512*1024*1024) throw new Error("download size limit exceeded"); chunks.push(chunk); }
  const bytes=Buffer.concat(chunks); if (expected && createHash("sha256").update(bytes).digest("hex") !== expected) throw new Error("download hash mismatch");
  const partial=path+".partial"; writeFileSync(partial, bytes); renameSync(partial,path);
}
const forbidden = /\.(?:a|lib|dll|so|dylib|exe|node)$/i;
const notice = /(?:^|\/)(?:LICENSE|NOTICE|COPYING|README\.chromium)(?:\.[^/]*)?$/i;
async function treeArchive(key, select) {
  const item=sourceLock.sources[key], target=join(cache,item.archiveName);
  if (validZip(target) && item.sha256 && statSync(target).size===item.size && sha(target)===item.sha256) return target;
  const tree=await json(`https://api.github.com/repos/${item.repository}/git/trees/${item.commit}?recursive=1`);
  if (tree.truncated) throw new Error(`GitHub tree is truncated: ${key}`);
  const submodules=Object.fromEntries(tree.tree.filter(e=>e.type==="commit").map(e=>[e.path,e.sha]));
  if(JSON.stringify(submodules)!==JSON.stringify(item.expectedSubmodules||{})) throw new Error(`unexpected Git submodule set: ${key}`);
  const omitted=[]; const files=[];
  for (const e of tree.tree) if (e.type === "blob") {
    const reason=forbidden.test(e.path)?"prebuilt binary suffix":null;
    if (reason) { omitted.push({path:e.path,gitSha:e.sha,size:e.size,reason}); continue; }
    if (select(e.path)) {
      const encoded=e.path.split("/").map(encodeURIComponent).join("/");
      files.push({path:e.path,sha:e.sha,size:e.size,url:`https://raw.githubusercontent.com/${item.repository}/${item.commit}/${encoded}`});
    }
  }
  if (!files.length) throw new Error(`empty source selection: ${key}`);
  const spec=join(cache,`.${key}-tree.json`); writeFileSync(spec,JSON.stringify({root:`${key}-${item.commit}`,maxBytes:1073741824,files}));
  const partial=target+".partial"; rmSync(partial,{force:true});
  try { execFileSync("python",[join(ROOT,"scripts/archive-github-tree.py"),spec,partial],{stdio:"inherit",windowsHide:true}); renameSync(partial,target); } finally { rmSync(spec,{force:true}); rmSync(partial,{force:true}); }
  if(item.sha256 && (statSync(target).size!==item.size || sha(target)!==item.sha256)) throw new Error(`generated ${key} source does not match source lock`);
  writeFileSync(target+".omissions.json",JSON.stringify({schemaVersion:1,repository:item.repository,commit:item.commit,submodules,omissions:omitted},null,2)+"\n");
  return target;
}
async function verifiedGitHubArchive(key) {
  const item=sourceLock.sources[key], target=join(cache,item.archiveName);
  if (!existsSync(target)) await download(item.url,target,item.sha256 || null);
  if (item.sha256 && sha(target)!==item.sha256) throw new Error(`cached ${key} source hash mismatch`);
  const tree=await json(`https://api.github.com/repos/${item.repository}/git/trees/${item.commit}?recursive=1`);
  if(tree.truncated) throw new Error(`GitHub tree is truncated: ${key}`);
  if(tree.tree.some(e=>e.type==="commit")) throw new Error(`unresolved Git submodule in source: ${key}`);
  const spec=join(cache,`.${key}-verify.json`); writeFileSync(spec,JSON.stringify({root:`${item.repository.split('/')[1]}-${item.commit}`,files:tree.tree.filter(e=>e.type==="blob").map(e=>({path:e.path,sha:e.sha,size:e.size}))}));
  try{execFileSync("python",[join(ROOT,"scripts/verify-github-archive.py"),spec,target],{stdio:"inherit",windowsHide:true});}finally{rmSync(spec,{force:true});}
  return target;
}

mkdirSync(cache,{recursive:true}); mkdirSync(join(output,"sources"),{recursive:true});
if (existsSync(join(output,"engine-distribution-inventory.json"))) throw new Error("output directory already contains an engine distribution");
const staged=[];
let singSource=join(cache,sourceLock.sources.singBox.archiveName);
if (!existsSync(singSource)) await download(sourceLock.sources.singBox.url,singSource,sourceLock.sources.singBox.sha256);
if (sha(singSource)!==sourceLock.sources.singBox.sha256) throw new Error("cached sing-box source hash mismatch");
staged.push(singSource);
staged.push(await treeArchive("cronetGo",()=>true));
staged.push(await verifiedGitHubArchive("naiveProxyChromium"));
let xraySource=join(cache,sourceLock.sources.xray.archiveName);
if (!existsSync(xraySource)) await download(sourceLock.sources.xray.url,xraySource,sourceLock.sources.xray.sha256);
if (sha(xraySource)!==sourceLock.sources.xray.sha256) throw new Error("cached Xray source hash mismatch");
staged.push(xraySource);
const goNoticeInputs=[];
for(const file of goSourceLock.files){
  if(!safeName(file.path)) throw new Error("unsafe Go source artifact name");
  const p=join(goSourceRoot,file.path);
  if(!existsSync(p)||statSync(p).size!==file.size||sha(p)!==file.sha256) throw new Error(`Go source artifact mismatch: ${file.path}`);
  staged.push(p); if(file.path.endsWith("-NOTICES.txt")) goNoticeInputs.push(p);
}
// Keep the canonical, reviewed license bytes with the source so packaging does
// not depend on the availability of GNU's web server.
const gpl=join(ROOT,"engine/licenses/GPL-3.0.txt"), gplLock=sourceLock.canonicalLicenses.gpl3;
if(statSync(gpl).size!==gplLock.size||sha(gpl)!==gplLock.sha256) throw new Error("canonical GPL-3.0 text mismatch");
for (const p of staged) { const name=basename(p); if(!safeName(name)) throw new Error("unsafe source archive name"); copyFileSync(p,join(output,"sources",name)); if(existsSync(p+".omissions.json")) copyFileSync(p+".omissions.json",join(output,"sources",name+".omissions.json")); }
const sourceText=`Source code for bundled engines\n\nThe source assets are published as individual flat assets beside the RouteDeck portable ZIP at:\nhttps://github.com/oda02/RouteDeck/releases/tag/v0.1.1\n\nThose assets contain exact pinned source for sing-box ${sing.version} (${sing.releaseCommit}), cronet-go (${sourceLock.sources.cronetGo.commit}), the complete pinned NaiveProxy tree including Chromium ${sourceLock.sources.naiveProxyChromium.chromiumVersion} (${sourceLock.sources.naiveProxyChromium.commit}), and Xray-core ${xray.version} (${xray.releaseCommit}). The sing-box and Xray Go module source bundles contain every checksum-verified linked dependency; their provenance JSON files record the executable build settings and module identities read without executing either binary.\n\nCronet's archive deliberately omits prebuilt .a, .lib, .dll, .so, .dylib, .exe and .node files; its omissions manifest records every omitted path, Git blob identity, size, and reason. Every member of the NaiveProxy/Chromium archive is verified against the exact recursive Git tree.\n`;
execFileSync("python",[join(ROOT,"scripts/aggregate-engine-notices.py"),join(output,"ENGINE-THIRD-PARTY-NOTICES.txt"),gpl,...staged.filter(p=>p.endsWith('.zip')&&!basename(p).includes('-go-modules-source')),...goNoticeInputs],{stdio:"inherit",windowsHide:true}); writeFileSync(join(output,"SOURCE-CODE.txt"),sourceText);
const paths=["ENGINE-THIRD-PARTY-NOTICES.txt","SOURCE-CODE.txt",...staged.flatMap(p=>{const n=`sources/${basename(p)}`;return existsSync(p+".omissions.json")?[n,n+".omissions.json"]:[n]})];
const files=paths.sort().map(path=>{const p=join(output,...path.split("/"));return {path,size:statSync(p).size,sha256:sha(p)}});
writeFileSync(join(output,"engine-distribution-inventory.json"),JSON.stringify({schemaVersion:1,runtimeLocks:{singBoxSha256:sha(singLockPath),xraySha256:sha(xrayLockPath)},sources:sourceLock.sources,files},null,2)+"\n");
console.log(`Collected ${files.length} engine distribution files in ${output}`);
