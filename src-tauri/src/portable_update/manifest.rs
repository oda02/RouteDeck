//! Closed, signed update metadata. Pure validation: no paths are opened and no
//! processes or network operations are performed by this module.
use super::{Result, BUNDLE_LIMIT, ERROR, EXPANDED_LIMIT, MANIFEST_LIMIT, PUBLIC_KEY};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct BundleFile {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct UpdateManifest {
    pub schema_version: u32,
    pub version: String,
    pub platform: String,
    pub archive: String,
    pub size: u64,
    pub sha256: String,
    pub files: Vec<BundleFile>,
}

pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub(super) fn unhex<const N: usize>(value: &str) -> Result<[u8; N]> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ERROR);
    }
    let mut out = [0; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).map_err(|_| ERROR)?;
    }
    Ok(out)
}
pub(super) fn stable_version(value: &str) -> bool {
    value.len() <= 32
        && value.split('.').count() == 3
        && value.split('.').all(|p| {
            !p.is_empty()
                && p.len() <= 9
                && p.bytes().all(|b| b.is_ascii_digit())
                && (p.len() == 1 || !p.starts_with('0'))
        })
}
pub(super) fn newer(next: &str, current: &str) -> bool {
    stable_version(next)
        && stable_version(current)
        && next
            .split('.')
            .map(|s| s.parse::<u32>().unwrap())
            .collect::<Vec<_>>()
            > current
                .split('.')
                .map(|s| s.parse::<u32>().unwrap())
                .collect::<Vec<_>>()
}
pub(super) fn safe_relative(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 200
        && value.split('/').all(|p| {
            !p.is_empty()
                && p != "."
                && p != ".."
                && !p.ends_with('.')
                && !p.ends_with(' ')
                && p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                && !matches!(
                    p.split('.').next().unwrap().to_ascii_uppercase().as_str(),
                    "CON"
                        | "PRN"
                        | "AUX"
                        | "NUL"
                        | "COM1"
                        | "COM2"
                        | "COM3"
                        | "COM4"
                        | "COM5"
                        | "COM6"
                        | "COM7"
                        | "COM8"
                        | "COM9"
                        | "LPT1"
                        | "LPT2"
                        | "LPT3"
                        | "LPT4"
                        | "LPT5"
                        | "LPT6"
                        | "LPT7"
                        | "LPT8"
                        | "LPT9"
                )
        })
}
fn allowed_file(value: &str) -> bool {
    matches!(
        value,
        "routedeck.exe"
            | "routedeck-tun-helper.exe"
            | "routedeck-updater.exe"
            | "routedeck-build.json"
            | "README.txt"
            | "THIRD-PARTY-NOTICES.txt"
            | "dependency-inventory.json"
            | "ENGINE-THIRD-PARTY-NOTICES.txt"
            | "SOURCE-CODE.txt"
            | "engine-distribution-inventory.json"
    ) || [
        "engine/",
        "xray/",
        "runtime-pins/",
        "licenses/",
        "controller-sources/",
    ]
    .iter()
    .any(|p| value.starts_with(p))
}
pub(super) fn validate_manifest(manifest: &UpdateManifest) -> Result<()> {
    if manifest.schema_version != 1
        || !stable_version(&manifest.version)
        || manifest.platform != "windows-x64"
        || manifest.archive != format!("RouteDeck-{}-windows-x64.zip", manifest.version)
        || manifest.size == 0
        || manifest.size > BUNDLE_LIMIT
        || unhex::<32>(&manifest.sha256).is_err()
        || manifest.files.len() > 512
        || manifest.files.len() < 8
    {
        return Err(ERROR);
    }
    let mut names = BTreeSet::new();
    let mut total = 0u64;
    for file in &manifest.files {
        if !safe_relative(&file.path)
            || !allowed_file(&file.path)
            || !names.insert(file.path.to_ascii_lowercase())
            || file.size == 0
            || file.size > BUNDLE_LIMIT
            || unhex::<32>(&file.sha256).is_err()
        {
            return Err(ERROR);
        }
        total = total.checked_add(file.size).ok_or(ERROR)?;
    }
    for required in [
        "routedeck.exe",
        "routedeck-tun-helper.exe",
        "routedeck-updater.exe",
        "routedeck-build.json",
        "engine/sing-box.exe",
        "engine/libcronet.dll",
        "xray/xray.exe",
        "runtime-pins/sing-box.lock.json",
        "runtime-pins/xray-core.lock.json",
    ] {
        if !names.contains(required) {
            return Err(ERROR);
        }
    }
    if total > EXPANDED_LIMIT {
        return Err(ERROR);
    }
    // A file cannot also be another file's parent directory.
    if names.iter().any(|p| {
        p.split('/')
            .scan(String::new(), |parent, part| {
                if !parent.is_empty() {
                    parent.push('/');
                }
                parent.push_str(part);
                Some(parent.clone())
            })
            .any(|parent| parent != *p && names.contains(&parent))
    }) {
        return Err(ERROR);
    }
    Ok(())
}
pub(super) fn signed_manifest_with_key(
    body: &[u8],
    signature: &[u8],
    key: &[u8; 32],
) -> Result<UpdateManifest> {
    if body.len() > MANIFEST_LIMIT as usize || signature.len() != 64 {
        return Err(ERROR);
    }
    VerifyingKey::from_bytes(key)
        .map_err(|_| ERROR)?
        .verify_strict(body, &Signature::from_slice(signature).map_err(|_| ERROR)?)
        .map_err(|_| ERROR)?;
    let manifest: UpdateManifest = serde_json::from_slice(body).map_err(|_| ERROR)?;
    validate_manifest(&manifest)?;
    Ok(manifest)
}
pub(super) fn signed_manifest(body: &[u8], signature: &[u8]) -> Result<UpdateManifest> {
    signed_manifest_with_key(body, signature, &unhex(PUBLIC_KEY)?)
}
