use crate::domain::DomainError;

pub(crate) fn executable_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or("")
}

pub(crate) fn validate_executable_name(name: &str) -> Result<(), DomainError> {
    let lower = name.to_lowercase();
    let stem = lower.split('.').next().unwrap_or("");
    let reserved = matches!(stem, "con" | "prn" | "aux" | "nul")
        || (stem.len() == 4
            && (stem.starts_with("com") || stem.starts_with("lpt"))
            && matches!(stem.as_bytes()[3], b'1'..=b'9'));
    if name.len() > 260
        || name.len() <= 4
        || !lower.ends_with(".exe")
        || name != name.trim()
        || reserved
        || name.chars().any(|c| c.is_control() || matches!(c, '\\' | '/' | ':' | '<' | '>' | '"' | '|' | '?' | '*'))
    {
        return Err(DomainError::new("invalid executable file name"));
    }
    Ok(())
}

const PREFIX: &str = r"(?i)(?:^|[\\/])";
const META: &str = r"\.+*?()|[]{}^$";

// sing-box 1.13.21 process_name is case-sensitive. Generate a bounded literal
// basename matcher instead, using Go regexp's Unicode case-insensitive mode.
// No renderer-authored regular expression is accepted.
pub(crate) fn executable_name_pattern(name: &str) -> Result<String, DomainError> {
    validate_executable_name(name)?;
    let mut pattern = String::from(PREFIX);
    for c in name.chars() {
        if META.contains(c) { pattern.push('\\'); }
        pattern.push(c);
    }
    pattern.push('$');
    Ok(pattern)
}

// The elevated helper accepts exactly our generated grammar, not the engine's
// arbitrary regex capability. Decode, validate, and round-trip every literal.
pub(crate) fn validate_executable_name_pattern(pattern: &str) -> bool {
    if pattern.len() > PREFIX.len() + 260 * 2 + 1 { return false; }
    let Some(literal) = pattern.strip_prefix(PREFIX).and_then(|s| s.strip_suffix('$')) else { return false; };
    let mut name = String::new();
    let mut chars = literal.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            let Some(escaped) = chars.next() else { return false; };
            if !META.contains(escaped) { return false; }
            name.push(escaped);
        } else {
            if META.contains(c) { return false; }
            name.push(c);
        }
    }
    executable_name_pattern(&name).is_ok_and(|expected| expected == pattern)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basename_is_bounded_windows_executable_name() {
        for name in ["", ".exe", "name", "name.dll", "app.exe:stream", "C:\\app.exe", "a/b.exe", "a?.exe", "a*.exe", "CON.exe", " name.exe", "app\n.exe"] {
            assert!(validate_executable_name(name).is_err(), "accepted {name:?}");
        }
        assert!(validate_executable_name(&format!("{}.exe", "a".repeat(257))).is_err());
        for name in ["ChatGPT.exe", "codex.EXE", "Client (beta)+[1]$^.exe", "Программа.exe"] {
            assert!(validate_executable_name(name).is_ok());
        }
        assert_eq!(executable_name(r"C:\Apps\version\Client.exe"), "Client.exe");
        assert_eq!(executable_name("C:/Apps/version/Client.exe"), "Client.exe");
    }

    #[test]
    fn generated_name_patterns_escape_literals_and_have_one_closed_grammar() {
        assert_eq!(executable_name_pattern("ChatGPT.exe").unwrap(), r"(?i)(?:^|[\\/])ChatGPT\.exe$");
        assert_eq!(executable_name_pattern("Client (beta)+[1]$^.exe").unwrap(), r"(?i)(?:^|[\\/])Client \(beta\)\+\[1\]\$\^\.exe$");
        for name in ["ChatGPT.exe", "Client (beta)+[1]$^.exe", "Программа.exe"] {
            assert!(validate_executable_name_pattern(&executable_name_pattern(name).unwrap()));
        }
        for attack in [r".*", r"(?i)(?:^|[\\/]).*\.exe$", r"(?i)(?:^|[\\/])a.exe$", r"(?i)(?:^|[\\/])a\.exe$|.*", r"(?i)(?:^|[\\/])a\w\.exe$", r"(?i)(?:^|[\\/])a\.exe"] {
            assert!(!validate_executable_name_pattern(attack), "accepted {attack}");
        }
    }
}
