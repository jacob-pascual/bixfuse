//! The OpenPGP user ID of the `/.gnupg` keys (SPEC.md section 4).

use std::ffi::{CStr, CString};

use nix::unistd::{Uid, User};

/// The user ID `Name <email>`. A part that is not given comes from the
/// current user: the name is the full name in the user database (the GECOS
/// field), else the user name; the email is `<user name>@<fully qualified
/// host name>`.
pub fn user_id(name: Option<String>, email: Option<String>) -> Result<String, String> {
    let (name, email) = match (name, email) {
        (Some(name), Some(email)) => (name, email),
        (name, email) => {
            let uid = Uid::current();
            let user = User::from_uid(uid)
                .map_err(|e| format!("cannot read the user database: {e}"))?
                .ok_or_else(|| {
                    format!(
                        "user {uid} is not in the user database; use --gpg-name and --gpg-email"
                    )
                })?;
            let name = name.unwrap_or_else(|| full_name(&user.gecos.to_string_lossy(), &user.name));
            let email = match email {
                Some(email) => email,
                None => format!("{}@{}", user.name, fqdn()?),
            };
            (name, email)
        }
    };
    Ok(format!("{name} <{email}>"))
}

/// The full name in a GECOS field: the text before the first comma.
/// If it is empty, the user name.
pub fn full_name(gecos: &str, user_name: &str) -> String {
    match gecos.split(',').next().map(str::trim) {
        Some(name) if !name.is_empty() => name.to_string(),
        _ => user_name.to_string(),
    }
}

/// The fully qualified host name, as `hostname -f` gives it: the canonical
/// name of the host name. If the host name has no canonical name, the host
/// name.
fn fqdn() -> Result<String, String> {
    let host = nix::unistd::gethostname()
        .map_err(|e| format!("cannot read the host name: {e}"))?
        .into_string()
        .map_err(|_| "the host name is not UTF-8".to_string())?;
    Ok(canonical_name(&host).unwrap_or(host))
}

fn canonical_name(host: &str) -> Option<String> {
    let host = CString::new(host).ok()?;
    // SAFETY: an all-zero addrinfo is a valid "no preference" hints value.
    let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
    hints.ai_flags = libc::AI_CANONNAME;
    hints.ai_family = libc::AF_UNSPEC;
    let mut result: *mut libc::addrinfo = std::ptr::null_mut();
    // SAFETY: `host` is a C string, `hints` is valid, and `result` receives a
    // list that is freed below.
    let status = unsafe { libc::getaddrinfo(host.as_ptr(), std::ptr::null(), &hints, &mut result) };
    if status != 0 || result.is_null() {
        return None;
    }
    // SAFETY: getaddrinfo succeeded, so `result` points to a valid addrinfo,
    // and `ai_canonname` is null or a C string.
    let name = unsafe {
        let name = (*result).ai_canonname;
        (!name.is_null()).then(|| CStr::from_ptr(name).to_string_lossy().into_owned())
    };
    // SAFETY: `result` came from getaddrinfo and is freed once.
    unsafe { libc::freeaddrinfo(result) };
    name.filter(|name| !name.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_name_from_gecos() {
        assert_eq!(full_name("Alice Liddell,,,", "alice"), "Alice Liddell");
        assert_eq!(full_name("Alice Liddell", "alice"), "Alice Liddell");
        assert_eq!(full_name("", "alice"), "alice");
        assert_eq!(full_name(",Room 1,,", "alice"), "alice");
    }

    #[test]
    fn given_parts_need_no_lookup() {
        assert_eq!(
            user_id(Some("Test".into()), Some("test@example.org".into())),
            Ok("Test <test@example.org>".to_string())
        );
    }

    #[test]
    fn defaults_come_from_the_current_user() {
        let user = User::from_uid(Uid::current()).unwrap().unwrap();
        let id = user_id(Some("Test".into()), None).unwrap();
        assert!(
            id.starts_with(&format!("Test <{}@", user.name)) && id.ends_with('>'),
            "{id}"
        );
    }
}
