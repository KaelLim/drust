//! Logical file-path grammar for Files RLS (#950-B).
//!
//! `_system_files.path` is a caller-DECLARED label, not an address: the
//! physical Garage key stays the server-minted flat `<uuid>.<ext>`, and no
//! serving, signing or routing code ever reads `path`. It exists so a policy
//! can be attached to a PREFIX ("folder"), and so the admin UI can render a
//! fake tree. That is why this module is a pure grammar check with no I/O.
//!
//! Single choke point: every face that accepts a path (Mode-A multipart, tus
//! `Upload-Metadata`, the host-admin upload form) calls
//! [`validate_file_path`], and the policy registry calls
//! [`validate_file_prefix`]. A violation is rejected (`FILE_PATH_INVALID` /
//! `FILE_POLICY_PREFIX_INVALID`) — **never silently trimmed or normalized**.
//!
//! Deliberate non-goals, each load-bearing:
//!
//! * **No Unicode normalization.** NFC and NFD spellings are two different
//!   paths, stored and compared byte-for-byte. Normalizing here would make the
//!   stored value differ from what the caller declared, and the two policy
//!   evaluators (SQL and in-memory) would then have to agree on a normal form.
//! * **`%` and `_` are ordinary characters.** Prefix matching is a binary range
//!   (`path >= ?p AND path < ?p_upper`), never `LIKE`, so there is nothing to
//!   escape. (`_system_files` columns carry no COLLATE, i.e. BINARY, so the
//!   comparison is also case-SENSITIVE.)
//! * **Paths are not unique.** Two files may declare the same path; a
//!   uniqueness conflict would be an existence oracle for files the caller is
//!   not allowed to see.

/// Maximum length of a whole path (or prefix), in BYTES — not characters.
pub const MAX_PATH_BYTES: usize = 512;
/// Maximum length of one `/`-separated segment, in BYTES.
pub const MAX_SEGMENT_BYTES: usize = 255;

/// Validate a caller-declared file path.
///
/// Rules (spec §path 文法): non-empty, at most [`MAX_PATH_BYTES`] bytes, no
/// leading or trailing `/`, every `/`-separated segment 1..=[`MAX_SEGMENT_BYTES`]
/// bytes and neither `.` nor `..`, and no NUL / C0 control characters
/// (`< 0x20`) or DEL (`0x7F`) anywhere.
///
/// `Err` carries a human-readable reason for the caller to attach to its own
/// error code; it is not itself an error code.
pub fn validate_file_path(path: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err("path must not be empty (omit the field instead)".into());
    }
    if path.len() > MAX_PATH_BYTES {
        return Err(format!(
            "path is {} bytes, over the {} byte limit",
            path.len(),
            MAX_PATH_BYTES
        ));
    }
    if path.starts_with('/') {
        return Err("path must not start with '/'".into());
    }
    if path.ends_with('/') {
        return Err("path must not end with '/'".into());
    }
    for seg in path.split('/') {
        if seg.is_empty() {
            return Err("path must not contain an empty segment ('//')".into());
        }
        if seg.len() > MAX_SEGMENT_BYTES {
            return Err(format!(
                "path segment is {} bytes, over the {} byte limit",
                seg.len(),
                MAX_SEGMENT_BYTES
            ));
        }
        if seg == "." || seg == ".." {
            return Err("path must not contain a '.' or '..' segment".into());
        }
        if let Some(c) = seg.chars().find(is_forbidden_control) {
            return Err(format!(
                "path must not contain control character U+{:04X}",
                c as u32
            ));
        }
    }
    Ok(())
}

/// Validate a policy prefix.
///
/// A prefix is either the empty string (the tenant root, which every path
/// matches) or a valid path with a MANDATORY trailing `/`. The trailing slash
/// is what stops `avatars` from matching `avatarss/x.png`: the range upper
/// bound is derived from the prefix bytes, so a prefix that does not end at a
/// segment boundary would match unrelated siblings.
pub fn validate_file_prefix(prefix: &str) -> Result<(), String> {
    if prefix.is_empty() {
        // '' is the tenant root — legal, and matches every path INCLUDING the
        // NULL (unfiled) ones, which is why it is the seedable default.
        return Ok(());
    }
    if prefix.len() > MAX_PATH_BYTES {
        return Err(format!(
            "prefix is {} bytes, over the {} byte limit",
            prefix.len(),
            MAX_PATH_BYTES
        ));
    }
    let Some(body) = prefix.strip_suffix('/') else {
        return Err("a non-empty prefix must end with '/'".into());
    };
    if body.is_empty() {
        // "/" — the root prefix is the EMPTY string, not a bare slash.
        return Err("the root prefix is '' (empty), not '/'".into());
    }
    validate_file_path(body).map_err(|e| e.replace("path", "prefix"))
}

/// Exclusive upper bound for a prefix range scan: the prefix bytes with the
/// last byte incremented, so `path >= prefix AND path < upper` selects exactly
/// the paths starting with `prefix` under BINARY collation.
///
/// **Contract — the caller guarantees a NON-EMPTY prefix that has already
/// passed [`validate_file_prefix`].** Two things follow from that and neither
/// is checked at runtime in release builds:
///
/// * The last byte is `/` (0x2F), so `+ 1` yields `0` (0x30) and can never
///   overflow a `u8` nor break UTF-8 (both are ASCII).
/// * The root prefix `''` has no upper bound and must never reach here — the
///   root arm of the RLS query matches everything (including `path IS NULL`)
///   and uses no range at all.
///
/// If the contract is somehow violated and the incremented bytes are not valid
/// UTF-8, this returns the prefix UNCHANGED, which makes the range EMPTY —
/// fail-closed, never a wider match.
pub fn prefix_upper_bound(prefix: &str) -> String {
    debug_assert!(
        !prefix.is_empty(),
        "prefix_upper_bound called on the root prefix: the root arm must not use a range"
    );
    debug_assert!(
        prefix.ends_with('/'),
        "prefix_upper_bound called on an unvalidated prefix: {prefix:?} does not end with '/'"
    );
    let mut bytes = prefix.as_bytes().to_vec();
    match bytes.last_mut() {
        Some(last) => {
            debug_assert!(*last < 0xFF, "prefix last byte would overflow");
            *last = last.wrapping_add(1);
        }
        // Unreachable under the contract; an empty bound would be `""`, which
        // makes `path < ''` match nothing — fail-closed.
        None => return String::new(),
    }
    String::from_utf8(bytes).unwrap_or_else(|_| prefix.to_string())
}

fn is_forbidden_control(c: &char) -> bool {
    let u = *c as u32;
    u < 0x20 || u == 0x7F
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_paths() {
        // Exactly at the 512-byte path limit. It takes THREE segments to get
        // there: one segment may not exceed 255 bytes, so a 512-byte single
        // segment is illegal for a different reason and would not test this
        // boundary at all.
        let seg = "x".repeat(170);
        let at_limit = format!("{seg}/{seg}/{seg}");
        assert_eq!(at_limit.len(), MAX_PATH_BYTES);

        let ok = [
            "a/b.png",
            "avatars/alice/me.png",
            "single.txt",
            "照片/家庭/2026.png", // CJK: bytes, not chars
            "weird%name_v1.txt",  // % and _ are literal, never LIKE
            "a.b/c..d/..e",       // dots that are not a whole segment
            "spaces are fine/and so are 'q'.x",
            &at_limit,
        ];
        for p in ok {
            assert!(
                validate_file_path(p).is_ok(),
                "{p:?} should be a valid path: {:?}",
                validate_file_path(p)
            );
        }
    }

    #[test]
    fn rejects_invalid_paths() {
        let bad = [
            "",         // empty
            "/a",       // leading slash
            "a/",       // trailing slash
            "a//b",     // empty segment
            "../x",     // parent traversal
            "a/../b",   // traversal mid-path
            "a/./b",    // current-dir segment
            "a\0b",     // NUL
            "a\nb/c",   // C0 control
            "a\u{7F}b", // DEL
        ];
        for p in bad {
            assert!(
                validate_file_path(p).is_err(),
                "{p:?} should be rejected as a path"
            );
        }
        // Over the byte limits (checked separately so the repeat() is readable).
        assert!(validate_file_path(&"y".repeat(MAX_SEGMENT_BYTES + 1)).is_err());
        // One byte over the PATH limit while every segment is legal — the only
        // shape that exercises the whole-path limit rather than the segment one.
        let seg = "x".repeat(170);
        let over = format!("{seg}/{seg}/{seg}x");
        assert_eq!(over.len(), MAX_PATH_BYTES + 1);
        assert!(validate_file_path(&over).is_err());
        // A segment is measured in BYTES, not chars: 90 CJK chars are 270
        // bytes — under the 512-byte PATH limit, but over the 255-byte SEGMENT
        // limit, so only a byte-wise segment check rejects it.
        let cjk = "照".repeat(90);
        assert_eq!(cjk.len(), 270);
        assert!(validate_file_path(&cjk).is_err());
    }

    #[test]
    fn segment_limit_is_bytes_not_chars() {
        // 255 bytes of ASCII in one segment is the boundary — legal.
        let seg = "z".repeat(MAX_SEGMENT_BYTES);
        assert!(validate_file_path(&seg).is_ok());
        assert!(validate_file_path(&format!("{seg}/{seg}")).is_ok());
    }

    #[test]
    fn accepts_valid_prefixes() {
        for p in ["", "avatars/", "avatars/alice/", "照片/", "a.b/c/"] {
            assert!(
                validate_file_prefix(p).is_ok(),
                "{p:?} should be a valid prefix: {:?}",
                validate_file_prefix(p)
            );
        }
    }

    #[test]
    fn rejects_invalid_prefixes() {
        let bad = [
            "avatars",   // no trailing '/': would match avatarss/
            "/avatars/", // leading slash
            "a/../",     // traversal
            "a//",       // empty segment
            "a/./",      // current-dir segment
            "a\0/",      // NUL
            "/",         // root slash is not the root prefix ('' is)
        ];
        for p in bad {
            assert!(
                validate_file_prefix(p).is_err(),
                "{p:?} should be rejected as a prefix"
            );
        }
        assert!(validate_file_prefix(&format!("{}/", "x".repeat(MAX_PATH_BYTES))).is_err());
    }

    #[test]
    fn upper_bound_brackets_exactly_the_prefix() {
        assert_eq!(prefix_upper_bound("avatars/"), "avatars0");
        assert_eq!(prefix_upper_bound("a/b/"), "a/b0");
        // CJK prefix: the bound is still one byte past the ASCII '/'.
        assert_eq!(prefix_upper_bound("照片/"), "照片0");

        // The range semantics the SQL arm relies on, checked as byte order.
        let (lo, hi) = ("avatars/", prefix_upper_bound("avatars/"));
        for inside in ["avatars/a", "avatars/alice/me.png", "avatars/"] {
            assert!(
                inside.as_bytes() >= lo.as_bytes() && inside.as_bytes() < hi.as_bytes(),
                "{inside:?} must fall inside [{lo:?}, {hi:?})"
            );
        }
        for outside in ["avatar", "avatars", "avatarss/x", "avatart/x", "b"] {
            assert!(
                !(outside.as_bytes() >= lo.as_bytes() && outside.as_bytes() < hi.as_bytes()),
                "{outside:?} must fall OUTSIDE [{lo:?}, {hi:?})"
            );
        }
    }

    #[test]
    fn upper_bound_separates_a_longer_prefix_from_its_parent() {
        // The override case: 'avatars/alice/' must bracket a strict subset of
        // 'avatars/' — that is what makes longest-match a real refinement.
        let (plo, phi) = ("avatars/", prefix_upper_bound("avatars/"));
        let (clo, chi) = ("avatars/alice/", prefix_upper_bound("avatars/alice/"));
        assert!(clo.as_bytes() >= plo.as_bytes() && chi.as_bytes() <= phi.as_bytes());
        let child = "avatars/alice/me.png";
        assert!(child.as_bytes() >= clo.as_bytes() && child.as_bytes() < chi.as_bytes());
        let sibling = "avatars/bob/you.png";
        assert!(!(sibling.as_bytes() >= clo.as_bytes() && sibling.as_bytes() < chi.as_bytes()));
        assert!(sibling.as_bytes() >= plo.as_bytes() && sibling.as_bytes() < phi.as_bytes());
    }
}
