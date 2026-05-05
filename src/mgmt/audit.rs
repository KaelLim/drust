//! Admin-UI audit log viewer.
//!
//! Stateless read path on top of `$DRUST_LOG_DIR/audit-YYYY-MM-DD.jsonl{,.1,.N.gz}`.
//! No in-memory cache; every request rescans. See spec
//! `docs/superpowers/specs/2026-05-05-drust-audit-ui-design.md`.

#![allow(dead_code)] // scaffolding: types and helpers land in subsequent tasks

#[cfg(test)]
mod tests {
    #[test]
    fn module_compiles() {
        // sentinel — replaced by real tests in later tasks
    }
}
