//! Admin-UI handler for the built-in CHANGELOG viewer.
//!
//! Service-key admin only — the route lives under `tenants_router` in
//! `routes.rs`, which carries the admin-session layer. We render the
//! repo's `CHANGELOG.md` — embedded in the binary at compile time, see
//! [`CHANGELOG_MD`] — through `pulldown-cmark` with GFM extensions and
//! emit our own `<hN id="...">` so each `## v…` heading gets a stable
//! anchor for the in-page sidebar (`tenant_docs.html`'s docs-toc).

use crate::mgmt::i18n::{LocaleHint, Translator};
use askama::Template;
use axum::response::{Html, IntoResponse, Response};
use pulldown_cmark::{CodeBlockKind, Event, HeadingLevel, Options, Parser, Tag, TagEnd, html};
use std::collections::HashMap;

#[derive(Template)]
#[template(path = "tenant_docs.html")]
struct DocsPage {
    title: &'static str,
    body_html: String,
    nav: Vec<NavItem>,
    source_path: &'static str,
    version: &'static str,
    active: &'static str,
    t: Translator,
    admin: crate::mgmt::admin_profile::AdminProfileExt,
    palette_resolved: crate::mgmt::theme::ResolvedPalette,
    mascot_json_static: String,
    mascot_json_light: String,
    mascot_json_dark: String,
}

/// The repo's `CHANGELOG.md`, embedded at compile time.
///
/// The container image runs with cwd `/data` and ships the binary only, so a
/// cwd-relative read answered 404 there. Embedding also guarantees the page
/// shows the changelog of the build that is answering, which the page's own
/// `version` label already claims. Never read it from disk at request time:
/// `changelog_page_never_reads_the_filesystem` pins that.
const CHANGELOG_MD: &str = include_str!("../../CHANGELOG.md");

pub struct NavItem {
    pub slug: String,
    pub text: String,
}

pub async fn changelog_page(
    LocaleHint(locale): LocaleHint,
    crate::mgmt::theme::ThemeHint(theme): crate::mgmt::theme::ThemeHint,
    axum::Extension(admin): axum::Extension<crate::mgmt::admin_profile::AdminProfileExt>,
) -> Response {
    let (body_html, nav) = render_markdown(CHANGELOG_MD);
    let trc = crate::mgmt::theme::ThemeRenderCtx::build(theme);
    let page = DocsPage {
        title: "CHANGELOG",
        body_html,
        nav,
        // A label only: the content is the embedded copy.
        source_path: "CHANGELOG.md",
        version: env!("CARGO_PKG_VERSION"),
        active: "changelog",
        t: Translator::new(locale),
        admin,
        palette_resolved: trc.palette_resolved,
        mascot_json_static: trc.mascot_json_static,
        mascot_json_light: trc.mascot_json_light,
        mascot_json_dark: trc.mascot_json_dark,
    };
    Html(page.render().unwrap()).into_response()
}

fn render_markdown(src: &str) -> (String, Vec<NavItem>) {
    let mut opts = Options::empty();
    opts.insert(Options::ENABLE_TABLES);
    opts.insert(Options::ENABLE_STRIKETHROUGH);
    opts.insert(Options::ENABLE_TASKLISTS);
    opts.insert(Options::ENABLE_FOOTNOTES);
    opts.insert(Options::ENABLE_GFM);

    let parser = Parser::new_ext(src, opts);
    let mut events: Vec<Event> = Vec::new();
    let mut nav: Vec<NavItem> = Vec::new();
    let mut used: HashMap<String, u32> = HashMap::new();

    let mut in_heading: Option<HeadingLevel> = None;
    let mut heading_text = String::new();
    let mut heading_inner: Vec<Event> = Vec::new();

    let mut in_mermaid = false;
    let mut mermaid_buf = String::new();

    for event in parser {
        match event {
            Event::Start(Tag::CodeBlock(CodeBlockKind::Fenced(ref lang)))
                if lang.as_ref() == "mermaid" =>
            {
                in_mermaid = true;
                mermaid_buf.clear();
            }
            Event::End(TagEnd::CodeBlock) if in_mermaid => {
                in_mermaid = false;
                let escaped = html_escape(&mermaid_buf);
                events.push(Event::Html(
                    format!("<pre class=\"mermaid\">{escaped}</pre>").into(),
                ));
                mermaid_buf.clear();
            }
            Event::Text(t) if in_mermaid => mermaid_buf.push_str(&t),

            Event::Start(Tag::Heading { level, .. }) => {
                in_heading = Some(level);
                heading_text.clear();
                heading_inner.clear();
            }
            Event::End(TagEnd::Heading(level)) => {
                let slug = unique_slug(&heading_text, &mut used);
                let tag = heading_tag(level);
                events.push(Event::Html(format!("<{tag} id=\"{slug}\">").into()));
                events.append(&mut heading_inner);
                events.push(Event::Html(format!("</{tag}>").into()));
                if matches!(level, HeadingLevel::H2) {
                    nav.push(NavItem {
                        slug,
                        text: std::mem::take(&mut heading_text),
                    });
                }
                in_heading = None;
                heading_text.clear();
            }
            Event::Text(t) if in_heading.is_some() => {
                heading_text.push_str(&t);
                heading_inner.push(Event::Text(t));
            }
            Event::Code(c) if in_heading.is_some() => {
                heading_text.push_str(&c);
                heading_inner.push(Event::Code(c));
            }
            other if in_heading.is_some() => heading_inner.push(other),

            other if !in_mermaid => events.push(other),
            _ => {}
        }
    }

    let mut out = String::new();
    html::push_html(&mut out, events.into_iter());
    (out, nav)
}

fn heading_tag(level: HeadingLevel) -> &'static str {
    match level {
        HeadingLevel::H1 => "h1",
        HeadingLevel::H2 => "h2",
        HeadingLevel::H3 => "h3",
        HeadingLevel::H4 => "h4",
        HeadingLevel::H5 => "h5",
        HeadingLevel::H6 => "h6",
    }
}

fn slugify(text: &str) -> String {
    let mut s = String::with_capacity(text.len());
    let mut prev_dash = false;
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() {
            s.push(ch.to_ascii_lowercase());
            prev_dash = false;
        } else if ch == '-' || ch == '_' {
            s.push(ch);
            prev_dash = ch == '-';
        } else if ch.is_whitespace() || ".,()[]{}!?'\"`/\\:;|<>".contains(ch) {
            if !prev_dash && !s.is_empty() {
                s.push('-');
                prev_dash = true;
            }
        } else {
            s.push(ch);
            prev_dash = false;
        }
    }
    while s.ends_with('-') {
        s.pop();
    }
    if s.is_empty() {
        s.push_str("section");
    }
    s
}

fn unique_slug(text: &str, used: &mut HashMap<String, u32>) -> String {
    let base = slugify(text);
    let count = used.entry(base.clone()).or_insert(0);
    let slug = if *count == 0 {
        base.clone()
    } else {
        format!("{base}-{}", *count)
    };
    *count += 1;
    slug
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changelog_is_embedded_and_renders() {
        assert!(
            !CHANGELOG_MD.trim().is_empty(),
            "the embedded CHANGELOG.md must not be empty"
        );
        let (body_html, nav) = render_markdown(CHANGELOG_MD);
        assert!(!body_html.is_empty(), "the embedded changelog must render");
        assert!(
            !nav.is_empty(),
            "the embedded changelog must yield at least one `## v…` nav entry"
        );
    }

    #[test]
    fn changelog_page_never_reads_the_filesystem() {
        // The image's cwd is /data and it ships the binary only, so any
        // request-time read of CHANGELOG.md 404s there. Code only: a comment
        // naming the old call must not trip (or hide) the pin.
        let code =
            crate::tenant::rooms::srcpin::code_only(include_str!("docs.rs")).replace(' ', "");
        let prod = crate::tenant::rooms::srcpin::production_half(&code);
        for needle in ["tokio::fs", "std::fs", "read_to_string(", "File::open("] {
            assert!(
                !prod.contains(needle),
                "src/mgmt/docs.rs production code must not read the filesystem (found `{needle}`)"
            );
        }
    }
}
