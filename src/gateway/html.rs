//! The auto-submitting launch page and its Content-Security-Policy.

use base64::{engine::general_purpose::STANDARD, Engine};
use ring::digest;

/// The only script on the page. Its hash goes into the CSP, so no
/// `'unsafe-inline'` is needed: any other inline script would be blocked.
pub const AUTO_SUBMIT_SCRIPT: &str = "document.forms[0].submit();";

pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

pub fn launch_page(action: &str, assertion: &str) -> String {
    format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"robots\" content=\"noindex\"><title>Signing you in…</title></head><body>\n\
         <form method=\"POST\" action=\"{}\">\
         <input type=\"hidden\" name=\"assertion\" value=\"{}\">\
         <noscript><button type=\"submit\">Continue to Xentree</button></noscript></form>\n\
         <script>{AUTO_SUBMIT_SCRIPT}</script>\n</body></html>\n",
        escape(action),
        escape(assertion),
    )
}

/// `form-action` limits where the assertion can be posted to Xentree's origin.
pub fn content_security_policy(form_action_origin: &str) -> String {
    let hash = STANDARD.encode(digest::digest(
        &digest::SHA256,
        AUTO_SUBMIT_SCRIPT.as_bytes(),
    ));
    format!(
        "default-src 'none'; form-action {form_action_origin}; script-src 'sha256-{hash}'; \
         frame-ancestors 'none'; base-uri 'none'"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_everything_that_can_break_out_of_an_attribute() {
        assert_eq!(escape(r#"a&b<c>d"e'f"#), "a&amp;b&lt;c&gt;d&quot;e&#39;f");
        assert_eq!(escape("plain-JWT.abc_123"), "plain-JWT.abc_123");
    }

    #[test]
    fn hostile_values_cannot_inject_markup() {
        let page = launch_page(
            r#"https://x.example/"><script>alert(1)</script>"#,
            r#""><img src=x onerror=alert(1)>"#,
        );
        assert!(!page.contains("<script>alert"));
        assert!(!page.contains("<img"));
        assert!(page.contains("&quot;&gt;&lt;script&gt;"));
        // exactly one script element: ours
        assert_eq!(page.matches("<script>").count(), 1);
    }

    #[test]
    fn page_posts_a_hidden_assertion_field() {
        let page = launch_page("https://my.xentree.ai/connect/v1/launch/c1", "AAA.BBB.CCC");
        assert!(page.contains(
            r#"<form method="POST" action="https://my.xentree.ai/connect/v1/launch/c1">"#
        ));
        assert!(page.contains(r#"<input type="hidden" name="assertion" value="AAA.BBB.CCC">"#));
        assert!(page.contains(&format!("<script>{AUTO_SUBMIT_SCRIPT}</script>")));
        assert!(page.contains("<noscript>"));
    }

    #[test]
    fn csp_is_locked_down_and_pins_the_script_by_hash() {
        let csp = content_security_policy("https://my.xentree.ai");
        assert!(csp.starts_with("default-src 'none'; form-action https://my.xentree.ai;"));
        assert!(csp.contains("script-src 'sha256-"));
        assert!(!csp.contains("unsafe-inline"));
        assert!(csp.contains("frame-ancestors 'none'") && csp.contains("base-uri 'none'"));
    }
}
