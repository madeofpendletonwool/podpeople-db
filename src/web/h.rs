//! Small formatting helpers called from templates.

/// Proxied image URL (avoids mixed content and hotlink blocks, keeps visitor IPs private).
pub fn img(url: &str) -> String {
    if url.starts_with('/') {
        return url.to_string();
    }
    format!("/img?u={}", urlencoding::encode(url))
}

/// Like `img`, but falls back to the cover placeholder instead of the avatar one.
pub fn cover_img(url: &str) -> String {
    format!("{}&k=cover", img(url))
}

pub fn person_url(id: &i64, slug: &str) -> String {
    format!("/people/{id}/{slug}")
}

pub fn initials(name: &str) -> String {
    let words: Vec<&str> = name.split_whitespace().filter(|w| w.chars().next().is_some_and(char::is_alphanumeric)).collect();
    let mut out = String::new();
    if let Some(first) = words.first() {
        out.extend(first.chars().next().map(|c| c.to_uppercase().collect::<String>()));
    }
    if words.len() > 1 {
        if let Some(last) = words.last() {
            out.extend(last.chars().next().map(|c| c.to_uppercase().collect::<String>()));
        }
    }
    if out.is_empty() {
        "?".into()
    } else {
        out
    }
}

/// Stable, readable background for an initials avatar.
pub fn avatar_color(name: &str) -> String {
    let hash = name.bytes().fold(5381u32, |h, b| h.wrapping_mul(33) ^ b as u32);
    format!("hsl({} 38% 42%)", hash % 360)
}

/// Templates hand helpers either values or references; accept both.
pub trait Int {
    fn int(&self) -> i64;
}
impl Int for i64 {
    fn int(&self) -> i64 {
        *self
    }
}
impl Int for usize {
    fn int(&self) -> i64 {
        *self as i64
    }
}
impl<T: Int + ?Sized> Int for &T {
    fn int(&self) -> i64 {
        (**self).int()
    }
}

pub fn num(n: impl Int) -> String {
    let s = n.int().to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 && c != '-' {
            out.push(',');
        }
        out.push(c);
    }
    out
}

pub fn plural(n: impl Int, word: &str) -> String {
    let n = n.int();
    let w = match (n, word) {
        (1, w) => w.to_string(),
        (_, "person") => "people".to_string(),
        (_, w) => format!("{w}s"),
    };
    format!("{} {w}", num(n))
}

fn parse(ts: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    crate::db::parse_ts(ts)
}

pub fn date<S: AsRef<str>>(ts: &Option<S>) -> String {
    ts.as_ref().and_then(|t| parse(t.as_ref())).map(|t| t.format("%b %-d, %Y").to_string()).unwrap_or_default()
}

pub fn ago(ts: &str) -> String {
    let Some(t) = parse(ts) else { return String::new() };
    let secs = (chrono::Utc::now() - t).num_seconds().max(0);
    match secs {
        0..=59 => "just now".into(),
        60..=3599 => format!("{}m ago", secs / 60),
        3600..=86_399 => format!("{}h ago", secs / 3600),
        86_400..=2_591_999 => format!("{}d ago", secs / 86_400),
        _ => t.format("%b %-d, %Y").to_string(),
    }
}

pub fn duration(secs: impl Int) -> String {
    let secs = secs.int();
    if secs <= 0 {
        return String::new();
    }
    let (h, m) = (secs / 3600, (secs % 3600) / 60);
    if h > 0 {
        format!("{h}h {m:02}m")
    } else {
        format!("{}m", m.max(1))
    }
}

/// Feed descriptions are HTML; show them as plain text, capped.
pub fn plain(html: &str, max: usize) -> String {
    let mut out = String::with_capacity(html.len().min(max + 16));
    let mut in_tag = false;
    for c in html.chars() {
        match c {
            '<' => {
                in_tag = true;
                out.push(' ');
            }
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    let text = out
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&rsquo;", "’")
        .replace("&lsquo;", "‘")
        .replace("&ldquo;", "“")
        .replace("&rdquo;", "”");
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if text.chars().count() > max {
        let cut: String = text.chars().take(max).collect();
        format!("{}…", cut.trim_end())
    } else {
        text
    }
}

/// "https://www.example.com/x" -> "example.com"
pub fn host_of(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.trim_start_matches("www.").to_string()))
        .unwrap_or_else(|| url.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats() {
        assert_eq!(initials("Griffin McElroy"), "GM");
        assert_eq!(initials("Madonna"), "M");
        assert_eq!(initials("  "), "?");
        assert_eq!(num(1234567i64), "1,234,567");
        assert_eq!(plural(1i64, "person"), "1 person");
        assert_eq!(plural(3i64, "person"), "3 people");
        assert_eq!(duration(3723i64), "1h 02m");
        assert_eq!(plain("<p>Hi &amp; <b>bye</b></p>", 100), "Hi & bye");
        assert_eq!(host_of("https://www.example.com/a"), "example.com");
    }
}
