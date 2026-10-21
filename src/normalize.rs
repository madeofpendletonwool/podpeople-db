//! Name, role and URL normalization shared by the crawler, submissions and search.

use unicode_normalization::UnicodeNormalization;

/// Canonical key for matching people by name: accent-folded, lowercased, punctuation dropped,
/// whitespace collapsed. "Griffin McElroy", "griffin  mcelroy" and "Griffin Mcélroy" all map to
/// "griffin mcelroy".
pub fn normalize_name(name: &str) -> String {
    let folded: String = name
        .nfkd()
        .filter(|c| !unicode_normalization::char::is_combining_mark(*c))
        .flat_map(|c| c.to_lowercase())
        .map(|c| match c {
            'ß' => 's',
            'ø' => 'o',
            'æ' => 'a',
            'đ' | 'ð' => 'd',
            'ł' => 'l',
            other => other,
        })
        .collect();
    let mut out = String::with_capacity(folded.len());
    for c in folded.chars() {
        if c.is_alphanumeric() {
            out.push(c);
        } else if c.is_whitespace() || c == '-' || c == '_' {
            out.push(' ');
        }
        // Other punctuation (".", "'", ...) is dropped: "J.R.R. Tolkien" ~ "JRR Tolkien".
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// URL slug for a person page: "Griffin McElroy" -> "griffin-mcelroy".
pub fn slugify(name: &str) -> String {
    let slug = normalize_name(name).replace(' ', "-");
    if slug.is_empty() {
        "person".into()
    } else {
        slug.chars().take(80).collect()
    }
}

/// Tidy a display name: trim, collapse internal whitespace, cap length.
pub fn clean_name(name: &str) -> String {
    name.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(120).collect()
}

/// Podcasting 2.0 roles (https://podcasttaxonomy.com), lowercased, mapped to their group.
const ROLES: &[(&str, &str)] = &[
    ("host", "cast"),
    ("co-host", "cast"),
    ("guest", "cast"),
    ("guest host", "cast"),
    ("announcer", "cast"),
    ("voice actor", "cast"),
    ("narrator", "cast"),
    ("cover art designer", "visuals"),
    ("producer", "creative direction"),
    ("executive producer", "creative direction"),
    ("director", "creative direction"),
    ("editor", "post production"),
    ("audio editor", "audio post-production"),
    ("sound designer", "audio production"),
    ("composer", "audio production"),
    ("writer", "writing"),
    ("researcher", "writing"),
    ("social media manager", "misc."),
];

/// Lowercase and canonicalize a role. Unknown roles are kept (feeds use free text), so this only
/// fixes spelling variants of the common ones. Empty input means "host" (the spec's default).
pub fn normalize_role(role: &str) -> String {
    let r = role.trim().to_lowercase().replace(['_'], " ");
    let r = r.split_whitespace().collect::<Vec<_>>().join(" ");
    match r.as_str() {
        "" => "host".into(),
        "cohost" | "co host" => "co-host".into(),
        "guests" => "guest".into(),
        "hosts" => "host".into(),
        _ => r.chars().take(60).collect(),
    }
}

/// Group for a role, per the taxonomy; unknown roles fall back to the given group or "cast".
pub fn group_for_role(role: &str, given: Option<&str>) -> String {
    if let Some(g) = given.map(str::trim).filter(|g| !g.is_empty()) {
        return g.to_lowercase();
    }
    ROLES
        .iter()
        .find(|(r, _)| *r == role)
        .map(|(_, g)| g.to_string())
        .unwrap_or_else(|| "cast".into())
}

/// Roles that mean "regular on the show" when credited at podcast level.
pub fn is_host_role(role: &str) -> bool {
    matches!(role, "host" | "co-host")
}

/// Split a free-text list of names the way people type them: "Alice, Bob and Carol",
/// "Alice & Bob", or one per line. Used by the contribute form so pasting several names creates
/// several people.
pub fn split_names(input: &str) -> Vec<String> {
    let mut names = Vec::new();
    for line in input.split(['\n', ',', ';']) {
        for part in split_on_conjunctions(line) {
            let n = clean_name(&part);
            if !n.is_empty() && !names.iter().any(|x: &String| normalize_name(x) == normalize_name(&n)) {
                names.push(n);
            }
        }
    }
    names
}

fn split_on_conjunctions(s: &str) -> Vec<String> {
    let mut out = vec![String::new()];
    for word in s.split_whitespace() {
        if matches!(word.to_lowercase().as_str(), "and" | "&" | "+" | "with") {
            out.push(String::new());
        } else {
            let cur = out.last_mut().unwrap();
            if !cur.is_empty() {
                cur.push(' ');
            }
            cur.push_str(word);
        }
    }
    out.into_iter().filter(|p| !p.is_empty()).collect()
}

/// Canonical form of a feed URL for dedup: trimmed, scheme/host lowercased, no fragment.
pub fn normalize_feed_url(raw: &str) -> Option<String> {
    let mut u = url::Url::parse(raw.trim()).ok()?;
    if !matches!(u.scheme(), "http" | "https") {
        return None;
    }
    u.set_fragment(None);
    Some(u.to_string())
}

/// Accept only http(s) URLs for user-supplied links and images.
pub fn clean_url(raw: Option<&str>) -> Option<String> {
    let raw = raw?.trim();
    if raw.is_empty() {
        return None;
    }
    let u = url::Url::parse(raw).ok()?;
    matches!(u.scheme(), "http" | "https").then(|| u.to_string())
}

pub fn clean_text(raw: Option<&str>, max: usize) -> Option<String> {
    let t = raw?.trim();
    (!t.is_empty()).then(|| t.chars().take(max).collect())
}

/// Accept an integer as a JSON number or a string. Query strings go through serde's flatten as
/// strings, so every flattened numeric query field needs this.
pub fn de_opt_i64<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<i64>, D::Error> {
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum NumOrStr {
        Num(i64),
        Str(String),
    }
    match <Option<NumOrStr> as serde::Deserialize>::deserialize(d)? {
        None => Ok(None),
        Some(NumOrStr::Num(n)) => Ok(Some(n)),
        Some(NumOrStr::Str(s)) if s.trim().is_empty() => Ok(None),
        Some(NumOrStr::Str(s)) => s.trim().parse().map(Some).map_err(serde::de::Error::custom),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_names() {
        assert_eq!(normalize_name("  Griffin   McElroy "), "griffin mcelroy");
        assert_eq!(normalize_name("Beyoncé"), "beyonce");
        assert_eq!(normalize_name("J.R.R. Tolkien"), "jrr tolkien");
        assert_eq!(normalize_name("Jean-Luc Picard"), "jean luc picard");
        assert_eq!(slugify("Jean-Luc Picard"), "jean-luc-picard");
    }

    #[test]
    fn splits_name_lists() {
        assert_eq!(split_names("Alice, Bob and Carol"), vec!["Alice", "Bob", "Carol"]);
        assert_eq!(split_names("Alice & Bob\nDave"), vec!["Alice", "Bob", "Dave"]);
        assert_eq!(split_names("Alice, alice"), vec!["Alice"]);
        assert_eq!(split_names("  "), Vec::<String>::new());
    }

    #[test]
    fn normalizes_roles() {
        assert_eq!(normalize_role("Host"), "host");
        assert_eq!(normalize_role(""), "host");
        assert_eq!(normalize_role("CoHost"), "co-host");
        assert_eq!(group_for_role("producer", None), "creative direction");
        assert_eq!(group_for_role("guest", Some("Cast")), "cast");
    }
}
