//! RSS parsing: podcast metadata, items, and every `<podcast:person>` tag (channel and item level).
//!
//! Streams with quick-xml so tag order, line layout, namespace prefixes and escaped attribute
//! values don't matter, and a malformed tail still yields everything before it.

use quick_xml::events::{BytesStart, Event};

#[derive(Debug, Clone, PartialEq)]
pub struct FeedPerson {
    pub name: String,
    pub role: Option<String>,
    pub group: Option<String>,
    pub img: Option<String>,
    pub href: Option<String>,
}

#[derive(Debug, Default, Clone)]
pub struct FeedItem {
    pub guid: Option<String>,
    pub title: String,
    pub description: Option<String>,
    pub link: Option<String>,
    pub enclosure_url: Option<String>,
    pub image: Option<String>,
    pub pub_date: Option<String>,
    pub duration: Option<i64>,
    pub season: Option<i64>,
    pub episode_number: Option<i64>,
    pub people: Vec<FeedPerson>,
}

#[derive(Debug, Default, Clone)]
pub struct ParsedFeed {
    pub title: String,
    pub description: Option<String>,
    pub link: Option<String>,
    pub author: Option<String>,
    pub owner_name: Option<String>,
    pub image: Option<String>,
    pub podcast_guid: Option<String>,
    pub people: Vec<FeedPerson>,
    pub items: Vec<FeedItem>,
}

impl ParsedFeed {
    pub fn has_person_tags(&self) -> bool {
        !self.people.is_empty() || self.items.iter().any(|i| !i.people.is_empty())
    }
}

fn attr(e: &BytesStart, key: &str) -> Option<String> {
    e.attributes()
        .flatten()
        .find(|a| a.key.as_ref() == key)
        .and_then(|a| a.normalized_value(quick_xml::XmlVersion::Implicit1_0).ok().map(|v| v.trim().to_string()))
        .filter(|v| !v.is_empty())
}

/// What a closing tag's text should be stored as.
#[derive(Clone, Copy, PartialEq)]
enum Field {
    Title,
    Description,
    Summary,
    Link,
    Author,
    OwnerName,
    ImageUrl,
    Guid,
    PubDate,
    Duration,
    Season,
    Episode,
    PodcastGuid,
    Person,
}

fn field_for(qname: &str, in_item: bool, in_owner: bool, in_image: bool) -> Option<Field> {
    let (prefix, local) = qname.split_once(':').unwrap_or(("", qname));
    Some(match (prefix, local) {
        ("", "title") if !in_image => Field::Title,
        ("", "description") => Field::Description,
        ("itunes", "summary") => Field::Summary,
        ("", "link") if !in_image => Field::Link,
        ("itunes", "author") if !in_item => Field::Author,
        ("itunes", "name") if in_owner => Field::OwnerName,
        ("", "url") if in_image => Field::ImageUrl,
        ("", "guid") if in_item => Field::Guid,
        ("", "pubDate") if in_item => Field::PubDate,
        ("itunes", "duration") if in_item => Field::Duration,
        ("itunes", "season") if in_item => Field::Season,
        ("itunes", "episode") if in_item => Field::Episode,
        (_, "guid") if !prefix.is_empty() && !in_item => Field::PodcastGuid,
        (_, "person") if !prefix.is_empty() => Field::Person,
        _ => return None,
    })
}

/// `itunes:duration` is seconds, MM:SS or HH:MM:SS.
pub fn parse_duration(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let mut total: i64 = 0;
    for part in s.split(':') {
        let n: f64 = part.trim().parse().ok()?;
        total = total * 60 + n as i64;
    }
    Some(total)
}

/// RFC 2822 pubDate (with the usual real-world sloppiness) to schema timestamp.
pub fn parse_pub_date(s: &str) -> Option<String> {
    let s = s.trim();
    if let Ok(t) = chrono::DateTime::parse_from_rfc2822(s) {
        return Some(crate::db::fmt_ts(t.with_timezone(&chrono::Utc)));
    }
    // Common breakage: named zones chrono doesn't know ("PST", "EDT"), or a missing weekday.
    let fixed = s
        .replace(" PST", " -0800")
        .replace(" PDT", " -0700")
        .replace(" EST", " -0500")
        .replace(" EDT", " -0400")
        .replace(" CST", " -0600")
        .replace(" CDT", " -0500")
        .replace(" UTC", " +0000")
        .replace(" UT", " +0000")
        .replace(" Z", " +0000");
    if let Ok(t) = chrono::DateTime::parse_from_rfc2822(&fixed) {
        return Some(crate::db::fmt_ts(t.with_timezone(&chrono::Utc)));
    }
    for fmt in ["%d %b %Y %H:%M:%S %z", "%a, %d %b %Y %H:%M %z"] {
        if let Ok(t) = chrono::DateTime::parse_from_str(&fixed, fmt) {
            return Some(crate::db::fmt_ts(t.with_timezone(&chrono::Utc)));
        }
    }
    crate::db::parse_ts(s).map(crate::db::fmt_ts)
}

pub fn parse(bytes: &[u8]) -> Result<ParsedFeed, String> {
    let mut reader = quick_xml::Reader::from_reader(bytes);
    reader.config_mut().trim_text(false);
    let mut buf = Vec::new();

    let mut feed = ParsedFeed::default();
    let mut saw_channel = false;
    let mut item: Option<FeedItem> = None;
    let mut in_owner = false;
    let mut in_image = false;
    // Raw (still-escaped) text of the innermost element, and the element it belongs to.
    let mut text = String::new();
    let mut person_attrs: Option<BytesStart<'static>> = None;
    let mut channel_summary: Option<String> = None;
    let mut item_summary: Option<String> = None;

    loop {
        let event = match reader.read_event_into(&mut buf) {
            Ok(Event::Eof) => break,
            Ok(ev) => ev,
            Err(e) => {
                if !saw_channel {
                    return Err(format!("not a valid RSS feed: {e}"));
                }
                tracing::debug!("feed parse stopped early: {e}");
                break;
            }
        };
        match event {
            Event::Start(e) => {
                // Only a field's own start resets the buffer, so markup nested inside a
                // non-CDATA description doesn't cut its text short.
                if field_for(e.name().as_ref(), item.is_some(), in_owner, in_image).is_some() {
                    text.clear();
                }
                match e.name().as_ref() {
                    "channel" => saw_channel = true,
                    "item" => {
                        item = Some(FeedItem::default());
                        item_summary = None;
                    }
                    "itunes:owner" => in_owner = true,
                    "image" => in_image = true,
                    _ => {}
                }
                if field_for(e.name().as_ref(), item.is_some(), in_owner, in_image) == Some(Field::Person) {
                    person_attrs = Some(e.into_owned());
                }
            }
            Event::Empty(e) => {
                match (e.name().as_ref(), item.as_mut()) {
                    ("enclosure", Some(it)) => {
                        if it.enclosure_url.is_none() {
                            it.enclosure_url = attr(&e, "url");
                        }
                    }
                    ("itunes:image", Some(it)) => it.image = it.image.take().or_else(|| attr(&e, "href")),
                    ("itunes:image", None) => {
                        if let Some(href) = attr(&e, "href") {
                            feed.image = Some(href);
                        }
                    }
                    _ => {}
                }
            }
            Event::Text(t) => text.push_str(&t.xml10_content()),
            Event::GeneralRef(r) => {
                text.push('&');
                text.push_str(&r.xml10_content());
                text.push(';');
            }
            Event::CData(c) => {
                text.push_str(&quick_xml::escape::escape(c.into_inner().into_owned()));
            }
            Event::End(e) => {
                let qname = e.name();
                let qname = qname.as_ref();
                let mut value = || {
                    let raw = std::mem::take(&mut text);
                    let v = quick_xml::escape::unescape(&raw).map(|c| c.into_owned()).unwrap_or(raw);
                    let v = v.trim().to_string();
                    (!v.is_empty()).then_some(v)
                };
                match qname {
                    "item" => {
                        if let Some(mut it) = item.take() {
                            if it.description.is_none() {
                                it.description = item_summary.take();
                            }
                            if !it.title.is_empty() || it.enclosure_url.is_some() {
                                feed.items.push(it);
                            }
                        }
                        continue;
                    }
                    "itunes:owner" => {
                        in_owner = false;
                        continue;
                    }
                    "image" => {
                        in_image = false;
                        continue;
                    }
                    _ => {}
                }
                let Some(field) = field_for(qname, item.is_some(), in_owner, in_image) else {
                    continue;
                };
                let Some(v) = value() else {
                    person_attrs = None;
                    continue;
                };
                match (field, item.as_mut()) {
                    (Field::Person, target) => {
                        if let Some(a) = person_attrs.take() {
                            let p = FeedPerson {
                                name: crate::normalize::clean_name(&v),
                                role: attr(&a, "role"),
                                group: attr(&a, "group"),
                                img: attr(&a, "img"),
                                href: attr(&a, "href"),
                            };
                            let list = match target {
                                Some(it) => &mut it.people,
                                None => &mut feed.people,
                            };
                            if !p.name.is_empty() && !list.contains(&p) {
                                list.push(p);
                            }
                        }
                    }
                    (Field::Title, Some(it)) => it.title = v,
                    (Field::Description, Some(it)) => it.description = Some(v),
                    (Field::Summary, Some(_)) => item_summary = Some(v),
                    (Field::Link, Some(it)) => it.link = Some(v),
                    (Field::Guid, Some(it)) => it.guid = Some(v),
                    (Field::PubDate, Some(it)) => it.pub_date = parse_pub_date(&v),
                    (Field::Duration, Some(it)) => it.duration = parse_duration(&v),
                    (Field::Season, Some(it)) => it.season = v.parse().ok(),
                    (Field::Episode, Some(it)) => it.episode_number = v.parse().ok(),
                    (Field::Title, None) if feed.title.is_empty() => feed.title = v,
                    (Field::Description, None) if feed.description.is_none() => feed.description = Some(v),
                    (Field::Summary, None) => channel_summary = Some(v),
                    (Field::Link, None) if feed.link.is_none() => feed.link = Some(v),
                    (Field::Author, None) => feed.author = Some(v),
                    (Field::OwnerName, None) => feed.owner_name = Some(v),
                    (Field::ImageUrl, None) if feed.image.is_none() => feed.image = Some(v),
                    (Field::PodcastGuid, None) => feed.podcast_guid = Some(v),
                    _ => {}
                }
            }
            _ => {}
        }
        buf.clear();
    }

    if !saw_channel {
        return Err("not an RSS feed (no <channel>)".into());
    }
    if feed.description.is_none() {
        feed.description = channel_summary;
    }
    Ok(feed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FEED: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:itunes="http://www.itunes.com/dtds/podcast-1.0.dtd" xmlns:podcast="https://podcastindex.org/namespace/1.0">
<channel>
  <title>Test &amp; Show</title>
  <link>https://example.com</link>
  <description><![CDATA[A <b>great</b> show]]></description>
  <itunes:author>Alice Example &amp; Bob Example</itunes:author>
  <itunes:owner><itunes:name>Alice Example</itunes:name><itunes:email>a@example.com</itunes:email></itunes:owner>
  <itunes:image href="https://example.com/cover.jpg"/>
  <image><url>https://example.com/rss.jpg</url><title>ignored</title><link>https://ignored</link></image>
  <podcast:guid>917393e3-1b1e-5cef-ace4-edaa54e1f810</podcast:guid>
  <podcast:person role="host" img="https://example.com/alice.jpg" href="https://alice.example">Alice Example</podcast:person>
  <podcast:person
      role="Co-Host">Bob
      Example</podcast:person>
  <item>
    <title>Episode 2</title>
    <guid isPermaLink="false">ep-2</guid>
    <pubDate>Tue, 20 Oct 2026 10:00:00 PDT</pubDate>
    <itunes:duration>1:02:03</itunes:duration>
    <enclosure url="https://cdn.example.com/2.mp3?a=1&amp;b=2" type="audio/mpeg" length="1"/>
    <podcast:person role="guest" group="cast">Carol Guest</podcast:person>
  </item>
  <item>
    <title>Episode 1</title>
    <itunes:summary>Summary only</itunes:summary>
    <enclosure url="https://cdn.example.com/1.mp3" type="audio/mpeg" length="1"/>
    <itunes:duration>95</itunes:duration>
  </item>
</channel>
</rss>"#;

    #[test]
    fn parses_metadata_people_and_items() {
        let f = parse(FEED.as_bytes()).unwrap();
        assert_eq!(f.title, "Test & Show");
        assert_eq!(f.author.as_deref(), Some("Alice Example & Bob Example"));
        assert_eq!(f.owner_name.as_deref(), Some("Alice Example"));
        assert_eq!(f.image.as_deref(), Some("https://example.com/cover.jpg"));
        assert_eq!(f.podcast_guid.as_deref(), Some("917393e3-1b1e-5cef-ace4-edaa54e1f810"));
        assert_eq!(f.description.as_deref(), Some("A <b>great</b> show"));

        assert_eq!(f.people.len(), 2);
        assert_eq!(f.people[0].name, "Alice Example");
        assert_eq!(f.people[0].img.as_deref(), Some("https://example.com/alice.jpg"));
        assert_eq!(f.people[1].name, "Bob Example", "multi-line tag text is collapsed");
        assert_eq!(f.people[1].role.as_deref(), Some("Co-Host"));

        assert_eq!(f.items.len(), 2);
        let e2 = &f.items[0];
        assert_eq!(e2.guid.as_deref(), Some("ep-2"));
        assert_eq!(e2.enclosure_url.as_deref(), Some("https://cdn.example.com/2.mp3?a=1&b=2"));
        assert_eq!(e2.duration, Some(3723));
        assert_eq!(e2.pub_date.as_deref(), Some("2026-10-20T17:00:00Z"));
        assert_eq!(e2.people, vec![FeedPerson {
            name: "Carol Guest".into(),
            role: Some("guest".into()),
            group: Some("cast".into()),
            img: None,
            href: None,
        }]);
        assert_eq!(f.items[1].description.as_deref(), Some("Summary only"));
        assert_eq!(f.items[1].duration, Some(95));
        assert!(f.has_person_tags());
    }

    #[test]
    fn single_line_feed() {
        let one_line = FEED.replace('\n', "");
        let f = parse(one_line.as_bytes()).unwrap();
        assert_eq!(f.people.len(), 2);
        assert_eq!(f.items[0].people.len(), 1);
    }

    #[test]
    fn rejects_non_feeds() {
        assert!(parse(b"<html><body>nope</body></html>").is_err());
        assert!(parse(b"not xml at all").is_err());
    }
}
