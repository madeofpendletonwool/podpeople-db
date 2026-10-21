//! Database access. Everything public-facing filters out `hidden` rows.

pub mod admin;
pub mod credits;
pub mod people;
pub mod podcasts;
pub mod stats;
pub mod submissions;

use serde::Serialize;

/// The fields of a person every listing needs.
#[derive(Debug, Clone, Serialize, sqlx::FromRow, PartialEq)]
pub struct PersonRef {
    pub id: i64,
    pub slug: String,
    pub name: String,
    pub img: Option<String>,
    pub verified: bool,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Person {
    pub id: i64,
    pub slug: String,
    pub name: String,
    pub bio: Option<String>,
    pub img: Option<String>,
    pub website: Option<String>,
    pub verified: bool,
    pub created_at: String,
    pub updated_at: String,
}

impl Person {
    pub fn as_ref(&self) -> PersonRef {
        PersonRef {
            id: self.id,
            slug: self.slug.clone(),
            name: self.name.clone(),
            img: self.img.clone(),
            verified: self.verified,
        }
    }
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Podcast {
    pub id: i64,
    pub podcastindex_id: Option<i64>,
    pub podcast_guid: Option<String>,
    pub feed_url: Option<String>,
    pub title: String,
    pub description: Option<String>,
    pub author: Option<String>,
    pub owner_name: Option<String>,
    pub image: Option<String>,
    pub link: Option<String>,
    pub has_person_tags: bool,
    pub last_crawled_at: Option<String>,
    pub crawl_error: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Compact podcast reference for listings.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct PodcastRef {
    pub id: i64,
    pub podcastindex_id: Option<i64>,
    pub title: String,
    pub image: Option<String>,
    pub feed_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Episode {
    pub id: i64,
    pub podcast_id: i64,
    pub guid: Option<String>,
    pub enclosure_url: Option<String>,
    pub title: String,
    pub description: Option<String>,
    pub link: Option<String>,
    pub image: Option<String>,
    pub pub_date: Option<String>,
    pub duration: Option<i64>,
    pub season: Option<i64>,
    pub episode_number: Option<i64>,
}

/// Columns for `PersonRef`, prefixed with the people alias `p`.
pub const PERSON_REF_COLS: &str = "p.id, p.slug, p.name, p.img, p.verified";
pub const PERSON_COLS: &str = "p.id, p.slug, p.name, p.bio, p.img, p.website, p.verified, p.created_at, p.updated_at";
pub const PODCAST_COLS: &str = "id, podcastindex_id, podcast_guid, feed_url, title, description, author, owner_name, \
    image, link, has_person_tags, last_crawled_at, crawl_error, created_at, updated_at";
pub const EPISODE_COLS: &str = "e.id, e.podcast_id, e.guid, e.enclosure_url, e.title, e.description, e.link, e.image, \
    e.pub_date, e.duration, e.season, e.episode_number";
