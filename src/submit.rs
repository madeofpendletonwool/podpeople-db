//! Community contributions. Everything goes live immediately (marked unverified) and is recorded
//! in `submissions` with enough detail for an admin to approve or revert it later.

use serde::{Deserialize, Serialize};

use crate::crawler::{self, PodcastKey};
use crate::error::{AppError, AppResult};
use crate::normalize::{clean_name, clean_text, clean_url, normalize_name};
use crate::state::AppState;
use crate::store::credits::{self, NewCredit};
use crate::store::submissions::{self, NewSubmission, Payload};
use crate::store::{people, podcasts, PersonRef, PodcastRef};

pub const MAX_PEOPLE_PER_SUBMISSION: usize = 25;

#[derive(Debug, Default, Deserialize)]
pub struct PodcastInput {
    #[serde(flatten)]
    pub key: PodcastKey,
    /// For podcasts with no feed at all (#7): create from these if nothing matches the key.
    pub title: Option<String>,
    pub link: Option<String>,
    pub image: Option<String>,
    pub author: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct EpisodeInput {
    pub id: Option<i64>,
    pub guid: Option<String>,
    pub enclosure_url: Option<String>,
    /// Used to create the episode if we don't have it yet.
    pub title: Option<String>,
    pub pub_date: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct PersonInput {
    /// An existing person (picked from typeahead).
    pub person_id: Option<i64>,
    /// Or a name. Matching an existing person exactly reuses them instead of creating a duplicate.
    pub name: Option<String>,
    /// Defaults to "host" for a podcast and "guest" for an episode.
    pub role: Option<String>,
    pub img: Option<String>,
    pub website: Option<String>,
    pub bio: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct SubmissionRequest {
    pub podcast: PodcastInput,
    pub episode: Option<EpisodeInput>,
    pub people: Vec<PersonInput>,
    /// Random per-installation id sent by PinePods servers.
    pub instance_id: Option<String>,
    /// Honeypot. Real clients leave it empty.
    #[serde(default)]
    pub homepage: String,
}

/// Who is submitting: filled in by the HTTP layer.
pub struct Origin {
    pub client: &'static str,
    pub ip: String,
}

#[derive(Debug, Serialize)]
pub struct AddedCredit {
    pub credit_id: i64,
    pub person: PersonRef,
    pub role: String,
    /// False when this exact credit already existed.
    pub created: bool,
    pub new_person: bool,
}

#[derive(Debug, Serialize)]
pub struct SubmissionResult {
    pub submission_id: Option<i64>,
    pub podcast: Option<PodcastRef>,
    pub episode_id: Option<i64>,
    pub credits: Vec<AddedCredit>,
}

pub async fn check_rate(state: &AppState, ip_hash: &str) -> AppResult<()> {
    if submissions::recent_from_ip(&state.db, ip_hash).await? >= state.config.submissions_per_hour as i64 {
        return Err(AppError::TooManyRequests);
    }
    Ok(())
}

pub async fn submit_credits(state: &AppState, req: SubmissionRequest, origin: Origin) -> AppResult<SubmissionResult> {
    if !req.homepage.trim().is_empty() {
        // Bots get a believable success so they don't adapt.
        return Ok(SubmissionResult { submission_id: None, podcast: None, episode_id: None, credits: Vec::new() });
    }
    if req.people.is_empty() {
        return Err(AppError::bad_request("add at least one person"));
    }
    if req.people.len() > MAX_PEOPLE_PER_SUBMISSION {
        return Err(AppError::bad_request(format!("at most {MAX_PEOPLE_PER_SUBMISSION} people per submission")));
    }
    let ip_hash = state.hash_ip(&origin.ip);
    check_rate(state, &ip_hash).await?;

    let mut payload = Payload::default();

    // Podcast: known, or added from the Index/feed, or created by hand.
    let podcast = if req.podcast.key.is_empty() {
        None
    } else {
        crawler::find_or_add(state, &req.podcast.key).await?
    };
    let podcast = match podcast {
        Some(p) => p,
        None => {
            let title = clean_text(req.podcast.title.as_deref(), 200).ok_or_else(|| {
                AppError::bad_request("podcast not found; give its Podcast Index id, feed URL, or a title to add it by hand")
            })?;
            let id = podcasts::insert_manual(
                &state.db,
                &title,
                clean_url(req.podcast.link.as_deref()).as_deref(),
                clean_url(req.podcast.image.as_deref()).as_deref(),
                clean_text(req.podcast.author.as_deref(), 200).as_deref(),
            )
            .await?;
            payload.created_podcast_id = Some(id);
            podcasts::get(&state.db, id).await?.ok_or(AppError::NotFound)?
        }
    };

    let mut tx = state.db.begin().await?;

    // Episode, when crediting a single episode.
    let episode_id = match &req.episode {
        None => None,
        Some(ep) => {
            let found = match ep.id {
                Some(id) => podcasts::episode(&state.db, id).await?.filter(|e| e.podcast_id == podcast.id),
                None => podcasts::find_episode(&state.db, podcast.id, ep.guid.as_deref(), ep.enclosure_url.as_deref()).await?,
            };
            match found {
                Some(e) => Some(e.id),
                None => {
                    let title = clean_text(ep.title.as_deref(), 300)
                        .ok_or_else(|| AppError::bad_request("episode not found; include its title to add it"))?;
                    if ep.guid.is_none() && ep.enclosure_url.is_none() {
                        return Err(AppError::bad_request("an episode needs a guid or enclosure_url"));
                    }
                    let pub_date = ep.pub_date.as_deref().and_then(crate::db::parse_ts).map(crate::db::fmt_ts);
                    let id = podcasts::insert_episode(&mut tx, podcast.id, ep.guid.as_deref(), ep.enclosure_url.as_deref(), &title, pub_date.as_deref()).await?;
                    payload.created_episode_id = Some(id);
                    Some(id)
                }
            }
        }
    };
    let default_role = if episode_id.is_some() { "guest" } else { "host" };

    let sub_id = submissions::create(&mut tx, &NewSubmission {
        kind: "credits",
        summary: String::new(),
        podcast_id: Some(podcast.id),
        person_id: None,
        client: origin.client,
        instance_id: req.instance_id.as_deref().map(|s| &s[..s.len().min(64)]),
        ip_hash: Some(&ip_hash),
    })
    .await?;

    let mut added = Vec::new();
    for input in &req.people {
        let img = clean_url(input.img.as_deref());
        let website = clean_url(input.website.as_deref());
        let bio = clean_text(input.bio.as_deref(), 2000);
        let (person_id, new_person) = match input.person_id {
            Some(id) => {
                let p = people::get(&state.db, id).await?.ok_or_else(|| AppError::bad_request(format!("unknown person {id}")))?;
                (p.id, false)
            }
            None => {
                let name = clean_name(input.name.as_deref().unwrap_or(""));
                if normalize_name(&name).is_empty() {
                    return Err(AppError::bad_request("every person needs a name"));
                }
                match existing_by_name(&mut tx, podcast.id, &name).await? {
                    Some(id) => (id, false),
                    None => {
                        let id = people::insert(&mut tx, &name, bio.as_deref(), img.as_deref(), website.as_deref(), false).await?;
                        payload.created_people.push(id);
                        (id, true)
                    }
                }
            }
        };
        if !new_person {
            fill_empty_fields(&mut tx, person_id, img.as_deref(), website.as_deref(), bio.as_deref(), &mut payload).await?;
        }
        let role = input.role.as_deref().filter(|r| !r.trim().is_empty()).unwrap_or(default_role);
        let (credit_id, created) = credits::add(&mut tx, &NewCredit {
            person_id,
            podcast_id: podcast.id,
            episode_id,
            role,
            group: None,
            source: "community",
            verified: false,
            submission_id: Some(sub_id),
        })
        .await?;
        if created {
            payload.credit_ids.push(credit_id);
        }
        let person = people::get_any(&mut tx, person_id).await?.ok_or(AppError::NotFound)?;
        added.push(AddedCredit {
            credit_id,
            person: person.as_ref(),
            role: crate::normalize::normalize_role(role),
            created,
            new_person,
        });
    }

    let names: Vec<&str> = added.iter().filter(|a| a.created).map(|a| a.person.name.as_str()).collect();
    if names.is_empty() && payload.created_podcast_id.is_none() {
        // Nothing new: don't leave an empty submission in the review queue.
        tx.rollback().await?;
        return Ok(SubmissionResult {
            submission_id: None,
            podcast: Some(podcast_ref(&podcast)),
            episode_id,
            credits: added,
        });
    }
    let target = match episode_id {
        Some(eid) => {
            let title: String = sqlx::query_scalar("SELECT title FROM episodes WHERE id = ?").bind(eid).fetch_one(&mut *tx).await?;
            format!("{} › {}", podcast.title, title)
        }
        None => podcast.title.clone(),
    };
    let summary = format!("{} added to {}", names.join(", "), target);
    submissions::set_payload(&mut tx, sub_id, &payload, &summary).await?;
    tx.commit().await?;
    state.notify.submission(&summary);

    Ok(SubmissionResult {
        submission_id: Some(sub_id),
        podcast: Some(podcast_ref(&podcast)),
        episode_id,
        credits: added,
    })
}

fn podcast_ref(p: &crate::store::Podcast) -> PodcastRef {
    PodcastRef {
        id: p.id,
        podcastindex_id: p.podcastindex_id,
        title: p.title.clone(),
        image: p.image.clone(),
        feed_url: p.feed_url.clone(),
    }
}

/// An existing person a typed name should resolve to: one with that exact (normalized) name,
/// preferring someone already on this podcast, then whoever is credited most.
async fn existing_by_name(conn: &mut sqlx::SqliteConnection, podcast_id: i64, name: &str) -> AppResult<Option<i64>> {
    Ok(sqlx::query_scalar(
        "SELECT p.id FROM people p
         WHERE p.name_normalized = ? AND p.hidden = 0
         ORDER BY EXISTS (SELECT 1 FROM credits c WHERE c.person_id = p.id AND c.podcast_id = ?) DESC,
                  (SELECT COUNT(*) FROM credits c WHERE c.person_id = p.id) DESC, p.id
         LIMIT 1",
    )
    .bind(normalize_name(name))
    .bind(podcast_id)
    .fetch_optional(&mut *conn)
    .await?)
}

/// Contributors can add a missing photo/link/bio while crediting someone. Only empty fields are
/// filled; the previous (empty) values are recorded so a revert clears them again.
async fn fill_empty_fields(
    conn: &mut sqlx::SqliteConnection,
    person_id: i64,
    img: Option<&str>,
    website: Option<&str>,
    bio: Option<&str>,
    payload: &mut Payload,
) -> AppResult<()> {
    let Some(p) = people::get_any(conn, person_id).await? else { return Ok(()) };
    let mut after = serde_json::Map::new();
    if p.img.as_deref().is_none_or(str::is_empty) {
        if let Some(v) = img {
            after.insert("img".into(), v.into());
        }
    }
    if p.website.as_deref().is_none_or(str::is_empty) {
        if let Some(v) = website {
            after.insert("website".into(), v.into());
        }
    }
    if p.bio.as_deref().is_none_or(str::is_empty) {
        if let Some(v) = bio {
            after.insert("bio".into(), v.into());
        }
    }
    if after.is_empty() {
        return Ok(());
    }
    let get = |k: &str| after.get(k).and_then(|v| v.as_str());
    people::update(conn, person_id, &people::PersonEdit { name: None, bio: get("bio"), img: get("img"), website: get("website") }).await?;
    let fills = payload.fills.get_or_insert_with(Default::default);
    fills.push(Fill { person_id, fields: after.keys().cloned().collect() });
    Ok(())
}

pub use crate::store::submissions::Fill;

#[derive(Debug, Default, Deserialize)]
pub struct PersonEditRequest {
    pub name: Option<String>,
    pub bio: Option<String>,
    pub img: Option<String>,
    pub website: Option<String>,
    #[serde(default)]
    pub homepage: String,
}

/// Edit a person's details. Applied immediately; the previous values are kept for revert.
pub async fn edit_person(state: &AppState, person_id: i64, req: PersonEditRequest, origin: Origin) -> AppResult<Option<i64>> {
    if !req.homepage.trim().is_empty() {
        return Ok(None);
    }
    let ip_hash = state.hash_ip(&origin.ip);
    check_rate(state, &ip_hash).await?;
    let person = people::get(&state.db, person_id).await?.ok_or(AppError::NotFound)?;

    // Only fields that were sent and actually change. Empty string clears (except the name).
    let mut before = serde_json::Map::new();
    let mut after = serde_json::Map::new();
    let mut diff = |key: &str, old: Option<&str>, new: Option<String>| {
        if let Some(new) = new {
            if old.unwrap_or("") != new {
                before.insert(key.into(), old.unwrap_or("").into());
                after.insert(key.into(), new.into());
            }
        }
    };
    let name = req.name.as_deref().map(clean_name).filter(|n| !normalize_name(n).is_empty());
    diff("name", Some(&person.name), name);
    let url_field = |v: &Option<String>| v.as_ref().map(|s| if s.trim().is_empty() { String::new() } else { clean_url(Some(s)).unwrap_or_default() });
    diff("img", person.img.as_deref(), url_field(&req.img));
    diff("website", person.website.as_deref(), url_field(&req.website));
    diff("bio", person.bio.as_deref(), req.bio.as_ref().map(|b| b.trim().chars().take(2000).collect()));
    if after.is_empty() {
        return Ok(None);
    }

    let mut tx = state.db.begin().await?;
    let summary = format!("Edited {} ({})", person.name, after.keys().cloned().collect::<Vec<_>>().join(", "));
    let sub_id = submissions::create(&mut tx, &NewSubmission {
        kind: "person_edit",
        summary: summary.clone(),
        podcast_id: None,
        person_id: Some(person_id),
        client: origin.client,
        instance_id: None,
        ip_hash: Some(&ip_hash),
    })
    .await?;
    let get = |k: &str| after.get(k).and_then(|v| v.as_str());
    people::update(&mut tx, person_id, &people::PersonEdit { name: get("name"), bio: get("bio"), img: get("img"), website: get("website") }).await?;
    let payload = Payload {
        before: Some(serde_json::Value::Object(before)),
        after: Some(serde_json::Value::Object(after.clone())),
        ..Default::default()
    };
    submissions::set_payload(&mut tx, sub_id, &payload, &summary).await?;
    tx.commit().await?;
    state.notify.submission(&summary);
    Ok(Some(sub_id))
}
