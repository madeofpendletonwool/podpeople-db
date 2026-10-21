//! `/api/v2`: the JSON API used by PinePods and anyone else.

use std::collections::HashMap;

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use super::{clamp_limit, client_kind, ClientIp};
use crate::crawler::{self, PodcastKey};
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use crate::store::credits::{self, CommunityEpisodeCredit, EpisodeCredit, PodcastPerson};
use crate::store::people::{self, PersonEpisode, PersonPodcast, PersonSearchHit, RankedPerson};
use crate::store::podcasts::{self, PopularPodcast};
use crate::store::{stats, Episode, Person, Podcast};
use crate::submit::{self, Origin, PersonEditRequest, SubmissionRequest, SubmissionResult};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/podcasts/lookup", get(lookup_podcast))
        .route("/podcasts/batch", post(batch_podcasts))
        .route("/podcasts/search", get(search_podcasts))
        .route("/podcasts/{id}", get(get_podcast))
        .route("/podcasts/{id}/episodes", get(podcast_episodes))
        .route("/episodes/lookup", get(lookup_episode))
        .route("/episodes/{id}", get(get_episode))
        .route("/people/search", get(search_people))
        .route("/people/{id}", get(get_person))
        .route("/people/{id}/episodes", get(person_episodes))
        .route("/people/{id}/edit", post(edit_person))
        .route("/submissions", post(create_submission))
        .route("/split-names", get(split_names))
        .route("/stats", get(get_stats))
        .route("/discover/recent-people", get(recent_people))
        .route("/discover/top-people", get(top_people))
        .route("/discover/popular-podcasts", get(popular_podcasts))
        .route("/changes", get(changes))
        .route("/dump", get(dump))
}

#[derive(Serialize)]
pub struct PodcastPeople {
    pub podcast: Podcast,
    /// The show's people: hosts, co-hosts, crew credited on the show, and anyone credited as a
    /// host on episodes.
    pub people: Vec<PodcastPerson>,
    /// Guests and other episode-only credits, most frequent first.
    pub guests: Vec<PodcastPerson>,
    /// Names the feed hints at (itunes:author/owner) that nobody has credited yet.
    pub suggestions: Vec<String>,
    pub episode_count: i64,
}

pub async fn podcast_people(state: &AppState, podcast: Podcast) -> AppResult<PodcastPeople> {
    let (people, guests) = credits::people_for_podcast(&state.db, podcast.id, 50).await?;
    let suggestions = podcasts::suggestions(&state.db, &podcast).await?;
    let episode_count = podcasts::episode_count(&state.db, podcast.id).await?;
    Ok(PodcastPeople { podcast, people, guests, suggestions, episode_count })
}

#[derive(Deserialize)]
struct LookupQuery {
    #[serde(flatten)]
    key: PodcastKey,
    /// Add the podcast (from the Podcast Index or its feed) if we don't have it. Default true.
    /// A string because flattened query structs only see strings.
    add: Option<String>,
}

/// Find a podcast by Podcast Index id, feed URL or podcast:guid, adding and crawling it on first
/// sight, and return everyone credited on it.
async fn lookup_podcast(State(state): State<AppState>, Query(q): Query<LookupQuery>) -> AppResult<Json<PodcastPeople>> {
    if q.key.is_empty() {
        return Err(AppError::bad_request("give podcastindex_id, feed_url or guid"));
    }
    let podcast = if q.add.as_deref() != Some("false") {
        crawler::find_or_add(&state, &q.key).await?
    } else {
        crawler::find(&state, &q.key).await?
    };
    let podcast = podcast.ok_or(AppError::NotFound)?;
    Ok(Json(podcast_people(&state, podcast).await?))
}

async fn get_podcast(State(state): State<AppState>, Path(id): Path<i64>) -> AppResult<Json<PodcastPeople>> {
    let podcast = podcasts::get(&state.db, id).await?.ok_or(AppError::NotFound)?;
    Ok(Json(podcast_people(&state, podcast).await?))
}

#[derive(Deserialize)]
struct BatchRequest {
    podcasts: Vec<PodcastKey>,
    /// Also return community credits on individual episodes (feed credits are omitted: the
    /// caller has the feed).
    #[serde(default)]
    include_episode_credits: bool,
}

#[derive(Serialize)]
struct BatchResult {
    /// Position of the key in the request.
    index: usize,
    podcast_id: i64,
    podcastindex_id: Option<i64>,
    feed_url: Option<String>,
    people: Vec<PodcastPerson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    episode_credits: Option<Vec<CommunityEpisodeCredit>>,
}

#[derive(Serialize)]
struct BatchResponse {
    results: Vec<BatchResult>,
}

/// People for many podcasts in one call, from local data only (never crawls). Unknown podcasts
/// are simply absent from `results`. PinePods calls this from its background sync.
async fn batch_podcasts(State(state): State<AppState>, Json(req): Json<BatchRequest>) -> AppResult<Json<BatchResponse>> {
    if req.podcasts.len() > 500 {
        return Err(AppError::bad_request("at most 500 podcasts per batch"));
    }
    let mut results = Vec::new();
    for (index, key) in req.podcasts.iter().enumerate() {
        let Some(podcast) = crawler::find(&state, key).await? else { continue };
        let (people, _) = credits::people_for_podcast(&state.db, podcast.id, 0).await?;
        let episode_credits = if req.include_episode_credits {
            Some(credits::community_episode_credits(&state.db, podcast.id).await?)
        } else {
            None
        };
        if people.is_empty() && episode_credits.as_ref().is_none_or(Vec::is_empty) {
            continue;
        }
        results.push(BatchResult {
            index,
            podcast_id: podcast.id,
            podcastindex_id: podcast.podcastindex_id,
            feed_url: podcast.feed_url,
            people,
            episode_credits,
        });
    }
    Ok(Json(BatchResponse { results }))
}

#[derive(Deserialize)]
struct SearchQuery {
    q: String,
    limit: Option<i64>,
}

#[derive(Serialize)]
struct PodcastSearch {
    /// Podcasts we already have (includes ones not in the Podcast Index).
    local: Vec<PopularPodcast>,
    /// Podcast Index results we don't have yet.
    index: Vec<IndexHit>,
}

#[derive(Serialize)]
struct IndexHit {
    podcastindex_id: i64,
    title: String,
    author: String,
    image: Option<String>,
    feed_url: String,
}

async fn search_podcasts(State(state): State<AppState>, Query(q): Query<SearchQuery>) -> AppResult<Json<PodcastSearch>> {
    let query = q.q.trim();
    if query.chars().count() < 2 {
        return Ok(Json(PodcastSearch { local: vec![], index: vec![] }));
    }
    let limit = clamp_limit(q.limit, 10, 40);
    let local = podcasts::search(&state.db, query, limit).await?;
    let known: Vec<i64> = local.iter().filter_map(|p| p.podcastindex_id).collect();
    let index = match state.index.search_podcasts(query).await {
        Ok(feeds) => feeds
            .into_iter()
            .filter(|f| f.id > 0 && !known.contains(&f.id))
            .take(limit as usize)
            .map(|f| IndexHit { image: f.image(), podcastindex_id: f.id, title: f.title, author: f.author, feed_url: f.url })
            .collect(),
        Err(e) => {
            tracing::warn!("podcast index search failed: {e}");
            Vec::new()
        }
    };
    Ok(Json(PodcastSearch { local, index }))
}

#[derive(Serialize)]
pub struct EpisodeWithPeople {
    #[serde(flatten)]
    pub episode: Episode,
    pub people: Vec<EpisodeCredit>,
}

#[derive(Serialize)]
struct EpisodePage {
    episodes: Vec<EpisodeWithPeople>,
    total: i64,
}

#[derive(Deserialize)]
struct PageQuery {
    limit: Option<i64>,
    offset: Option<i64>,
}

pub async fn attach_people(state: &AppState, episodes: Vec<Episode>) -> AppResult<Vec<EpisodeWithPeople>> {
    let ids: Vec<i64> = episodes.iter().map(|e| e.id).collect();
    let mut by_episode: HashMap<i64, Vec<EpisodeCredit>> = HashMap::new();
    for c in credits::for_episodes(&state.db, &ids).await? {
        by_episode.entry(c.episode_id).or_default().push(c);
    }
    Ok(episodes
        .into_iter()
        .map(|e| {
            let people = by_episode.remove(&e.id).unwrap_or_default();
            EpisodeWithPeople { episode: e, people }
        })
        .collect())
}

async fn podcast_episodes(State(state): State<AppState>, Path(id): Path<i64>, Query(q): Query<PageQuery>) -> AppResult<Json<EpisodePage>> {
    podcasts::get(&state.db, id).await?.ok_or(AppError::NotFound)?;
    let episodes = podcasts::episodes(&state.db, id, clamp_limit(q.limit, 20, 100), q.offset.unwrap_or(0).max(0)).await?;
    Ok(Json(EpisodePage { episodes: attach_people(&state, episodes).await?, total: podcasts::episode_count(&state.db, id).await? }))
}

#[derive(Serialize)]
struct EpisodeDetail {
    episode: EpisodeWithPeople,
    podcast: Podcast,
}

async fn get_episode(State(state): State<AppState>, Path(id): Path<i64>) -> AppResult<Json<EpisodeDetail>> {
    let episode = podcasts::episode(&state.db, id).await?.ok_or(AppError::NotFound)?;
    let podcast = podcasts::get(&state.db, episode.podcast_id).await?.ok_or(AppError::NotFound)?;
    let episode = attach_people(&state, vec![episode]).await?.remove(0);
    Ok(Json(EpisodeDetail { episode, podcast }))
}

#[derive(Deserialize)]
struct EpisodeLookup {
    #[serde(flatten)]
    podcast: PodcastKey,
    episode_guid: Option<String>,
    enclosure_url: Option<String>,
}

/// Episode-level credits for one episode, identified by its podcast and GUID/enclosure URL.
async fn lookup_episode(State(state): State<AppState>, Query(q): Query<EpisodeLookup>) -> AppResult<Json<EpisodeDetail>> {
    let podcast = crawler::find(&state, &q.podcast).await?.ok_or(AppError::NotFound)?;
    let episode = podcasts::find_episode(&state.db, podcast.id, q.episode_guid.as_deref(), q.enclosure_url.as_deref())
        .await?
        .ok_or(AppError::NotFound)?;
    let episode = attach_people(&state, vec![episode]).await?.remove(0);
    Ok(Json(EpisodeDetail { episode, podcast }))
}

async fn search_people(State(state): State<AppState>, Query(q): Query<SearchQuery>) -> AppResult<Json<Vec<PersonSearchHit>>> {
    Ok(Json(people::search(&state.db, &q.q, clamp_limit(q.limit, 10, 50)).await?))
}

#[derive(Serialize)]
pub struct PersonDetail {
    pub person: Person,
    /// Set when the requested id was merged into this person; integrations should store this id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merged_from: Option<i64>,
    pub podcasts: Vec<PersonPodcast>,
    pub episode_count: i64,
    pub recent_episodes: Vec<PersonEpisode>,
}

pub async fn person_detail(state: &AppState, id: i64) -> AppResult<PersonDetail> {
    let person = people::get(&state.db, id).await?.ok_or(AppError::NotFound)?;
    let merged_from = (person.id != id).then_some(id);
    let podcasts = people::podcasts_for(&state.db, person.id).await?;
    let episode_count = people::episode_count_for(&state.db, person.id).await?;
    let recent_episodes = people::episodes_for(&state.db, person.id, 20, 0).await?;
    Ok(PersonDetail { person, merged_from, podcasts, episode_count, recent_episodes })
}

async fn get_person(State(state): State<AppState>, Path(id): Path<i64>) -> AppResult<Json<PersonDetail>> {
    Ok(Json(person_detail(&state, id).await?))
}

async fn person_episodes(State(state): State<AppState>, Path(id): Path<i64>, Query(q): Query<PageQuery>) -> AppResult<Json<Vec<PersonEpisode>>> {
    let person = people::get(&state.db, id).await?.ok_or(AppError::NotFound)?;
    Ok(Json(people::episodes_for(&state.db, person.id, clamp_limit(q.limit, 50, 200), q.offset.unwrap_or(0).max(0)).await?))
}

#[derive(Serialize)]
struct EditResult {
    submission_id: Option<i64>,
    person: Person,
}

async fn edit_person(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Json(req): Json<PersonEditRequest>,
) -> AppResult<Json<EditResult>> {
    let submission_id = submit::edit_person(&state, id, req, Origin { client: client_kind(&headers), ip }).await?;
    let person = people::get(&state.db, id).await?.ok_or(AppError::NotFound)?;
    Ok(Json(EditResult { submission_id, person }))
}

/// Add people to a podcast or episode. Live immediately; see `submit::submit_credits`.
async fn create_submission(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Json(req): Json<SubmissionRequest>,
) -> AppResult<Json<SubmissionResult>> {
    Ok(Json(submit::submit_credits(&state, req, Origin { client: client_kind(&headers), ip }).await?))
}

#[derive(Deserialize)]
struct SplitQuery {
    text: String,
}

async fn split_names(Query(q): Query<SplitQuery>) -> Json<Vec<String>> {
    Json(crate::normalize::split_names(&q.text))
}

async fn get_stats(State(state): State<AppState>) -> AppResult<Json<stats::Stats>> {
    Ok(Json(stats::get(&state.db).await?))
}

#[derive(Deserialize)]
struct LimitQuery {
    limit: Option<i64>,
}

async fn recent_people(State(state): State<AppState>, Query(q): Query<LimitQuery>) -> AppResult<Json<Vec<RankedPerson>>> {
    Ok(Json(people::recent(&state.db, clamp_limit(q.limit, 12, 100)).await?))
}

async fn top_people(State(state): State<AppState>, Query(q): Query<LimitQuery>) -> AppResult<Json<Vec<RankedPerson>>> {
    Ok(Json(people::top(&state.db, clamp_limit(q.limit, 24, 100)).await?))
}

async fn popular_podcasts(State(state): State<AppState>, Query(q): Query<LimitQuery>) -> AppResult<Json<Vec<PopularPodcast>>> {
    Ok(Json(podcasts::popular(&state.db, clamp_limit(q.limit, 12, 100)).await?))
}

#[derive(Deserialize)]
struct ChangesQuery {
    since: String,
}

/// Delta sync. `since` is RFC 3339 or Unix seconds; feed back the response's `until` next time.
async fn changes(State(state): State<AppState>, Query(q): Query<ChangesQuery>) -> AppResult<Json<stats::Changes>> {
    let since = match q.since.trim().parse::<i64>() {
        Ok(secs) => chrono::DateTime::from_timestamp(secs, 0).map(crate::db::fmt_ts),
        Err(_) => crate::db::parse_ts(&q.since).map(crate::db::fmt_ts),
    }
    .ok_or_else(|| AppError::bad_request("since must be RFC 3339 or Unix seconds"))?;
    Ok(Json(stats::changes(&state.db, &since).await?))
}

/// The whole public dataset.
async fn dump(State(state): State<AppState>) -> AppResult<Json<stats::Changes>> {
    Ok(Json(stats::changes(&state.db, "0000").await?))
}
