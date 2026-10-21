use askama::Template;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::Router;
use serde::Deserialize;

use super::{page_error, render, Layout};
use crate::api::v2::{attach_people, podcast_people, EpisodeWithPeople};
use crate::auth::MaybeAdmin;
use crate::crawler::{self, PodcastKey};
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use crate::store::credits::{self, PodcastPerson};
use crate::store::people::{self, PersonEpisode, PersonPodcast, PersonSearchHit, RankedPerson};
use crate::store::podcasts::{self, PopularPodcast};
use crate::store::{stats, Person, Podcast};

const EPISODES_PER_PAGE: i64 = 25;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(home))
        .route("/discover", get(discover))
        .route("/search", get(search))
        .route("/podcast/{index_id}", get(podcast_by_index_id))
        .route("/podcast/", get(podcast_by_index_query))
        .route("/podcasts/add", get(podcast_by_feed))
        .route("/podcasts/{id}", get(podcast_page))
        .route("/podcasts/{id}/episodes/{episode_id}", get(episode_page))
        .route("/episode/{index_id}/{*audio_url}", get(legacy_episode))
        .route("/people/{id}", get(person_page))
        .route("/people/{id}/{slug}", get(person_page_slug))
        .route("/sitemap.xml", get(sitemap))
        .route("/about", get(about))
        .route("/contribute", get(contribute))
        .route("/docs/api", get(api_docs))
        .route("/docs/self-host", get(self_host))
        // v1 docs URLs
        .route("/docs/what-is-this-for", get(|| async { Redirect::permanent("/about") }))
        .route("/docs/adding-hosts", get(|| async { Redirect::permanent("/contribute") }))
        .route("/docs/integration", get(|| async { Redirect::permanent("/docs/api") }))
}

/// Run a page handler, rendering errors as HTML.
async fn page(state: &AppState, result: AppResult<Response>) -> Response {
    match result {
        Ok(r) => r,
        Err(e) => page_error(state, e).await,
    }
}

#[derive(Template)]
#[template(path = "home.html")]
struct HomePage {
    l: Layout,
    stats: stats::Stats,
    top: Vec<RankedPerson>,
    recent: Vec<RankedPerson>,
    popular: Vec<PopularPodcast>,
}

async fn home(State(state): State<AppState>, MaybeAdmin(admin): MaybeAdmin) -> Response {
    let res = async {
        let l = Layout::new(&state, &admin, "The open database of podcast people", "Find the hosts and guests of any podcast, follow people across shows, and add the ones that are missing.", "home").await;
        Ok(render(HomePage {
            l: l.canonical(&state, "/"),
            stats: stats::get(&state.db).await?,
            top: people::top(&state.db, 12).await?,
            recent: people::recent(&state.db, 6).await?,
            popular: podcasts::popular(&state.db, 9).await?,
        }))
    }
    .await;
    page(&state, res).await
}

#[derive(Template)]
#[template(path = "discover.html")]
struct DiscoverPage {
    l: Layout,
    top: Vec<RankedPerson>,
    recent: Vec<RankedPerson>,
    popular: Vec<PopularPodcast>,
}

async fn discover(State(state): State<AppState>, MaybeAdmin(admin): MaybeAdmin) -> Response {
    let res = async {
        let l = Layout::new(&state, &admin, "Discover", "Podcast people on the most shows, the newest additions, and the shows with the biggest casts.", "discover").await;
        Ok(render(DiscoverPage {
            l,
            top: people::top(&state.db, 48).await?,
            recent: people::recent(&state.db, 24).await?,
            popular: podcasts::popular(&state.db, 24).await?,
        }))
    }
    .await;
    page(&state, res).await
}

#[derive(Deserialize)]
struct SearchQuery {
    #[serde(default)]
    q: String,
}

pub struct IndexHit {
    pub podcastindex_id: i64,
    pub title: String,
    pub author: String,
    pub image: Option<String>,
}

#[derive(Template)]
#[template(path = "search.html")]
struct SearchPage {
    l: Layout,
    q: String,
    people: Vec<PersonSearchHit>,
    local: Vec<PopularPodcast>,
    index: Vec<IndexHit>,
}

async fn search(State(state): State<AppState>, MaybeAdmin(admin): MaybeAdmin, Query(q): Query<SearchQuery>) -> Response {
    let res = async {
        let query = q.q.trim().to_string();
        let mut l = Layout::new(&state, &admin, if query.is_empty() { "Search".to_string() } else { format!("“{query}”") }, "Search podcast hosts, guests and shows.", "search").await;
        l.query = query.clone();
        if query.chars().count() < 2 {
            return Ok(render(SearchPage { l, q: query, people: vec![], local: vec![], index: vec![] }));
        }
        let (people, local, index) = tokio::join!(
            people::search(&state.db, &query, 24),
            podcasts::search(&state.db, &query, 12),
            state.index.search_podcasts(&query),
        );
        let local = local?;
        let known: Vec<i64> = local.iter().filter_map(|p| p.podcastindex_id).collect();
        let index = index
            .unwrap_or_else(|e| {
                tracing::warn!("podcast index search failed: {e}");
                Vec::new()
            })
            .into_iter()
            .filter(|f| f.id > 0 && !known.contains(&f.id))
            .take(12)
            .map(|f| IndexHit { image: f.image(), podcastindex_id: f.id, title: f.title, author: f.author })
            .collect();
        Ok(render(SearchPage { l, q: query, people: people?, local, index }))
    }
    .await;
    page(&state, res).await
}

#[derive(Template)]
#[template(path = "podcast.html")]
struct PodcastPage {
    l: Layout,
    podcast: Podcast,
    people: Vec<PodcastPerson>,
    guests: Vec<PodcastPerson>,
    suggestions: Vec<String>,
    episodes: Vec<EpisodeWithPeople>,
    episode_count: i64,
    page: i64,
    has_more: bool,
}

#[derive(Deserialize)]
struct PageQuery {
    page: Option<i64>,
}

async fn render_podcast(state: &AppState, admin: &Option<crate::auth::Admin>, podcast: Podcast, page: i64) -> AppResult<Response> {
    let page = page.max(1);
    let data = podcast_people(state, podcast).await?;
    let episodes = podcasts::episodes(&state.db, data.podcast.id, EPISODES_PER_PAGE, (page - 1) * EPISODES_PER_PAGE).await?;
    let episodes = attach_people(state, episodes).await?;
    let has_more = page * EPISODES_PER_PAGE < data.episode_count;
    // "Frequent" guests: repeat guests when there are any, otherwise the first few.
    let mut guests = data.guests;
    if guests.iter().any(|g| g.episode_count >= 2) {
        guests.retain(|g| g.episode_count >= 2);
    }
    guests.truncate(12);
    let names: Vec<&str> = data.people.iter().take(4).map(|p| p.person.name.as_str()).collect();
    let description = if names.is_empty() {
        format!("Who hosts {}? Help fill in the hosts and guests.", data.podcast.title)
    } else {
        format!("{} hosted by {}. Hosts, guests and episode credits on PodPeopleDB.", data.podcast.title, names.join(", "))
    };
    let mut l = Layout::new(state, admin, data.podcast.title.clone(), description, "").await.canonical(state, &format!("/podcasts/{}", data.podcast.id));
    l.og_image = data.podcast.image.clone();
    Ok(render(PodcastPage {
        l,
        podcast: data.podcast,
        people: data.people,
        guests,
        suggestions: data.suggestions,
        episodes,
        episode_count: data.episode_count,
        page,
        has_more,
    }))
}

async fn podcast_page(State(state): State<AppState>, MaybeAdmin(admin): MaybeAdmin, Path(id): Path<i64>, Query(q): Query<PageQuery>) -> Response {
    let res = async {
        let podcast = podcasts::get(&state.db, id).await?.ok_or(AppError::NotFound)?;
        render_podcast(&state, &admin, podcast, q.page.unwrap_or(1)).await
    }
    .await;
    page(&state, res).await
}

/// `/podcast/{podcastindex_id}`: the URL Pinepods and v1 link to. Adds the podcast on first visit.
async fn podcast_by_index_id(State(state): State<AppState>, MaybeAdmin(admin): MaybeAdmin, Path(index_id): Path<String>, Query(q): Query<PageQuery>) -> Response {
    let res = async {
        let index_id: i64 = index_id.trim().parse().map_err(|_| AppError::NotFound)?;
        if index_id <= 0 {
            // v1 sent people here for podcasts that aren't in the Podcast Index (#1).
            return Err(AppError::bad_request(
                "This podcast isn't in the Podcast Index. Search for it by name, or add it by its feed URL or by hand.",
            ));
        }
        let key = PodcastKey { podcastindex_id: Some(index_id), ..Default::default() };
        let podcast = crawler::find_or_add(&state, &key).await?.ok_or(AppError::NotFound)?;
        render_podcast(&state, &admin, podcast, q.page.unwrap_or(1)).await
    }
    .await;
    page(&state, res).await
}

#[derive(Deserialize)]
struct IdQuery {
    id: Option<String>,
}

async fn podcast_by_index_query(Query(q): Query<IdQuery>) -> Redirect {
    Redirect::to(&format!("/podcast/{}", q.id.unwrap_or_default().trim()))
}

#[derive(Deserialize)]
struct FeedQuery {
    feed_url: String,
}

/// Open a podcast by feed URL (adding it if it's new), then redirect to its page.
async fn podcast_by_feed(State(state): State<AppState>, Query(q): Query<FeedQuery>) -> Response {
    let res = async {
        let key = PodcastKey { feed_url: Some(q.feed_url), ..Default::default() };
        let podcast = crawler::find_or_add(&state, &key).await?.ok_or(AppError::NotFound)?;
        Ok(Redirect::to(&format!("/podcasts/{}", podcast.id)).into_response())
    }
    .await;
    page(&state, res).await
}

#[derive(Template)]
#[template(path = "episode.html")]
struct EpisodePage {
    l: Layout,
    podcast: Podcast,
    episode: EpisodeWithPeople,
    show_people: Vec<PodcastPerson>,
}

async fn episode_page(State(state): State<AppState>, MaybeAdmin(admin): MaybeAdmin, Path((id, episode_id)): Path<(i64, i64)>) -> Response {
    let res = async {
        let podcast = podcasts::get(&state.db, id).await?.ok_or(AppError::NotFound)?;
        let episode = podcasts::episode(&state.db, episode_id).await?.filter(|e| e.podcast_id == podcast.id).ok_or(AppError::NotFound)?;
        let episode = attach_people(&state, vec![episode]).await?.remove(0);
        let (show, _) = credits::people_for_podcast(&state.db, podcast.id, 0).await?;
        let on_episode: Vec<i64> = episode.people.iter().map(|c| c.person.id).collect();
        let show_people = show.into_iter().filter(|p| !on_episode.contains(&p.person.id)).collect();
        let l = Layout::new(&state, &admin, format!("{} · {}", episode.episode.title, podcast.title), format!("Who's on “{}”, an episode of {}.", episode.episode.title, podcast.title), "")
            .await
            .canonical(&state, &format!("/podcasts/{}/episodes/{}", podcast.id, episode_id));
        Ok(render(EpisodePage { l, podcast, episode, show_people }))
    }
    .await;
    page(&state, res).await
}

/// v1 episode URLs: `/episode/{podcastindex_id}/{url-encoded enclosure URL}`.
async fn legacy_episode(State(state): State<AppState>, Path((index_id, audio_url)): Path<(i64, String)>) -> Response {
    let res = async {
        let key = PodcastKey { podcastindex_id: Some(index_id), ..Default::default() };
        let podcast = crawler::find_or_add(&state, &key).await?.ok_or(AppError::NotFound)?;
        let url = urlencoding::decode(&audio_url).map(|c| c.into_owned()).unwrap_or(audio_url);
        let target = match podcasts::find_episode(&state.db, podcast.id, None, Some(&url)).await? {
            Some(e) => format!("/podcasts/{}/episodes/{}", podcast.id, e.id),
            None => format!("/podcasts/{}", podcast.id),
        };
        Ok(Redirect::permanent(&target).into_response())
    }
    .await;
    page(&state, res).await
}

#[derive(Template)]
#[template(path = "person.html")]
struct PersonPage {
    l: Layout,
    person: Person,
    podcasts: Vec<PersonPodcast>,
    episodes: Vec<PersonEpisode>,
    episode_count: i64,
    page: i64,
    has_more: bool,
}

async fn person_page(state: State<AppState>, admin: MaybeAdmin, Path(id): Path<String>, q: Query<PageQuery>) -> Response {
    person_page_slug(state, admin, Path((id, String::new())), q).await
}

async fn person_page_slug(State(state): State<AppState>, MaybeAdmin(admin): MaybeAdmin, Path((id, slug)): Path<(String, String)>, Query(q): Query<PageQuery>) -> Response {
    let res = async {
        let id: i64 = id.parse().map_err(|_| AppError::NotFound)?;
        let person = people::get(&state.db, id).await?.ok_or(AppError::NotFound)?;
        // Canonicalize merged ids and stale slugs.
        if person.id != id || person.slug != slug {
            let page = q.page.map(|p| format!("?page={p}")).unwrap_or_default();
            return Ok(Redirect::permanent(&format!("/people/{}/{}{page}", person.id, person.slug)).into_response());
        }
        let page = q.page.unwrap_or(1).max(1);
        let podcasts = people::podcasts_for(&state.db, person.id).await?;
        let episode_count = people::episode_count_for(&state.db, person.id).await?;
        let episodes = people::episodes_for(&state.db, person.id, EPISODES_PER_PAGE, (page - 1) * EPISODES_PER_PAGE).await?;
        let shows: Vec<&str> = podcasts.iter().take(3).map(|p| p.podcast.title.as_str()).collect();
        let description = match &person.bio {
            Some(b) => super::h::plain(b, 200),
            None if !shows.is_empty() => format!("{} is on {}.", person.name, shows.join(", ")),
            None => format!("{} on PodPeopleDB.", person.name),
        };
        let mut l = Layout::new(&state, &admin, person.name.clone(), description, "").await.canonical(&state, &format!("/people/{}/{}", person.id, person.slug));
        l.og_image = person.img.clone();
        Ok(render(PersonPage { l, has_more: page * EPISODES_PER_PAGE < episode_count, person, podcasts, episodes, episode_count, page }))
    }
    .await;
    page(&state, res).await
}

#[derive(Template)]
#[template(path = "about.html")]
struct AboutPage {
    l: Layout,
    section: &'static str,
}

#[derive(Template)]
#[template(path = "contribute.html")]
struct ContributePage {
    l: Layout,
    section: &'static str,
}

#[derive(Template)]
#[template(path = "api.html")]
struct ApiPage {
    l: Layout,
    section: &'static str,
    base_url: String,
}

#[derive(Template)]
#[template(path = "self_host.html")]
struct SelfHostPage {
    l: Layout,
    section: &'static str,
}

async fn about(State(state): State<AppState>, MaybeAdmin(admin): MaybeAdmin) -> Response {
    let l = Layout::new(&state, &admin, "What this is", "PodPeopleDB is the open, community-built database of podcast hosts and guests.", "about").await;
    render(AboutPage { l, section: "about" })
}

async fn contribute(State(state): State<AppState>, MaybeAdmin(admin): MaybeAdmin) -> Response {
    let l = Layout::new(&state, &admin, "Contributing", "How to add hosts and guests to PodPeopleDB. No account needed.", "contribute").await;
    render(ContributePage { l, section: "contribute" })
}

async fn api_docs(State(state): State<AppState>, MaybeAdmin(admin): MaybeAdmin) -> Response {
    let l = Layout::new(&state, &admin, "API", "The PodPeopleDB JSON API: podcast people, person profiles, contributions and mirroring.", "docs").await;
    render(ApiPage { l, section: "api", base_url: state.config.base_url.clone() })
}

async fn self_host(State(state): State<AppState>, MaybeAdmin(admin): MaybeAdmin) -> Response {
    let l = Layout::new(&state, &admin, "Self-hosting", "Run your own PodPeopleDB.", "docs").await;
    render(SelfHostPage { l, section: "self-host" })
}

/// People and podcasts, for search engines.
async fn sitemap(State(state): State<AppState>) -> Response {
    let res = async {
        let base = &state.config.base_url;
        let people: Vec<(i64, String, String)> =
            sqlx::query_as("SELECT id, slug, updated_at FROM people WHERE hidden = 0 AND EXISTS (SELECT 1 FROM credits WHERE person_id = people.id) LIMIT 40000")
                .fetch_all(&state.db)
                .await?;
        let podcasts: Vec<(i64, String)> =
            sqlx::query_as("SELECT id, updated_at FROM podcasts WHERE EXISTS (SELECT 1 FROM credits WHERE podcast_id = podcasts.id) LIMIT 10000")
                .fetch_all(&state.db)
                .await?;
        let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n");
        xml.push_str(&format!("<url><loc>{base}/</loc></url>\n"));
        for (id, slug, updated) in people {
            xml.push_str(&format!("<url><loc>{base}/people/{id}/{slug}</loc><lastmod>{}</lastmod></url>\n", &updated[..10.min(updated.len())]));
        }
        for (id, updated) in podcasts {
            xml.push_str(&format!("<url><loc>{base}/podcasts/{id}</loc><lastmod>{}</lastmod></url>\n", &updated[..10.min(updated.len())]));
        }
        xml.push_str("</urlset>\n");
        Ok(([(axum::http::header::CONTENT_TYPE, "application/xml")], xml).into_response())
    }
    .await;
    page(&state, res).await
}
