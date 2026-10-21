# PodPeopleDB

The open, community-built database of podcast hosts and guests: who's on which podcast, and where
else they turn up. Live at [podpeopledb.com](https://podpeopledb.com) and built into
[Pinepods](https://www.pinepods.online).

- **Reads the feeds.** Shows that use the Podcasting 2.0 `<podcast:person>` tag are crawled and
  their credits kept in sync, channel- and episode-level.
- **Fills the gaps with the community.** Anyone can add people to a show or an episode: no account,
  name is the only required field, paste a list to add several. Additions go live immediately
  (marked unverified) and admins review them afterwards, with one-click revert.
- **Open data.** JSON API, full JSON dump, scrubbed SQLite download, and a changes feed for mirrors.

## Running it

```yaml
services:
  podpeopledb:
    image: madeofpendletonwool/podpeople_db:latest
    ports: ["8085:8085"]
    environment:
      BASE_URL: https://people.example.com
      ADMIN_USERNAME: admin
      ADMIN_PASSWORD: change-me
      SEARCH_API_URL: https://search.pinepods.online
      IP_HASH_SALT: change-me-to-something-random
    volumes:
      - ./podpeople-data:/app/podpeople-data
```

All settings are documented on the site at `/docs/self-host`.

**Upgrading from v1 (Go):** mount the same data folder. On first start v2 imports the old
`podpeopledb.sqlite` into a new `podpeople-v2.sqlite`, keeping person ids (Pinepods stores them),
admin passwords and pending submissions. The v1 file is never written to.

## API

`/api/v2` is documented at `/docs/api`. The v1 endpoints (`/api/hosts/{id}`, `/api/host-search`,
`/api/podcast/{id}`, `/api/discover/*`) still answer in their old shapes for older Pinepods.

## Development

Rust (axum, sqlx/SQLite, askama templates). Static assets and templates are compiled into the binary.

```sh
DB_PATH=./dev.sqlite ADMIN_PASSWORD=devpassword cargo run
cargo test   # unit + end-to-end tests, no network needed
```

Layout: `src/feed.rs` (RSS parsing), `src/crawler.rs`, `src/store/` (queries), `src/submit.rs`
(contributions), `src/api/` (JSON API, v2 + legacy), `src/web/` (pages + admin), `templates/`,
`static/`, `migrations/`.

## License

GPL-3.0
