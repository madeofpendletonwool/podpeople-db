//! Admin notifications through ntfy. Fire-and-forget: a dead ntfy never fails a request.

use crate::config::Config;
use crate::net::Http;

#[derive(Clone)]
pub struct Notifier {
    http: Http,
    url: Option<String>,
    base_url: String,
}

impl Notifier {
    pub fn new(http: Http, config: &Config) -> Self {
        let url = config
            .ntfy_topic
            .as_ref()
            .map(|topic| format!("{}/{}", config.ntfy_url.trim_end_matches('/'), topic));
        Notifier { http, url, base_url: config.base_url.clone() }
    }

    pub fn submission(&self, summary: &str) {
        let Some(url) = self.url.clone() else { return };
        let client = self.http.client().clone();
        let body = summary.to_string();
        let review = format!("{}/admin", self.base_url);
        tokio::spawn(async move {
            let res = client
                .post(url)
                .header("Title", "New PodPeopleDB contribution")
                .header("Tags", "busts_in_silhouette")
                .header("Click", review)
                .body(body)
                .send()
                .await;
            if let Err(e) = res {
                tracing::warn!("ntfy notification failed: {e}");
            }
        });
    }
}
