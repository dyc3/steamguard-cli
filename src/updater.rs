use std::time::Duration;

use serde::de::DeserializeOwned;
use update_informer::{
	http_client::{HeaderMap, HttpClient},
	registry, Check, Version,
};

use crate::debug;

pub fn check_for_update() -> update_informer::Result<Option<Version>> {
	let name = "dyc3/steamguard-cli";
	let version = env!("CARGO_PKG_VERSION");
	debug!("Checking for updates to {} v{}", name, version);
	let informer = update_informer::new(registry::GitHub, name, version)
		.http_client(ReqwestHttpClient)
		.interval(Duration::from_secs(60 * 60 * 24 * 2));

	informer.check_version()
}

struct ReqwestHttpClient;

impl HttpClient for ReqwestHttpClient {
	fn get<T: DeserializeOwned>(
		url: &str,
		timeout: Duration,
		headers: HeaderMap,
	) -> update_informer::Result<T> {
		let mut req = reqwest::blocking::Client::builder()
			.timeout(timeout)
			.build()?
			.get(url)
			.header(reqwest::header::USER_AGENT, "steamguard-cli");

		for (key, value) in headers {
			req = req.header(key, value);
		}

		let resp = req.send()?;
		debug!("Update check response status: {:?}", resp.status());
		let json = resp.json()?;

		Ok(json)
	}
}
